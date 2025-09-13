# app/main.py
from __future__ import annotations

import asyncio
import inspect
import json
import os
import secrets
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

APP_VERSION = "v3.2"

# ---------------------------------------------------------------------------
# Optionele interne imports (engine/schemas/notify bestaan al in je repo)
# ---------------------------------------------------------------------------
schemas = None
decide_engine = None
notify_mod = None

try:
    from app import schemas as _schemas  # type: ignore
    schemas = _schemas
except Exception:
    pass

try:
    from app.engine import decide as _decide_engine  # type: ignore
    decide_engine = _decide_engine
except Exception:
    pass

try:
    from app import notify as _notify  # type: ignore
    notify_mod = _notify
except Exception:
    notify_mod = None


def _notify(event: str, payload: Dict[str, Any], headers: Dict[str, str]) -> None:
    """
    Non-blocking, best-effort notify -> JSONL + (optioneel) Telegram.
    Onderdrukken met header 'X-No-Notify: 1'.
    """
    if headers.get("x-no-notify", "") in ("1", "true", "True"):
        return
    if notify_mod and hasattr(notify_mod, "notify_event"):
        try:
            # notify_event(event:str, data:dict)
            notify_mod.notify_event(event, payload)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Config uit env
# ---------------------------------------------------------------------------
API_KEY = os.getenv("API_KEY", "").strip()
EXEC_ENABLED = os.getenv("EXEC_ENABLED", "false").lower() in ("1", "true", "yes")

# Saxo env
SAXO_ENV = os.getenv("SAXO_ENV", "SIM").upper()
SAXO_BASEURL = os.getenv(
    "SAXO_BASEURL",
    "https://gateway.saxobank.com/sim/openapi" if SAXO_ENV == "SIM" else "https://gateway.saxobank.com/openapi",
)
SAXO_AUTH_URL = os.getenv(
    "SAXO_AUTH_URL",
    "https://sim.logonvalidation.net/authorize" if SAXO_ENV == "SIM" else "https://live.logonvalidation.net/authorize",
)
SAXO_TOKEN_URL = os.getenv(
    "SAXO_TOKEN_URL",
    "https://sim.logonvalidation.net/token" if SAXO_ENV == "SIM" else "https://live.logonvalidation.net/token",
)
SAXO_REDIRECT_URL = os.getenv("SAXO_REDIRECT_URL", "")
SAXO_APP_KEY = os.getenv("SAXO_APP_KEY", "")
SAXO_APP_SECRET = os.getenv("SAXO_APP_SECRET", "")
SAXO_ACCOUNT_KEY = os.getenv("SAXO_ACCOUNT_KEY", "")  # verplicht voor échte orders

# UIC mapping (ticker -> Saxo UIC)
def _load_uic_map() -> Dict[str, int]:
    raw = os.getenv("TICKER_UIC_MAP", "")
    if not raw:
        return {}
    try:
        m = json.loads(raw)
        # normaliseer keys naar upper
        return {str(k).upper(): int(v) for k, v in m.items()}
    except Exception:
        return {}


UIC_MAP = _load_uic_map()

TOKEN_FILE = Path("/mnt/data/saxo_token.json")
_oauth_states: set[str] = set()

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(title="sniperbot", version=APP_VERSION)

# CORS – laat je eigen toolings toe; pas desgewenst aan
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# API-key guard
# ---------------------------------------------------------------------------
def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    if API_KEY:
        if not x_api_key or x_api_key != API_KEY:
            raise HTTPException(status_code=401, detail="invalid api key")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _now_et_iso() -> str:
    # Render draait meestal UTC; voor weergave houden we het simpel bij UTC-ISO
    return datetime.now(timezone.utc).isoformat()


async def _call_engine_decide(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not decide_engine:
        raise HTTPException(status_code=501, detail="engine not available")
    # zoek functie
    fn = getattr(decide_engine, "decide", None) or getattr(decide_engine, "decide_one", None)
    if not fn:
        raise HTTPException(status_code=501, detail="decide() not available")
    if inspect.iscoroutinefunction(fn):
        return await fn(payload)
    # sync
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: fn(payload))


async def _call_engine_scan(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not decide_engine:
        raise HTTPException(status_code=501, detail="engine not available")
    fn = getattr(decide_engine, "scan", None) or getattr(decide_engine, "scan_candidates", None)
    if fn:
        if inspect.iscoroutinefunction(fn):
            return await fn(payload)
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: fn(payload))
    # Fallback: loop over candidates en roep decide aan
    cands = payload.get("candidates", [])
    top_k = int(payload.get("top_k", 3))
    results = []
    for c in cands:
        r = await _call_engine_decide(c)
        results.append(r)
    tradables = [r for r in results if str(r.get("decision", "")).startswith("TRADE")]
    tradables_sorted = sorted(tradables, key=lambda r: float(r.get("sniper_score", 0.0)), reverse=True)[:top_k]
    return {
        "universe_name": payload.get("universe_name", "custom"),
        "scanned": len(results),
        "tradeables": len(tradables),
        "top": tradables_sorted,
        "summary": {
            "TRADE_LONG": sum(1 for r in results if r.get("decision") == "TRADE_LONG"),
            "TRADE_SHORT": sum(1 for r in results if r.get("decision") == "TRADE_SHORT"),
            "NO_TRADE": sum(1 for r in results if r.get("decision") == "NO_TRADE"),
            "rejections": {},  # engine kan dit bepalen; leeg laten als onbekend
        },
        "meta": {"version": APP_VERSION, "nowET": _now_et_iso(), "latency_ms": 150, "universe_size": len(cands)},
    }


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/healthz")
def healthz():
    return {"ok": True, "version": APP_VERSION}


# ---------------------------------------------------------------------------
# Decide
# ---------------------------------------------------------------------------
@app.post("/decide", dependencies=[Depends(require_api_key)])
async def decide_endpoint(
    request: Request,
):
    try:
        body: Dict[str, Any] = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid json")

    t0 = datetime.now()
    out = await _call_engine_decide(body)
    out.setdefault("meta", {})
    out["meta"].update({"version": APP_VERSION, "nowET": _now_et_iso()})

    # notify (non-blocking)
    try:
        event = out.get("decision", "NO_DECISION")
        _notify(event, {"in": body, "out": out, "ms": (datetime.now() - t0).total_seconds() * 1000}, request.headers)
    except Exception:
        pass

    return JSONResponse(out)


# ---------------------------------------------------------------------------
# Scan (batch decide)
# ---------------------------------------------------------------------------
@app.post("/scan", dependencies=[Depends(require_api_key)])
async def scan_endpoint(request: Request):
    try:
        body: Dict[str, Any] = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid json")

    t0 = datetime.now()
    out = await _call_engine_scan(body)
    try:
        _notify("SCAN", {"in": body, "out": out, "ms": (datetime.now() - t0).total_seconds() * 1000}, request.headers)
    except Exception:
        pass
    return JSONResponse(out)


# ---------------------------------------------------------------------------
# Universe helper (optioneel; laat engine evt. overriden)
# GET /universe?name=SP100|custom
# ---------------------------------------------------------------------------
_DEFAULT_SP100 = [
    # Compacte lijst; je eigen engine kan de volledige lijst leveren.
    "AAPL", "MSFT", "NVDA", "GOOGL", "GOOG", "AMZN", "META", "TSLA",
    "JNJ", "JPM", "XOM", "PG", "HD", "V", "MA", "LLY", "UNH", "CVX",
]

def _extra_tickers() -> list[str]:
    raw = os.getenv("EXTRA_TICKERS", "")
    if not raw.strip():
        return []
    return [t.strip().upper() for t in raw.split(",") if t.strip()]

@app.get("/universe", dependencies=[Depends(require_api_key)])
def universe(name: str = "SP100"):
    name = name.lower()
    if name == "sp100":
        tickers = _DEFAULT_SP100 + [t for t in _extra_tickers() if t not in _DEFAULT_SP100]
        return {"universe_name": "SP100", "count": len(tickers), "tickers": tickers}
    if name == "custom":
        t = _extra_tickers()
        return {"universe_name": "custom", "count": len(t), "tickers": t}
    return {"universe_name": name, "count": 0, "tickers": []}


# ---------------------------------------------------------------------------
# Saxo OAuth helpers
# ---------------------------------------------------------------------------
def _save_token(payload: dict):
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(payload.get("expires_in", 0)) - 60)
    data = {
        "access_token": payload.get("access_token"),
        "refresh_token": payload.get("refresh_token"),
        "token_type": payload.get("token_type"),
        "expires_at": expires_at.isoformat(),
    }
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    TOKEN_FILE.write_text(json.dumps(data))


def _load_token() -> Optional[dict]:
    if not TOKEN_FILE.exists():
        return None
    try:
        return json.loads(TOKEN_FILE.read_text())
    except Exception:
        return None


async def _refresh_if_needed() -> Optional[dict]:
    tok = _load_token()
    if not tok:
        return None
    try:
        exp = datetime.fromisoformat(tok["expires_at"])
    except Exception:
        exp = datetime.now(timezone.utc) - timedelta(seconds=1)
    if exp > datetime.now(timezone.utc) + timedelta(seconds=15):
        return tok  # nog geldig

    # Refresh
    if not tok.get("refresh_token"):
        return None
    form = {
        "grant_type": "refresh_token",
        "refresh_token": tok["refresh_token"],
        "client_id": SAXO_APP_KEY,
        "client_secret": SAXO_APP_SECRET,
        "redirect_uri": SAXO_REDIRECT_URL,
    }
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(SAXO_TOKEN_URL, data=form, headers={"Content-Type": "application/x-www-form-urlencoded"})
        r.raise_for_status()
        payload = r.json()
        _save_token(payload)
    return _load_token()


# ---------------------------------------------------------------------------
# Saxo OAuth routes
# ---------------------------------------------------------------------------
@app.get("/oauth/saxo/start")
def saxo_oauth_start():
    if not (SAXO_APP_KEY and SAXO_REDIRECT_URL):
        return HTMLResponse("<b>Misconfiguratie:</b> zet SAXO_APP_KEY en SAXO_REDIRECT_URL in env.", status_code=500)
    state = secrets.token_urlsafe(24)
    _oauth_states.add(state)
    params = {
        "response_type": "code",
        "client_id": SAXO_APP_KEY,
        "redirect_uri": SAXO_REDIRECT_URL,
        "state": state,
    }
    url = SAXO_AUTH_URL + "?" + urllib.parse.urlencode(params)
    return RedirectResponse(url)


@app.get("/oauth/saxo/callback")
async def saxo_oauth_callback(code: Optional[str] = None, state: Optional[str] = None):
    if not code:
        return HTMLResponse("Geen 'code' ontvangen.", status_code=400)
    if state and state in _oauth_states:
        _oauth_states.discard(state)

    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": SAXO_REDIRECT_URL,
        "client_id": SAXO_APP_KEY,
        "client_secret": SAXO_APP_SECRET,
    }
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(SAXO_TOKEN_URL, data=form, headers={"Content-Type": "application/x-www-form-urlencoded"})
        if r.status_code >= 400:
            return HTMLResponse(f"Token exchange failed: {r.status_code} {r.text}", status_code=500)
        payload = r.json()
        _save_token(payload)

    return HTMLResponse("<h3>✅ Saxo gekoppeld</h3><p>Token opgeslagen. Je kunt dit venster sluiten.</p>")


@app.get("/saxo/accounts", dependencies=[Depends(require_api_key)])
async def saxo_accounts():
    tok = await _refresh_if_needed()
    if not tok:
        return {"ok": False, "error": "no_token"}
    headers = {"Authorization": f"Bearer {tok['access_token']}"}
    async with httpx.AsyncClient(timeout=20, headers=headers) as client:
        r = await client.get(f"{SAXO_BASEURL}/port/v1/accounts/me")
        if r.status_code >= 400:
            return {"ok": False, "status": r.status_code, "body": r.text}
        return {"ok": True, "data": r.json()}


# ---------------------------------------------------------------------------
# Execute (paper by default; live wanneer alle checks slagen)
# Body: { ticker, shares, entry, stop, confirm }
# ---------------------------------------------------------------------------
@app.post("/execute", dependencies=[Depends(require_api_key)])
async def execute_order(request: Request):
    """
    - DRY_RUN wanneer EXEC_ENABLED=false of geen geldige Saxo token of ontbrekende accountKey/UIC mapping.
    - Live SIM/Live pas wanneer confirm=true + alles aanwezig.
    """
    try:
        body: Dict[str, Any] = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid json")

    ticker = str(body.get("ticker", "")).upper()
    shares = int(body.get("shares", 0))
    entry = float(body.get("entry", 0.0))
    stop = float(body.get("stop", 0.0)) if body.get("stop") is not None else 0.0
    confirm = bool(body.get("confirm", False))

    # preflight – voorwaarden voor live
    preflight_reasons = []
    if not EXEC_ENABLED:
        preflight_reasons.append("EXEC_DISABLED")
    tok = await _refresh_if_needed()
    if not tok:
        preflight_reasons.append("NO_TOKEN")
    if not SAXO_ACCOUNT_KEY:
        preflight_reasons.append("NO_ACCOUNT_KEY")
    uic = UIC_MAP.get(ticker)
    if not uic:
        preflight_reasons.append("NO_UIC")

    if (preflight_reasons) or (not confirm):
        # DRY RUN pad
        return {
            "ok": True,
            "mode": "DRY_RUN",
            "entry_result": {"dry_run": True, "status": "skip", "reason": "preflight" if preflight_reasons else "confirm"},
            "stop_result": {"dry_run": True, "status": "skip", "reason": "preflight" if preflight_reasons else "confirm"},
        }

    # --- Live order pad (SIM/Live) ---
    headers = {"Authorization": f"Bearer {tok['access_token']}", "Content-Type": "application/json"}
    # 1) Market BUY
    order_req = {
        "AccountKey": SAXO_ACCOUNT_KEY,
        "Uic": uic,
        "AssetType": "Stock",
        "BuySell": "Buy",
        "OrderType": "Market",
        "Amount": shares,
        "ManualOrder": False,
    }

    async with httpx.AsyncClient(timeout=20, headers=headers) as client:
        r1 = await client.post(f"{SAXO_BASEURL}/trade/v2/orders", content=json.dumps(order_req))
        if r1.status_code >= 400:
            return {"ok": False, "where": "entry", "status": r1.status_code, "body": r1.text}
        entry_res = r1.json()

        # 2) (optioneel) plaats een stop-loss MKT
        stop_res: Dict[str, Any] | None = None
        if stop and stop > 0:
            sl_req = {
                "AccountKey": SAXO_ACCOUNT_KEY,
                "Uic": uic,
                "AssetType": "Stock",
                "BuySell": "Sell",
                "OrderType": "StopIfTraded",
                "StopPrice": round(float(stop), 4),
                "Amount": shares,
                "ManualOrder": False,
            }
            r2 = await client.post(f"{SAXO_BASEURL}/trade/v2/orders", content=json.dumps(sl_req))
            if r2.status_code >= 400:
                stop_res = {"ok": False, "status": r2.status_code, "body": r2.text}
            else:
                stop_res = r2.json()

    out = {"ok": True, "mode": "LIVE", "entry_result": entry_res, "stop_result": stop_res or {"placed": False}}
    try:
        _notify("EXECUTE", {"in": body, "out": out}, request.headers)
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# Root
# ---------------------------------------------------------------------------
@app.get("/")
def root():
    return {
        "name": "sniperbot",
        "version": APP_VERSION,
        "time": _now_et_iso(),
        "docs": "/docs",
    }
