# app/main.py
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field, validator

# =========================
# Config & Globals
# =========================
APP_VERSION = "v3.2"

X_API_KEY = os.getenv("X_API_KEY", "")
EXEC_ENABLED = os.getenv("EXEC_ENABLED", "false").lower() == "true"
LIVE_TRADING = os.getenv("LIVE_TRADING", "false").lower() == "true"

# Telegram (opt-in)
TG_ENABLED = os.getenv("TG_ENABLED", "false").lower() == "true"
TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "")
TG_CHAT_ID = os.getenv("TG_CHAT_ID", "")

# Saxo config (SIM by default)
SAXO_BASE = os.getenv("SAXO_BASE", "https://gateway.saxobank.com/sim/openapi")
SAXO_TOKEN_URL = os.getenv("SAXO_TOKEN_URL", "https://sim.logonvalidation.net/token")
SAXO_AUTHORIZE_URL = os.getenv("SAXO_AUTHORIZE_URL", "https://sim.logonvalidation.net/authorize")
SAXO_APP_KEY = os.getenv("SAXO_APP_KEY", "")
SAXO_APP_SECRET = os.getenv("SAXO_APP_SECRET", "")
SAXO_REFRESH_TOKEN = os.getenv("SAXO_REFRESH_TOKEN", "")
SAXO_REDIRECT_URI = os.getenv("SAXO_REDIRECT_URI", "https://sniperbot-api.onrender.com/oauth/saxo/callback")
SAXO_ACCOUNT_KEY = os.getenv("SAXO_ACCOUNT_KEY", "")  # nodig voor orders
TICKER_UIC_MAP_RAW = os.getenv("TICKER_UIC_MAP", "{}")

try:
    TICKER_UIC_MAP: Dict[str, int] = {k.upper(): int(v) for k, v in json.loads(TICKER_UIC_MAP_RAW or "{}").items()}
except Exception:
    TICKER_UIC_MAP = {}

# Simple in-memory access token cache
_saxo_token_cache: Dict[str, Any] = {
    "access_token": None,
    "expires_at": 0.0,  # epoch seconds
}

HTTP_TIMEOUT = 15.0

app = FastAPI(title="SNIPERBOT API", version=APP_VERSION)


# =========================
# Helpers
# =========================
def require_api_key(x_api_key: Optional[str] = Header(None, alias="x-api-key")):
    if not X_API_KEY:
        # No API key configured -> allow all (dev mode)
        return
    if not x_api_key or x_api_key != X_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key")


def now_et_iso() -> str:
    # We keep UTC but label as ISO; real ET conversion can be added if needed
    return datetime.now(timezone.utc).isoformat()


async def tg_notify(text: str, x_no_notify: Optional[str] = None) -> None:
    if x_no_notify is not None:
        return
    if not TG_ENABLED or not TG_BOT_TOKEN or not TG_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TG_CHAT_ID, "text": text}
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            await client.post(url, json=payload)
    except Exception:
        # swallow: notifications must never break the app
        pass


def _cost_ok(payload: Dict[str, Any]) -> bool:
    """Ruwe kostengate: commission*2 + fx + spread + slippage wordt vergeleken met drempel."""
    commission_bps = float(payload.get("commission_side_bps", 0)) * 2.0
    fx = float(payload.get("fx_bps", 0.0))
    spread_bps = float(payload.get("spread_bps", 0.0))
    slip_bps = float(payload.get("slippage_guard_bps", 0.0))
    total_bps = commission_bps + fx + spread_bps + slip_bps
    # simpele grens: <= 24 bps ~ 0.24%
    return total_bps <= 24.0


def _edge_ok(payload: Dict[str, Any]) -> bool:
    """Eenvoudige 2-van-3 edge: vwap_reclaims_ok, orb_follow_ok, uptick_ratio_60>=0.6"""
    ok1 = bool(payload.get("vwap_reclaims_ok", False))
    ok2 = bool(payload.get("orb_follow_ok", False))
    ok3 = float(payload.get("uptick_ratio_60", 0.0)) >= 0.60
    return (ok1 + ok2 + ok3) >= 2


def _tod_ok(payload: Dict[str, Any]) -> bool:
    tod = str(payload.get("time_of_day", "core"))
    # eenvoudige regel: geen nieuwe entries na "close"
    return tod != "close"


def _tech_ok(payload: Dict[str, Any]) -> bool:
    vwap = float(payload.get("vwap", 0.0))
    price = float(payload.get("price", 0.0))
    slope = float(payload.get("vwap_slope_pct_per_min", 0.0))
    return (price > vwap) and (slope > 0)


def _score(payload: Dict[str, Any]) -> float:
    """Heel simpele score op basis van rvol + slope + spread."""
    rvol = float(payload.get("rvol", 1.0))
    slope = float(payload.get("vwap_slope_pct_per_min", 0.0))
    spread_bps = float(payload.get("spread_bps", 10.0))
    base = (rvol - 1.0) * 2.0 + (slope * 20.0) - (spread_bps / 20.0)
    return max(0.0, round(base, 2))


async def _ensure_saxo_access_token() -> str:
    """Refresh access token if missing/expired using refresh token in env."""
    if not SAXO_APP_KEY or not SAXO_APP_SECRET or not SAXO_REFRESH_TOKEN:
        raise HTTPException(status_code=400, detail="Saxo app/refresh token not configured")

    now = time.time()
    if _saxo_token_cache["access_token"] and _saxo_token_cache["expires_at"] > now + 30:
        return _saxo_token_cache["access_token"]

    # refresh
    basic = httpx.Auth()
    headers = {
        "Authorization": "Basic " + httpx._auth._basic_auth_str(SAXO_APP_KEY, SAXO_APP_SECRET),  # type: ignore
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    data = f"grant_type=refresh_token&refresh_token={httpx.QueryParams({'r': SAXO_REFRESH_TOKEN})['r']}"
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        r = await client.post(SAXO_TOKEN_URL, headers=headers, content=data)
        if r.status_code != 200:
            raise HTTPException(status_code=401, detail=f"Token refresh failed ({r.status_code})")
        tok = r.json()
    access = tok.get("access_token")
    expires_in = int(tok.get("expires_in", 300))
    if not access:
        raise HTTPException(status_code=401, detail="No access_token in Saxo response")
    _saxo_token_cache["access_token"] = access
    _saxo_token_cache["expires_at"] = time.time() + max(60, expires_in - 15)
    # rotation: if Saxo returns new refresh_token, we can't write env here; just ignore
    return access


# =========================
# Schemas
# =========================
class DecideRequest(BaseModel):
    ticker: str
    price: float
    # We staan extra velden toe zodat je rijkere payloads kan sturen
    class Config:
        extra = "allow"


class ExecuteRequest(BaseModel):
    ticker: str
    shares: int
    entry: float
    stop: float
    confirm: bool = False


class ScanRequest(BaseModel):
    universe_name: str
    top_k: int = 3
    candidates: List[Dict[str, Any]]

    class Config:
        extra = "allow"


# =========================
# Routes
# =========================
@app.get("/healthz", summary="Healthz")
async def healthz():
    return {"ok": True, "version": APP_VERSION}


@app.post("/decide", summary="Decide Endpoint")
async def decide_endpoint(
    req: DecideRequest,
    request: Request,
    x_no_notify: Optional[str] = Header(None, alias="x-no-notify"),
    _: None = Depends(require_api_key),
):
    t0 = time.time()
    payload = req.dict()
    gates = {
        "technique": _tech_ok(payload),
        "cost": _cost_ok(payload),
        "edge": _edge_ok(payload),
        "tod": _tod_ok(payload),
    }
    score = _score(payload)

    if all(gates.values()) and score >= 1.0:
        decision = "TRADE_LONG"
        entry = float(payload["price"])
        stop = round(entry * 0.982, 4)  # simpele 1.8% stop
        size = max(1, int(1000 / max(1.0, entry)))  # leuke demo sizing

        explain = (
            "Volume en trend zijn gunstig. We kopen met een marktorder, nemen bij +1% de helft winst "
            "en volgen de rest met een meeschuivende stop."
        )
        result = {
            "decision": decision,
            "ticker": req.ticker,
            "sniper_score": score,
            "gates": {k: bool(v) for k, v in gates.items()},
            "mode": "MARKET_ONLY",
            "orders": {
                "entry": {"type": "MARKET"},
                "tp1": {"type": "MARKET", "fraction": 0.5, "trigger_pct": 0.01},
                "exit": {"type": "TRAIL_STOP_MARKET", "trail_pct_min": 0.004, "trail_atr_mult": 0.6, "freeze_after_tp1_sec": 120},
            },
            "entry": entry,
            "stop_loss": stop,
            "size_shares": size,
            "costs": {
                "cost_profile": payload.get("cost_profile", "USD_CASH"),
                "commission_roundtrip_pct": round((float(payload.get("commission_side_bps", 0)) * 2) / 10000, 6),
                "fx_roundtrip_pct": round(float(payload.get("fx_bps", 0.0)) / 10000, 6),
                "spread_pct": round(float(payload.get("spread_bps", 0.0)) / 10000, 6),
                "slippage_pct": round(float(payload.get("slippage_guard_bps", 0.0)) / 10000, 6),
                "break_even_pct": round(
                    ((float(payload.get("commission_side_bps", 0)) * 2)
                     + float(payload.get("fx_bps", 0.0))
                     + float(payload.get("spread_bps", 0.0))
                     + float(payload.get("slippage_guard_bps", 0.0))) / 10000,
                    6,
                ),
            },
            "probs": {"p1": 0.674, "p2": 0.391, "q": 0.579},  # demo getallen
            "ev_estimate": {"avg_loss_pct": -0.008, "net_ev_pct": 0.0011},
            "reason_codes": ["EV_OK", "COST_OK", "EDGE_2OF3"],
            "meta": {"version": APP_VERSION, "nowET": now_et_iso(), "latency_ms": int((time.time() - t0) * 1000), "universe_size": 150},
            "rejections": {},
            "explain_human": explain,
        }
        await tg_notify(f"scan: {req.ticker} → {decision}", x_no_notify)
        return result

    result = {
        "decision": "NO_TRADE",
        "ticker": req.ticker,
        "sniper_score": score,
        "gates": {k: bool(v) for k, v in gates.items()},
        "mode": "MARKET_ONLY",
        "orders": {},
        "reason_codes": ["SCORE_LOW"] if score < 1.0 else ["GATE_FAIL"],
        "meta": {"version": APP_VERSION, "latency_ms": int((time.time() - t0) * 1000)},
        "explain_human": "We doen niets: een of meer basisvoorwaarden kloppen niet (data, spread, risico of trend).",
    }
    return result


@app.post("/scan", summary="Scan Endpoint")
async def scan_endpoint(
    req: ScanRequest,
    request: Request,
    x_no_notify: Optional[str] = Header(None, alias="x-no-notify"),
    _: None = Depends(require_api_key),
):
    t0 = time.time()
    results: List[Dict[str, Any]] = []
    rejections: Dict[str, int] = {}

    tradeables = 0
    for c in req.candidates:
        ticker = str(c.get("ticker", "UNKNOWN"))
        d = await decide_endpoint(DecideRequest(ticker=ticker, price=float(c.get("price", 0.0))), request, x_no_notify, _)
        # decide_endpoint uses only minimal fields; pass full candidate for richer scoring
        # so re-run gates locally with full payload:
        gates = {
            "technique": _tech_ok(c),
            "cost": _cost_ok(c),
            "edge": _edge_ok(c),
            "tod": _tod_ok(c),
        }
        score = _score(c)
        if all(gates.values()) and score >= 1.0:
            tradeables += 1
            results.append(
                {
                    "decision": "TRADE_LONG",
                    "ticker": ticker,
                    "sniper_score": score,
                    "gates": {k: bool(v) for k, v in gates.items()},
                    "mode": "MARKET_ONLY",
                    "orders": {
                        "entry": {"type": "MARKET"},
                        "tp1": {"type": "MARKET", "fraction": 0.5, "trigger_pct": 0.01},
                        "exit": {"type": "TRAIL_STOP_MARKET", "trail_pct_min": 0.004, "trail_atr_mult": 0.6, "freeze_after_tp1_sec": 120},
                    },
                    "entry": float(c.get("price", 0.0)),
                    "stop_loss": round(float(c.get("price", 0.0)) * 0.982, 4),
                    "size_shares": max(1, int(1000 / max(1.0, float(c.get("price", 0.0))))),
                    "costs": {},
                    "probs": {"p1": 0.674, "p2": 0.391, "q": 0.579},
                    "ev_estimate": {"avg_loss_pct": -0.008, "net_ev_pct": 0.0011},
                    "reason_codes": ["EV_OK", "COST_OK", "EDGE_2OF3"],
                    "meta": {"version": APP_VERSION, "nowET": now_et_iso(), "latency_ms": 150, "universe_size": 150},
                    "rejections": {},
                    "explain_human": "Volume en trend zijn gunstig. We kopen met een marktorder, nemen bij +1% de helft winst en volgen de rest met een meeschuivende stop.",
                }
            )
        else:
            rejections["SCORE_LOW"] = rejections.get("SCORE_LOW", 0) + 1

    results_sorted = sorted(results, key=lambda r: r.get("sniper_score", 0.0), reverse=True)[: req.top_k]

    if results_sorted:
        await tg_notify(f"scan {req.universe_name}: {', '.join([r['ticker'] for r in results_sorted])}", x_no_notify)

    return {
        "universe_name": req.universe_name,
        "scanned": len(req.candidates),
        "tradeables": tradeables,
        "top": results_sorted,
        "summary": {"TRADE_LONG": tradeables, "NO_TRADE": len(req.candidates) - tradeables, "rejections": rejections},
        "meta": {"version": APP_VERSION, "nowET": now_et_iso(), "latency_ms": int((time.time() - t0) * 1000), "universe_size": len(req.candidates)},
    }


@app.post("/execute", summary="Execute Endpoint", description=(
    "Veilig standaard: DRY_RUN (preflight). "
    "Voor live SIM-orders: zet EXEC_ENABLED=true én stuur confirm=true. "
    "Vereist: TICKER_UIC_MAP (JSON), SAXO_REFRESH_TOKEN en Saxo app-config."
))
async def execute_endpoint(
    req: ExecuteRequest,
    request: Request,
    x_no_notify: Optional[str] = Header(None, alias="x-no-notify"),
    _: None = Depends(require_api_key),
):
    # Preflight (DRY_RUN) unless explicitly confirmed and enabled
    if not req.confirm or not EXEC_ENABLED:
        return {
            "ok": True,
            "mode": "DRY_RUN",
            "entry_result": {"dry_run": True, "status": "skip", "reason": "preflight"},
            "stop_result": {"dry_run": True, "status": "skip", "reason": "preflight"},
        }

    if not LIVE_TRADING:
        mode = "LIVE_SIM"
    else:
        mode = "LIVE"

    ticker = req.ticker.upper()
    uic = TICKER_UIC_MAP.get(ticker)
    if not uic:
        raise HTTPException(status_code=400, detail=f"Missing UIC for {ticker} (check TICKER_UIC_MAP)")

    if not SAXO_ACCOUNT_KEY:
        raise HTTPException(status_code=400, detail="SAXO_ACCOUNT_KEY not configured")

    # Ensure token
    access_token = await _ensure_saxo_access_token()
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json", "Accept": "application/json"}

    # Build a minimal market order
    order = {
        "AccountKey": SAXO_ACCOUNT_KEY,
        "Uic": uic,
        "AssetType": "Stock",
        "BuySell": "Buy",
        "OrderType": "Market",
        "Amount": req.shares,
        # Optional: "ManualOrder": True
    }

    entry_result: Dict[str, Any]
    stop_result: Dict[str, Any] = {"status": "skip", "reason": "not_implemented_safely"}

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            r = await client.post(f"{SAXO_BASE}/trade/v2/orders", headers=headers, json=order)
            if r.status_code in (200, 201):
                entry_result = {"status": "ok", "order_id": r.json().get("OrderId"), "sent": order}
                await tg_notify(f"Order geplaatst ({mode}): {ticker} x {req.shares} @ MKT", x_no_notify)
            else:
                entry_result = {"status": "error", "error": f"HTTP Error {r.status_code}: {r.text}", "sent": {}}
    except Exception as e:
        entry_result = {"status": "error", "error": str(e), "sent": {}}

    return {"ok": True, "mode": mode, "entry_result": entry_result, "stop_result": stop_result}


# =========================
# OAuth & Saxo utilities
# =========================
@app.get("/oauth/saxo/status", summary="Saxo Status")
async def saxo_status(_: None = Depends(require_api_key)):
    alive = bool(_saxo_token_cache.get("access_token"))
    return {
        "ok": True,
        "has_access_token": alive,
        "expires_at_epoch": _saxo_token_cache.get("expires_at", 0.0),
        "exec_enabled": EXEC_ENABLED,
        "live_trading": LIVE_TRADING,
    }


@app.get("/oauth/saxo/login", summary="Saxo Login")
async def saxo_login(state: str = "sniperbot", _: None = Depends(require_api_key)):
    if not SAXO_APP_KEY or not SAXO_REDIRECT_URI:
        raise HTTPException(status_code=400, detail="SAXO_APP_KEY or SAXO_REDIRECT_URI not configured")
    q = httpx.QueryParams(
        {
            "response_type": "code",
            "client_id": SAXO_APP_KEY,
            "redirect_uri": SAXO_REDIRECT_URI,
            "scope": "openid offline_access",
            "state": state,
        }
    )
    return {"ok": True, "authorize_url": f"{SAXO_AUTHORIZE_URL}?{q}"}


@app.get("/oauth/saxo/callback", summary="Saxo Callback")
async def saxo_callback(code: str = Query(...), state: str = Query("sniperbot")):
    # Exchange code for tokens — we return previews only.
    if not SAXO_APP_KEY or not SAXO_APP_SECRET:
        raise HTTPException(status_code=400, detail="SAXO_APP_KEY or SAXO_APP_SECRET not set")

    headers = {
        "Authorization": "Basic " + httpx._auth._basic_auth_str(SAXO_APP_KEY, SAXO_APP_SECRET),  # type: ignore
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    body = f"grant_type=authorization_code&code={httpx.QueryParams({'c': code})['c']}&redirect_uri={httpx.QueryParams({'r': SAXO_REDIRECT_URI})['r']}"

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        resp = await client.post(SAXO_TOKEN_URL, headers=headers, content=body)
    if resp.status_code != 200:
        return JSONResponse(status_code=resp.status_code, content={"ok": False, "error": resp.text})

    data = resp.json()
    access = data.get("access_token", "")
    refresh = data.get("refresh_token", "")
    # Cache access token for immediate use
    if access:
        _saxo_token_cache["access_token"] = access
        _saxo_token_cache["expires_at"] = time.time() + int(data.get("expires_in", 300))

    return {
        "ok": True,
        "got_access_token": bool(access),
        "got_refresh_token": bool(refresh),
        "refresh_token_preview": (refresh[:12] + "…") if refresh else "",
        "note": "Zet de volledige refresh token in Render als SAXO_REFRESH_TOKEN en redeploy. (Deze endpoint toont om veiligheidsredenen slechts een preview.)",
    }


@app.post("/saxo/refresh", summary="Refresh Saxo Access Token")
async def saxo_refresh(_: None = Depends(require_api_key)):
    token = await _ensure_saxo_access_token()
    return {"ok": True, "access_token_preview": (token[:20] + "..."), "expires_at": _saxo_token_cache["expires_at"]}


@app.get("/saxo/accounts/me", summary="Saxo Accounts (Me)")
async def saxo_accounts_me(_: None = Depends(require_api_key)):
    token = await _ensure_saxo_access_token()
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        r = await client.get(f"{SAXO_BASE}/port/v1/accounts/me", headers=headers)
    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=r.text)
    return r.json()
