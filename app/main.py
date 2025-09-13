# app/main.py
from __future__ import annotations

import os
import json
import time
import logging
import urllib.parse
import urllib.request
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

# ------------------------------------------------------------
# Import jouw schema’s en engine
# (sluiten aan op de file-indeling die je al hebt)
# ------------------------------------------------------------
try:
    from app.schemas import (
        DecideRequest, DecideResponse,
        ScanRequest, ScanResponse,
        ExecuteRequest, ExecuteResponse,
    )
except Exception:
    # Fallback: minimale typedicts als schema’s ontbreken
    from pydantic import BaseModel

    class DecideRequest(BaseModel):
        ticker: str
        price: float

    class DecideResponse(BaseModel):
        decision: str
        ticker: str
        explain_human: Optional[str] = None

    class ScanRequest(BaseModel):
        universe_name: str
        top_k: int = 3
        candidates: list

    class ScanResponse(BaseModel):
        universe_name: str
        scanned: int
        tradeables: int
        top: list
        summary: dict
        meta: dict

    class ExecuteRequest(BaseModel):
        ticker: str
        shares: int
        entry: float
        stop: float
        confirm: bool = False

    class ExecuteResponse(BaseModel):
        ok: bool
        mode: str
        entry_result: dict
        stop_result: dict

# Engine functies (zoals je ze al in je repo hebt)
try:
    from app.engine.decide import run_decision, run_scan
except Exception:
    # Dummy fallbacks als engine import mislukt (gebruikt je echte engine in prod)
    def run_decision(req: DecideRequest) -> Dict[str, Any]:
        return {
            "decision": "NO_TRADE",
            "ticker": getattr(req, "ticker", "TICK"),
            "sniper_score": 0.0,
            "gates": {},
            "mode": "MARKET_ONLY",
            "orders": {},
            "entry": None,
            "stop_loss": None,
            "size_shares": None,
            "costs": {},
            "probs": {},
            "ev_estimate": {},
            "reason_codes": ["SCORE_LOW"],
            "meta": {"version": "v3.2"},
            "rejections": {},
            "explain_human": "Dummy engine: geen trade.",
        }

    def run_scan(req: ScanRequest) -> Dict[str, Any]:
        return {
            "universe_name": req.universe_name,
            "scanned": len(req.candidates or []),
            "tradeables": 0,
            "top": [],
            "summary": {"NO_TRADE": len(req.candidates or []), "rejections": {}},
            "meta": {"version": "v3.2", "universe_size": len(req.candidates or [])},
        }

# ------------------------------------------------------------
# App
# ------------------------------------------------------------
app = FastAPI(title="SNIPERBOT API", version="v3.2")
logger = logging.getLogger("uvicorn.error")

# ------------------------------------------------------------
# Config / ENV
# ------------------------------------------------------------
API_KEY = os.getenv("API_KEY")

TG_ENABLED = os.getenv("TG_ENABLED", "0").lower() in ("1", "true", "yes", "on")
TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN")
TG_CHAT_ID = os.getenv("TG_CHAT_ID")

# Saxo OAuth / Token endpoints
SAXO_AUTH_URL = os.getenv("SAXO_AUTH_URL", "https://sim.logonvalidation.net/authorize")
SAXO_TOKEN_URL = os.getenv("SAXO_TOKEN_URL", "https://sim.logonvalidation.net/token")
SAXO_APP_KEY = os.getenv("SAXO_APP_KEY")
SAXO_APP_SECRET = os.getenv("SAXO_APP_SECRET")
SAXO_REDIRECT = os.getenv(
    "SAXO_REDIRECT_URL",
    "https://sniperbot-api.onrender.com/oauth/saxo/callback",
)
SAXO_REFRESH_TOKEN = os.getenv("SAXO_REFRESH_TOKEN")

EXEC_ENABLED = os.getenv("EXEC_ENABLED", "0").lower() in ("1", "true", "yes", "on")

# Ticker → UIC map (JSON string in env)
_TICKER_UIC_MAP: Dict[str, int] = {}
try:
    if os.getenv("TICKER_UIC_MAP"):
        _TICKER_UIC_MAP = json.loads(os.getenv("TICKER_UIC_MAP"))
except Exception:
    _TICKER_UIC_MAP = {}

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def require_api_key(x_api_key: Optional[str] = Header(None)):
    if API_KEY:
        if not x_api_key or x_api_key != API_KEY:
            raise HTTPException(status_code=401, detail="Unauthorized")
    return True


def _tg_send(text: str, disable_notification: bool = False) -> None:
    """
    Non-blocking best effort: log naar JSONL en stuur Telegram wanneer TG_ENABLED true is.
    Zet header X-No-Notify: 1 om te dempen per request.
    """
    # Log naar JSONL (CI-proof, geen netwerk vereist)
    try:
        line = json.dumps({"ts": int(time.time()), "msg": text}, ensure_ascii=False)
        with open("/tmp/sniperbot_events.jsonl", "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

    if not TG_ENABLED or not TG_BOT_TOKEN or not TG_CHAT_ID:
        return
    try:
        payload = json.dumps(
            {"chat_id": TG_CHAT_ID, "text": text, "disable_notification": disable_notification}
        ).encode("utf-8")
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5).read()  # fire & forget
    except Exception:
        # Geen harde error in API-flow
        pass


def _human_decision_message(resp: Dict[str, Any]) -> str:
    d = resp.get("decision", "NO_TRADE")
    t = resp.get("ticker", "")
    if d.startswith("TRADE_"):
        side = "KOOP" if d == "TRADE_LONG" else "VERKOOP"
        entry = resp.get("entry")
        stop = resp.get("stop_loss")
        size = resp.get("size_shares")
        probs = resp.get("probs", {})
        p1 = probs.get("p1")
        p2 = probs.get("p2")
        ev = (resp.get("ev_estimate") or {}).get("net_ev_pct")
        reasons = ", ".join(resp.get("reason_codes") or [])
        return (
            f"{side} {t}. Instap {entry}, stop {stop}, grootte {size}.\n"
            f"Doel: +1% snel wat winst nemen, daarna de rest laten meelopen.\n"
            f"Waarom: verwachte waarde oké, kosten oké. (kans +1% ≈ {round(p1*100,2) if isinstance(p1,(int,float)) else '?'}%; "
            f"+2% ≈ {round(p2*100,2) if isinstance(p2,(int,float)) else '?'}%; EV ≈ "
            f"{round(ev*100,2) if isinstance(ev,(int,float)) else '?'}%)"
        )
    else:
        why = resp.get("explain_human") or "We doen niets."
        return why


def _human_scan_message(resp: Dict[str, Any]) -> str:
    top = resp.get("top") or []
    uni = resp.get("universe_name", "?")
    scanned = resp.get("scanned", 0)
    tradeables = resp.get("tradeables", 0)
    if not top:
        return f"Scan {uni}: {scanned} bekeken, 0 kandidaten om te handelen."
    # Toon max 3
    lines = [f"Scan {uni}: {scanned} bekeken, {tradeables} tradeable.\nTop picks:"]
    for item in top[:3]:
        t = item.get("ticker", "?")
        s = item.get("sniper_score", 0)
        d = item.get("decision", "")
        lines.append(f"• {t} — score {round(s,2)} — {d}")
    return "\n".join(lines)


def _saxo_require_env():
    missing = [k for k, v in {
        "SAXO_APP_KEY": SAXO_APP_KEY,
        "SAXO_APP_SECRET": SAXO_APP_SECRET,
        "SAXO_REDIRECT_URL": SAXO_REDIRECT
    }.items() if not v]
    if missing:
        raise HTTPException(status_code=500, detail=f"Missing env: {', '.join(missing)}")


def _saxo_token_request(payload: Dict[str, str]) -> Dict[str, Any]:
    body = urllib.parse.urlencode(payload).encode()
    req = urllib.request.Request(
        SAXO_TOKEN_URL, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode())


def _get_access_token_from_refresh() -> str:
    """Gebruik SAXO_REFRESH_TOKEN om een access token op te halen."""
    if not SAXO_REFRESH_TOKEN:
        raise HTTPException(status_code=400, detail="Missing SAXO_REFRESH_TOKEN")
    _saxo_require_env()
    tok = _saxo_token_request({
        "grant_type": "refresh_token",
        "refresh_token": SAXO_REFRESH_TOKEN,
        "client_id": SAXO_APP_KEY,
        "client_secret": SAXO_APP_SECRET,
        "redirect_uri": SAXO_REDIRECT,
    })
    access = tok.get("access_token")
    if not access:
        raise HTTPException(status_code=502, detail="Could not obtain access_token from refresh_token")
    return access


# ------------------------------------------------------------
# Routes
# ------------------------------------------------------------
@app.get("/healthz")
def healthz():
    return {"ok": True, "version": "v3.2"}


@app.post("/decide", dependencies=[Depends(require_api_key)])
def decide_endpoint(
    req: DecideRequest,
    request: Request,
    x_no_notify: Optional[str] = Header(None),
):
    t0 = time.time()
    resp = run_decision(req)
    resp["meta"] = resp.get("meta", {})
    resp["meta"].update({"latency_ms": int((time.time() - t0) * 1000)})

    # Telegram melding (tenzij X-No-Notify)
    if not x_no_notify:
        try:
            _tg_send(_human_decision_message(resp))
        except Exception:
            pass
    return resp


@app.post("/scan", dependencies=[Depends(require_api_key)])
def scan_endpoint(
    req: ScanRequest,
    request: Request,
    x_no_notify: Optional[str] = Header(None),
):
    t0 = time.time()
    resp = run_scan(req)
    resp["meta"] = resp.get("meta", {})
    resp["meta"].update({"latency_ms": int((time.time() - t0) * 1000)})

    if not x_no_notify:
        try:
            _tg_send(_human_scan_message(resp))
        except Exception:
            pass
    return resp


@app.post("/execute", dependencies=[Depends(require_api_key)])
def execute_endpoint(
    req: ExecuteRequest,
    request: Request,
    x_no_notify: Optional[str] = Header(None),
):
    """
    Veilig standaard: DRY_RUN (preflight).
    Voor live SIM-orders: zet EXEC_ENABLED=true én stuur confirm=true.
    Vereist: TICKER_UIC_MAP (JSON), SAXO_REFRESH_TOKEN en Saxo app-config.
    """
    # Altijd eerst preflight tenzij je expliciet bevestigt én EXEC_ENABLED aan staat
    if not req.confirm or not EXEC_ENABLED:
        return {
            "ok": True,
            "mode": "DRY_RUN",
            "entry_result": {"dry_run": True, "status": "skip", "reason": "preflight"},
            "stop_result": {"dry_run": True, "status": "skip", "reason": "preflight"},
        }

    ticker = req.ticker.upper()
    uic = _TICKER_UIC_MAP.get(ticker)
    if not uic:
        raise HTTPException(status_code=400, detail=f"Missing UIC for {ticker} (check TICKER_UIC_MAP env)")

    # Access token uit refresh
    access_token = _get_access_token_from_refresh()

    # Saxo order body (simpel market BUY)
    order_body = {
        "AccountKey": os.getenv("SAXO_ACCOUNT_KEY"),  # optioneel; anders default
        "AssetType": "Stock",
        "Amount": req.shares,
        "BuySell": "Buy",
        "OrderType": "Market",
        "Uic": int(uic),
        "ExternalReference": f"sniperbot-{int(time.time())}",
    }

    # Plaats order (entry)
    entry_result = {}
    try:
        payload = json.dumps(order_body).encode("utf-8")
        req_http = urllib.request.Request(
            "https://gateway.saxobank.com/sim/openapi/trade/v2/orders",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req_http, timeout=20) as r:
            entry_result = json.loads(r.read().decode())
    except Exception as e:
        # Als live call faalt, fail zacht en geef terug wat we probeerden
        entry_result = {"status": "error", "error": str(e), "sent": order_body}

    # Stop‐loss (indicatief; afhankelijk van account/permissions)
    stop_result = {"status": "skip", "reason": "not_implemented_safely"}
    # (Je kunt hier een tweede call doen naar /orders of /orders/{id}/related)

    if not x_no_notify:
        try:
            _tg_send(f"SIM order ingestuurd voor {ticker}: {req.shares} stuks (mode=LIVE_SIM).")
        except Exception:
            pass

    return {
        "ok": True,
        "mode": "LIVE_SIM",
        "entry_result": entry_result,
        "stop_result": stop_result,
    }


# ---------------- Saxo OAuth helper routes -----------------
@app.get("/oauth/saxo/login")
def saxo_login():
    _saxo_require_env()
    params = {
        "response_type": "code",
        "client_id": SAXO_APP_KEY,
        "redirect_uri": SAXO_REDIRECT,
        "scope": "openid offline_access",  # nodig voor refresh_token
        "state": "sniperbot",
    }
    url = SAXO_AUTH_URL + "?" + urllib.parse.urlencode(params)
    return RedirectResponse(url, status_code=302)


@app.get("/oauth/saxo/callback")
def saxo_callback(code: str, state: str = "sniperbot"):
    _saxo_require_env()
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": SAXO_REDIRECT,
        "client_id": SAXO_APP_KEY,
        "client_secret": SAXO_APP_SECRET,
    }
    try:
        tok = _saxo_token_request(data)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Token exchange failed: {e}")

    refresh = tok.get("refresh_token")
    access = tok.get("access_token")

    preview = (refresh[:10] + "…") if isinstance(refresh, str) and len(refresh) > 14 else refresh
    note = (
        "Zet de volledige refresh token in Render als SAXO_REFRESH_TOKEN "
        "en herdeploy. (Deze endpoint toont om veiligheidsredenen slechts een preview.)"
    )
    return JSONResponse({
        "ok": True,
        "got_access_token": bool(access),
        "got_refresh_token": bool(refresh),
        "refresh_token_preview": preview,
        "note": note,
    })
