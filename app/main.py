# main.py
# SNIPERBOT API v3.2 – FastAPI + Saxo auto-refresh (SIM), met simpele scan/execute.
#
# Vereiste ENV variabelen (Render e.d.):
# - SINGLE_API_KEY=lenbogy123                 # of eigen API key; header: X-API-Key
# - EXEC_ENABLED=true                         # verplicht voor live SIM orders
# - LIVE_TRADING=true                         # puur label; SIM blijft SIM (SAXO_BASE = /sim/)
# - SAXO_BASE=https://gateway.saxobank.com/sim/openapi
# - SAXO_TOKEN_URL=https://sim.logonvalidation.net/token
# - SAXO_APP_KEY=<je SIM app key>
# - SAXO_APP_SECRET=<je SIM app secret>
# - SAXO_REFRESH_TOKEN=<initiële refresh token>   # wordt daarna geroteerd (indien Redis)
# - SAXO_ACCOUNT_KEY=<accountKey zoals ytESP3...> # optioneel; anders auto-ophalen
# - TICKER_UIC_MAP={"AAPL":211,"MSFT":261,...}    # JSON string
# - REDIS_URL=rediss://:<pwd>@<host>:<port>/0     # optioneel maar aangeraden
# - SAXO_REDIRECT_URI=https://oauth.pstmn.io/v1/callback   # optioneel (voor /oauth flow)
#
# Endpoints:
# - GET  /healthz
# - POST /decide        {ticker, price}
# - POST /scan          {universe_name, top_k=3, candidates:[...]}
# - POST /execute       {ticker, shares, entry, stop, confirm=false}
# - GET  /oauth/saxo/status
# - POST /saxo/refresh  (force refresh)
#
# Opmerking:
# - /execute plaatst 2 orders bij Saxo (MARKET Buy, daarna Stop Sell) ALS confirm=true & EXEC_ENABLED=true
# - Anders DRY_RUN met preflight-uitkomst.
# - Alle Saxo-calls gebruiken auto-refresh met 401 retry en refresh-token-rotatie.

import os
import json
import time
import threading
import logging
from typing import Any, Dict, List, Optional

import requests
import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field, validator

# Import async token manager
from .token_manager import SaxoTokenManager

APP_VERSION = "v3.2"
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("sniperbot")

app = FastAPI(title="SNIPERBOT API", version=APP_VERSION)

# ======= Startup/Shutdown Events =======

@app.on_event("startup")
async def startup_event():
    """Initialize token manager background refresh"""
    if saxo_token_manager:
        saxo_token_manager.start()
        log.info("SaxoTokenManager background refresh started")

@app.on_event("shutdown")
async def shutdown_event():
    """Clean up token manager"""
    if saxo_token_manager and saxo_token_manager._bg_task:
        saxo_token_manager._bg_task.cancel()
        log.info("SaxoTokenManager background task cancelled")

# ======= Config uit ENV =======

SINGLE_API_KEY = os.getenv("SINGLE_API_KEY", "lenbogy123")

SAXO_BASE       = os.getenv("SAXO_BASE", "https://gateway.saxobank.com/sim/openapi")
SAXO_TOKEN_URL  = os.getenv("SAXO_TOKEN_URL", "https://sim.logonvalidation.net/token")
SAXO_APP_KEY    = os.getenv("SAXO_APP_KEY", "")
SAXO_APP_SECRET = os.getenv("SAXO_APP_SECRET", "")
SAXO_REDIRECT   = os.getenv("SAXO_REDIRECT_URI", "https://oauth.pstmn.io/v1/callback")

EXEC_ENABLED    = os.getenv("EXEC_ENABLED", "false").lower() == "true"
LIVE_TRADING    = os.getenv("LIVE_TRADING", "false").lower() == "true"
SAXO_ACCOUNT_KEY_ENV = os.getenv("SAXO_ACCOUNT_KEY", "")

TICKER_UIC_MAP: Dict[str, int] = {}
try:
    if os.getenv("TICKER_UIC_MAP"):
        TICKER_UIC_MAP = {k.upper(): int(v) for k, v in json.loads(os.getenv("TICKER_UIC_MAP", "{}")).items()}
except Exception as e:
    log.warning("Kon TICKER_UIC_MAP niet parsen: %s", e)
    TICKER_UIC_MAP = {}

REDIS_URL = os.getenv("REDIS_URL", "")


# ======= Security (API Key) =======

def require_api_key(x_api_key: Optional[str]) -> None:
    expected = SINGLE_API_KEY.strip()
    if expected:
        if not x_api_key or x_api_key.strip() != expected:
            raise HTTPException(status_code=401, detail="Invalid X-API-Key")
    # Als SINGLE_API_KEY leeg zou zijn, geen check (dev).


# ======= Pydantic modellen =======

class DecideRequest(BaseModel):
    ticker: str
    price: float


class ScanRequest(BaseModel):
    universe_name: str
    top_k: int = 3
    candidates: List[Dict[str, Any]]

    @validator("top_k")
    def _cap_topk(cls, v):
        return max(1, min(10, int(v)))


class ExecuteRequest(BaseModel):
    ticker: str
    shares: int
    entry: float
    stop: float
    confirm: bool = False

    @validator("shares")
    def _shares_ok(cls, v):
        if v <= 0:
            raise ValueError("shares must be > 0")
        return v

    @validator("stop")
    def _stop_ok(cls, v, values):
        # Alleen basiscontrole; bij short is deze anders (nu enkel long)
        if "entry" in values and v >= values["entry"]:
            raise ValueError("stop must be < entry for long")
        return v


# ======= Initialize Saxo Token Manager (async, disk-based) =======

def _get_initial_refresh_token() -> str:
    """Get refresh token from env - disk fallback is handled by SaxoTokenManager"""
    env_rt = os.getenv("SAXO_REFRESH_TOKEN", "")
    if not env_rt:
        raise HTTPException(status_code=400, detail="SAXO_REFRESH_TOKEN ontbreekt.")
    return env_rt.strip()

# Initialize async token manager with disk storage
saxo_token_manager: Optional[SaxoTokenManager] = None
if SAXO_APP_KEY and SAXO_APP_SECRET:
    try:
        initial_refresh_token = _get_initial_refresh_token()
        saxo_token_manager = SaxoTokenManager(
            app_key=SAXO_APP_KEY,
            app_secret=SAXO_APP_SECRET,
            refresh_token=initial_refresh_token,
            token_url=SAXO_TOKEN_URL,
            strategy="disk",
            storage_path="/var/data/saxo_tokens.json",
            auto_refresh=True,
            safety_margin_sec=90
        )
        log.info("SaxoTokenManager initialized with disk storage")
    except Exception as e:
        log.warning("SaxoTokenManager init failed: %s", e)
        saxo_token_manager = None
else:
    log.warning("SAXO_APP_KEY/SECRET missing - SaxoTokenManager not initialized")


# ======= Saxo helpers (async) =======

async def get_auth_header() -> Dict[str, str]:
    """Get authorization header with fresh access token"""
    if not saxo_token_manager:
        raise HTTPException(status_code=400, detail="SaxoTokenManager not initialized")
    
    access_token = await saxo_token_manager.get_access_token()
    return {"Authorization": f"Bearer {access_token}"}

async def saxo_get(path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    url = f"{SAXO_BASE}{path}"
    log.debug("Saxo GET %s with params: %s", path, params)
    
    try:
        h = await get_auth_header()
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(url, headers=h, params=params)
            
            if r.status_code == 401:
                # Force refresh and retry once
                log.debug("401 on Saxo GET %s, forcing token refresh", path)
                if saxo_token_manager:
                    await saxo_token_manager.refresh_access_token()
                h = await get_auth_header()
                r = await client.get(url, headers=h, params=params)
            
            r.raise_for_status()
            return r.json()
    except httpx.HTTPError as e:
        status_code = getattr(e.response, 'status_code', 502) if hasattr(e, 'response') else 502
        response_text = getattr(e.response, 'text', str(e)) if hasattr(e, 'response') else str(e)
        log.error("Saxo GET %s failed (%s): %s", path, status_code, response_text)
        raise HTTPException(status_code=502, detail=f"Saxo GET {path} failed ({status_code}): {response_text}") from e


async def saxo_post(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    url = f"{SAXO_BASE}{path}"
    log.debug("Saxo POST %s with payload keys: %s", path, list(payload.keys()))
    
    try:
        h = {**await get_auth_header(), "Content-Type": "application/json", "Accept": "application/json"}
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.post(url, headers=h, json=payload)
            
            if r.status_code == 401:
                # Force refresh and retry once
                log.debug("401 on Saxo POST %s, forcing token refresh", path)
                if saxo_token_manager:
                    await saxo_token_manager.refresh_access_token()
                h = {**await get_auth_header(), "Content-Type": "application/json", "Accept": "application/json"}
                r = await client.post(url, headers=h, json=payload)
            
            r.raise_for_status()
            if r.text.strip():
                return r.json()
            return {"ok": True}
    except httpx.HTTPError as e:
        status_code = getattr(e.response, 'status_code', 502) if hasattr(e, 'response') else 502
        response_text = getattr(e.response, 'text', str(e)) if hasattr(e, 'response') else str(e)
        log.error("Saxo POST %s failed (%s): %s", path, status_code, response_text)
        raise HTTPException(status_code=502, detail=f"Saxo POST {path} failed ({status_code}): {response_text}") from e


# ======= Utils =======

async def get_account_key() -> str:
    if SAXO_ACCOUNT_KEY_ENV:
        return SAXO_ACCOUNT_KEY_ENV
    # fallback: haal actief account op
    js = await saxo_get("/port/v1/accounts/me")
    # Verwacht payload met "Data":[{...}]
    try:
        data = js.get("Data", [])
        for acc in data:
            if acc.get("Active", True):
                return acc["AccountKey"]
        # anders eerste
        if data:
            return data[0]["AccountKey"]
    except Exception:
        pass
    raise HTTPException(status_code=502, detail=f"Kon AccountKey niet bepalen uit /port/v1/accounts/me: {js}")


def uic_for_ticker(ticker: str) -> int:
    t = ticker.strip().upper()
    if t not in TICKER_UIC_MAP:
        raise HTTPException(status_code=400, detail=f"Ticker '{t}' niet gevonden in TICKER_UIC_MAP.")
    return int(TICKER_UIC_MAP[t])


# ======= Endpoints =======

@app.get("/healthz", summary="Healthz")
def healthz():
    return {"ok": True, "version": APP_VERSION}


@app.get("/oauth/saxo/status", summary="Saxo Status")
async def saxo_status(x_api_key: Optional[str] = Header(None)):
    require_api_key(x_api_key)
    
    if not saxo_token_manager:
        return {
            "ok": False,
            "error": "SaxoTokenManager not initialized",
            "exec_enabled": EXEC_ENABLED,
            "live_trading": LIVE_TRADING,
        }
    
    status = saxo_token_manager.status()
    return {
        "ok": True,
        "has_access_token": status.get("has_access_token", False),
        "expires_in_s": status.get("expires_in_s"),
        "last_refresh_ts": status.get("last_refresh_ts"),
        "storage_strategy": status.get("strategy"),
        "storage_path": status.get("storage_path"),
        "exec_enabled": EXEC_ENABLED,
        "live_trading": LIVE_TRADING,
    }


@app.post("/saxo/refresh", summary="Forceer Saxo token refresh")
async def saxo_refresh(x_api_key: Optional[str] = Header(None)):
    require_api_key(x_api_key)
    
    if not saxo_token_manager:
        raise HTTPException(status_code=400, detail="SaxoTokenManager not initialized")
    
    # Force refresh with debug logging
    try:
        log.info("Manual token refresh requested")
        old_bundle = saxo_token_manager._bundle
        log.debug("Before refresh - expires_in_s: %s", old_bundle.seconds_left)
        
        new_bundle = await saxo_token_manager.refresh_access_token()
        
        log.info("Token refresh completed successfully")
        log.debug("After refresh - expires_in_s: %s", new_bundle.seconds_left)
        
        return {
            "ok": True, 
            "access_token_preview": (new_bundle.access_token[:20] + "..." if new_bundle.access_token else "None"),
            "expires_in_s": new_bundle.seconds_left,
            "last_refresh_ts": new_bundle.last_refresh_ts
        }
    except Exception as e:
        log.error("Token refresh failed: %s", str(e))
        raise HTTPException(status_code=502, detail=f"Token refresh failed: {str(e)}")


@app.post("/decide", summary="Decide Endpoint")
def decide_endpoint(req: DecideRequest, x_api_key: Optional[str] = Header(None), x_no_notify: Optional[str] = Header(None)):
    require_api_key(x_api_key)
    # Simpele placeholder (consistent met je vorige NO_TRADE output)
    return {
        "decision": "NO_TRADE",
        "ticker": req.ticker.upper(),
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
        "meta": {"version": APP_VERSION, "latency_ms": 0},
        "rejections": {},
        "explain_human": "Dummy engine: geen trade.",
    }


@app.post("/scan", summary="Scan Endpoint")
def scan_endpoint(req: ScanRequest, x_api_key: Optional[str] = Header(None), x_no_notify: Optional[str] = Header(None)):
    require_api_key(x_api_key)

    def score(c: Dict[str, Any]) -> float:
        # Eenvoudige heuristiek: vwap_slope > 0 en rvol hoog → hogere score
        vwap_slope = float(c.get("vwap_slope_pct_per_min", 0) or 0)
        rvol = float(c.get("rvol", 1) or 1)
        spread_bps = float(c.get("spread_bps", 10) or 10)
        halted = bool(c.get("halted", False))
        if halted:
            return 0.0
        base = max(0.0, vwap_slope * 1000.0) + (rvol - 1.0) * 1.5 - (spread_bps / 10.0)
        return round(max(0.0, base), 2)

    tops: List[Dict[str, Any]] = []
    tradeables = 0
    for c in req.candidates:
        s = score(c)
        if s <= 0.0:
            continue
        tradeables += 1
        tkr = str(c.get("ticker", "?")).upper()
        price = float(c.get("price", 0) or 0)
        # simpele orders: tp1 1%, trail stop
        tops.append({
            "decision": "TRADE_LONG",
            "ticker": tkr,
            "sniper_score": s,
            "gates": {k: True for k in [
                "data", "liquidity", "risk", "regime", "technique", "compliance",
                "cost", "market_safety", "tod", "event_guard", "latency_vwap"
            ]},
            "mode": "MARKET_ONLY",
            "orders": {
                "entry": {"type": "MARKET"},
                "tp1": {"type": "MARKET", "fraction": 0.5, "trigger_pct": 0.01},
                "exit": {"type": "TRAIL_STOP_MARKET", "trail_pct_min": 0.004, "trail_atr_mult": 0.6, "freeze_after_tp1_sec": 120},
            },
            "entry": price,
            "stop_loss": round(price * 0.983, 4),
            "size_shares": 100,
            "costs": {
                "cost_profile": c.get("cost_profile", "USD_CASH"),
                "commission_roundtrip_pct": 0.0016,
                "fx_roundtrip_pct": 0.0,
                "spread_pct": float(c.get("spread_bps", 3) or 3) / 10000.0,
                "slippage_pct": 0.0005,
                "break_even_pct": 0.0024,
            },
            "probs": {"p1": 0.67, "p2": 0.39, "q": 0.58},
            "ev_estimate": {"avg_loss_pct": -0.008, "net_ev_pct": 0.0011},
            "reason_codes": ["EV_OK", "COST_OK", "EDGE_2OF3"],
            "meta": {"version": APP_VERSION, "nowET": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()), "latency_ms": 150, "universe_size": len(req.candidates)},
            "rejections": {},
            "explain_human": "Volume en trend zijn gunstig. We kopen met een marktorder, nemen bij +1% de helft winst en volgen de rest met een meeschuivende stop.",
        })

    # sorteer op score en cap top_k
    tops.sort(key=lambda x: x.get("sniper_score", 0.0), reverse=True)
    tops = tops[:req.top_k]

    summary = {"TRADE_LONG": sum(1 for t in tops if t["decision"] == "TRADE_LONG"),
               "NO_TRADE": len(req.candidates) - len(tops),
               "rejections": {}}

    return {
        "universe_name": req.universe_name,
        "scanned": len(req.candidates),
        "tradeables": tradeables,
        "top": tops,
        "summary": summary,
        "meta": {"version": APP_VERSION, "universe_size": len(req.candidates), "latency_ms": 0},
    }


@app.post("/execute", summary="Execute Endpoint",
          description="Veilig standaard: DRY_RUN (preflight). Voor live SIM-orders: EXEC_ENABLED=true én confirm=true. Vereist: TICKER_UIC_MAP, Saxo OAuth config.")
async def execute_endpoint(req: ExecuteRequest, x_api_key: Optional[str] = Header(None), x_no_notify: Optional[str] = Header(None)):
    require_api_key(x_api_key)

    tkr = req.ticker.upper()
    result = {"ok": True}

    # Preflight checks
    problems: List[str] = []
    if req.shares <= 0:
        problems.append("shares <= 0")
    if req.stop >= req.entry:
        problems.append("stop >= entry (long)")
    uic = None
    try:
        uic = uic_for_ticker(tkr)
    except HTTPException as e:
        problems.append(e.detail if isinstance(e.detail, str) else "Uic missing")

    mode = "DRY_RUN"
    if not problems and req.confirm and EXEC_ENABLED:
        mode = "LIVE_SIM"

    # DRY_RUN
    if mode == "DRY_RUN":
        return {
            "ok": True,
            "mode": mode,
            "entry_result": {"dry_run": True, "status": "skip", "reason": "preflight" if problems else "confirm_required"},
            "stop_result": {"dry_run": True, "status": "skip", "reason": "preflight" if problems else "confirm_required"},
            "problems": problems,
        }

    # LIVE_SIM (alleen als confirm & EXEC_ENABLED)
    # Nogmaals sanity:
    if problems:
        return {
            "ok": False,
            "mode": mode,
            "entry_result": {"status": "error", "error": f"preflight: {', '.join(problems)}"},
            "stop_result": {"status": "skip", "reason": "preflight_error"},
        }

    # Vereiste tokens aanwezig?
    if not saxo_token_manager:
        raise HTTPException(status_code=400, detail="SaxoTokenManager not initialized")

    # Haal/refresh access token en account key
    try:
        access_token = await saxo_token_manager.get_access_token()
        at_preview = access_token[:20] + "..."
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Token refresh failed: {str(e)}")
    
    try:
        account_key = await get_account_key()
    except HTTPException as e:
        return {
            "ok": True,
            "mode": mode,
            "entry_result": {"status": "error", "error": f"account_key: {e.detail}"},
            "stop_result": {"status": "skip", "reason": "no_account_key"},
        }

    # 1) MARKET BUY
    entry_payload = {
        "AccountKey": account_key,
        "Uic": uic,
        "AssetType": "Stock",
        "BuySell": "Buy",
        "Amount": req.shares,
        "OrderType": "Market",
        "OrderDuration": {"DurationType": "DayOrder"},
    }

    try:
        entry_resp = await saxo_post("/trade/v2/orders", entry_payload)
        entry_ok = True
    except HTTPException as e:
        entry_resp = {"status": "error", "error": str(e.detail), "sent": entry_payload}
        entry_ok = False

    # 2) STOP SELL (alleen als entry gelukt)
    if entry_ok:
        stop_payload = {
            "AccountKey": account_key,
            "Uic": uic,
            "AssetType": "Stock",
            "BuySell": "Sell",
            "OrderType": "Stop",
            "StopPrice": float(req.stop),
            "Amount": req.shares,
            "OrderDuration": {"DurationType": "GoodTillCancel"},
        }
        try:
            stop_resp = await saxo_post("/trade/v2/orders", stop_payload)
        except HTTPException as e:
            stop_resp = {"status": "error", "error": str(e.detail), "sent": stop_payload}
    else:
        stop_resp = {"status": "skip", "reason": "entry_failed"}

    return {
        "ok": True,
        "mode": mode,
        "entry_result": entry_resp,
        "stop_result": stop_resp,
        "note": f"access_token={at_preview}",
    }
