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
import logging
from typing import Any, Dict, List, Optional
from contextlib import asynccontextmanager

import requests
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field, validator

from .token_manager import SaxoTokenManager
from .broker.saxo import SaxoClient

# Redis is optioneel
try:
    import redis  # type: ignore
except Exception:  # pragma: no cover
    redis = None

APP_VERSION = "v3.2"
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("sniperbot")

# Global instances - will be initialized in lifespan
token_manager: Optional[SaxoTokenManager] = None
saxo_client: Optional[SaxoClient] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan handler for startup/shutdown"""
    global token_manager, saxo_client
    
    # Startup
    log.info("Starting up SniperBot...")
    
    # Initialize TokenManager with disk persistence
    if SAXO_APP_KEY and SAXO_APP_SECRET:
        saxo_token_path = os.getenv("SAXO_TOKEN_PATH", "/var/data/saxo_tokens.json")
        initial_refresh_token = os.getenv("SAXO_REFRESH_TOKEN", "")
        
        if initial_refresh_token:
            token_manager = SaxoTokenManager(
                app_key=SAXO_APP_KEY,
                app_secret=SAXO_APP_SECRET,
                refresh_token=initial_refresh_token,
                token_url=SAXO_TOKEN_URL,
                strategy="disk",
                storage_path=saxo_token_path,
                auto_refresh=True,
            )
            # Start background refresh
            token_manager.start()
            log.info(f"TokenManager initialized with disk persistence at {saxo_token_path}")
            
            # Initialize SaxoClient with async bearer provider
            async def get_bearer() -> str:
                if not token_manager:
                    raise RuntimeError("TokenManager not available")
                return await token_manager.get_access_token()
            
            saxo_client = SaxoClient(get_bearer=get_bearer)
            log.info("SaxoClient initialized with TokenManager bearer provider")
        else:
            log.warning("SAXO_REFRESH_TOKEN not provided, TokenManager not initialized")
    else:
        log.warning("SAXO_APP_KEY/SECRET not provided, TokenManager not initialized")
    
    yield
    
    # Shutdown
    log.info("Shutting down SniperBot...")
    if token_manager and hasattr(token_manager, '_bg_task') and token_manager._bg_task:
        token_manager._bg_task.cancel()
        try:
            await token_manager._bg_task
        except:
            pass

app = FastAPI(title="SNIPERBOT API", version=APP_VERSION, lifespan=lifespan)

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

# ======= Redis client (optioneel, aanbevolen voor refresh-rotatie) =======

rds: Optional["redis.Redis"] = None
if REDIS_URL and redis is not None:
    try:
        rds = redis.from_url(REDIS_URL, decode_responses=True, ssl=True)
        # Smoke test
        rds.ping()
        log.info("Redis OK.")
    except Exception as e:
        log.warning("Redis init faalde: %s", e)
        rds = None


def kv_get(key: str) -> Optional[str]:
    if rds:
        try:
            return rds.get(key)
        except Exception:
            return None
    return None


def kv_set(key: str, value: str, ttl: Optional[int] = None) -> None:
    if rds:
        try:
            if ttl:
                rds.setex(key, ttl, value)
            else:
                rds.set(key, value)
        except Exception:
            pass


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


# ======= Saxo OAuth Token Manager =======
# Using the existing SaxoTokenManager with disk persistence - see lifespan handler above

# Legacy helper functions for backward compatibility
def kv_get(key: str) -> Optional[str]:
    if rds:
        try:
            return rds.get(key)
        except Exception:
            return None
    return None

def kv_set(key: str, value: str, ttl: Optional[int] = None) -> None:
    if rds:
        try:
            if ttl:
                rds.setex(key, ttl, value)
            else:
                rds.set(key, value)
        except Exception:
            pass


# ======= Saxo helpers =======

async def _get_auth_header() -> Dict[str, str]:
    """Get auth header using TokenManager"""
    if not token_manager:
        raise HTTPException(status_code=503, detail="TokenManager not available")
    token = await token_manager.get_access_token()
    return {"Authorization": f"Bearer {token}"}

async def saxo_get(path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    url = f"{SAXO_BASE}{path}"
    try:
        h = await _get_auth_header()
        r = requests.get(url, headers=h, params=params, timeout=20)
        if r.status_code == 401:
            # één stille refresh + retry
            h = await _get_auth_header()
            r = requests.get(url, headers=h, params=params, timeout=20)
        r.raise_for_status()
        return r.json()
    except requests.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Saxo GET {path} failed ({r.status_code}): {r.text}") from e  # type: ignore


async def saxo_post(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    url = f"{SAXO_BASE}{path}"
    try:
        auth_h = await _get_auth_header()
        h = {**auth_h, "Content-Type": "application/json", "Accept": "application/json"}
        r = requests.post(url, headers=h, json=payload, timeout=20)
        if r.status_code == 401:
            auth_h = await _get_auth_header()
            h = {**auth_h, "Content-Type": "application/json", "Accept": "application/json"}
            r = requests.post(url, headers=h, json=payload, timeout=20)
        r.raise_for_status()
        if r.text.strip():
            return r.json()
        return {"ok": True}
    except requests.HTTPError as e:
        msg = r.text if "r" in locals() else str(e)
        code = r.status_code if "r" in locals() else 502
        raise HTTPException(status_code=502, detail=f"Saxo POST {path} failed ({code}): {msg}") from e


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


@app.get("/oauth/saxo/status", summary="Saxo Status (Legacy)")
def saxo_status(x_api_key: Optional[str] = Header(None)):
    require_api_key(x_api_key)
    # Legacy endpoint - redirect to new token status
    if not token_manager:
        return {
            "ok": False,
            "error": "TokenManager not initialized",
            "exec_enabled": EXEC_ENABLED,
            "live_trading": LIVE_TRADING,
        }
    
    status = token_manager.status()
    return {
        "ok": True,
        "has_access_token": status["has_access_token"],
        "expires_at_epoch": time.time() + (status["expires_in_s"] or 0),
        "exec_enabled": EXEC_ENABLED,
        "live_trading": LIVE_TRADING,
    }


@app.get("/saxo/token/status", summary="Saxo Token Status")
def saxo_token_status(x_api_key: Optional[str] = Header(None)):
    require_api_key(x_api_key)
    if not token_manager:
        raise HTTPException(status_code=503, detail="TokenManager not available")
    return token_manager.status()


@app.post("/saxo/token/refresh", summary="Saxo Token Refresh")
async def saxo_token_refresh(x_api_key: Optional[str] = Header(None)):
    require_api_key(x_api_key)
    if not token_manager:
        raise HTTPException(status_code=503, detail="TokenManager not available")
    
    try:
        bundle = await token_manager.refresh_access_token()
        return {
            "ok": True,
            "access_token_preview": (bundle.access_token[:20] + "..." if bundle.access_token else "None"),
            "expires_in_s": bundle.seconds_left,
            "last_refresh_ts": bundle.last_refresh_ts,
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Token refresh failed: {str(e)}")


@app.post("/saxo/refresh", summary="Forceer Saxo token refresh (Legacy)")
async def saxo_refresh(x_api_key: Optional[str] = Header(None)):
    require_api_key(x_api_key)
    # Legacy endpoint - redirect to new token refresh
    if not token_manager:
        raise HTTPException(status_code=503, detail="TokenManager not available")
    
    try:
        bundle = await token_manager.refresh_access_token()
        return {
            "ok": True, 
            "access_token_preview": (bundle.access_token[:20] + "..." if bundle.access_token else "None"),
            "expires_at_epoch": bundle.expires_at or 0,
        }
    except Exception as e:
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

    # Vereiste TokenManager aanwezig?
    if not token_manager:
        raise HTTPException(status_code=503, detail="TokenManager not available")

    # Haal access token en account key
    try:
        token = await token_manager.get_access_token()
        at_preview = token[:20] + "..."
        account_key = await get_account_key()
    except Exception as e:
        return {
            "ok": True,
            "mode": mode,
            "entry_result": {"status": "error", "error": f"auth/account error: {str(e)}"},
            "stop_result": {"status": "skip", "reason": "auth_error"},
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
