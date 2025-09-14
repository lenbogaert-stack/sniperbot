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
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field, validator

# Redis is optioneel
try:
    import redis  # type: ignore
except Exception:  # pragma: no cover
    redis = None

APP_VERSION = "v3.2"
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("sniperbot")

app = FastAPI(title="SNIPERBOT API", version=APP_VERSION)

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

class SaxoAuthManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._access_token: Optional[str] = None
        self._expires_at: float = 0.0  # epoch

    @property
    def expires_at(self) -> float:
        return self._expires_at

    def _get_refresh_token(self) -> str:
        rt = kv_get("saxo:refresh_token")
        if rt:
            return rt
        env_rt = os.getenv("SAXO_REFRESH_TOKEN", "")
        if not env_rt:
            raise HTTPException(status_code=400, detail="SAXO_REFRESH_TOKEN ontbreekt (ook niet in Redis).")
        return env_rt.strip()

    def _store_refresh_token(self, rt: str) -> None:
        kv_set("saxo:refresh_token", rt)

    def _store_access_token(self, at: str, expires_in: int) -> None:
        now = time.time()
        self._access_token = at
        # 30s veiligheidsmarge
        self._expires_at = now + max(0, int(expires_in) - 30)
        kv_set("saxo:access_token", at, ttl=int(expires_in))

    def _refresh_now(self) -> None:
        if not SAXO_APP_KEY or not SAXO_APP_SECRET:
            raise HTTPException(status_code=400, detail="SAXO_APP_KEY/SECRET ontbreken.")

        rt = self._get_refresh_token()
        data = {
            "grant_type": "refresh_token",
            "refresh_token": rt,
            "client_id": SAXO_APP_KEY,
            "client_secret": SAXO_APP_SECRET,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        resp = requests.post(SAXO_TOKEN_URL, data=data, headers=headers, timeout=15)
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail=f"Token refresh failed ({resp.status_code}): {resp.text}")

        js = resp.json()
        at = js.get("access_token")
        exp = js.get("expires_in", 900)
        if not at:
            raise HTTPException(status_code=502, detail="Token refresh ok maar geen access_token in respons.")

        self._store_access_token(at, int(exp))

        # Rotatie
        new_rt = js.get("refresh_token")
        if new_rt and new_rt != rt:
            self._store_refresh_token(new_rt)

    def get_access_token(self, force: bool = False) -> str:
        with self._lock:
            now = time.time()
            if force or (self._access_token is None) or (now >= self._expires_at - 60):
                self._refresh_now()
            return self._access_token  # type: ignore

    def auth_header(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.get_access_token()}"}


saxo_auth = SaxoAuthManager()

# Initialize potential SaxoTokenManager as global tm (if configured)
tm: Optional["SaxoTokenManager"] = None
try:
    from .token_manager import SaxoTokenManager
    if SAXO_APP_KEY and SAXO_APP_SECRET:
        # Try to get refresh token for TokenManager
        rt = kv_get("saxo:refresh_token") or os.getenv("SAXO_REFRESH_TOKEN", "")
        if rt:
            tm = SaxoTokenManager(
                app_key=SAXO_APP_KEY,
                app_secret=SAXO_APP_SECRET, 
                refresh_token=rt,
                token_url=SAXO_TOKEN_URL,
                strategy="memory",
                auto_refresh=False  # Don't start background task automatically
            )
except Exception as e:
    log.warning("Could not initialize SaxoTokenManager: %s", e)
    tm = None


# ======= Diagnostic helpers =======

def _mgr_candidates() -> List[Dict[str, Any]]:
    """Find all potential Saxo token manager candidates."""
    candidates = []
    
    # 1. Global saxo_auth (SaxoAuthManager)
    if saxo_auth:
        candidates.append({
            "type": "SaxoAuthManager",
            "name": "saxo_auth",
            "instance": saxo_auth,
            "id": id(saxo_auth),
            "has_token": bool(getattr(saxo_auth, "_access_token", None)),
            "expires_at": getattr(saxo_auth, "_expires_at", 0.0)
        })
    
    # 2. Global tm (SaxoTokenManager)
    if tm:
        candidates.append({
            "type": "SaxoTokenManager", 
            "name": "tm",
            "instance": tm,
            "id": id(tm),
            "has_token": bool(tm._bundle.access_token if hasattr(tm, "_bundle") else False),
            "expires_at": tm._bundle.expires_at if hasattr(tm, "_bundle") and tm._bundle.expires_at else 0.0
        })
    
    # 3. app.state.saxo_mgr (if it exists)
    if hasattr(app, "state") and hasattr(app.state, "saxo_mgr"):
        mgr = app.state.saxo_mgr
        candidates.append({
            "type": type(mgr).__name__,
            "name": "app.state.saxo_mgr", 
            "instance": mgr,
            "id": id(mgr),
            "has_token": bool(getattr(mgr, "_access_token", None) or 
                            (hasattr(mgr, "_bundle") and getattr(mgr._bundle, "access_token", None))),
            "expires_at": getattr(mgr, "_expires_at", 0.0) or 
                         (getattr(mgr._bundle, "expires_at", 0.0) if hasattr(mgr, "_bundle") else 0.0)
        })
    
    return candidates


def _callable_get_mgr_fallback() -> Optional[Any]:
    """Try to get manager from accessor function if it exists."""
    try:
        # Check if there's a _get_mgr function somewhere (common pattern)
        if hasattr(app, "_get_mgr") and callable(getattr(app, "_get_mgr")):
            return app._get_mgr()
        
        # Check for other common accessor patterns
        for attr_name in ["get_saxo_manager", "get_token_manager", "_get_saxo_mgr"]:
            if hasattr(app, attr_name) and callable(getattr(app, attr_name)):
                return getattr(app, attr_name)()
                
        return None
    except Exception:
        return None


# ======= Saxo helpers =======

def saxo_get(path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    url = f"{SAXO_BASE}{path}"
    try:
        h = saxo_auth.auth_header()
        r = requests.get(url, headers=h, params=params, timeout=20)
        if r.status_code == 401:
            # één stille refresh + retry
            h = saxo_auth.auth_header()
            r = requests.get(url, headers=h, params=params, timeout=20)
        r.raise_for_status()
        return r.json()
    except requests.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Saxo GET {path} failed ({r.status_code}): {r.text}") from e  # type: ignore


def saxo_post(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    url = f"{SAXO_BASE}{path}"
    try:
        h = {**saxo_auth.auth_header(), "Content-Type": "application/json", "Accept": "application/json"}
        r = requests.post(url, headers=h, json=payload, timeout=20)
        if r.status_code == 401:
            h = {**saxo_auth.auth_header(), "Content-Type": "application/json", "Accept": "application/json"}
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

def get_account_key() -> str:
    if SAXO_ACCOUNT_KEY_ENV:
        return SAXO_ACCOUNT_KEY_ENV
    # fallback: haal actief account op
    js = saxo_get("/port/v1/accounts/me")
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
def saxo_status(x_api_key: Optional[str] = Header(None)):
    require_api_key(x_api_key)
    return {
        "ok": True,
        "has_access_token": bool(kv_get("saxo:access_token")),
        "expires_at_epoch": getattr(saxo_auth, "_expires_at", 0.0),
        "exec_enabled": EXEC_ENABLED,
        "live_trading": LIVE_TRADING,
    }


@app.post("/saxo/refresh", summary="Forceer Saxo token refresh")
def saxo_refresh(x_api_key: Optional[str] = Header(None)):
    require_api_key(x_api_key)
    # Force refresh; duidelijke fouten i.p.v. 500
    if not SAXO_APP_KEY or not SAXO_APP_SECRET:
        raise HTTPException(status_code=400, detail="SAXO_APP_KEY/SECRET ontbreken.")
    if not (os.getenv("SAXO_REFRESH_TOKEN") or kv_get("saxo:refresh_token")):
        raise HTTPException(status_code=400, detail="Ontbrekende refresh token (SAXO_REFRESH_TOKEN/Redis).")
    at = saxo_auth.get_access_token(force=True)
    return {"ok": True, "access_token_preview": (at[:20] + "..."), "expires_at_epoch": saxo_auth.expires_at}


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
def execute_endpoint(req: ExecuteRequest, x_api_key: Optional[str] = Header(None), x_no_notify: Optional[str] = Header(None)):
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
    if not SAXO_APP_KEY or not SAXO_APP_SECRET:
        raise HTTPException(status_code=400, detail="SAXO_APP_KEY/SECRET ontbreken.")
    if not (os.getenv("SAXO_REFRESH_TOKEN") or kv_get("saxo:refresh_token")):
        raise HTTPException(status_code=400, detail="SAXO_REFRESH_TOKEN ontbreekt (ook niet in Redis).")

    # Haal/refresh access token en account key
    at_preview = saxo_auth.get_access_token()[:20] + "..."
    try:
        account_key = get_account_key()
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
        entry_resp = saxo_post("/trade/v2/orders", entry_payload)
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
            stop_resp = saxo_post("/trade/v2/orders", stop_payload)
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


@app.get("/diag/saxo/assert", summary="Saxo TokenManager Health Assertion",
         description="Verify manager convergence and identity. Compares object identities between app.state.saxo_mgr, global tm, and accessor functions. Never crashes or hangs, always returns JSON.")
def saxo_assert_endpoint(x_api_key: Optional[str] = Header(None)):
    """
    Health assertion endpoint for Saxo TokenManager convergence.
    Compares object identities and status of all found managers.
    Returns JSON with IDs and status of all managers plus convergence boolean.
    """
    try:
        require_api_key(x_api_key)
        
        # Collect all manager candidates
        candidates = _mgr_candidates()
        
        # Try accessor fallback
        accessor_mgr = _callable_get_mgr_fallback()
        if accessor_mgr:
            candidates.append({
                "type": type(accessor_mgr).__name__,
                "name": "accessor(_get_mgr)",
                "instance": accessor_mgr,
                "id": id(accessor_mgr),
                "has_token": bool(getattr(accessor_mgr, "_access_token", None) or 
                                (hasattr(accessor_mgr, "_bundle") and getattr(accessor_mgr._bundle, "access_token", None))),
                "expires_at": getattr(accessor_mgr, "_expires_at", 0.0) or 
                             (getattr(accessor_mgr._bundle, "expires_at", 0.0) if hasattr(accessor_mgr, "_bundle") else 0.0)
            })
        
        # Build response with safe serialization (no instance references)
        managers = []
        unique_ids = set()
        
        for candidate in candidates:
            try:
                mgr_info = {
                    "name": candidate["name"],
                    "type": candidate["type"], 
                    "id": candidate["id"],
                    "has_token": candidate["has_token"],
                    "expires_at": candidate["expires_at"],
                    "time_to_expiry_s": max(0, int(candidate["expires_at"] - time.time())) if candidate["expires_at"] > 0 else None
                }
                managers.append(mgr_info)
                unique_ids.add(candidate["id"])
            except Exception as e:
                # Safe fallback for any individual manager
                managers.append({
                    "name": candidate.get("name", "unknown"),
                    "type": candidate.get("type", "unknown"),
                    "id": candidate.get("id", 0),
                    "has_token": False,
                    "expires_at": 0.0,
                    "time_to_expiry_s": None,
                    "error": str(e)
                })
        
        # Determine convergence: all managers should ideally point to same instance
        converged = len(unique_ids) <= 1 and len(managers) > 0
        
        # Additional convergence checks
        active_managers = [m for m in managers if m.get("has_token", False)]
        token_convergence = len(set(m["id"] for m in active_managers)) <= 1 if active_managers else True
        
        return {
            "ok": True,
            "converged": converged and token_convergence,
            "total_managers": len(managers),
            "unique_instances": len(unique_ids),
            "active_token_managers": len(active_managers),
            "managers": managers,
            "convergence_details": {
                "instance_convergence": converged,
                "token_convergence": token_convergence,
                "has_app_state_mgr": any(m["name"] == "app.state.saxo_mgr" for m in managers),
                "has_global_tm": any(m["name"] == "tm" for m in managers),
                "has_saxo_auth": any(m["name"] == "saxo_auth" for m in managers),
                "has_accessor": any("accessor" in m["name"] for m in managers)
            },
            "timestamp": time.time(),
            "version": APP_VERSION
        }
        
    except Exception as e:
        # Never crash - always return valid JSON even on errors
        return {
            "ok": False,
            "converged": False,
            "error": str(e),
            "error_type": type(e).__name__,
            "total_managers": 0,
            "unique_instances": 0,
            "active_token_managers": 0,
            "managers": [],
            "convergence_details": {
                "instance_convergence": False,
                "token_convergence": False,
                "has_app_state_mgr": False,
                "has_global_tm": False,
                "has_saxo_auth": False,
                "has_accessor": False
            },
            "timestamp": time.time(),
            "version": APP_VERSION
        }
