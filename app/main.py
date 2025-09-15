# main.py
# SNIPERBOT API v3.2 – FastAPI + Saxo auto-refresh (SIM/LIVE), met scan/decide/execute.
#
# Vereiste ENV variabelen (Render e.d.):
# - SINGLE_API_KEY=lenbogy123                 # header: X-API-Key
# - EXEC_ENABLED=true                         # vereist voor LIVE_SIM in /execute
# - LIVE_TRADING=true                         # label; SIM blijft SIM als SAXO_BASE op /sim/ staat
# - SAXO_BASE=https://gateway.saxobank.com/sim/openapi
# - SAXO_TOKEN_URL=https://sim.logonvalidation.net/token
# - SAXO_APP_KEY=<SIM/LIVE app key>
# - SAXO_APP_SECRET=<SIM/LIVE app secret>
# - SAXO_REFRESH_TOKEN=<initiële refresh token>   # kan geroteerd worden
# - SAXO_ACCOUNT_KEY=<AccountKey>                 # optioneel; anders auto-ophalen
# - TICKER_UIC_MAP={"AAPL":265598,"MSFT":1900}    # JSON string, UIC's voor tickers
# - REDIS_URL=rediss://:<pwd>@<host>:<port>/0     # optioneel voor token-rotatie/persist
#
# Endpoints:
# - GET  /healthz
# - POST /decide
# - POST /scan
# - POST /execute
# - GET  /oauth/saxo/status
# - GET  /oauth/saxo/assert
# - POST /oauth/saxo/probe
# - POST /saxo/refresh

import os
import json
import time
import base64
import threading
import logging
from typing import Any, Dict, List, Optional

import requests
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, validator

# Optional Redis
try:
    import redis  # type: ignore
except Exception:  # pragma: no cover
    redis = None

APP_VERSION = "v3.2"
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("sniperbot")
log_saxo = logging.getLogger("saxo")

app = FastAPI(title="SNIPERBOT API", version=APP_VERSION)

# ==================== Config uit ENV ====================

SINGLE_API_KEY = os.getenv("SINGLE_API_KEY", "lenbogy123").strip()

SAXO_BASE       = os.getenv("SAXO_BASE", "https://gateway.saxobank.com/sim/openapi").rstrip("/")
SAXO_TOKEN_URL  = os.getenv("SAXO_TOKEN_URL", "https://sim.logonvalidation.net/token")
SAXO_APP_KEY    = os.getenv("SAXO_APP_KEY", "").strip()
SAXO_APP_SECRET = os.getenv("SAXO_APP_SECRET", "").strip()

EXEC_ENABLED    = os.getenv("EXEC_ENABLED", "false").lower() == "true"
LIVE_TRADING    = os.getenv("LIVE_TRADING", "false").lower() == "true"
SAXO_ACCOUNT_KEY_ENV = os.getenv("SAXO_ACCOUNT_KEY", "").strip()

TICKER_UIC_MAP: Dict[str, int] = {}
try:
    raw_map = os.getenv("TICKER_UIC_MAP", "")
    if raw_map:
        TICKER_UIC_MAP = {k.upper(): int(v) for k, v in json.loads(raw_map).items()}
except Exception as e:
    log.warning("Kon TICKER_UIC_MAP niet parsen: %s", e)
    TICKER_UIC_MAP = {}

REDIS_URL = os.getenv("REDIS_URL", "").strip()

# ==================== Redis client (optioneel) ====================

rds: Optional["redis.Redis"] = None
if REDIS_URL and redis is not None:
    try:
        rds = redis.from_url(REDIS_URL, decode_responses=True)
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
            if ttl and ttl > 0:
                rds.setex(key, ttl, value)
            else:
                rds.set(key, value)
        except Exception:
            pass


# ==================== Security (API key) ====================

def require_api_key(x_api_key: Optional[str]) -> None:
    if SINGLE_API_KEY:
        if not x_api_key or x_api_key.strip() != SINGLE_API_KEY:
            raise HTTPException(status_code=401, detail="Invalid X-API-Key")
    # Als SINGLE_API_KEY leeg is, geen check (dev).


# ==================== Pydantic modellen ====================

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
        # Basiscontrole; nu alleen long
        if "entry" in values and v >= values["entry"]:
            raise ValueError("stop must be < entry for long")
        return v


# ==================== Saxo OAuth Token Manager ====================

class SaxoAuthManager:
    """
    Simpele, thread-safe token manager met refresh_token flow (Basic Auth).
    - Houdt access_token in memory (en optioneel in Redis met TTL)
    - Skew marge van 60s vóór expiry
    - Schrijft nieuwe refresh_token naar Redis (als aanwezig)
    """
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
        env_rt = os.getenv("SAXO_REFRESH_TOKEN", "").strip()
        if not env_rt:
            raise HTTPException(status_code=400, detail="SAXO_REFRESH_TOKEN ontbreekt (ook niet in Redis).")
        return env_rt

    def _store_refresh_token(self, rt: str) -> None:
        kv_set("saxo:refresh_token", rt)

    def _store_access_token(self, at: str, expires_in: int) -> None:
        now = time.time()
        self._access_token = at
        # 60s veiligheidsmarge
        self._expires_at = now + max(0, int(expires_in) - 60)
        # TTL in Redis (optioneel)
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
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }

    resp = requests.post(SAXO_TOKEN_URL, data=data, headers=headers, timeout=15)

    # ✅ accepteer 200 én 201
    if resp.status_code not in (200, 201):
        raise HTTPException(status_code=502, detail=f"Token refresh failed ({resp.status_code}): {resp.text}")

    try:
        js = resp.json()
    except Exception:
        raise HTTPException(status_code=502, detail=f"Token refresh decode failed: {resp.text[:400]}")

    at = js.get("access_token")
    exp = int(js.get("expires_in", 900))
    if not at:
        raise HTTPException(status_code=502, detail="Token refresh ok maar geen access_token in respons.")

    # access token + expiry opslaan
    self._store_access_token(at, exp)

    # refresh-token rotatie opslaan (Redis of disk, afhankelijk van jouw kv_set)
    new_rt = js.get("refresh_token")
    if new_rt and new_rt != rt:
        self._store_refresh_token(new_rt)

    def get_access_token(self, force: bool = False) -> str:
        with self._lock:
            now = time.time()
            if force or (self._access_token is None) or (now >= self._expires_at - 60):
                self._refresh_now()
            return self._access_token  # type: ignore[return-value]

    def auth_header(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.get_access_token()}"}

    def status(self) -> Dict[str, Any]:
        return {"ok": True, "expires_at": self._expires_at, "access_token": bool(self._access_token)}

    async def refresh_access_token(self) -> Dict[str, Any]:
        # async wrapper
        self._refresh_now()
        return {"ok": True, "expires_at": self._expires_at, "access_token": bool(self._access_token)}


saxo_auth = SaxoAuthManager()
# Eén bron van waarheid voor routes
app.state.saxo_mgr = saxo_auth
globals()["tm"] = saxo_auth


# ==================== Saxo HTTP helpers ====================

def saxo_get(path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    url = f"{SAXO_BASE}{path}"
    try:
        h = saxo_auth.auth_header()
        r = requests.get(url, headers=h, params=params, timeout=20)
        if r.status_code == 401:
            # Forceer refresh + één retry
            saxo_auth.get_access_token(force=True)
            h = saxo_auth.auth_header()
            r = requests.get(url, headers=h, params=params, timeout=20)
        r.raise_for_status()
        return r.json()
    except requests.HTTPError as e:
        msg = r.text if "r" in locals() else str(e)  # type: ignore[name-defined]
        code = r.status_code if "r" in locals() else 502  # type: ignore[name-defined]
        raise HTTPException(status_code=502, detail=f"Saxo GET {path} failed ({code}): {msg}") from e


def saxo_post(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    url = f"{SAXO_BASE}{path}"
    try:
        h = {**saxo_auth.auth_header(), "Content-Type": "application/json", "Accept": "application/json"}
        r = requests.post(url, headers=h, json=payload, timeout=20)
        if r.status_code == 401:
            saxo_auth.get_access_token(force=True)
            h = {**saxo_auth.auth_header(), "Content-Type": "application/json", "Accept": "application/json"}
            r = requests.post(url, headers=h, json=payload, timeout=20)
        r.raise_for_status()
        return r.json() if r.text.strip() else {"ok": True}
    except requests.HTTPError as e:
        msg = r.text if "r" in locals() else str(e)  # type: ignore[name-defined]
        code = r.status_code if "r" in locals() else 502  # type: ignore[name-defined]
        raise HTTPException(status_code=502, detail=f"Saxo POST {path} failed ({code}): {msg}") from e


# ==================== Utils ====================

def get_account_key() -> str:
    if SAXO_ACCOUNT_KEY_ENV:
        return SAXO_ACCOUNT_KEY_ENV
    # Probeer accounts endpoint
    js = saxo_get("/port/v1/accounts", params={"IncludeSubAccounts": "true"})
    try:
        data = js.get("Data", [])
        for acc in data:
            if acc.get("Active", True):
                return acc["AccountKey"]
        if data:
            return data[0]["AccountKey"]
    except Exception:
        pass
    raise HTTPException(status_code=502, detail=f"Kon AccountKey niet bepalen uit accounts: {js}")


def uic_for_ticker(ticker: str) -> int:
    t = ticker.strip().upper()
    if t not in TICKER_UIC_MAP:
        raise HTTPException(status_code=400, detail=f"Ticker '{t}' niet gevonden in TICKER_UIC_MAP.")
    return int(TICKER_UIC_MAP[t])


# ==================== Diagnostics & Refresh routes ====================

def _resolve_mgr():
    """Eén plaats om de TokenManager te vinden."""
    mgr = getattr(app.state, "saxo_mgr", None) if hasattr(app, "state") else None
    return mgr or globals().get("tm", None)


@app.get("/oauth/saxo/assert")
def oauth_saxo_assert(x_api_key: Optional[str] = Header(None)):
    require_api_key(x_api_key)
    mgr_state  = getattr(app.state, "saxo_mgr", None) if hasattr(app, "state") else None
    mgr_global = globals().get("tm", None)
    mgr = mgr_state or mgr_global

    def _safe_id(x): return id(x) if x is not None else None

    ids = {
        "app_state.saxo_mgr": _safe_id(mgr_state),
        "global.tm":          _safe_id(mgr_global),
        "chosen":             _safe_id(mgr),
    }
    converged = (
        ids["chosen"] is not None and
        (ids["chosen"] == ids["app_state.saxo_mgr"] or ids["app_state.saxo_mgr"] is None) and
        (ids["chosen"] == ids["global.tm"]         or ids["global.tm"]         is None)
    )
    safe_status = None
    try:
        safe_status = mgr.status() if (mgr and hasattr(mgr, "status")) else None
    except Exception as e:
        safe_status = {"ok": False, "error": f"{type(e).__name__}: {e}"}
    return {"ok": True, "converged": converged, "ids": ids, "manager_status": safe_status}


import base64
from typing import Optional
from fastapi import Header

@app.post("/oauth/saxo/probe")
def oauth_saxo_probe(x_api_key: Optional[str] = Header(None),
                     x_debug_refresh_token: Optional[str] = Header(None)):
    """
    Diagnose: test refresh direct tegen SAXO_TOKEN_URL mbv ENV. Toont geen secrets.
    Accepteert 200/201. Probeert Basic en valt terug op client_secret_post.
    Je kan optioneel een refresh_token overschrijven met header X-Debug-Refresh-Token.
    """
    require_api_key(x_api_key)

    token_url = os.getenv("SAXO_TOKEN_URL", "https://sim.logonvalidation.net/token").strip()
    app_key   = os.getenv("SAXO_APP_KEY", "").strip()
    app_sec   = os.getenv("SAXO_APP_SECRET", "").strip()
    rtok_env  = os.getenv("SAXO_REFRESH_TOKEN", "").strip()
    rtok      = (x_debug_refresh_token or rtok_env).strip()

    missing = [k for k,v in {
        "SAXO_APP_KEY": app_key, "SAXO_APP_SECRET": app_sec, "SAXO_REFRESH_TOKEN": rtok
    }.items() if not v]
    if missing:
        return {"ok": False, "reason": "missing_env", "missing_env": missing,
                "using": {"token_url": token_url, "app_key_tail": app_key[-4:], "rt_tail": rtok[-8:]}}

    def safe_using():
        return {"token_url": token_url, "app_key_tail": app_key[-4:], "rt_tail": rtok[-8:]}

    # Try BASIC first
    basic = base64.b64encode(f"{app_key}:{app_sec}".encode("ascii")).decode("ascii")
    headers = {"Authorization": f"Basic {basic}",
               "Content-Type": "application/x-www-form-urlencoded",
               "Accept": "application/json"}
    data = {"grant_type": "refresh_token", "refresh_token": rtok}

    try:
        resp = requests.post(token_url, headers=headers, data=data, timeout=15)
        ok = resp.status_code in (200, 201)
        preview = resp.text[:600] if isinstance(resp.text, str) else str(resp.text)
        try: j = resp.json()
        except Exception: j = None
        if ok:
            return {"ok": True, "http_status": resp.status_code,
                    "json_keys": sorted(j.keys()) if isinstance(j, dict) else None,
                    "using": safe_using(), "method": "basic"}
        # Fallback: client_secret_post
        resp2 = requests.post(token_url, data={**data, "client_id": app_key, "client_secret": app_sec}, timeout=15)
        ok2 = resp2.status_code in (200, 201)
        preview2 = resp2.text[:600] if isinstance(resp2.text, str) else str(resp2.text)
        try: j2 = resp2.json()
        except Exception: j2 = None
        return {"ok": ok2, "http_status": resp2.status_code,
                "json_keys": sorted(j2.keys()) if isinstance(j2, dict) else None,
                "preview": (preview2 if not ok2 else None),
                "using": safe_using(), "method": "client_secret_post"}
    except Exception as e:
        return {"ok": False, "error": type(e).__name__, "detail": str(e), "using": safe_using()}

@app.post("/saxo/refresh")
async def saxo_refresh(x_api_key: Optional[str] = Header(None)):
    require_api_key(x_api_key)
    mgr = _resolve_mgr()
    if not mgr:
        return {"ok": False, "reason": "TokenManager not available"}

    # Preflight: toon welke env er (eventueel) ontbreken
    missing = [k for k in ("SAXO_APP_KEY", "SAXO_APP_SECRET", "SAXO_REFRESH_TOKEN") if not os.getenv(k)]
    env_info = {
        "missing_env": missing,
        "exec_enabled": os.getenv("EXEC_ENABLED"),
        "token_strategy": os.getenv("TOKEN_STRATEGY"),
        "token_storage_path": os.getenv("TOKEN_STORAGE_PATH"),
    }

    try:
        res = await mgr.refresh_access_token()
        st  = mgr.status() if hasattr(mgr, "status") else {}
        return {"ok": True, "result": res, "status": st, **({"env": env_info} if missing else {})}

    except HTTPException as e:
        return {
            "ok": False,
            "error": "HTTPException",
            "http_status": getattr(e, "status_code", None),
            "detail": getattr(e, "detail", None),
            "env": env_info,
        }
        ...
    except Exception as e:
        log_saxo.exception("Saxo refresh failed")
        return {"ok": False, "error": type(e).__name__, "detail": str(e), "env": env_info}


# ==================== Core endpoints ====================

@app.get("/healthz", summary="Healthz")
def healthz():
    return {"ok": True, "version": APP_VERSION}


@app.get("/oauth/saxo/status", summary="Saxo Status")
def saxo_status(x_api_key: Optional[str] = Header(None)):
    require_api_key(x_api_key)
    in_redis  = bool(kv_get("saxo:access_token"))
    in_memory = bool(getattr(saxo_auth, "_access_token", None))
    return {
        "ok": True,
        "has_access_token": in_redis or in_memory,
        "expires_at_epoch": getattr(saxo_auth, "_expires_at", 0.0),
        "exec_enabled": EXEC_ENABLED,
        "live_trading": LIVE_TRADING,
    }


@app.post("/decide", summary="Decide Endpoint")
def decide_endpoint(req: DecideRequest, x_api_key: Optional[str] = Header(None), x_no_notify: Optional[str] = Header(None)):
    require_api_key(x_api_key)
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
        tops.append({
            "decision": "TRADE_LONG",
            "ticker": tkr,
            "sniper_score": s,
            "gates": {k: True for k in [
                "data","liquidity","risk","regime","technique","compliance",
                "cost","market_safety","tod","event_guard","latency_vwap"
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
            "reason_codes": ["EV_OK","COST_OK","EDGE_2OF3"],
            "meta": {"version": APP_VERSION, "nowET": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()), "latency_ms": 150, "universe_size": len(req.candidates)},
            "rejections": {},
            "explain_human": "Volume en trend zijn gunstig. We kopen met een marktorder, nemen bij +1% de helft winst en volgen de rest met een meeschuivende stop.",
        })

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
          description="Standaard DRY_RUN (preflight). Voor LIVE_SIM: EXEC_ENABLED=true én confirm=true. Vereist: TICKER_UIC_MAP en Saxo OAuth config.")
def execute_endpoint(req: ExecuteRequest, x_api_key: Optional[str] = Header(None), x_no_notify: Optional[str] = Header(None)):
    require_api_key(x_api_key)

    tkr = req.ticker.upper()
    problems: List[str] = []
    if req.shares <= 0:
        problems.append("shares <= 0")
    if req.stop >= req.entry:
        problems.append("stop >= entry (long)")
    try:
        uic = uic_for_ticker(tkr)
    except HTTPException as e:
        problems.append(e.detail if isinstance(e.detail, str) else "Uic missing")
        uic = None  # type: ignore

    mode = "DRY_RUN"
    if not problems and req.confirm and EXEC_ENABLED:
        mode = "LIVE_SIM"

    if mode == "DRY_RUN":
        return {
            "ok": True,
            "mode": mode,
            "entry_result": {"dry_run": True, "status": "skip", "reason": "preflight" if problems else "confirm_required"},
            "stop_result": {"dry_run": True, "status": "skip", "reason": "preflight" if problems else "confirm_required"},
            "problems": problems,
        }

    # LIVE_SIM pad
    if problems:
        return {
            "ok": False,
            "mode": mode,
            "entry_result": {"status": "error", "error": f"preflight: {', '.join(problems)}"},
            "stop_result": {"status": "skip", "reason": "preflight_error"},
        }

    if not SAXO_APP_KEY or not SAXO_APP_SECRET:
        raise HTTPException(status_code=400, detail="SAXO_APP_KEY/SECRET ontbreken.")
    if not (os.getenv("SAXO_REFRESH_TOKEN") or kv_get("saxo:refresh_token")):
        raise HTTPException(status_code=400, detail="SAXO_REFRESH_TOKEN ontbreekt (ook niet in Redis).")

    # Token + account key
    try:
        _ = saxo_auth.get_access_token()
        account_key = get_account_key()
    except HTTPException as e:
        return {
            "ok": True,
            "mode": mode,
            "entry_result": {"status": "error", "error": f"auth/account: {e.detail}"},
            "stop_result": {"status": "skip", "reason": "auth_failed"},
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

    # 2) STOP SELL
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
    }
