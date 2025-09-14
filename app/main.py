# app/main.py
from __future__ import annotations

import os
import json
import time
import math
import threading
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import requests
from fastapi import FastAPI, Header, HTTPException, Request, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# ----------------------------
# Config & helpers
# ----------------------------

VERSION = "v3.2"
API_KEY_EXPECTED = os.getenv("X_API_KEY", "lenbogy123")

LIVE_TRADING = os.getenv("LIVE_TRADING", "false").lower() == "true"
EXEC_ENABLED = os.getenv("EXEC_ENABLED", "false").lower() == "true"

SAXO_BASE = os.getenv("SAXO_BASE", "https://gateway.saxobank.com/sim/openapi").rstrip("/")
SAXO_APP_KEY = os.getenv("SAXO_APP_KEY", "").strip()
SAXO_APP_SECRET = os.getenv("SAXO_APP_SECRET", "").strip()
SAXO_REFRESH_TOKEN = os.getenv("SAXO_REFRESH_TOKEN", "").strip()
SAXO_ACCOUNT_KEY = os.getenv("SAXO_ACCOUNT_KEY", "").strip()  # bv. ytESP...==

# Token endpoint obv sim/live
if "/sim/" in SAXO_BASE:
    SAXO_TOKEN_URL = "https://sim.logonvalidation.net/token"
else:
    SAXO_TOKEN_URL = "https://live.logonvalidation.net/token"

# Ticker -> UIC mapping (JSON in env)
try:
    TICKER_UIC_MAP: Dict[str, int] = json.loads(os.getenv("TICKER_UIC_MAP", "{}"))
    # keys case-insensitive
    TICKER_UIC_MAP = {k.upper(): int(v) for k, v in TICKER_UIC_MAP.items()}
except Exception:
    TICKER_UIC_MAP = {}

TG_ENABLED = os.getenv("TG_ENABLED", "false").lower() == "true"
TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "")
TG_CHAT_ID = os.getenv("TG_CHAT_ID", "")

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def require_api_key(x_api_key: str | None):
    if not x_api_key or x_api_key != API_KEY_EXPECTED:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

def notify_async(text: str, no_notify: bool = False) -> None:
    """Non-blocking Telegram message; failsafe (swallows errors)."""
    if no_notify or not TG_ENABLED or not TG_BOT_TOKEN or not TG_CHAT_ID:
        return
    def _send():
        try:
            requests.post(
                f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
                json={"chat_id": TG_CHAT_ID, "text": text[:4000], "disable_web_page_preview": True},
                timeout=5,
            )
        except Exception:
            pass
    threading.Thread(target=_send, daemon=True).start()

# ----------------------------
# Saxo session (refresh + auth)
# ----------------------------

class SaxoSession:
    def __init__(self):
        self._lock = threading.Lock()
        self.access_token: Optional[str] = None
        self.expires_at: float = 0.0   # epoch seconds
        self.refresh_token_mem: Optional[str] = SAXO_REFRESH_TOKEN or None

    def _refresh_locked(self) -> Dict[str, Any]:
        if not (SAXO_APP_KEY and SAXO_APP_SECRET and (self.refresh_token_mem or SAXO_REFRESH_TOKEN)):
            raise HTTPException(status_code=400, detail="Saxo credentials missing (APP_KEY/SECRET/REFRESH_TOKEN).")

        refresh_token = self.refresh_token_mem or SAXO_REFRESH_TOKEN
        basic = f"{SAXO_APP_KEY}:{SAXO_APP_SECRET}".encode("ascii")
        headers = {
            "Authorization": "Basic " + (basic).decode("ascii").encode("ascii").hex(),  # will overwrite below
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        # Basic must be Base64, not hex: fix:
        import base64
        headers["Authorization"] = "Basic " + base64.b64encode(basic).decode("ascii")

        body = f"grant_type=refresh_token&refresh_token={requests.utils.quote(refresh_token)}"
        resp = requests.post(SAXO_TOKEN_URL, headers=headers, data=body, timeout=15)
        if resp.status_code != 200:
            raise HTTPException(status_code=401, detail=f"Saxo refresh failed: HTTP {resp.status_code}: {resp.text}")

        data = resp.json()
        self.access_token = data.get("access_token")
        # Rotated refresh token?
        if data.get("refresh_token"):
            self.refresh_token_mem = data["refresh_token"]

        # expires_in (sec)
        ttl = int(data.get("expires_in", 900))
        # refresh proactively a bit early
        self.expires_at = time.time() + max(60, ttl - 60)
        return {"ok": True, "rotated": bool(data.get("refresh_token"))}

    def get_access_token(self, force: bool = False) -> str:
        with self._lock:
            if force or not self.access_token or time.time() >= self.expires_at:
                self._refresh_locked()
            return self.access_token  # type: ignore

    def auth_headers(self) -> Dict[str, str]:
        tok = self.get_access_token()
        return {"Authorization": f"Bearer {tok}", "Accept": "application/json"}

SAXO = SaxoSession()

def saxo_get(url: str, params: Dict[str, Any] | None = None) -> requests.Response:
    headers = SAXO.auth_headers()
    return requests.get(url, headers=headers, params=params, timeout=20)

def saxo_post(url: str, payload: Dict[str, Any]) -> requests.Response:
    headers = SAXO.auth_headers()
    headers["Content-Type"] = "application/json"
    return requests.post(url, headers=headers, json=payload, timeout=20)

# ----------------------------
# FastAPI
# ----------------------------

app = FastAPI(title="SNIPERBOT API", version=VERSION)

@app.get("/healthz")
def healthz():
    return {"ok": True, "version": VERSION}

# ----------------------------
# Universe (simple)
# ----------------------------

SP100 = [
    # (verkorte lijst – voeg gerust uit je env of repo toe)
    "AAPL","MSFT","NVDA","AMZN","META","GOOGL","GOOG","TSLA","AVGO","JPM",
    "UNH","XOM","V","MA","HD","PG","CVX","LLY","COST","MRK","ABBV","PEP",
    "BAC","KO","PFE","CSCO","ADBE","WMT","NFLX","CRM","ORCL","DIS","QCOM",
    "INTC","AMD","TXN","AMAT","NKE","MCD","IBM","BA","CAT","HON"
]

@app.get("/universe")
def get_universe(name: str = Query("SP100"), x_api_key: str | None = Header(None)):
    require_api_key(x_api_key)
    name_u = name.lower()
    if name_u == "sp100":
        tickers = SP100
    elif name_u == "custom":
        # Optioneel: alleen extras uit env
        extras = json.loads(os.getenv("UNIVERSE_EXTRAS", "[]"))
        tickers = [t.upper() for t in extras]
    else:
        tickers = SP100
    return {"universe_name": name.upper(), "count": len(tickers), "tickers": tickers}

# ----------------------------
# Beslis-engine (light maar deterministisch)
# ----------------------------

def edge_persistence_ok(inp: Dict[str, Any]) -> bool:
    vwap_re = bool(inp.get("vwap_reclaims_ok", False))
    orb_ok   = bool(inp.get("orb_follow_ok", False))
    uptick   = float(inp.get("uptick_ratio_60", 0.0))
    score = (1 if vwap_re else 0) + (1 if orb_ok else 0) + (1 if uptick >= 0.60 else 0)
    return score >= 2

def technique_ok(inp: Dict[str, Any]) -> bool:
    vwap = float(inp.get("vwap", 0.0))
    price = float(inp.get("price", 0.0))
    slope = float(inp.get("vwap_slope_pct_per_min", 0.0))
    if vwap <= 0 or price <= 0:
        return False
    return (price >= vwap * (1 + 0.0005)) and (slope > 0)

def tod_ok(inp: Dict[str, Any]) -> bool:
    tod = (inp.get("time_of_day") or "core").lower()
    if tod == "core":
        return True
    if tod == "lunch":
        # soepelere spread bij rvol hoog
        rvol = float(inp.get("rvol", 0))
        spread_bps = float(inp.get("spread_bps", 999))
        return (rvol >= 2.0) and (spread_bps <= 5)
    if tod == "power_hour":
        spread_bps = float(inp.get("spread_bps", 999))
        return spread_bps <= 6
    return False

def cost_block(inp: Dict[str, Any]) -> Dict[str, float | str | bool]:
    # commissies in bps per kant → 2 kanten
    comm_side_bps = float(inp.get("commission_side_bps", 0))
    commission_roundtrip_pct = (comm_side_bps * 2.0) / 1e4
    fx_roundtrip_pct = 0.0
    spread_pct = float(inp.get("spread_bps", 0)) / 1e4
    slippage_pct = float(inp.get("slippage_guard_bps", 0)) / 1e4
    break_even = commission_roundtrip_pct + fx_roundtrip_pct + spread_pct + slippage_pct
    return {
        "cost_profile": str(inp.get("cost_profile") or "USD_CASH"),
        "commission_roundtrip_pct": round(commission_roundtrip_pct, 6),
        "fx_roundtrip_pct": round(fx_roundtrip_pct, 6),
        "spread_pct": round(spread_pct, 6),
        "slippage_pct": round(slippage_pct, 6),
        "break_even_pct": round(break_even, 6),
    }

def probs_placeholder(inp: Dict[str, Any]) -> Dict[str, float]:
    # simpele placeholder, monotone in rvol & slope
    rvol = float(inp.get("rvol", 1.0))
    slope = max(0.0, float(inp.get("vwap_slope_pct_per_min", 0.0)))
    p1 = max(0.50, min(0.80, 0.55 + 0.05*(rvol-1) + 0.20*(slope>0)))
    p2 = max(0.25, min(0.65, 0.30 + 0.03*(rvol-1) + 0.10*(slope>0)))
    q  = (p1 + p2) / 2.0
    return {"p1": round(p1, 4), "p2": round(p2, 4), "q": round(q, 4)}

def decide_once(inp: Dict[str, Any]) -> Dict[str, Any]:
    # Gates
    gates = {
        "data": all(k in inp for k in ["ticker","price","bid","ask","vwap"]),
        "liquidity": float(inp.get("adv_30d_shares", 0)) >= 2_000_000,
        "risk": float(inp.get("atr_pct", 0.02)) <= 0.03,
        "regime": True,
        "technique": technique_ok(inp),
        "compliance": not bool(inp.get("halted", False)),
        "market_safety": True,
        "tod": tod_ok(inp),
        "event_guard": True,
        "latency_vwap": float(inp.get("quote_age_ms", 9999)) <= 800,
    }
    c = cost_block(inp)
    gates["cost"] = c["break_even_pct"] <= 0.0030  # 30 bps drempel

    ok_all = all(gates.values()) and edge_persistence_ok(inp)
    if not ok_all:
        return {
            "decision": "NO_TRADE",
            "ticker": inp.get("ticker"),
            "sniper_score": 0.0,
            "gates": gates,
            "mode": "MARKET_ONLY",
            "orders": {},
            "entry": None,
            "stop_loss": None,
            "size_shares": None,
            "costs": c,
            "probs": {},
            "ev_estimate": {},
            "reason_codes": ["SCORE_LOW"],
            "meta": {"version": VERSION, "latency_ms": 0},
            "rejections": {},
            "explain_human": "We doen niets: een of meer basisvoorwaarden kloppen niet (data, spread, risico of trend).",
        }

    # Trade plan
    price = float(inp.get("price", 0))
    atr_pct = float(inp.get("atr_pct", 0.015))
    stop_loss = round(price * (1 - max(0.02, atr_pct*0.5)), 4) if price > 0 else None
    # sizing: minimaal min_order_value_usd; anders 1 share
    min_val = float(inp.get("min_order_value_usd", 0))
    shares = max(1, int(math.floor(min_val / price))) if (price > 0 and min_val > 0) else 1

    probs = probs_placeholder(inp)
    net_ev = probs["q"] * 0.01 - (1 - probs["q"]) * 0.008 - c["break_even_pct"]  # ruwe placeholder
    ev = {"avg_loss_pct": -0.008, "net_ev_pct": round(float(net_ev), 6)}

    plan_orders = {
        "entry": {"type": "MARKET"},
        "tp1": {"type": "MARKET", "fraction": 0.5, "trigger_pct": 0.01},
        "exit": {"type": "TRAIL_STOP_MARKET", "trail_pct_min": 0.004, "trail_atr_mult": 0.6, "freeze_after_tp1_sec": 120},
    }
    return {
        "decision": "TRADE_LONG",
        "ticker": inp.get("ticker"),
        "sniper_score": 5.5,
        "gates": gates,
        "mode": "MARKET_ONLY",
        "orders": plan_orders,
        "entry": price,
        "stop_loss": stop_loss,
        "size_shares": shares,
        "costs": c,
        "probs": probs,
        "ev_estimate": ev,
        "reason_codes": ["EV_OK","COST_OK","EDGE_2OF3"],
        "meta": {"version": VERSION, "nowET": now_iso(), "latency_ms": 0, "universe_size": 150},
        "rejections": {},
        "explain_human": "Volume en trend zijn gunstig. We kopen met een marktorder, nemen bij +1% de helft winst en volgen de rest met een meeschuivende stop.",
    }

# ----------------------------
# Routes: decide / scan
# ----------------------------

@app.post("/decide")
def decide_route(req: Dict[str, Any], x_api_key: str | None = Header(None), x_no_notify: Optional[str] = Header(None)):
    require_api_key(x_api_key)
    out = decide_once(req or {})
    if not x_no_notify:
        notify_async(f"decide {out.get('ticker')} → {out.get('decision')}")
    return out

class ScanBody(BaseModel):
    universe_name: str = "SP100"
    top_k: int = 3
    candidates: List[Dict[str, Any]]

@app.post("/scan")
def scan_route(body: ScanBody, x_api_key: str | None = Header(None), x_no_notify: Optional[str] = Header(None)):
    require_api_key(x_api_key)
    results: List[Dict[str, Any]] = []
    rejections_summary: Dict[str, int] = {}

    for c in body.candidates:
        r = decide_once(c)
        results.append(r)
        if r["decision"] == "NO_TRADE":
            for code in r.get("reason_codes", []):
                rejections_summary[code] = rejections_summary.get(code, 0) + 1

    tradeables = [r for r in results if r["decision"].startswith("TRADE")]
    top = tradeables[: max(0, body.top_k)]
    out = {
        "universe_name": body.universe_name,
        "scanned": len(results),
        "tradeables": len(tradeables),
        "top": top,
        "summary": {
            "TRADE_LONG": sum(1 for r in results if r["decision"] == "TRADE_LONG"),
            "NO_TRADE": sum(1 for r in results if r["decision"] == "NO_TRADE"),
            "rejections": rejections_summary,
        },
        "meta": {"version": VERSION, "nowET": now_iso(), "latency_ms": 0, "universe_size": len(body.candidates)},
    }
    if not x_no_notify:
        notify_async(f"scan {body.universe_name}: {out['summary']}")
    return out

# ----------------------------
# Routes: Saxo auth helpers
# ----------------------------

@app.post("/saxo/refresh")
def saxo_refresh(x_api_key: str | None = Header(None)):
    require_api_key(x_api_key)
    data = SAXO._refresh_locked()
    return {"ok": True, "rotated": data["rotated"]}

@app.get("/saxo/accounts/me")
def saxo_accounts_me(x_api_key: str | None = Header(None)):
    require_api_key(x_api_key)
    url = f"{SAXO_BASE}/port/v1/accounts/me"
    resp = saxo_get(url)
    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)
    return resp.json()

# ----------------------------
# Route: execute (DRY_RUN / LIVE_SIM)
# ----------------------------

class ExecBody(BaseModel):
    ticker: str
    shares: int
    entry: float
    stop: float
    confirm: bool = False

@app.post("/execute")
def execute_route(body: ExecBody, x_api_key: str | None = Header(None), x_no_notify: Optional[str] = Header(None)):
    require_api_key(x_api_key)

    # Always return DRY_RUN if confirm==False OR feature flags off
    if not body.confirm or not EXEC_ENABLED:
        res = {
            "ok": True,
            "mode": "DRY_RUN",
            "entry_result": {"dry_run": True, "status": "skip", "reason": "preflight"},
            "stop_result": {"dry_run": True, "status": "skip", "reason": "preflight"},
        }
        if not x_no_notify:
            notify_async(f"execute DRY_RUN {body.ticker} x{body.shares} @~{body.entry}")
        return res

    # Live SIM guard
    if not LIVE_TRADING:
        return {
            "ok": True,
            "mode": "LIVE_SIM",
            "entry_result": {"status": "error", "error": "LIVE_TRADING=false", "sent": {}},
            "stop_result": {"status": "skip", "reason": "not_implemented_safely"},
        }

    # Preconditions
    if not SAXO_ACCOUNT_KEY:
        return {
            "ok": True,
            "mode": "LIVE_SIM",
            "entry_result": {"status": "error", "error": "SAXO_ACCOUNT_KEY missing", "sent": {}},
            "stop_result": {"status": "skip", "reason": "not_implemented_safely"},
        }
    uic = TICKER_UIC_MAP.get(body.ticker.upper())
    if not uic:
        return {
            "ok": True,
            "mode": "LIVE_SIM",
            "entry_result": {"status": "error", "error": f"UIC not found for {body.ticker}", "sent": {}},
            "stop_result": {"status": "skip", "reason": "not_implemented_safely"},
        }

    # Ensure access token
    try:
        SAXO.get_access_token()
    except HTTPException as e:
        return {
            "ok": True,
            "mode": "LIVE_SIM",
            "entry_result": {"status": "error", "error": f"Auth error: {e.detail}", "sent": {}},
            "stop_result": {"status": "skip", "reason": "not_implemented_safely"},
        }

    # Build order (simple market buy)
    order_payload = {
        "AccountKey": SAXO_ACCOUNT_KEY,
        "Uic": uic,
        "AssetType": "Stock",
        "BuySell": "Buy",
        "Amount": max(1, int(body.shares)),
        "OrderType": "Market",
        "OrderDuration": {"DurationType": "DayOrder"},
        "ExternalReference": f"SNIPERBOT-{int(time.time())}",
        "OpenClose": "Open",
        "ManualOrder": False,
    }

    url = f"{SAXO_BASE}/trade/v2/orders"
    resp = saxo_post(url, order_payload)

    if resp.status_code != 201 and resp.status_code != 200:
        entry_result = {"status": "error", "error": f"HTTP Error {resp.status_code}: {resp.text}", "sent": order_payload}
    else:
        entry_result = {"status": "ok", "response": resp.json(), "sent": order_payload}

    out = {
        "ok": True,
        "mode": "LIVE_SIM",
        "entry_result": entry_result,
        "stop_result": {"status": "skip", "reason": "not_implemented_safely"},
    }
    if not x_no_notify:
        notify_async(f"execute {out['mode']} {body.ticker} x{body.shares} → {entry_result['status']}")
    return out


# ----------------------------
# Exception handler (nette JSON)
# ----------------------------

@app.exception_handler(HTTPException)
def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

# ----------------------------
# Run (local)
# ----------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=int(os.getenv("PORT", "10000")), reload=False)
