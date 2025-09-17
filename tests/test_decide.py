import os

os.environ["SINGLE_API_KEY"] = ""

from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)

BASE = {
  "ticker": "AAPL",
  "price": 192.35, "open": 190.80, "high": 193.20, "low": 189.90, "prev_close": 188.90,
  "bid": 192.34, "ask": 192.36, "quote_age_ms": 120,
  "vwap": 191.70, "vwap_slope_pct_per_min": 0.05,
  "rvol": 1.8, "gap_pct": 0.009, "spread_bps": 5, "atr_pct": 0.016,
  "mkt_regime": { "spy_pct": 0.004, "vix": 13.5 },
  "news_tier": "T2", "halted": False,
  "adv_30d_shares": 25000000, "mcap_usd": 125000000000,
  "time_of_day": "core",
  "cost_profile": "USD_CASH", "commission_side_bps": 8, "min_order_value_usd": 2500, "slippage_guard_bps": 8,
  "vwap_reclaims_ok": True, "orb_follow_ok": True, "uptick_ratio_60": 0.60
}

def test_healthz():
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["ok"] is True

def test_no_trade_on_spread_wide():
    p = dict(BASE); p["spread_bps"] = 20
    r = client.post("/decide", json=p)
    assert r.status_code == 200
    assert r.json()["decision"] == "NO_TRADE"

def test_trade_or_not():
    r = client.post("/decide", json=BASE)
    assert r.status_code == 200
    data = r.json()
    assert data["decision"] in ("TRADE_LONG","NO_TRADE")
    if data["decision"] == "TRADE_LONG":
        assert data["probs"]["p1"] >= 0.60
        assert data["ev_estimate"]["net_ev_pct"] > 0
