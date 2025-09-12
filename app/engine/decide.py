from datetime import datetime, timezone
from typing import Tuple, Dict
from .utils import time_of_day_spread_limit_bps, rvol_score, catalyst_bonus, vwap_score, regime_tailwind

def cost_break_even(cost_profile: str, commission_side_bps: int, spread_bps: float, slippage_guard_bps: int) -> float:
    # commissies*2 + fx + spread + slippage (als percentages)
    commission_roundtrip_pct = 2 * commission_side_bps / 10_000
    fx_roundtrip_pct = 0.0050 if cost_profile == "PER_TRADE_FX" else 0.0
    spread_est_pct = spread_bps / 10_000.0
    slippage_pct = slippage_guard_bps / 10_000.0
    return commission_roundtrip_pct + fx_roundtrip_pct + spread_est_pct + slippage_pct

def gates(inp) -> Tuple[Dict[str,bool], list[str], float]:
    reasons = []
    # A) Data
    data_ok = (inp.ask > inp.bid and inp.quote_age_ms <= 500 and inp.price <= inp.high and inp.price >= inp.low)
    # B) Liquiditeit
    lim = time_of_day_spread_limit_bps(inp.time_of_day)
    liq_ok = (inp.spread_bps <= lim and inp.adv_30d_shares >= 2_000_000)
    # C) Risico
    risk_ok = (0.008 <= inp.atr_pct <= 0.05)
    # D) Regime
    regime_ok = (inp.mkt_regime.vix <= 25 and inp.mkt_regime.spy_pct >= -0.003)
    # E) Techniek
    technique_ok = (inp.price >= inp.vwap*(1+0.0005) and inp.vwap_slope_pct_per_min > 0)
    # F) Compliance
    compliance_ok = (not inp.halted)
    # G) Cost Gate
    be_cost = cost_break_even(inp.cost_profile, inp.commission_side_bps, inp.spread_bps, inp.slippage_guard_bps)
    cost_ok = (be_cost <= (0.0075 if inp.cost_profile=="PER_TRADE_FX" else 0.0025))
    # H) Market Safety
    safety_ok = (inp.rvol >= 1.2)
    # I) Time-of-day regels
    if inp.time_of_day == "lunch":
        tod_ok = (inp.rvol >= 2.0 and inp.spread_bps <= 5)
    elif inp.time_of_day == "power_hour":
        tod_ok = (inp.spread_bps <= 6)
    else:
        tod_ok = True
    # J) Event-Guard (placeholder)
    event_ok = True
    # K) Latency & VWAP sanity
    latency_vwap_ok = (inp.quote_age_ms <= 500 and abs(inp.price - inp.vwap) <= 0.75 * inp.atr_pct * inp.price)

    g = dict(
        data=data_ok, liquidity=liq_ok, risk=risk_ok, regime=regime_ok, technique=technique_ok,
        compliance=compliance_ok, cost=cost_ok, market_safety=safety_ok, tod=tod_ok, event_guard=event_ok, latency_vwap=latency_vwap_ok
    )
    for k,v in g.items():
        if not v:
            reasons.append("COST_TOO_HIGH" if k=="cost" else ("TOD_FAIL" if k=="tod" else k.upper()+"_FAIL"))
    return g, reasons, be_cost

def score(inp) -> float:
    s = 0.0
    s += rvol_score(inp.rvol)                       # 0..4
    s += catalyst_bonus(inp.gap_pct, inp.news_tier) # 0..2
    s += vwap_score(inp.price, inp.vwap, inp.atr_pct, inp.vwap_slope_pct_per_min)  # 0..2.25
    s += regime_tailwind(inp.mkt_regime.spy_pct)    # 0..0.8
    return round(float(s), 2)

def edge_persistence_ok(inp) -> bool:
    """2-van-3: vwap_reclaims_ok, orb_follow_ok, uptick_ratio_60 ≥ 0.55 (fallback quote_uptick_ratio_60)."""
    vwap_ok = bool(getattr(inp, "vwap_reclaims_ok", False))
    orb_ok  = bool(getattr(inp, "orb_follow_ok", False))
    ur = getattr(inp, "uptick_ratio_60", None)
    if ur is None:
        ur = float(getattr(inp, "quote_uptick_ratio_60", 0.0))
    uptick_ok = (ur >= 0.55)
    return (1 if vwap_ok else 0) + (1 if orb_ok else 0) + (1 if uptick_ok else 0) >= 2

def probs_placeholder(inp):
    # simpele, deterministische schatter tot §7 is geïmplementeerd
    base = 0.55 + min(0.10, 0.03*max(0.0, inp.rvol-1.2)) + (0.03 if inp.vwap_slope_pct_per_min>0 else -0.03)
    base += 0.02 if inp.price >= inp.vwap*(1+0.0005) else -0.02
    base += 0.02 if inp.news_tier in ("T2","T3") else 0.0
    p1 = max(0.0, min(0.9, base))
    q  = 0.55 + (0.05 if inp.news_tier=="T3" else (0.03 if inp.news_tier=="T2" else 0.0))
    q  -= min(0.03, inp.spread_bps/10000.0*2)
    q  = max(0.3, min(0.85, q))
    p2 = max(0.0, min(0.85, p1*q))
    return round(p1,4), round(p2,4), round(q,4)

def expected_value(p1, p2, atr_pct, cost_be):
    avg_loss_pct = -max(0.0045, 0.5*atr_pct)
    ev = p2*(0.012) + (p1-p2)*(0.005) - (1-p1)*abs(avg_loss_pct) - cost_be
    return round(avg_loss_pct,6), round(ev,6)

def decide(inp, universe_size: int = 150) -> dict:
    g, reasons, be_cost = gates(inp)
    sniper_score = score(inp)
    threshold = 6.0 if inp.cost_profile == "PER_TRADE_FX" else 5.5
    nowET = datetime.now(timezone.utc).isoformat()

    # Gates
    if not all(g.values()) or sniper_score < threshold:
        return {
            "decision": "NO_TRADE",
            "ticker": inp.ticker,
            "sniper_score": sniper_score,
            "gates": g,
            "reason_codes": list(set(["SCORE_LOW" if sniper_score < threshold else ""] + reasons) - {""}),
            "meta": {"version":"v3.2","nowET":nowET,"latency_ms":150,"universe_size":universe_size},
            "rejections": {},
            "explain_human": "We doen niets: een of meer basisvoorwaarden kloppen niet (data, spread, risico of trend)."
        }

    # Edge gate (harde gate vóór p1/p2/EV)
    if not edge_persistence_ok(inp):
        return {
            "decision": "NO_TRADE",
            "ticker": inp.ticker,
            "sniper_score": sniper_score,
            "gates": g,
            "reason_codes": ["NO_EDGE_PERSISTENCE"],
            "meta": {"version":"v3.2","nowET":nowET,"latency_ms":150,"universe_size":universe_size},
            "rejections": {},
            "explain_human": "We doen niets: het momentum hield niet stand (2 van 3 signalen faalden)."
        }

    # p1/p2 + EV
    p1, p2, q = probs_placeholder(inp)
    if p1 < 0.60:
        return {
            "decision": "NO_TRADE",
            "ticker": inp.ticker,
            "sniper_score": sniper_score,
            "gates": g,
            "reason_codes": ["P1_TOO_LOW"],
            "meta": {"version":"v3.2","nowET":nowET,"latency_ms":150,"universe_size":universe_size},
            "rejections": {},
            "explain_human": "We doen niets: kans op +1% is te laag."
        }

    avg_loss_pct, ev = expected_value(p1, p2, inp.atr_pct, be_cost)
    if ev <= 0:
        return {
            "decision": "NO_TRADE",
            "ticker": inp.ticker,
            "sniper_score": sniper_score,
            "gates": g,
            "reason_codes": ["EV_WEAK"],
            "meta": {"version":"v3.2","nowET":nowET,"latency_ms":150,"universe_size":universe_size},
            "rejections": {},
            "explain_human": "We doen niets: verwachte waarde is negatief na kosten en risico."
        }

    # Entry/Stop/Sizing (conservatief)
    entry = inp.price
    stop = min(entry*(1 - max(0.0045, 0.5*inp.atr_pct)), inp.vwap*(1-0.0015), inp.low*(1-0.0010))
    per_share_risk = entry - stop
    risk_cash = 100_000 * 0.005  # 0.5% van fictieve 100k
    size = max(1, int(risk_cash / max(0.01, per_share_risk)))

    costs = {
        "cost_profile": inp.cost_profile,
        "commission_roundtrip_pct": round(2*inp.commission_side_bps/10_000,6),
        "fx_roundtrip_pct": 0.0050 if inp.cost_profile=="PER_TRADE_FX" else 0.0,
        "spread_pct": round(inp.spread_bps/10_000.0,6),
        "slippage_pct": round(inp.slippage_guard_bps/10_000.0,6),
        "break_even_pct": round(be_cost,6)
    }

    return {
        "decision": "TRADE_LONG",
        "ticker": inp.ticker,
        "sniper_score": sniper_score,
        "gates": g,
        "mode": "MARKET_ONLY",
        "orders": {
            "entry": {"type":"MARKET"},
            "tp1":   {"type":"MARKET", "fraction": 0.5, "trigger_pct": 0.01},
            "exit":  {"type":"TRAIL_STOP_MARKET", "trail_pct_min": 0.004, "trail_atr_mult": 0.6, "freeze_after_tp1_sec": 120}
        },
        "entry": round(entry, 4),
        "stop_loss": round(stop, 4),
        "size_shares": size,
        "costs": costs,
        "probs": {"p1": p1, "p2": p2, "q": q},
        "ev_estimate": {"avg_loss_pct": avg_loss_pct, "net_ev_pct": ev},
        "reason_codes": ["EV_OK","COST_OK","EDGE_2OF3"],
        "meta": {"version":"v3.2","nowET":nowET,"latency_ms":150,"universe_size":universe_size},
        "rejections": {},
        "explain_human": "Volume en trend zijn gunstig. We kopen met een marktorder, nemen bij +1% de helft winst en volgen de rest met een meeschuivende stop."
    }
