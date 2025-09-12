import math

def clip(x: float, a: float, b: float) -> float:
    return max(a, min(b, x))

def time_of_day_spread_limit_bps(tod: str) -> int:
    if tod == "open": return 12
    if tod == "core": return 8
    if tod == "power_hour": return 6
    if tod == "lunch": return 8  # lunch-check apart
    return 9999

def rvol_score(rvol: float) -> float:
    if rvol <= 0: return 0.0
    return clip(2 * math.log(rvol), 0.0, 4.0)

def catalyst_bonus(gap_pct: float, news_tier: str) -> float:
    if gap_pct < 0.005: return 0.0
    return {"T3": 2.0, "T2": 1.5, "T1": 1.0, "NONE": 0.5}.get(news_tier, 0.0)

def vwap_score(price: float, vwap: float, atr_pct: float, slope_ppm: float) -> float:
    if atr_pct <= 0 or price <= 0 or vwap <= 0: return 0.0
    z = (price - vwap) / (atr_pct * price)
    base = clip(z, 0.0, 1.0) * 2.0
    if slope_ppm > 0: base += 0.25
    return base

def regime_tailwind(spy_pct: float) -> float:
    if spy_pct >= 0.003: return 0.8
    if spy_pct >= 0.0:   return 0.4
    return 0.0
