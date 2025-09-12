from pydantic import BaseModel, Field, field_validator
from typing import Optional, Literal, Dict

class MarketRegime(BaseModel):
    spy_pct: float = Field(..., description="SPY change as decimal (0.004 = +0.4%)")
    vix: float

class DecideInput(BaseModel):
    ticker: str
    price: float; open: float; high: float; low: float; prev_close: float
    bid: float; ask: float; quote_age_ms: int
    vwap: float; vwap_slope_pct_per_min: float
    rvol: float; gap_pct: float; spread_bps: float; atr_pct: float
    mkt_regime: MarketRegime
    news_tier: Literal["T3","T2","T1","NONE"]
    halted: bool
    adv_30d_shares: int
    mcap_usd: Optional[int] = 0
    time_of_day: Literal["open","core","lunch","power_hour"]

    # Kosten/uitvoering
    cost_profile: Optional[Literal["USD_CASH","PER_TRADE_FX"]] = "USD_CASH"
    commission_side_bps: Optional[int] = 8
    min_order_value_usd: Optional[int] = 2500
    slippage_guard_bps: Optional[int] = 8

    # Edge-persistentie (tijdelijk via input)
    vwap_reclaims_ok: Optional[bool] = None
    orb_follow_ok: Optional[bool] = None
    uptick_ratio_60: Optional[float] = None
    quote_uptick_ratio_60: Optional[float] = None

    @field_validator("ask")
    @classmethod
    def _ask_gt_bid(cls, v, info):
        bid = info.data.get("bid", 0.0)
        if v <= 0 or v <= bid:
            raise ValueError("ask must be > bid")
        return v

class OrdersSpec(BaseModel):
    entry: Dict[str, object]
    tp1: Dict[str, object]
    exit: Dict[str, object]

class Gates(BaseModel):
    data: bool; liquidity: bool; risk: bool; regime: bool; technique: bool
    compliance: bool; cost: bool; market_safety: bool; tod: bool; event_guard: bool; latency_vwap: bool

class Meta(BaseModel):
    version: str; nowET: str; latency_ms: int; universe_size: int

class DecideOutput(BaseModel):
    decision: Literal["TRADE_LONG","NO_TRADE"]
    ticker: str
    sniper_score: float
    gates: Gates
    mode: Optional[Literal["MARKET_ONLY","MARKETABLE_LIMIT"]] = "MARKET_ONLY"
    orders: Optional[OrdersSpec] = None
    entry: Optional[float] = None
    stop_loss: Optional[float] = None
    size_shares: Optional[int] = None
    costs: Optional[dict] = None
    probs: Optional[dict] = None
    ev_estimate: Optional[dict] = None
    reason_codes: list[str]
    meta: Optional[Meta] = None
    rejections: Optional[dict] = None
    explain_human: str
