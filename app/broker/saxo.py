import os, json, httpx
from typing import Optional, Callable

class SaxoClient:
    """
    Minimale Saxo OpenAPI adapter.
    - Default: DRY RUN (SAXO_ENABLED=false) -> alleen loggen, niets sturen.
    - LIVE HTTP: zet SAXO_ENABLED=true, vul env (token, account, base_url).
    - UIC Mapping: via env TICKER_UIC_MAP='{"AAPL":265598,"MSFT":1904}' (voorbeeld).
    - Runtime Bearer: get_bearer callable for dynamic token retrieval.
    """

    def __init__(self, get_bearer: Optional[Callable[[], str]] = None):
        self.enabled = os.getenv("SAXO_ENABLED", "false").lower() == "true"
        self.base_url = os.getenv("SAXO_BASE_URL", "").rstrip("/")
        self.access_token = os.getenv("SAXO_ACCESS_TOKEN", "")
        self.account_key = os.getenv("SAXO_ACCOUNT_KEY", "")
        self.get_bearer = get_bearer  # Runtime bearer token provider
        # eenvoudige symbol→UIC mapping om zonder extra API-calls te werken
        try:
            self.ticker_uic_map = json.loads(os.getenv("TICKER_UIC_MAP", "{}"))
        except Exception:
            self.ticker_uic_map = {}

        # optionele failsafe: marketable-limit in plaats van pure market
        self.market_limit_bps = float(os.getenv("SAXO_MARKETABLE_LIMIT_BPS", "0"))  # 0 = uit

    # ---------- helpers ----------
    def _headers(self):
        # Runtime bearer via TokenManager or fallback to env
        bearer_token = None
        if self.get_bearer:
            try:
                bearer_token = self.get_bearer()
            except Exception:
                bearer_token = None
        
        # Fallback to env token
        if not bearer_token:
            bearer_token = self.access_token
        
        if not bearer_token:
            raise RuntimeError("No bearer token available (neither from get_bearer nor env)")
            
        return {
            "Authorization": f"Bearer {bearer_token}",
            "Content-Type": "application/json",
        }

    def _uic_for(self, ticker: str) -> Optional[int]:
        return self.ticker_uic_map.get(ticker.upper())

    def _ensure_live_ready(self):
        if not self.enabled:
            raise RuntimeError("SAXO_ENABLED=false (dry-run)")
        for k, v in {
            "SAXO_BASE_URL": self.base_url,
            "SAXO_ACCESS_TOKEN": self.access_token,
            "SAXO_ACCOUNT_KEY": self.account_key,
        }.items():
            if not v:
                raise RuntimeError(f"Missing env: {k}")

    # ---------- public API ----------
    async def place_market_buy(self, ticker: str, shares: int, last_price: float) -> dict:
        """
        Stuurt een MARKT-buy (of marketable limit als bps>0).
        In DRY RUN retourneert een pseudo-order.
        Let op: Saxo verwacht UIC (instrument id) & AssetType.
        """
        payload = {
            "ticker": ticker,
            "shares": int(shares),
            "price_hint": float(last_price),
            "mode": "MARKET_ONLY" if self.market_limit_bps <= 0 else "MARKETABLE_LIMIT",
        }

        # Dry-run?
        if not self.enabled:
            return {"dry_run": True, "status": "ok", "order_id": "SIM-ENTRY", "payload": payload}

        self._ensure_live_ready()

        uic = self._uic_for(ticker)
        if not uic:
            raise RuntimeError(f"UIC onbekend voor {ticker}. Zet TICKER_UIC_MAP in env.")

        # MARKT of Marketable Limit (cap = last + bps)
        order = {
            "AccountKey": self.account_key,
            "Uic": uic,
            "AssetType": "Stock",
            "BuySell": "Buy",
            "Amount": int(shares),
            "OrderDuration": {"DurationType": "DayOrder"},
            "OrderType": "Market",
            "ManualOrder": False,
        }
        if self.market_limit_bps > 0 and last_price > 0:
            cap = last_price * (1 + self.market_limit_bps / 10000.0)
            order["OrderType"] = "Limit"
            order["Price"] = round(cap, 2)

        # NB: endpointpad kan per Saxo-versie verschillen; maak configureerbaar:
        orders_url = os.getenv("SAXO_ORDERS_ENDPOINT", f"{self.base_url}/trade/v2/orders")

        async with httpx.AsyncClient(timeout=5.0) as cli:
            r = await cli.post(orders_url, headers=self._headers(), json=order)
            try:
                data = r.json()
            except Exception:
                data = {"text": r.text}
            if r.status_code >= 300:
                raise RuntimeError(f"Saxo order error {r.status_code}: {data}")
            return {"dry_run": False, "status": "ok", "order_id": data.get("OrderId") or data, "request": order}

    async def place_stop_market(self, ticker: str, shares: int, stop_price: float) -> dict:
        """
        Zet een afzonderlijke STOP MARKET. (Simpel model; in praktijk kun je OCO/related order gebruiken.)
        """
        payload = {
            "ticker": ticker,
            "shares": int(shares),
            "stop_price": float(stop_price),
            "type": "STOP_MARKET",
        }

        if not self.enabled:
            return {"dry_run": True, "status": "ok", "order_id": "SIM-STOP", "payload": payload}

        self._ensure_live_ready()

        uic = self._uic_for(ticker)
        if not uic:
            raise RuntimeError(f"UIC onbekend voor {ticker}. Zet TICKER_UIC_MAP in env.")

        order = {
            "AccountKey": self.account_key,
            "Uic": uic,
            "AssetType": "Stock",
            "BuySell": "Sell",
            "Amount": int(shares),
            "OrderDuration": {"DurationType": "DayOrder"},
            "OrderType": "Stop",
            "StopPrice": round(stop_price, 2),
            "ManualOrder": False,
        }
        orders_url = os.getenv("SAXO_ORDERS_ENDPOINT", f"{self.base_url}/trade/v2/orders")
        async with httpx.AsyncClient(timeout=5.0) as cli:
            r = await cli.post(orders_url, headers=self._headers(), json=order)
            try:
                data = r.json()
            except Exception:
                data = {"text": r.text}
            if r.status_code >= 300:
                raise RuntimeError(f"Saxo stop error {r.status_code}: {data}")
            return {"dry_run": False, "status": "ok", "order_id": data.get("OrderId") or data, "request": order}
