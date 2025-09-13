import os
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Header, Depends, Query
from .schemas import (
    DecideInput, DecideOutput,
    ScanRequest, ScanResponse, Meta,
    ExecuteRequest, ExecuteResponse,
)
from .engine.decide import decide
from .engine.scan import run_scan, rank_tradeables
from .universe import get_universe
from .notify import notify
from .broker.saxo import SaxoClient

app = FastAPI(title="SNIPERBOT API", version="v3.2")

# ── API-key beveiliging ─────────────────────────────────────────────────────────
_API_KEYS = {k.strip() for k in os.getenv("API_KEYS", os.getenv("API_KEY", "")).split(",") if k.strip()}

def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    """
    - Geen keys in env? -> laat door (voorkomt lock-out tijdens setup).
    - Wel keys? -> header moet exact matchen, anders 401.
    """
    if not _API_KEYS:
        return
    if not x_api_key or x_api_key not in _API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

# ── Helpers ─────────────────────────────────────────────────────────────────────
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _should_notify(x_no_notify: str | None) -> bool:
    if not x_no_notify:
        return True
    return x_no_notify.strip().lower() not in ("1", "true", "yes", "on")

# ── Endpoints ───────────────────────────────────────────────────────────────────

@app.get("/healthz")
def healthz():
    return {"ok": True, "version": "v3.2"}

@app.get("/universe")
def universe_endpoint(
    name: str = Query(default="SP100", description="SP100 of 'custom' (alleen EXTRA_TICKERS)"),
    _: None = Depends(require_api_key),
):
    u = get_universe(name)
    return {"universe_name": name, "count": len(u), "tickers": u}

@app.post("/decide", response_model=DecideOutput)
async def decide_endpoint(
    inp: DecideInput,
    _: None = Depends(require_api_key),
    x_no_notify: str | None = Header(default=None, alias="X-No-Notify"),
):
    try:
        result = decide(inp)
        if _should_notify(x_no_notify):
            event = "NO_TRADE" if result.get("decision") == "NO_TRADE" else "ENTRY_MKT"
            await notify(event, {
                "ticker": result.get("ticker"),
                "decision": result.get("decision"),
                "entry": result.get("entry"),
                "stop": result.get("stop_loss"),
                "size": result.get("size_shares"),
                "reason_codes": result.get("reason_codes", []),
                "p1": (result.get("probs") or {}).get("p1"),
                "p2": (result.get("probs") or {}).get("p2"),
                "ev": (result.get("ev_estimate") or {}).get("net_ev_pct"),
            })
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/scan", response_model=ScanResponse)
async def scan_endpoint(
    req: ScanRequest,
    _: None = Depends(require_api_key),
    x_no_notify: str | None = Header(default=None, alias="X-No-Notify"),
):
    try:
        results, summary = run_scan(req.candidates)
        ranked = rank_tradeables(results)
        top = ranked[: max(1, int(req.top_k))]

        meta = Meta(version="v3.2", nowET=_now_iso(), latency_ms=150, universe_size=len(req.candidates))
        resp = ScanResponse(
            universe_name=req.universe_name or "custom",
            scanned=len(results),
            tradeables=len(ranked),
            top=top,
            summary=summary,
            meta=meta,
        )

        if _should_notify(x_no_notify):
            await notify("SCAN", {
                "n": len(results),
                "tradeables": len(ranked),
                "top": [t.get("ticker") for t in top],
            })
        return resp
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/execute", response_model=ExecuteResponse)
async def execute_endpoint(
    req: ExecuteRequest,
    _: None = Depends(require_api_key),
    x_live_trade: str | None = Header(default=None, alias="X-Live-Trade"),  # tweede bevestiging
    x_no_notify: str | None = Header(default=None, alias="X-No-Notify"),
):
    """
    2-fasen executie:
      - confirm=false          → altijd preflight (DRY_RUN; geen orders)
      - confirm=true + X-Live-Trade in (1|true|yes|on)
          → als SAXO_ENABLED=true en env compleet: echte orders (LIVE)
    """
    sc = SaxoClient()

    # Preflight standaardresultaten
    entry_result: dict = {"dry_run": True, "status": "skip", "reason": "preflight"}
    stop_result: dict  = {"dry_run": True, "status": "skip", "reason": "preflight"}

    live_ok = (req.confirm is True) and (x_live_trade or "").strip().lower() in ("1", "true", "yes", "on")

    try:
        if live_ok:
            # Entry & Stop versturen (of exception als env onvolledig)
            entry_result = await sc.place_market_buy(req.ticker, int(req.shares), float(req.entry))
            stop_result  = await sc.place_stop_market(req.ticker, int(req.shares), float(req.stop))

            if _should_notify(x_no_notify):
                try:
                    await notify("EXEC_SENT", {
                        "ticker": req.ticker,
                        "entry": req.entry,
                        "stop": req.stop,
                        "size": req.shares,
                        "live": sc.enabled and not entry_result.get("dry_run", True),
                    })
                except Exception:
                    pass

        mode = "LIVE" if (live_ok and sc.enabled) else "DRY_RUN"
        return ExecuteResponse(ok=True, mode=mode, entry_result=entry_result, stop_result=stop_result)
    except Exception as e:
        # Fout tijdens live attempt -> 400 met detail
        raise HTTPException(status_code=400, detail=str(e))

# ── Lokaal starten (niet gebruikt op Render) ────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "10000"))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=False)
