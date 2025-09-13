import os
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Header, Depends, Query
from .schemas import DecideInput, DecideOutput, ScanRequest, ScanResponse, Meta
from .engine.decide import decide
from .engine.scan import run_scan, rank_tradeables
from .universe import get_universe
from .notify import notify

app = FastAPI(title="SNIPERBOT API", version="v3.2")

# ---- API-key beveiliging (header: X-API-Key) ----
_API_KEYS = {
    k.strip() for k in os.getenv("API_KEYS", os.getenv("API_KEY", "")).split(",") if k.strip()
}
def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    if not _API_KEYS:  # geen keys gezet -> laat door (brick niet per ongeluk)
        return
    if not x_api_key or x_api_key not in _API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

# ---- Helpers ----
def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# ---- Endpoints ----

@app.get("/healthz")
def healthz():
    return {"ok": True, "version": "v3.2"}

@app.get("/universe")
def universe_endpoint(
    name: str = Query(default="SP100", description="SP100 of empty"),
    _: None = Depends(require_api_key),
):
    u = get_universe(name)
    return {"universe_name": name, "count": len(u), "tickers": u}

@app.post("/decide", response_model=DecideOutput)
async def decide_endpoint(inp: DecideInput, _: None = Depends(require_api_key)):
    try:
        result = decide(inp)
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
async def scan_endpoint(req: ScanRequest, _: None = Depends(require_api_key)):
    try:
        results, summary = run_scan(req.candidates)
        ranked = rank_tradeables(results)
        top = ranked[: max(1, int(req.top_k))]

        meta = Meta(version="v3.2", nowET=_now_iso(), latency_ms=150, universe_size=len(req.candidates))
        resp = ScanResponse(
            universe_name=req.universe_name or "custom",
            scanned=len(results),
            tradeables=len(ranked),
            top=top,  # List[DecideOutput]-vorm past doordat decide() al het schema volgt
            summary=summary,
            meta=meta,
        )

        # Korte scan-melding
        await notify("SCAN", {
            "n": len(results),
            "tradeables": len(ranked),
            "top": [t.get("ticker") for t in top],
        })
        return resp
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Lokaal starten (niet gebruikt op Render)
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "10000"))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=False)
