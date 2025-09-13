import os
from fastapi import FastAPI, HTTPException, Header, Depends
from .schemas import DecideInput, DecideOutput
from .engine.decide import decide
from .notify import notify

app = FastAPI(title="SNIPERBOT API", version="v3.2")

# ---- API-key beveiliging (header: X-API-Key) ----
# Zet in Render env: API_KEYS = "key1,key2,..." (1 of meer, komma-gescheiden).
_API_KEYS = {
    k.strip() for k in os.getenv("API_KEYS", os.getenv("API_KEY", "")).split(",") if k.strip()
}

def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    """
    - Als er GEEN keys zijn gezet in env -> laat door (brick je service niet per ongeluk).
    - Als er WEL keys zijn -> header moet exact matchen, anders 401.
    """
    if not _API_KEYS:
        return
    if not x_api_key or x_api_key not in _API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

# ---- Endpoints ----

@app.get("/healthz")
def healthz():
    return {"ok": True, "version": "v3.2"}

@app.post("/decide", response_model=DecideOutput)
async def decide_endpoint(inp: DecideInput, _: None = Depends(require_api_key)):
    try:
        result = decide(inp)

        # Event voor Telegram + log
        event = "NO_TRADE" if result.get("decision") == "NO_TRADE" else "ENTRY_MKT"
        await notify(
            event,
            {
                "ticker": result.get("ticker"),
                "decision": result.get("decision"),
                "entry": result.get("entry"),
                "stop": result.get("stop_loss"),
                "size": result.get("size_shares"),
                "reason_codes": result.get("reason_codes", []),
                "p1": (result.get("probs") or {}).get("p1"),
                "p2": (result.get("probs") or {}).get("p2"),
                "ev": (result.get("ev_estimate") or {}).get("net_ev_pct"),
            },
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Lokaal starten (niet gebruikt op Render)
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "10000"))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=False)
