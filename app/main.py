from fastapi import FastAPI, HTTPException
from .schemas import DecideInput, DecideOutput
from .engine.decide import decide
from .notify import notify

app = FastAPI(title="SNIPERBOT API", version="v3.2")

@app.get("/healthz")
def healthz():
    return {"ok": True, "version": "v3.2"}

@app.post("/decide", response_model=DecideOutput)
async def decide_endpoint(inp: DecideInput):
    try:
        result = decide(inp)
        event = "NO_TRADE" if result["decision"] == "NO_TRADE" else "ENTRY_MKT"
        await notify(event, {"ticker": result.get("ticker"), "reason_codes": result.get("reason_codes", [])})
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
