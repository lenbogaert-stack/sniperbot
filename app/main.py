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

        # Bepaal eventtype en stuur compacte, nuttige data mee naar Telegram
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
        # Houd het simpel: geef 400 terug met de fouttekst
        raise HTTPException(status_code=400, detail=str(e))


# Lokale dev entrypoint (niet gebruikt op Render, wel handig lokaal)
if __name__ == "__main__":
    import os
    import uvicorn

    port = int(os.getenv("PORT", "10000"))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=False)
