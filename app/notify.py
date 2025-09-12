import os, json, httpx
from datetime import datetime, timezone

# Opt-in Telegram; in CI blijft dit uit
TG_ENABLED     = os.getenv("TG_ENABLED", "false").lower() == "true"
TG_BOT_TOKEN   = os.getenv("TG_BOT_TOKEN", "")
TG_CHAT_ID     = os.getenv("TG_CHAT_ID", "")
TG_TIMEOUT_SEC = float(os.getenv("TG_TIMEOUT_SEC", "1.0"))
TG_SINK_JSONL  = os.getenv("TG_SINK_JSONL", "logs/events.jsonl")

def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()

def _write_jsonl(obj: dict) -> None:
    try:
        os.makedirs(os.path.dirname(TG_SINK_JSONL), exist_ok=True)
        with open(TG_SINK_JSONL, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
    except Exception:
        # logging mag nooit de flow breken
        pass

async def _send_tg(text: str) -> None:
    if not (TG_ENABLED and TG_BOT_TOKEN and TG_CHAT_ID):
        return
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TG_CHAT_ID, "text": text, "disable_web_page_preview": True}
    try:
        async with httpx.AsyncClient(timeout=TG_TIMEOUT_SEC) as cli:
            await cli.post(url, json=payload)
    except Exception:
        # netwerkfouten negeren (non-blocking)
        pass

def _pct(x):
    try:
        return f"{x*100:.2f}%"
    except Exception:
        return "n/a"

def _human(event: str, data: dict) -> str:
    t   = data.get("ticker","?")
    rc  = ", ".join(data.get("reason_codes", [])[:2]) or "-"
    ent = data.get("entry"); stp = data.get("stop"); sz = data.get("size")
    ev  = data.get("ev")

    if event == "ENTRY_MKT":
        ent_s = f"{ent:.2f}" if isinstance(ent,(int,float)) else "?"
        stp_s = f"{stp:.2f}" if isinstance(stp,(int,float)) else "?"
        sz_s  = f"{sz}" if sz else "?"
        ev_s  = _pct(ev)
        return f"KOOP {t}: @ {ent_s}, SL {stp_s}, size {sz_s}. TP1 = +1% → halve winst. EV {ev_s}. Reden: {rc}."

    if event == "TP1_HIT":
        return f"{t}: +1% geraakt, helft verkocht. Stop naar instap."

    if event == "STOP_HIT":
        return f"{t}: stop geraakt. Trade klaar."

    if event == "NO_TRADE":
        p1 = data.get("p1"); p2 = data.get("p2")
        p1s = _pct(p1); p2s = _pct(p2)
        return f"GEEN TRADE {t}: {rc}. p1 {p1s}, p2 {p2s}."

    return f"{event} {t}"

async def notify(event: str, data: dict) -> None:
    _write_jsonl({"ts": _ts(), "event": event, "data": data})
    await _send_tg(_human(event, data))
