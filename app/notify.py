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

def _human(event: str, data: dict) -> str:
    if event == "ENTRY_MKT":
        return f"KOOP {data.get('ticker','?')}: +1% = halve winst; stop naar instap. Reden: {', '.join(data.get('reason_codes',[])[:2])}."
    if event == "TP1_HIT":
        return f"{data.get('ticker','?')}: +1% geraakt, helft verkocht. Stop naar instap."
    if event == "STOP_HIT":
        return f"UIT {data.get('ticker','?')}: stop geraakt. Verlies beperkt."
    if event == "NO_TRADE":
        return f"GEEN TRADE {data.get('ticker','?')}: {', '.join(data.get('reason_codes',[])[:1])}."
    return f"{event} {data.get('ticker','?')}"

async def notify(event: str, data: dict) -> None:
    _write_jsonl({"ts": _ts(), "event": event, "data": data})
    await _send_tg(_human(event, data))
