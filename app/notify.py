import os, json, httpx, time
from collections import deque
from datetime import datetime, timezone

# ── Config via env ──────────────────────────────────────────────────────────────
TG_ENABLED      = os.getenv("TG_ENABLED", "false").lower() == "true"
TG_BOT_TOKEN    = os.getenv("TG_BOT_TOKEN", "")
TG_CHAT_ID      = os.getenv("TG_CHAT_ID", "")
TG_TIMEOUT_SEC  = float(os.getenv("TG_TIMEOUT_SEC", "1.0"))
TG_SINK_JSONL   = os.getenv("TG_SINK_JSONL", "logs/events.jsonl")
TG_DEDUP_SEC    = float(os.getenv("TG_DEDUP_SEC", "10"))   # binnen X sec geen dubbele melding

# Dedup cache (in-memory, best-effort)
_recent = deque(maxlen=128)  # items: (key, ts)

# ── Helpers ────────────────────────────────────────────────────────────────────
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

# Percentages:
# - p1/p2: hele procenten (bv. 67%)
# - EV: met teken en 2 decimalen (bv. +0,11%)
def _pct_int(x):
    try:
        return f"{round(float(x)*100):d}%"
    except Exception:
        return "nvt"

def _pct2_sign(x):
    try:
        return f"{float(x)*100:+.2f}%"
    except Exception:
        return "nvt"

def _num2(x):
    try:
        return f"{float(x):.2f}"
    except Exception:
        return "?"

# Redencodes → gewone taal (max 2 tonen)
REASON_HUMAN = {
    "COST_TOO_HIGH": "kosten te hoog",
    "SCORE_LOW": "score te laag",
    "NO_EDGE_PERSISTENCE": "momentum hield niet stand",
    "EV_WEAK": "verwachte waarde te laag",
    "TOD_FAIL": "tijdslot-regels",
    "LIQUIDITY_FAIL": "te weinig handel",
    "RISK_FAIL": "risico buiten bereik",
    "REGIME_FAIL": "markt ongunstig",
    "TECHNIQUE_FAIL": "patroon onvoldoende",
    "COMPLIANCE_FAIL": "compliance-regel",
    "MARKET_SAFETY_FAIL": "volume te laag",
    "LATENCY_VWAP_FAIL": "quote/VWAP check",
    "DATA_FAIL": "data klopt niet",
    "EV_OK": "verwachte waarde oké",
    "COST_OK": "kosten oké",
    "EDGE_2OF3": "momentum sterk",
}

def _friendly_reasons(codes):
    txts = []
    for c in (codes or []):
        t = REASON_HUMAN.get(c, c.replace("_", " ").lower())
        if t not in txts:
            txts.append(t)
        if len(txts) >= 2:
            break
    return ", ".join(txts) if txts else "-"

def _human(event: str, data: dict) -> str:
    # Algemene velden
    t   = str(data.get("ticker", "?"))
    rc  = _friendly_reasons(data.get("reason_codes"))
    ent = data.get("entry"); stp = data.get("stop"); sz = data.get("size")
    p1  = data.get("p1"); p2 = data.get("p2"); ev = data.get("ev")

    ents = _num2(ent); stps = _num2(stp); szs = str(sz) if sz is not None else "?"

    # Specifieke events
    if event == "ENTRY_MKT":
        line1 = f"Koop {t}. Instap {ents}, stop {stps}, grootte {szs}."
        line2 = "Doel: +1% snel wat winst nemen, daarna de rest laten meelopen."
        extra = []
        if p1 is not None: extra.append(f"kans +1% ≈ {_pct_int(p1)}")
        if p2 is not None: extra.append(f"+2% ≈ {_pct_int(p2)}")
        if ev is not None: extra.append(f"EV ≈ {_pct2_sign(ev)}")
        line3 = f"Waarom: {rc}." + (f" ({'; '.join(extra)})" if extra else "")
        return "\n".join([line1, line2, line3])

    if event == "NO_TRADE":
        line1 = f"Geen trade in {t}."
        line2 = f"Waarom: {rc}."
        extra = []
        if p1 is not None: extra.append(f"+1% ≈ {_pct_int(p1)}")
        if p2 is not None: extra.append(f"+2% ≈ {_pct_int(p2)}")
        if ev is not None: extra.append(f"EV ≈ {_pct2_sign(ev)}")
        line3 = f"Inschatting: {', '.join(extra)}." if extra else ""
        return "\n".join([line1, line2, line3]).strip()

    if event == "SCAN":
        n   = data.get("n", 0)
        trd = data.get("tradeables", 0)
        top = data.get("top") or []
        tops = ", ".join(top[:3]) if top else "-"
        return f"Scan: {n} bekeken, {trd} kansrijk. Top: {tops}."

    if event == "TP1_HIT":
        return f"{t}: +1% geraakt, helft verkocht. Stop naar instap."
    if event == "STOP_HIT":
        return f"{t}: stop geraakt. Trade klaar."
    return f"{event} {t}"

def _dedup_key(event: str, data: dict) -> str:
    t = data.get("ticker")
    e = data.get("entry"); s = data.get("stop"); sz = data.get("size")
    # Rond af om mini-verschillen te dempen
    try: e = round(float(e), 2)
    except Exception: e = e or 0
    try: s = round(float(s), 2)
    except Exception: s = s or 0
    return f"{event}|{t}|{e}|{s}|{sz}"

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

# ── Publieke notify ────────────────────────────────────────────────────────────
async def notify(event: str, data: dict) -> None:
    # Dedup: sla identieke meldingen binnen TG_DEDUP_SEC over
    key = _dedup_key(event, data)
    now = time.time()
    # Verwijder oude entries
    try:
        while _recent and now - _recent[0][1] > TG_DEDUP_SEC:
            _recent.popleft()
        if any(k == key for k, ts in _recent):
            _write_jsonl({"ts": _ts(), "event": event, "data": data, "skipped": "duplicate"})
            return
        _recent.append((key, now))
    except Exception:
        # Dedup faalt? Ga gewoon door (best-effort)
        pass

    # Log altijd (best effort), stuur Telegram opt-in
    _write_jsonl({"ts": _ts(), "event": event, "data": data})
    await _send_tg(_human(event, data))
