from datetime import datetime, timezone
from typing import List, Dict, Tuple
from .decide import decide

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def run_scan(candidates: List) -> Tuple[List[dict], Dict]:
    """
    Voert decide() uit voor alle kandidaten.
    Geeft (alle_results, summary) terug.
    """
    results: List[dict] = [decide(c) for c in candidates]

    summary = {"TRADE_LONG": 0, "NO_TRADE": 0, "rejections": {}}
    for r in results:
        if r.get("decision") == "TRADE_LONG":
            summary["TRADE_LONG"] += 1
        else:
            summary["NO_TRADE"] += 1
            for code in r.get("reason_codes", []):
                summary["rejections"][code] = summary["rejections"].get(code, 0) + 1
    return results, summary

def rank_tradeables(results: List[dict]) -> List[dict]:
    """
    Sorteer tradeables op:
      1) hoogste sniper_score
      2) laagste break_even_pct (kosten)
      3) hoogste p1
      4) hoogste p2
    """
    tradeables = [r for r in results if r.get("decision") == "TRADE_LONG"]

    def _key(r: dict):
        probs = r.get("probs") or {}
        costs = r.get("costs") or {}
        return (
            -float(r.get("sniper_score", 0.0)),
            float(costs.get("break_even_pct", 1.0)),
            -float(probs.get("p1", 0.0)),
            -float(probs.get("p2", 0.0)),
        )

    return sorted(tradeables, key=_key)
