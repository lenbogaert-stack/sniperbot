## Doel
De huidige p₁/p₂ is een placeholder. Vervang door de **bucket-methode met Beta-smoothing** zoals in Spec §7, inclusief recency-weging.

## Scope (volgens §7)
- Buckets:
  - rvol(1.2–1.5 / 1.5–2 / 2–3 / 3+)
  - gap(0–0.5 / 0.5–1 / 1–2 / 2+)
  - vwap_z(≤0 / 0–0.5 / ≥0.5)
  - vwap_slope(neg / flat / pos)
  - orb_state(none / test / break)
  - spread_bps(≤4 / 4–6 / 6–8)
  - time_of_day(open / core / lunch / power_hour)
  - news_tier(NONE / T1 / T2 / T3)
  - atr_pct(0.8–1.2 / 1.2–2 / 2–3 / 3–5)
- Tellen met recency-gewicht: `w = exp(−age_days/20)`.
- Smoothing:
  - `p̄1 = 0.58`, `p̄q = 0.60` tot parent ≥ 2000 gewogen trials.
  - `p1_hat = BetaSmooth(H1,N1; α0=5*p̄1, β0=5*(1−p̄1))`
  - `q_hat  = BetaSmooth(Hq,Nq; α0q=5*p̄q, β0q=5*(1−p̄q))`
  - `p2_hat = p1_hat * q_hat`
- Back-off bij weinig data: `λ = N/(N+50)`, meng met parent.
- Output: `p1_hat`, `p2_hat`, `q_hat`, plus debug-teller (H/N per bucket) achter een flag.

## Acceptatiecriteria
- [ ] Nieuwe functie `estimate_probs(bucketed_features, now)` levert `(p1_hat, p2_hat, q_hat)`.
- [ ] Unit-tests met synthetische buckets: monotoniciteit en smoothing gecontroleerd.
- [ ] /decide blijft **enforce** `p1_hat ≥ 0.60` (anders `P1_TOO_LOW`), ongewijzigd.
- [ ] Geen netwerk; deterministisch; tests blijven groen.

## Notities
- Data-bron voor counts: voorlopig in-memory/fixtures om CI groen te houden. Later vervangen door persistente store.