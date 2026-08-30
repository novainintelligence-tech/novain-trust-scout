# novain-risk engine changelog

## novain-risk-2.0 (current)

- Evidence-first scoring: UNKNOWN and UNAVAILABLE contribute exactly 0.
- Risk gates applied after raw score (domain age, reachability, unsafe redirect, reputation threat).
- Sources: HTTP (IP-pinned), TLS, DNS, WHOIS, content, reputation, CT.
- Reputation providers: Safe Browsing (optional key), URLhaus, OpenPhish feed, VirusTotal (optional key).
- CT: crt.sh presence / history depth.
- Baseline score 40; explicit pass/fail point table in `app/engine/risk_engine.py`.

### Phase A additions (intelligence)
- Multi-provider reputation with circuit breakers.
- Certificate Transparency signals.
- Offline labeled evaluation set under `evaluation/`.

### Phase B additions (agent surface)
- `POST /api/public/v1/verify/website/batch` (max 20 targets).
- Short TTL verify cache (identical target + engine version).

### Phase C additions (ops)
- In-process metrics counters/latency.
- Provider circuit breakers (fail open to UNAVAILABLE).
