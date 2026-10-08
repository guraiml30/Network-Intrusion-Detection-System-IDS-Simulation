# Architecture

```
 scripts/generate_dataset.py / simulator.py  (synthetic flow records)   or   uploaded CSV
                         |
                features.py  validate -> clean -> features (pps, ratios, internal/external,
                         |      60 s window counts per source, beacon regularity)
        +----------------+----------------+
      rules.py         anomaly.py        ml_model.py (optional)
  signature/threshold   per-service       Random Forest
  /behavioural rules    median/MAD z
        +----------------+----------------+
                         |   risk = rule pts + anomaly pts (+ ML pts), 0-100
                  engine.py -> classification (NORMAL / SUSPICIOUS / POTENTIAL INTRUSION)
                         |
                  alerts.py  group flows into alerts, severity INFO..CRITICAL, evidence
                         |
        +----------------+-----------------+
   database.py (SQLite)   report.py (.md)   app.py (Streamlit)  /  api.py (FastAPI)
```

## Design decisions
- **Flow-based, not packet-based**: like NetFlow/Zeek logs, so it runs on any laptop with no capture rights.
- **Three detection styles** (signature, threshold, anomaly) show why real IDSs combine methods.
- **Explainable**: every flow lists the rules that fired; every alert has description, MITRE technique (context), evidence and a recommended response.
- **Alert grouping** turns hundreds of flows into one alert per source and rule burst, like a SIEM does.
- **Safety**: all addresses are private 10.x or reserved documentation ranges; no sockets, no scanning; uploads validated (columns, IPs, size); SQL is parameterised; DB connections are always closed.

## Known limitations (say these in interviews)
- Baseline is learned from the same batch being analysed, so a large attack on a rare service can become "normal" (the simulated flood on port 80 does this).
- Thresholds are hand-tuned on synthetic data; real networks need tuning per environment.
- No packet payload inspection, TLS analysis, geo/threat-intel lookups or live capture.
- ML learns from the same generator as the test data, so its scores are optimistic.
- Windowed rules cannot fire on the first flows of an attack (about 35% of the scan flows go unflagged).
