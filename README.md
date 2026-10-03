# 🛡️ Network Intrusion Detection System (IDS) Simulation

A **defensive, educational** IDS simulator. It generates or loads synthetic network-flow records, detects scans, brute force, floods, data exfiltration, beaconing and backdoor traffic, scores risk, raises severity-rated alerts (INFO to CRITICAL), and gives a SOC-style dashboard with incident reports.

> **Safety:** no packet capture, scanning or attack traffic. Everything is synthetic; internal hosts are 10.x.x.x and "external" hosts use reserved documentation addresses (192.0.2.x, 198.51.100.x, 203.0.113.x). Never point security tools at systems you do not own.

## Features
- Traffic simulator with 6 attack patterns + benign oddities (Telnet, nightly backup)
- 11 rules: signature, threshold (60 s window) and behavioural (beaconing)
- Anomaly detector (per-service median/MAD), optional Random Forest
- Risk score 0-100, classes NORMAL / SUSPICIOUS / POTENTIAL INTRUSION
- Alert engine: grouping, INFO/LOW/MEDIUM/HIGH/CRITICAL, MITRE ATT&CK context, recommendations
- SQLite events, SOC console (status + notes), Markdown incident/summary reports
- Traffic analytics, live replay, FastAPI, 20 unit tests

## Quick start
1. Install Python 3.10+ and open a terminal in this folder.
2. `python -m venv .venv` then activate it (Windows: `.venv\Scripts\activate`).
3. `pip install -r requirements.txt`
4. **Run everything:** `python run_all.py` (tests, dataset, ML model, API and dashboard)
   - Dashboard: http://127.0.0.1:8511  |  API docs: http://127.0.0.1:8010/docs
   - Flags: `--skip-ml`, `--no-tests`, `--api-only`, `--ui-only`
5. Or manually: `streamlit run app.py`; tests: `python -m unittest discover -s tests` (Windows PowerShell: `$env:PYTHONPATH="src"` first for scripts/modules).

## Project structure
```
app.py  api.py  run_all.py
src/netids/   config simulator features rules anomaly ml_model engine alerts database report
scripts/generate_dataset.py     data/sample_flows.csv (generated)
tests/test_ids.py               docs/  screenshots/
```

## Detection rules
| ID | Detects | Points |
|---|---|---|
| R001 | Backdoor/botnet port | 40 |
| R002 | Telnet/FTP | 8 |
| R003 | SYN-only probe + RST | 5 |
| R004 | 5+ failed logins in a flow | 25 |
| R005 | 5 MB+ outbound to external | 25 |
| R006 | 1000+ packets/s | 30 |
| R007 | External source to admin port | 15 |
| R008 | Off-hours 1 MB+ outbound | 10 |
| W001 | Port scan: 15+ ports/60 s | 50 |
| W002 | Brute force: 8+ tries/60 s | 40 |
| W003 | SYN/connection flood | 45 |
| W004 | Periodic beaconing | 25 |

Tune everything in `src/netids/config.py` and `rules.py`.

## Using your own data
Upload a CSV with columns: `timestamp, src_ip, dst_ip, dst_port, protocol, duration, bytes_out, bytes_in, packets, syn_count, rst_count, failed_auth` (optional `label`).

## Limitations
Synthetic data and hand-tuned thresholds mean the reported precision/recall are not real-world accuracy. See `docs/ARCHITECTURE.md`.

## License
MIT
