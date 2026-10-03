"""Markdown incident and summary reports."""


def _table(rows, cols):
    head = "| " + " | ".join(cols) + " |\n|" + "---|" * len(cols) + "\n"
    return head + "\n".join("| " + " | ".join(str(r.get(c, "")) for c in cols) + " |" for r in rows)


def incident_report(a):
    ev = a.get("evidence", [])[:10]
    return f"""# Incident Report {a['alert_id']}

> Generated from SYNTHETIC lab data for education. No real systems were involved.

| Field | Value |
|---|---|
| Severity | **{a['severity']}** |
| Classification | {a['classification']} |
| Risk score | {a.get('max_risk', a.get('risk'))}/100 |
| Detection | {a['rule_id']} - {a['rule_name']} |
| MITRE ATT&CK (context) | {a['mitre']} |
| Source | {a['src_ip']} |
| Targets | {', '.join(a['dst_ips'])} |
| Ports | {', '.join(map(str, a['dst_ports']))} |
| First seen / last seen | {a['first_seen']} / {a['last_seen']} |
| Flows involved | {a['flow_count']} |
| Status | {a.get('status', 'New')} |

## What happened
{a['description']}

## Evidence (highest-risk flows)
{_table(ev, ['timestamp', 'dst_ip', 'dst_port', 'protocol', 'bytes_out', 'packets', 'risk', 'rules'])}

## Recommended response
- {a['recommendation']}
- Preserve the flow logs above and record actions taken.
- Mark as False Positive if the activity is confirmed legitimate.

## Analyst notes
{a.get('notes') or '_none yet_'}
"""


def summary_report(summary, alerts):
    sev = ", ".join(f"{k}: {v}" for k, v in summary["alerts_by_severity"].items()) or "none"
    ev = summary.get("evaluation")
    ev_txt = "n/a (no ground-truth labels)" if not ev else (
        f"precision {ev['precision']}, recall {ev['recall']}, F1 {ev['f1']} "
        f"(FP flows: {ev['false_positives']}, FN flows: {ev['false_negatives']}) on synthetic labels")
    rows = [{"id": a["alert_id"], "severity": a["severity"], "risk": a.get("max_risk", a.get("risk")),
             "rule": a["rule_name"], "source": a["src_ip"], "flows": a["flow_count"]} for a in alerts[:15]]
    return f"""# IDS Summary Report

Time range: {summary['time_range'][0]} to {summary['time_range'][1]}

| Metric | Value |
|---|---|
| Flows analysed | {summary['total_flows']} |
| Normal / Suspicious / Potential intrusion | {summary['normal_flows']} / {summary['suspicious_flows']} / {summary['intrusion_flows']} |
| Alerts | {summary['alerts']} ({sev}) |

Detection quality: {ev_txt}

## Top alerts
{_table(rows, ['id', 'severity', 'risk', 'rule', 'source', 'flows'])}
"""
