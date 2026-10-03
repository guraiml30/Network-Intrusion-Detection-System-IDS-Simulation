"""Alert engine: turns scored flows into de-duplicated, SOC-style alerts."""
from datetime import datetime, timezone

from .config import (ALERT_GAP_SECONDS, NORMAL_MAX, RECOMMENDATIONS, SEVERITY_BANDS,
                     SEVERITY_ORDER)
from .rules import RULE_INDEX

ANOM_META = ("Statistical anomaly", "anomaly", "N/A",
             "Traffic volume or shape far outside the usual profile for this service.")


def severity_for(risk):
    for limit, label in SEVERITY_BANDS:
        if risk < limit:
            return label
    return "CRITICAL"


def _iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


def build_alerts(d, gap=ALERT_GAP_SECONDS, max_evidence=50):
    """One alert per (source, primary rule) burst. `d` must be time-sorted and scored."""
    from .engine import classify
    cand = d[(d["rules"] != "") | (d["risk"] >= NORMAL_MAX)]
    open_, alerts = {}, []
    for row in cand.itertuples():
        rid = row.primary_rule or "ANOM"
        key = (row.src_ip, rid)
        a = open_.get(key)
        if a is None or row.ts - a["_last"] > gap:
            if rid in RULE_INDEX:
                r = RULE_INDEX[rid]
                name, kind, mitre, desc = r.name, r.kind, r.mitre, r.description
            else:
                name, kind, mitre, desc = ANOM_META
            a = {"src_ip": row.src_ip, "rule_id": rid, "rule_name": name, "kind": kind,
                 "mitre": mitre, "description": desc,
                 "recommendation": RECOMMENDATIONS.get(rid, RECOMMENDATIONS["ANOM"]),
                 "first_seen": _iso(row.ts), "flow_count": 0, "max_risk": 0,
                 "dst_ips": [], "dst_ports": [], "evidence": [], "_last": row.ts}
            open_[key] = a
            alerts.append(a)
        a["_last"] = row.ts
        a["last_seen"] = _iso(row.ts)
        a["flow_count"] += 1
        a["max_risk"] = max(a["max_risk"], int(row.risk))
        if row.dst_ip not in a["dst_ips"] and len(a["dst_ips"]) < 10:
            a["dst_ips"].append(row.dst_ip)
        if int(row.dst_port) not in a["dst_ports"] and len(a["dst_ports"]) < 10:
            a["dst_ports"].append(int(row.dst_port))
        a["evidence"].append({"timestamp": _iso(row.ts), "src_ip": row.src_ip, "dst_ip": row.dst_ip,
                              "dst_port": int(row.dst_port), "protocol": row.protocol,
                              "bytes_out": int(row.bytes_out), "bytes_in": int(row.bytes_in),
                              "packets": int(row.packets), "risk": int(row.risk), "rules": row.rules})
    for i, a in enumerate(alerts, 1):
        a["alert_id"] = f"ALR-{i:04d}"
        a["severity"] = severity_for(a["max_risk"])
        a["classification"] = classify(a["max_risk"])
        a["evidence"] = sorted(a["evidence"], key=lambda e: -e["risk"])[:max_evidence]
        a.pop("_last")
    return sorted(alerts, key=lambda a: (-SEVERITY_ORDER.index(a["severity"]), -a["max_risk"], a["first_seen"]))
