"""Network IDS Simulation dashboard (Streamlit). Run: streamlit run app.py"""
import sys
import time
from pathlib import Path

# Ensure the local src/ package is importable when running from the project root.
SRC_DIR = Path(__file__).resolve().parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# pyright: reportMissingImports=false
import pandas as pd
import streamlit as st

from netids import database
from netids.config import DATASET_PATH, MAX_UPLOAD_BYTES, SEVERITY_ORDER, STATUSES
from netids.engine import analyze
from netids.report import incident_report, summary_report
from netids.rules import RULES
from netids.simulator import generate_traffic

st.set_page_config(page_title="Network IDS Simulation", page_icon="🛡️", layout="wide")
st.title("🛡️ Network Intrusion Detection System (IDS) Simulation")
st.caption("Educational and defensive. Analyses synthetic flow records only; it never touches a real network.")

page = st.sidebar.radio("Navigate", ["Run analysis", "Traffic analytics", "SOC console",
                                     "Live replay", "Reports", "Learn"])
res = st.session_state.get("res")
FLOW_COLS = ["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "bytes_out", "packets",
             "risk", "classification", "rules"]


def need_result():
    if res is None:
        st.info("Run an analysis first (page: Run analysis).")
        st.stop()


if page == "Run analysis":
    src = st.radio("Traffic source", ["Generate synthetic traffic", "Load sample CSV", "Upload CSV"], horizontal=True)
    c1, c2 = st.columns(2)
    seed = c1.number_input("Random seed", 0, 10_000, 42)
    n_normal = c2.slider("Normal flows", 500, 10_000, 3000, 500)
    up = st.file_uploader("CSV of flow records", type=["csv"]) if src == "Upload CSV" else None
    o1, o2 = st.columns(2)
    use_ml = o1.checkbox("Blend in optional ML model (if trained)")
    save = o2.checkbox("Save alerts to database", value=True)

    if st.button("Run IDS", type="primary"):
        try:
            if src == "Generate synthetic traffic":
                df, label = generate_traffic(n_normal, int(seed)), f"synthetic seed={seed}"
            elif src == "Load sample CSV":
                df, label = pd.read_csv(DATASET_PATH), "sample_flows.csv"
            else:
                if up is None:
                    st.warning("Please choose a CSV file.")
                    st.stop()
                if up.size > MAX_UPLOAD_BYTES:
                    st.error("File too large.")
                    st.stop()
                df, label = pd.read_csv(up), f"upload:{up.name[:40]}"
            with st.spinner("Analysing flows..."):
                res = analyze(df, use_ml)
            st.session_state["res"] = res
            if save:
                database.save_run(label, res)
        except (ValueError, FileNotFoundError) as e:
            st.error(f"Could not analyse: {e}")
            st.stop()
        if use_ml and not res.ml_used:
            st.caption("ML model not found. Train it with `python -m netids.ml_model` (see README).")

    if res is not None:
        s = res.summary
        k = st.columns(5)
        k[0].metric("Flows", s["total_flows"])
        k[1].metric("Potential intrusion flows", s["intrusion_flows"])
        k[2].metric("Suspicious flows", s["suspicious_flows"])
        k[3].metric("Alerts", s["alerts"])
        k[4].metric("High/Critical alerts", s["alerts_by_severity"].get("HIGH", 0) + s["alerts_by_severity"].get("CRITICAL", 0))
        st.subheader("Alerts by severity")
        st.bar_chart(pd.Series({x: s["alerts_by_severity"].get(x, 0) for x in SEVERITY_ORDER}))
        ev = s["evaluation"]
        if ev:
            st.subheader("Detection quality (synthetic ground truth)")
            e = st.columns(4)
            e[0].metric("Precision", ev["precision"])
            e[1].metric("Recall", ev["recall"])
            e[2].metric("F1", ev["f1"])
            e[3].metric("False-positive flows", ev["false_positives"])
            st.dataframe(pd.DataFrame(ev["per_attack"]).T, width="stretch")
            st.caption("Scores come from data made by the same author as the rules, so real-world accuracy would be lower.")

elif page == "Traffic analytics":
    need_result()
    d = res.flows
    a, b = st.columns(2)
    a.subheader("Flows per hour (UTC)")
    a.bar_chart(d.groupby("hour").size())
    b.subheader("Bytes out per hour (UTC)")
    b.bar_chart(d.groupby("hour")["bytes_out"].sum())
    a.subheader("Protocol mix")
    a.bar_chart(d["protocol"].value_counts())
    b.subheader("Top destination ports")
    b.bar_chart(d["dst_port"].astype(str).value_counts().head(10))
    a.subheader("Top sources by flows")
    a.bar_chart(d["src_ip"].value_counts().head(10))
    b.subheader("Classification")
    b.bar_chart(d["classification"].value_counts())
    st.subheader("Risk score distribution")
    st.bar_chart(pd.cut(d["risk"], [-1, 24, 49, 74, 100], labels=["0-24", "25-49", "50-74", "75-100"]).value_counts().sort_index())

elif page == "SOC console":
    rows = database.fetch_alerts(database.latest_run_id())
    if not rows:
        st.info("No saved alerts. Run an analysis with 'Save alerts to database' ticked.")
        st.stop()
    sev = st.multiselect("Severity", SEVERITY_ORDER, default=SEVERITY_ORDER[1:])
    stat = st.multiselect("Status", STATUSES, default=STATUSES)
    view = [r for r in rows if r["severity"] in sev and r["status"] in stat]
    view.sort(key=lambda r: (-SEVERITY_ORDER.index(r["severity"]), -r["risk"]))
    if not view:
        st.warning("No alerts match the filters.")
        st.stop()
    tbl = pd.DataFrame(view)[["alert_id", "severity", "risk", "rule_id", "rule_name", "src_ip", "flow_count", "status"]]
    st.dataframe(tbl, width="stretch", hide_index=True)
    pick = st.selectbox("Investigate alert", [r["alert_id"] for r in view])
    a = next(r for r in view if r["alert_id"] == pick)
    st.subheader(f"{a['alert_id']}: {a['rule_name']}")
    m = st.columns(4)
    m[0].metric("Severity", a["severity"])
    m[1].metric("Risk", a["risk"])
    m[2].metric("Flows", a["flow_count"])
    m[3].metric("MITRE (context)", a["mitre"])
    st.write(a["description"])
    st.write(f"**Source:** {a['src_ip']}  |  **Targets:** {', '.join(a['dst_ips'])}  |  **Ports:** {', '.join(map(str, a['dst_ports']))}")
    st.write(f"**First / last seen:** {a['first_seen']} / {a['last_seen']}")
    st.info(f"Recommended response: {a['recommendation']}")
    st.dataframe(pd.DataFrame(a["evidence"]), width="stretch", hide_index=True)
    s1, s2 = st.columns([1, 2])
    new = s1.selectbox("Status", STATUSES, index=STATUSES.index(a["status"]))
    notes = s2.text_area("Analyst notes", a["notes"], max_chars=2000)
    if st.button("Save status and notes"):
        database.update_status(a["id"], new, notes)
        st.rerun()
    st.download_button("Download incident report (.md)", incident_report({**a, "status": new, "notes": notes}),
                       f"{a['alert_id']}_incident_report.md", "text/markdown")

elif page == "Live replay":
    need_result()
    st.write("Replays the analysed traffic in time order, like a live monitor.")
    delay = st.slider("Delay per step (seconds)", 0.0, 0.5, 0.1)
    if st.button("Start replay"):
        d, n, steps = res.flows, len(res.flows), 40
        bar, box, chart, tbl = st.progress(0), st.empty(), st.empty(), st.empty()
        hist = []
        for i in range(1, steps + 1):
            cut = d.iloc[: n * i // steps]
            flagged = cut[cut["classification"] != "NORMAL"]
            hist.append({"flows seen": len(cut), "flagged flows": len(flagged)})
            c = box.columns(3)
            c[0].metric("Flows seen", len(cut))
            c[1].metric("Flagged flows", len(flagged))
            c[2].metric("Intrusion flows", int((cut["classification"] == "POTENTIAL INTRUSION").sum()))
            chart.line_chart(pd.DataFrame(hist)[["flagged flows"]])
            tbl.dataframe(flagged.tail(8)[FLOW_COLS], width="stretch", hide_index=True)
            bar.progress(i / steps)
            time.sleep(delay)

elif page == "Reports":
    need_result()
    md = summary_report(res.summary, res.alerts)
    st.markdown(md)
    st.download_button("Download summary report (.md)", md, "ids_summary_report.md", "text/markdown")
    with st.expander("Past runs"):
        st.dataframe(pd.DataFrame(database.fetch_runs()), width="stretch", hide_index=True)
        if st.checkbox("I understand this deletes all saved alerts and runs") and st.button("Clear database"):
            database.clear_all()
            st.rerun()

else:
    st.header("📚 How this IDS works")
    st.markdown("""
- **Signature rules** match known-bad patterns (backdoor ports, cleartext protocols, floods).
- **Threshold rules** count behaviour over a 60 s window (port scan, brute force, SYN flood).
- **Behavioural rule** spots evenly spaced beaconing to an outside host.
- **Anomaly detection** compares each flow with the usual profile for that service (median/MAD).
- **Risk score** = rule points + anomaly points (+ optional ML), capped at 100.
- **Classes:** NORMAL < 25, SUSPICIOUS 25-49, POTENTIAL INTRUSION 50+. **Severity:** INFO, LOW, MEDIUM, HIGH, CRITICAL.
- **Expected false positive:** the simulated nightly backup looks like a huge transfer. A SOC analyst would mark it *False Positive*.""")
    st.subheader("Rule catalogue")
    st.dataframe(pd.DataFrame([{"id": r.id, "name": r.name, "type": r.kind, "points": r.points,
                                "MITRE": r.mitre, "description": r.description} for r in RULES]),
                 width="stretch", hide_index=True)
