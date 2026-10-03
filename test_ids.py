import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

# The test suite adds the src-layout package to sys.path at runtime.
# Keep static analysis from reporting these valid runtime imports.
# pyright: reportMissingImports=false
from netids import database
from netids.alerts import severity_for
from netids.anomaly import AnomalyDetector
from netids.engine import analyze, classify
from netids.features import add_features, prepare, validate_flows
from netids.report import incident_report, summary_report
from netids.simulator import generate_traffic

T0 = datetime(2026, 1, 15, 10, 0, tzinfo=timezone.utc)


def flows(rows):
    base = dict(src_ip="10.0.1.10", dst_ip="10.0.2.10", dst_port=443, protocol="TCP", duration=1.0,
                bytes_out=500, bytes_in=5000, packets=10, syn_count=1, rst_count=0, failed_auth=0)
    out = []
    for i, r in enumerate(rows):
        x = {**base, **r}
        x.setdefault("timestamp", (T0 + timedelta(seconds=i)).isoformat())
        out.append(x)
    return pd.DataFrame(out)


class TestSimulator(unittest.TestCase):
    def test_deterministic_and_labels(self):
        a, b = generate_traffic(300, seed=1), generate_traffic(300, seed=1)
        self.assertTrue(a.equals(b))
        self.assertTrue({"port_scan", "brute_force", "dos_flood", "data_exfil", "beaconing",
                         "c2_backdoor", "normal"} <= set(a["label"]))

    def test_no_real_addresses(self):
        d = generate_traffic(300, seed=1)
        ips = set(d.src_ip) | set(d.dst_ip)
        ok = ("10.0.", "192.0.2.", "198.51.100.", "203.0.113.")
        self.assertTrue(all(ip.startswith(ok) for ip in ips))


class TestValidation(unittest.TestCase):
    def test_missing_column(self):
        with self.assertRaises(ValueError):
            validate_flows(flows([{}]).drop(columns=["dst_port"]))

    def test_bad_ip(self):
        with self.assertRaises(ValueError):
            prepare(flows([{"src_ip": "not-an-ip"}]))

    def test_empty(self):
        with self.assertRaises(ValueError):
            validate_flows(flows([{}]).iloc[0:0])


class TestFeatures(unittest.TestCase):
    def test_window_distinct_ports(self):
        d = add_features(prepare(flows([{"dst_port": 1000 + i} for i in range(20)])))
        self.assertEqual(d["src_dports_w"].iloc[-1], 20)

    def test_window_expires(self):
        rows = [{"dst_port": 1 + i, "timestamp": (T0 + timedelta(seconds=i * 100)).isoformat()} for i in range(5)]
        d = add_features(prepare(flows(rows)))
        self.assertEqual(d["src_dports_w"].max(), 1)

    def test_internal_flags(self):
        d = add_features(prepare(flows([{"src_ip": "198.51.100.5"}])))
        self.assertEqual((d.src_internal[0], d.dst_internal[0]), (0, 1))


class TestRules(unittest.TestCase):
    def hits(self, row):
        return analyze(flows([row])).flows["rules"].iloc[0].split()

    def test_backdoor_port(self):
        self.assertIn("R001", self.hits({"dst_port": 4444}))

    def test_cleartext(self):
        self.assertIn("R002", self.hits({"dst_port": 23}))

    def test_external_admin(self):
        self.assertIn("R007", self.hits({"src_ip": "198.51.100.5", "dst_port": 22}))

    def test_exfil(self):
        h = self.hits({"dst_ip": "203.0.113.5", "bytes_out": 9_000_000})
        self.assertIn("R005", h)

    def test_clean_flow_has_no_rules(self):
        self.assertEqual(self.hits({}), [])

    def test_port_scan_window_rule(self):
        r = analyze(flows([{"src_ip": "198.51.100.9", "dst_port": 1 + i, "packets": 1, "duration": .02,
                            "rst_count": 1} for i in range(30)]))
        self.assertIn("W001", r.flows["rules"].iloc[-1])
        self.assertEqual(r.flows["classification"].iloc[-1], "POTENTIAL INTRUSION")


class TestAnomaly(unittest.TestCase):
    def test_outlier_scores_high(self):
        d = add_features(prepare(generate_traffic(1500, seed=3, attacks=[])))
        det = AnomalyDetector().fit(d)
        odd = d[d.dst_port == 443].head(1).copy()
        odd["bytes_out"] = 5e8
        self.assertGreater(det.zscores(odd)[0], 10)
        self.assertLess(pd.Series(det.zscores(d)).quantile(0.99), 6)


class TestEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = analyze(generate_traffic(2000, seed=7))

    def test_quality_on_synthetic_labels(self):
        ev = self.r.summary["evaluation"]
        self.assertGreaterEqual(ev["precision"], 0.9)
        self.assertGreaterEqual(ev["recall"], 0.85)
        for name, v in ev["per_attack"].items():
            self.assertGreaterEqual(v["rate"], 0.5, name)

    def test_summary_is_json_safe(self):
        json.dumps(self.r.summary)

    def test_alerts_sorted_and_deduplicated(self):
        sev = [a["severity"] for a in self.r.alerts]
        order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        self.assertEqual(sev, sorted(sev, key=lambda s: -order.index(s)))
        keys = [(a["src_ip"], a["rule_id"], a["first_seen"]) for a in self.r.alerts]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertTrue(any(a["rule_id"] == "W001" for a in self.r.alerts))

    def test_thresholds(self):
        self.assertEqual([classify(x) for x in (0, 24, 25, 49, 50, 100)],
                         ["NORMAL", "NORMAL", "SUSPICIOUS", "SUSPICIOUS", "POTENTIAL INTRUSION",
                          "POTENTIAL INTRUSION"])
        self.assertEqual([severity_for(x) for x in (0, 25, 40, 60, 80)],
                         ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])


class TestDbAndReport(unittest.TestCase):
    def test_roundtrip_status_and_report(self):
        r = analyze(generate_traffic(800, seed=5))
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as t:
            p = Path(t) / "e.db"
            run_id = database.save_run("test", r, path=p)
            rows = database.fetch_alerts(run_id, path=p)
            self.assertEqual(len(rows), len(r.alerts))
            self.assertIsInstance(rows[0]["evidence"], list)
            database.update_status(rows[0]["id"], "Investigating", "x'); DROP TABLE alerts;--", path=p)
            self.assertEqual(database.fetch_alerts(run_id, path=p)[0]["status"], "Investigating")
            with self.assertRaises(ValueError):
                database.update_status(rows[0]["id"], "Hacked", path=p)
            self.assertIn(rows[0]["alert_id"], incident_report(rows[0]))
            database.clear_all(p)
            self.assertEqual(database.fetch_alerts(path=p), [])
        self.assertIn("IDS Summary Report", summary_report(r.summary, r.alerts))


if __name__ == "__main__":
    unittest.main()
