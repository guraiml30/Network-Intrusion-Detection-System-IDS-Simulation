"""SQLite event store. Parameterised queries only; connections are always closed
(important on Windows, where an open connection keeps the file locked)."""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from .config import DB_PATH, STATUSES

JSON_FIELDS = ("dst_ips", "dst_ports", "evidence")


@contextmanager
def _conn(path=None):
    path = path or DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(path)
    c.row_factory = sqlite3.Row
    try:
        with c:
            yield c
    finally:
        c.close()


def init_db(path=None):
    with _conn(path) as c:
        c.execute("""CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT,
            source TEXT, flows INTEGER, alerts INTEGER, intrusion_flows INTEGER, suspicious_flows INTEGER)""")
        c.execute("""CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER,
            alert_id TEXT, first_seen TEXT, last_seen TEXT, src_ip TEXT, rule_id TEXT, rule_name TEXT,
            mitre TEXT, flow_count INTEGER, risk INTEGER, severity TEXT, classification TEXT,
            description TEXT, recommendation TEXT, dst_ips TEXT, dst_ports TEXT, evidence TEXT,
            status TEXT DEFAULT 'New', notes TEXT DEFAULT '')""")


def save_run(source, result, path=None):
    init_db(path)
    s = result.summary
    with _conn(path) as c:
        cur = c.execute("INSERT INTO runs(ts,source,flows,alerts,intrusion_flows,suspicious_flows) VALUES(?,?,?,?,?,?)",
                        (datetime.now(timezone.utc).isoformat(timespec="seconds"), source, s["total_flows"],
                         s["alerts"], s["intrusion_flows"], s["suspicious_flows"]))
        run_id = cur.lastrowid
        for a in result.alerts:
            c.execute("""INSERT INTO alerts(run_id,alert_id,first_seen,last_seen,src_ip,rule_id,rule_name,mitre,
                flow_count,risk,severity,classification,description,recommendation,dst_ips,dst_ports,evidence)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (run_id, a["alert_id"], a["first_seen"], a["last_seen"], a["src_ip"], a["rule_id"],
                       a["rule_name"], a["mitre"], a["flow_count"], a["max_risk"], a["severity"],
                       a["classification"], a["description"], a["recommendation"],
                       json.dumps(a["dst_ips"]), json.dumps(a["dst_ports"]), json.dumps(a["evidence"])))
    return run_id


def _decode(row):
    d = dict(row)
    for f in JSON_FIELDS:
        d[f] = json.loads(d[f] or "[]")
    d["max_risk"] = d["risk"]
    return d


def latest_run_id(path=None):
    init_db(path)
    with _conn(path) as c:
        r = c.execute("SELECT MAX(id) AS m FROM runs").fetchone()
    return r["m"]


def fetch_alerts(run_id=None, path=None):
    init_db(path)
    with _conn(path) as c:
        if run_id is None:
            rows = c.execute("SELECT * FROM alerts ORDER BY id DESC").fetchall()
        else:
            rows = c.execute("SELECT * FROM alerts WHERE run_id=? ORDER BY id", (run_id,)).fetchall()
    return [_decode(r) for r in rows]


def update_status(row_id, status, notes="", path=None):
    if status not in STATUSES:
        raise ValueError(f"Status must be one of {STATUSES}")
    init_db(path)
    with _conn(path) as c:
        c.execute("UPDATE alerts SET status=?, notes=? WHERE id=?", (status, notes[:2000], int(row_id)))


def fetch_runs(path=None):
    init_db(path)
    with _conn(path) as c:
        return [dict(r) for r in c.execute("SELECT * FROM runs ORDER BY id DESC").fetchall()]


def clear_all(path=None):
    init_db(path)
    with _conn(path) as c:
        c.execute("DELETE FROM alerts")
        c.execute("DELETE FROM runs")
