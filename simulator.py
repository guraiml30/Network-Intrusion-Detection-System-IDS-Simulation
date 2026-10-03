"""Synthetic network-flow generator. Nothing here touches a real network.
Internal hosts use 10.x.x.x; 'external' hosts use reserved documentation ranges
(192.0.2.x, 198.51.100.x, 203.0.113.x) that are never routable on the internet."""
import random
from datetime import datetime, timedelta, timezone

import pandas as pd

BASE = datetime(2026, 1, 15, tzinfo=timezone.utc)
CLIENTS = [f"10.0.1.{i}" for i in range(10, 40)]
WEB, DNS, MAIL, DB, FILES, BACKUP, ADMIN = ("10.0.2.10", "10.0.2.53", "10.0.2.25",
                                            "10.0.2.30", "10.0.2.40", "10.0.2.99", "10.0.1.10")
EXTERNAL = [f"203.0.113.{i}" for i in range(1, 60)]
COLS = ["timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "duration",
        "bytes_out", "bytes_in", "packets", "syn_count", "rst_count", "failed_auth", "label"]
ATTACKS = ["port_scan", "brute_force", "dos_flood", "data_exfil", "beaconing", "c2_backdoor"]
HOUR_WEIGHTS = [1] * 6 + [3, 3] + [10] * 10 + [5] * 4 + [2, 2]

# name, weight, dst, port, proto, (bytes_out mu,sigma), (bytes_in), (packets), (duration) - log-normal params
SERVICES = [
    ("web", 40, WEB, 443, "TCP", (6.5, .5), (9.0, .8), (2.8, .4), (0.0, .6)),
    ("dns", 25, DNS, 53, "UDP", (4.2, .2), (4.8, .3), (0.7, .2), (-3.5, .4)),
    ("ext_https", 18, "ext", 443, "TCP", (6.8, .5), (9.5, .9), (3.0, .4), (0.3, .6)),
    ("mail", 5, MAIL, 587, "TCP", (7.5, .6), (6.0, .6), (2.9, .4), (0.5, .6)),
    ("smb", 6, FILES, 445, "TCP", (8.0, .8), (9.5, 1.0), (3.3, .5), (1.0, .7)),
    ("ntp", 2, DNS, 123, "UDP", (4.3, .1), (4.3, .1), (0.7, .1), (-3.0, .3)),
    ("db", 8, DB, 3306, "TCP", (6.0, .4), (7.5, .6), (2.5, .3), (-1.0, .5)),
    ("ssh", 1, "server", 22, "TCP", (7.0, .6), (7.5, .6), (3.0, .4), (2.5, .7)),
]


class _Gen:
    def __init__(self, seed):
        self.r = random.Random(seed)
        self.rows = []

    def ln(self, p):
        return self.r.lognormvariate(*p)

    def add(self, t, src, dst, dport, proto="TCP", dur=1.0, bo=100, bi=100, pk=5,
            syn=1, rst=0, fail=0, label="normal"):
        self.rows.append([(BASE + timedelta(seconds=t)).isoformat(timespec="milliseconds"), src,
                          self.r.randint(1025, 65000), dst, dport, proto, round(dur, 3),
                          int(bo), int(bi), max(1, int(pk)), int(syn), int(rst), int(fail), label])

    def normal(self, n):
        r = self.r
        weights = [s[1] for s in SERVICES]
        for _ in range(n):
            name, _, dst, port, proto, bo, bi, pk, du = r.choices(SERVICES, weights)[0]
            t = r.choices(range(24), HOUR_WEIGHTS)[0] * 3600 + r.random() * 3600
            src, fail = r.choice(CLIENTS), 0
            if dst == "ext":
                dst = r.choice(EXTERNAL)
            elif dst == "server":
                src, dst, fail = ADMIN, r.choice([WEB, MAIL, DB, FILES]), r.choice([0, 0, 0, 1, 2])
            elif name == "db":
                src = WEB
            self.add(t, src, dst, port, proto, dur=2.718 ** r.gauss(*du),
                     bo=self.ln(bo), bi=self.ln(bi), pk=2.718 ** r.gauss(*pk),
                     syn=1 if proto == "TCP" else 0, fail=fail)
        # benign oddities that make the data realistic
        for k in range(2):
            self.add(9 * 3600 + k * 600, ADMIN, FILES, 23, dur=30, bo=400, bi=900, pk=20)   # legacy Telnet
        for k in range(3):
            self.add(3600 + k * 900, FILES, BACKUP, 445, dur=600, bo=9e7 + r.random() * 3e7,
                     bi=5e4, pk=8e4)                                                        # nightly backup

    def port_scan(self):
        r = self.r
        for src, dst, t0 in (("198.51.100.23", WEB, 14 * 3600 + 300), ("10.0.1.27", FILES, 16 * 3600 + 2400)):
            for k, p in enumerate(r.sample(range(1, 1025), 40)):
                self.add(t0 + k * 0.5, src, dst, p, dur=0.02, bo=60, bi=r.choice([0, 0, 40]),
                         pk=r.choice([1, 2]), syn=1, rst=1 if r.random() < .8 else 0, label="port_scan")

    def brute_force(self):
        r = self.r
        for src, dst, port, t0, n in (("192.0.2.66", WEB, 22, 3 * 3600 + 720, 25),
                                      ("198.51.100.77", FILES, 3389, 22 * 3600 + 1800, 20)):
            for k in range(n):
                self.add(t0 + k * 6 + r.random(), src, dst, port, dur=1.5, bo=700, bi=900, pk=14,
                         fail=r.randint(3, 8), label="brute_force")

    def dos_flood(self):
        r = self.r
        for i in range(5):
            for k in range(80):
                self.add(11 * 3600 + 1800 + k * 0.4 + r.random() * .3, f"198.51.100.{100 + i}", WEB, 80,
                         dur=r.uniform(.05, .3), bo=r.randint(2000, 9000), bi=0, pk=r.randint(100, 400),
                         syn=r.randint(20, 60), label="dos_flood")

    def data_exfil(self):
        r = self.r
        for k in range(4):
            self.add(2 * 3600 + 2400 + k * 300, "10.0.1.23", "203.0.113.45", 443, dur=r.uniform(60, 120),
                     bo=r.uniform(8e6, 15e6), bi=r.randint(2000, 8000), pk=r.randint(6000, 11000),
                     label="data_exfil")

    def beaconing(self):
        r = self.r
        for k in range(180):
            self.add(9 * 3600 + k * 60 + r.uniform(-.5, .5), "10.0.1.31", "192.0.2.150", 8080, dur=.4,
                     bo=r.randint(300, 500), bi=r.randint(200, 600), pk=6, label="beaconing")

    def c2_backdoor(self):
        for k in range(3):
            self.add(13 * 3600 + 600 + k * 240, "10.0.1.12", "198.51.100.55", 4444, dur=45,
                     bo=5200, bi=8300, pk=60, label="c2_backdoor")


def generate_traffic(n_normal=3000, seed=42, attacks=None):
    """Return a DataFrame of synthetic flow records (label column = ground truth)."""
    g = _Gen(seed)
    g.normal(int(n_normal))
    for a in (ATTACKS if attacks is None else attacks):
        getattr(g, a)()
    df = pd.DataFrame(g.rows, columns=COLS).sort_values("timestamp").reset_index(drop=True)
    return df
