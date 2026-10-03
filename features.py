"""Validation and feature engineering for network-flow records."""
import ipaddress
from collections import Counter, deque

import numpy as np
import pandas as pd

from .config import INTERNAL_NETS, MAX_ROWS, REQUIRED_COLUMNS, WINDOW_SECONDS

PROTO_NUM = {"TCP": 6, "UDP": 17, "ICMP": 1}
NUMERIC = ["dst_port", "duration", "bytes_out", "bytes_in", "packets",
           "syn_count", "rst_count", "failed_auth"]


def validate_flows(df):
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing columns: {', '.join(missing)}")
    if len(df) == 0:
        raise ValueError("The file has no rows.")
    if len(df) > MAX_ROWS:
        raise ValueError(f"Too many rows (limit {MAX_ROWS}).")
    for col in ("src_ip", "dst_ip"):
        for ip in df[col].astype(str).unique():
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                raise ValueError(f"Invalid IP address in {col}: {ip[:40]!r}") from None


def is_internal(ip):
    a = ipaddress.ip_address(ip)
    return any(a in n for n in INTERNAL_NETS)


def prepare(df):
    """Validate, clean and sort raw flow records. Adds numeric epoch column `ts`."""
    validate_flows(df)
    d = df.copy()
    t = pd.to_datetime(d["timestamp"], utc=True, errors="coerce")
    if t.isna().any():
        raise ValueError("Some timestamps could not be parsed.")
    d["ts"] = (t - pd.Timestamp("1970-01-01", tz="UTC")).dt.total_seconds()
    for c in NUMERIC:
        d[c] = pd.to_numeric(d[c], errors="coerce").fillna(0).clip(lower=0)
    d["dst_port"] = d["dst_port"].clip(upper=65535).astype(int)
    d["protocol"] = d["protocol"].astype(str).str.upper()
    d["src_ip"] = d["src_ip"].astype(str)
    d["dst_ip"] = d["dst_ip"].astype(str)
    if "label" not in d.columns:
        d["label"] = "unknown"
    d = d.sort_values("ts", kind="stable").reset_index(drop=True)
    d["flow_id"] = np.arange(len(d))
    return d


def _window_features(d, window):
    n = len(d)
    out = {k: np.zeros(n) for k in
           ("src_flows_w", "src_dports_w", "src_syn_w", "src_fail_w", "pair_flows_w")}
    ts = d["ts"].to_numpy()
    dp = d["dst_port"].to_numpy()
    syn = d["syn_count"].to_numpy()
    fail = d["failed_auth"].to_numpy()
    dst = d["dst_ip"].to_numpy()
    for _, idx in d.groupby("src_ip").indices.items():
        q, ports, pairs = deque(), Counter(), Counter()
        s = f = 0.0
        for i in idx:  # idx is in time order because d is sorted
            q.append(i)
            ports[dp[i]] += 1
            pairs[(dst[i], dp[i])] += 1
            s += syn[i]
            f += fail[i]
            while ts[i] - ts[q[0]] > window:
                j = q.popleft()
                ports[dp[j]] -= 1
                if ports[dp[j]] == 0:
                    del ports[dp[j]]
                pairs[(dst[j], dp[j])] -= 1
                s -= syn[j]
                f -= fail[j]
            out["src_flows_w"][i] = len(q)
            out["src_dports_w"][i] = len(ports)
            out["src_syn_w"][i] = s
            out["src_fail_w"][i] = f
            out["pair_flows_w"][i] = pairs[(dst[i], dp[i])]
    for k, v in out.items():
        d[k] = v


def _beacon_features(d):
    """Regularity of the last 6 gaps between flows of the same src->dst:port pair."""
    n = len(d)
    cv, iv = np.full(n, 99.0), np.zeros(n)
    ts = d["ts"].to_numpy()
    for _, idx in d.groupby(["src_ip", "dst_ip", "dst_port"]).indices.items():
        if len(idx) < 7:
            continue
        for k in range(6, len(idx)):
            gaps = np.diff(ts[idx[k - 6:k + 1]])
            m = gaps.mean()
            iv[idx[k]] = m
            if m > 0:
                cv[idx[k]] = gaps.std() / m
    d["beacon_cv"], d["beacon_iv"] = cv, iv


def add_features(d, window=WINDOW_SECONDS):
    d = d.copy()
    d["pps"] = (d["packets"] / d["duration"].clip(lower=0.001)).clip(upper=1e6)
    d["byte_ratio"] = d["bytes_out"] / (d["bytes_in"] + 1)
    d["hour"] = ((d["ts"] % 86400) // 3600).astype(int)      # hour of day, UTC
    d["off_hours"] = (d["hour"] < 5).astype(int)
    cache = {ip: int(is_internal(ip)) for ip in pd.unique(pd.concat([d["src_ip"], d["dst_ip"]]))}
    d["src_internal"] = d["src_ip"].map(cache).astype(int)
    d["dst_internal"] = d["dst_ip"].map(cache).astype(int)
    d["proto_num"] = d["protocol"].map(PROTO_NUM).fillna(0)
    _window_features(d, window)
    _beacon_features(d)
    return d
