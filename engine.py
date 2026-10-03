"""IDS pipeline: features -> rules -> anomaly -> (optional ML) -> risk -> alerts."""
from collections import Counter
from dataclasses import dataclass

import numpy as np

from .alerts import build_alerts, severity_for
from .anomaly import AnomalyDetector
from .config import INTRUSION_MIN, NORMAL_MAX
from .features import add_features, prepare
from .rules import RULES


def classify(risk):
    if risk < NORMAL_MAX:
        return "NORMAL"
    return "SUSPICIOUS" if risk < INTRUSION_MIN else "POTENTIAL INTRUSION"


@dataclass
class IDSResult:
    flows: object
    alerts: list
    summary: dict
    ml_used: bool = False


def _evaluate(d):
    if (d["label"] == "unknown").all():
        return None
    y, p = d["label"].ne("normal"), d["classification"].ne("NORMAL")
    tp, fp, fn = int((y & p).sum()), int((~y & p).sum()), int((y & ~p).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    per = {}
    for lab, g in d[y].groupby("label"):
        det = int((g["classification"] != "NORMAL").sum())
        per[str(lab)] = {"flows": int(len(g)), "detected": det, "rate": round(det / len(g), 3)}
    return {"true_positives": tp, "false_positives": fp, "false_negatives": fn,
            "precision": round(prec, 3), "recall": round(rec, 3),
            "f1": round(2 * prec * rec / (prec + rec), 3) if prec + rec else 0.0, "per_attack": per}


def _summary(d, alerts):
    cls = d["classification"].value_counts()
    return {"total_flows": int(len(d)), "normal_flows": int(cls.get("NORMAL", 0)),
            "suspicious_flows": int(cls.get("SUSPICIOUS", 0)),
            "intrusion_flows": int(cls.get("POTENTIAL INTRUSION", 0)),
            "alerts": len(alerts), "alerts_by_severity": dict(Counter(a["severity"] for a in alerts)),
            "top_talkers": [(str(k), int(v)) for k, v in d["src_ip"].value_counts().head(5).items()],
            "time_range": [str(d["timestamp"].iloc[0]), str(d["timestamp"].iloc[-1])],
            "evaluation": _evaluate(d)}


def analyze(df, use_ml=False, detector=None):
    d = add_features(prepare(df))
    d["rule_points"], d["rules"], d["primary_rule"], d["_pp"] = 0, "", "", 0
    for r in RULES:
        m = r.mask(d).fillna(False).astype(bool)
        d.loc[m, "rule_points"] += r.points
        d.loc[m, "rules"] = d.loc[m, "rules"] + r.id + " "
        best = m & (r.points > d["_pp"])
        d.loc[best, "primary_rule"] = r.id
        d.loc[best, "_pp"] = r.points
    d["rules"] = d["rules"].str.strip()
    d["rule_points"] = d["rule_points"].clip(upper=85)
    det = detector or AnomalyDetector().fit(d)
    d["anomaly_z"] = det.zscores(d)
    d["anomaly_points"] = AnomalyDetector.points(d["anomaly_z"])
    d["ml_prob"], d["ml_points"], ml_used = 0.0, 0.0, False
    if use_ml:
        from . import ml_model
        p = ml_model.predict_proba(d)
        if p is not None:
            d["ml_prob"], d["ml_points"], ml_used = p, np.round(p * 25), True
    d["risk"] = (d["rule_points"] + d["anomaly_points"] + d["ml_points"]).clip(0, 100).round().astype(int)
    d["classification"] = d["risk"].map(classify)
    d["severity"] = d["risk"].map(severity_for)
    d = d.drop(columns=["_pp"])
    alerts = build_alerts(d)
    return IDSResult(d, alerts, _summary(d, alerts), ml_used)
