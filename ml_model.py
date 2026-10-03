"""OPTIONAL supervised ML layer (Random Forest). Trained on SYNTHETIC data: a learning demo."""
import numpy as np

from .config import DATASET_PATH, MODEL_PATH

FEATURES = ["dst_port", "proto_num", "duration", "bytes_out", "bytes_in", "packets", "syn_count",
            "rst_count", "failed_auth", "pps", "byte_ratio", "off_hours", "src_internal",
            "dst_internal", "src_flows_w", "src_dports_w", "src_syn_w", "src_fail_w", "pair_flows_w"]
_model = None


def train(dataset=DATASET_PATH, model_path=MODEL_PATH):
    import joblib
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import classification_report

    from .features import add_features, prepare
    from .simulator import generate_traffic

    tr = add_features(prepare(pd.read_csv(dataset)))
    te = add_features(prepare(generate_traffic(3000, seed=99)))   # a different random world
    ytr, yte = (tr["label"] != "normal").astype(int), (te["label"] != "normal").astype(int)
    clf = RandomForestClassifier(n_estimators=150, random_state=42, class_weight="balanced")
    clf.fit(tr[FEATURES], ytr)
    print(classification_report(yte, clf.predict(te[FEATURES]), target_names=["normal", "attack"]))
    top = sorted(zip(clf.feature_importances_, FEATURES), reverse=True)[:6]
    print("Top features:", ", ".join(f"{n} ({v:.2f})" for v, n in top))
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": clf, "features": FEATURES}, model_path)
    print("Saved model to", model_path)


def predict_proba(d):
    """P(attack) per flow, or None when no trained model / scikit-learn is available."""
    global _model
    try:
        if _model is None:
            import joblib
            if not MODEL_PATH.exists():
                return None
            _model = joblib.load(MODEL_PATH)
        return np.asarray(_model["model"].predict_proba(d[_model["features"]])[:, 1])
    except Exception:
        return None


if __name__ == "__main__":
    train()
