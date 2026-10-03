"""Anomaly-based detection: robust per-service statistical baseline (median / MAD)."""
import numpy as np

FEATURES = ["bytes_out", "bytes_in", "packets", "duration", "pps"]
MIN_SAMPLES = 30      # a port needs this many flows to get its own baseline
SCALE_FLOOR = 0.25    # avoids huge z-scores on near-constant features


def _fit_one(X):
    med = np.median(X, axis=0)
    mad = np.median(np.abs(X - med), axis=0) * 1.4826
    scale = np.where(mad > 1e-6, mad, X.std(axis=0))
    return med, np.maximum(scale, SCALE_FLOOR)


class AnomalyDetector:
    """Learns what 'usual' looks like for each destination port, then scores deviation.
    Median/MAD is robust: a minority of attack flows barely moves the baseline."""

    def __init__(self):
        self.models, self.global_ = {}, None

    @staticmethod
    def _matrix(d):
        return np.log1p(d[FEATURES].to_numpy(dtype=float))

    def fit(self, d):
        X = self._matrix(d)
        self.global_ = _fit_one(X)
        for port, idx in d.groupby("dst_port").indices.items():
            if len(idx) >= MIN_SAMPLES:
                self.models[int(port)] = _fit_one(X[idx])
        return self

    def zscores(self, d):
        X = self._matrix(d)
        z = np.zeros(len(d))
        for port, idx in d.groupby("dst_port").indices.items():
            med, scale = self.models.get(int(port), self.global_)
            z[idx] = (np.abs(X[idx] - med) / scale).max(axis=1)
        return z

    @staticmethod
    def points(z):
        """0 points up to z=4, then +4 per unit, capped at 25."""
        return np.clip((z - 4.0) * 4.0, 0, 25)
