"""14 flow-derived features and 8 strictly earlier completed-flow features."""
from collections import defaultdict, deque, Counter
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from .history import FlowHistory, HISTORY

ENGINEERED = ["eng_duration_seconds", "eng_total_packets", "eng_total_bytes",
    "eng_packets_per_second", "eng_bytes_per_second", "eng_forward_packet_fraction",
    "eng_backward_packet_fraction", "eng_forward_byte_fraction", "eng_bytes_per_packet",
    "eng_fwd_bytes_per_packet", "eng_bwd_bytes_per_packet", "eng_packet_direction_imbalance",
    "eng_byte_direction_imbalance", "eng_syn_per_packet"]


def divide(numerator, denominator):
    n, d = np.asarray(numerator, dtype=float), np.asarray(denominator, dtype=float)
    return np.divide(n, d, out=np.zeros_like(n), where=np.isfinite(d) & (d > 0))


def engineered(frame):
    f = lambda name: frame[name].to_numpy(dtype=float)
    duration = np.maximum(f("Flow Duration"), 0) / 1e6
    fp, bp = f("Total Fwd Packet"), f("Total Bwd packets")
    fb, bb = f("Total Length of Fwd Packet"), f("Total Length of Bwd Packet")
    packets, size = fp+bp, fb+bb
    values = [duration, packets, size, divide(packets,np.maximum(duration,1e-6)),
        divide(size,np.maximum(duration,1e-6)), divide(fp,packets), divide(bp,packets),
        divide(fb,size), divide(size,packets), divide(fb,fp), divide(bb,bp),
        divide(np.abs(fp-bp),packets), divide(np.abs(fb-bb),size), divide(f("SYN Flag Count"),packets)]
    return pd.DataFrame(dict(zip(ENGINEERED,values)), index=frame.index).replace([np.inf,-np.inf],np.nan)


def causal_history(frame, update_mask=None, state=None):
    """At a completion time t, use only retained flows completed strictly before t.

    Equal completion-time groups are scored before any row in that group updates
    history. No labels, model predictions, raw IP encodings, or future flows enter.
    History represents the sampled stream, not the original unsampled capture.
    """
    return (state if state is not None else FlowHistory()).process(frame,update_mask)


def matrix(frame, base_columns, variant):
    result = frame[base_columns].copy()
    if variant in {"engineered", "context"}:
        result = pd.concat([result,engineered(frame)],axis=1)
    if variant == "context":
        result = pd.concat([result,frame[HISTORY]],axis=1)
    if variant not in {"baseline","engineered","context"}:
        raise ValueError("Unknown feature variant")
    return result


class TrainOnlyTransform(BaseEstimator, TransformerMixin):
    """Fit medians, rate caps, and standardization on training records only."""
    def fit(self,x,y=None):
        self.columns_ = list(x.columns)
        self.rate_columns_ = [c for c in self.columns_ if "/s" in c or "per_second" in c]
        self.rate_caps_ = {c: float(x[c].replace([np.inf,-np.inf],np.nan).quantile(.995)) for c in self.rate_columns_}
        self.rate_caps_ = {c:v if np.isfinite(v) else 0. for c,v in self.rate_caps_.items()}
        capped = self._cap(x)
        self.imputer_ = SimpleImputer(strategy="median",keep_empty_features=True)
        a = self.imputer_.fit_transform(capped)
        self.scaler_ = StandardScaler().fit(a)
        return self

    def _cap(self,x):
        if list(x.columns) != self.columns_:
            raise ValueError("Feature schema/order differs from fitted training schema")
        a = x.replace([np.inf,-np.inf],np.nan).copy()
        for c,cap in self.rate_caps_.items():
            a[c] = a[c].clip(lower=0,upper=max(0,cap))
        return a

    def transform(self,x):
        a = self.scaler_.transform(self.imputer_.transform(self._cap(x)))
        return np.clip(a,-20,20).astype(np.float32)
