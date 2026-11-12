"""14 flow-derived features and 8 strictly earlier completed-flow features."""
from collections import defaultdict, deque, Counter
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler

ENGINEERED = ["eng_duration_seconds", "eng_total_packets", "eng_total_bytes",
    "eng_packets_per_second", "eng_bytes_per_second", "eng_forward_packet_fraction",
    "eng_backward_packet_fraction", "eng_forward_byte_fraction", "eng_bytes_per_packet",
    "eng_fwd_bytes_per_packet", "eng_bwd_bytes_per_packet", "eng_packet_direction_imbalance",
    "eng_byte_direction_imbalance", "eng_syn_per_packet"]
HISTORY = ["ctx_source_flows_60s", "ctx_source_flows_300s", "ctx_source_bytes_60s",
    "ctx_source_packets_60s", "ctx_source_mean_duration_60s", "ctx_seconds_since_previous",
    "ctx_source_unique_dst_ports_60s", "ctx_source_same_destination_60s"]


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


def causal_history(frame, update_mask=None):
    """At a completion time t, use only retained flows completed strictly before t.

    Equal completion-time groups are scored before any row in that group updates
    history. No labels, model predictions, raw IP encodings, or future flows enter.
    History represents the sampled stream, not the original unsampled capture.
    """
    if not frame["__ready_at"].is_monotonic_increasing:
        raise ValueError("Causal history requires sorted completion times")
    update_mask = np.ones(len(frame),dtype=bool) if update_mask is None else np.asarray(update_mask,dtype=bool)
    if update_mask.shape != (len(frame),):
        raise ValueError("History update mask must align with records")
    records = list(zip(frame["__ready_at"].to_numpy(dtype="datetime64[ns]").astype("int64")/1e9,
        frame["__src_ip"], frame["__dst_ip"], frame["Dst Port"],
        (frame["Total Length of Fwd Packet"]+frame["Total Length of Bwd Packet"]).fillna(0),
        (frame["Total Fwd Packet"]+frame["Total Bwd packets"]).fillna(0), frame["Flow Duration"].fillna(0)/1e6))
    windows = defaultdict(deque)
    last = {}
    out = np.zeros((len(frame),len(HISTORY)), dtype=np.float64)
    begin = 0
    while begin < len(records):
        end = begin+1
        while end < len(records) and records[end][0] == records[begin][0]:
            end += 1
        for i in range(begin,end):
            t,src,dst,port,size,packets,duration = records[i]
            queue = windows[src]
            while queue and queue[0][0] < t-300:
                queue.popleft()
            recent = [r for r in queue if r[0] >= t-60]
            out[i] = [len(recent),len(queue),sum(r[4] for r in recent),sum(r[5] for r in recent),
                np.mean([r[6] for r in recent]) if recent else 0,
                min(t-last[src],300) if src in last else 300,
                len({r[3] for r in recent}),sum(r[2] == dst for r in recent)]
        for i in range(begin,end):
            if not update_mask[i]:
                continue
            record = records[i]
            windows[record[1]].append(record)
            last[record[1]] = record[0]
        begin = end
    return pd.DataFrame(out,columns=HISTORY,index=frame.index)


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
