"""Bounded causal history. Equal-time updates remain pending across batches."""
from collections import OrderedDict, Counter, deque
import numpy as np
import pandas as pd

HISTORY = ["ctx_source_flows_60s","ctx_source_flows_300s","ctx_source_bytes_60s",
    "ctx_source_packets_60s","ctx_source_mean_duration_60s","ctx_seconds_since_previous",
    "ctx_source_unique_dst_ports_60s","ctx_source_same_destination_60s"]


class FlowHistory:
    def __init__(self,max_sources=4096,max_events_per_source=10000,
                 max_total_events=100000,max_pending_events=100000):
        self.limits=dict(max_sources=max_sources,max_events_per_source=max_events_per_source,
            max_total_events=max_total_events,max_pending_events=max_pending_events)
        if any(type(v) is not int or v<1 for v in self.limits.values()):
            raise ValueError("History limits must be positive integers")
        self.sources=OrderedDict()
        self.watermark=None
        self.pending=[]
        self.total_events=0
        self.evicted_sources=0
        self.truncated_events=0

    @staticmethod
    def _new():
        return dict(events=deque(),recent=deque(),ports=Counter(),destinations=Counter(),
            size=0.,packets=0.,duration=0.,last=None)

    @staticmethod
    def _remove_recent(state):
        event=state["recent"].popleft()
        _,dst,port,size,packets,duration=event
        state["size"]-=size;state["packets"]-=packets;state["duration"]-=duration
        for name,key in [("ports",port),("destinations",dst)]:
            state[name][key]-=1
            if state[name][key]==0:del state[name][key]

    def _expire(self,t):
        while self.sources:
            source=next(iter(self.sources))
            if self.sources[source]["last"]>=t-300_000_000_000:break
            self.total_events-=len(self.sources.pop(source)["events"])

    def _trim(self,state,t):
        while state["events"] and state["events"][0][0]<t-300_000_000_000:
            state["events"].popleft();self.total_events-=1
        while state["recent"] and state["recent"][0][0]<t-60_000_000_000:
            self._remove_recent(state)

    def _commit(self):
        for source,event in self.pending:
            state=self.sources.get(source)
            if state is None:
                state=self._new();self.sources[source]=state
            self._trim(state,event[0])
            state["events"].append(event);state["recent"].append(event);self.total_events+=1
            _,dst,port,size,packets,duration=event
            state["size"]+=size;state["packets"]+=packets;state["duration"]+=duration
            state["ports"][port]+=1;state["destinations"][dst]+=1;state["last"]=event[0]
            self.sources.move_to_end(source)
            while len(state["events"])>self.limits["max_events_per_source"]:
                removed=state["events"].popleft();self.total_events-=1;self.truncated_events+=1
                if state["recent"] and state["recent"][0]==removed:self._remove_recent(state)
            while len(self.sources)>self.limits["max_sources"] or self.total_events>self.limits["max_total_events"]:
                _,removed=self.sources.popitem(last=False)
                self.total_events-=len(removed["events"]);self.evicted_sources+=1
        self.pending=[]

    def process(self,frame,update_mask=None):
        if not frame["__ready_at"].is_monotonic_increasing or frame["__ready_at"].isna().any():
            raise ValueError("History requires valid, sorted completion times")
        mask=np.ones(len(frame),dtype=bool) if update_mask is None else np.asarray(update_mask)
        if mask.shape!=(len(frame),) or mask.dtype!=bool:
            raise ValueError("History observation mask must be aligned booleans")
        times=frame["__ready_at"].to_numpy(dtype="datetime64[ns]").astype("int64")
        if len(times) and self.watermark is not None and int(times[0])<self.watermark:
            raise ValueError("Late event precedes history watermark; reorder before scoring")
        sizes=(frame["Total Length of Fwd Packet"]+frame["Total Length of Bwd Packet"]).fillna(0)
        packets=(frame["Total Fwd Packet"]+frame["Total Bwd packets"]).fillna(0)
        durations=frame["Flow Duration"].fillna(0)/1e6
        records=zip(times,frame["__src_ip"].astype(str),frame["__dst_ip"].astype(str),
            frame["Dst Port"],sizes,packets,durations)
        out=np.zeros((len(frame),len(HISTORY)),dtype=float)
        for i,(time,src,dst,port,size,pkts,duration) in enumerate(records):
            t=int(time)
            if self.watermark is None or t>self.watermark:
                self._commit();self._expire(t);self.watermark=t
            state=self.sources.get(src)
            if state is None:
                out[i,5]=300.
            else:
                self._trim(state,t)
                count=len(state["recent"])
                out[i]=[count,len(state["events"]),state["size"],state["packets"],
                    state["duration"]/count if count else 0.,
                    min((t-state["last"])/1e9,300.),len(state["ports"]),state["destinations"].get(dst,0)]
            if mask[i]:
                if len(self.pending)>=self.limits["max_pending_events"]:
                    raise ValueError("Equal-time observation group exceeds configured pending limit")
                # Null port is one explicit missing category, never NaN dictionary keys.
                port_key="missing" if pd.isna(port) else str(float(port))
                self.pending.append((src,(t,dst,port_key,float(size),float(pkts),float(duration))))
        return pd.DataFrame(out,columns=HISTORY,index=frame.index)

    def snapshot(self):
        return dict(schema_version=1,limits=self.limits,watermark=self.watermark,pending=self.pending,
            sources=[dict(source=src,events=list(s["events"])) for src,s in self.sources.items()],
            evicted_sources=self.evicted_sources,truncated_events=self.truncated_events)

    @classmethod
    def restore(cls,payload):
        if payload.get("schema_version")!=1:raise ValueError("Unsupported history-state version")
        obj=cls(**payload["limits"])
        # Rebuild derived aggregates from the stored events; do not trust duplicate counters.
        for entry in payload["sources"]:
            if not entry["events"]:raise ValueError("Empty source in history state")
            obj.pending=[(entry["source"],tuple(event)) for event in entry["events"]]
            obj._commit()
        obj.watermark=payload["watermark"]
        obj.pending=[(src,tuple(event)) for src,event in payload["pending"]]
        if len(obj.pending)>obj.limits["max_pending_events"]:raise ValueError("Oversized pending state")
        obj.evicted_sources=payload["evicted_sources"];obj.truncated_events=payload["truncated_events"]
        return obj
