"""Versioned offline decisions with optional persistent, bounded history state."""
from pathlib import Path
import json
import joblib
import numpy as np
import pandas as pd
from .data import signature,write_json
from .features import matrix
from .history import FlowHistory
from .policy import attack_probability,risk_score,decide,ACTIONS
from .provenance import sha256,utc_now


class CompletedFlowScorer:
    def __init__(self,results,model_name,state=None):
        self.root=Path(results)
        self.manifest=json.loads((self.root/"frozen_selection_manifest.json").read_text())
        matches=[r for r in self.manifest["artifacts"] if r["name"]==model_name]
        if len(matches)!=1:raise ValueError("Choose one model from the frozen manifest")
        self.artifact=matches[0]
        path=self.root/"models"/(model_name+".joblib")
        if sha256(path)!=self.artifact["artifact_sha256"]:raise ValueError("Model artifact changed")
        # Only load locally generated bundles you trust. Hashes are not a sandbox.
        self.package=joblib.load(path)
        if self.package["policy"] is None:raise ValueError("No feasible selected policy")
        contract=self.package.get("history_contract",{})
        self.observation=contract.get("observation","legacy_batch")
        if state is not None:
            if state["model_sha256"]!=self.artifact["artifact_sha256"]:
                raise ValueError("History state belongs to another model version")
            if state.get("observation")!=self.observation:raise ValueError("Observation contract changed")
            self.history=FlowHistory.restore(state["history"])
            if contract and self.history.limits!=contract["limits"]:raise ValueError("History limits changed")
        else:self.history=FlowHistory(**contract.get("limits",{}))

    def score_frame(self,records,observation_column=None):
        frame=records.copy()
        frame.columns=frame.columns.str.strip()
        columns=self.package["base_columns"]
        missing=set(columns)-set(frame)
        if missing:raise ValueError("Missing flow features: "+str(sorted(missing)))
        frame[columns]=frame[columns].apply(pd.to_numeric,errors="coerce").replace([np.inf,-np.inf],np.nan)
        if frame[columns].notna().mean(axis=1).lt(.5).any() or frame["Flow Duration"].isna().any() or frame["Flow Duration"].lt(0).any():
            raise ValueError("Flow numeric/timing validity differs from preparation contract")
        if "__ready_at" not in frame:
            needed={"Timestamp","Src IP","Dst IP"}
            if not needed.issubset(frame):raise ValueError("Missing raw flow timing/address metadata")
            frame["__ready_at"]=pd.to_datetime(frame["Timestamp"],format="%d/%m/%Y %I:%M:%S %p",errors="raise")+pd.to_timedelta(frame["Flow Duration"],unit="us")
            frame["__src_ip"]=frame["Src IP"];frame["__dst_ip"]=frame["Dst IP"]
        else:frame["__ready_at"]=pd.to_datetime(frame["__ready_at"],errors="raise")
        metadata=["__ready_at","__src_ip","__dst_ip"]
        if not set(metadata).issubset(frame) or frame[metadata].isna().any().any():
            raise ValueError("Missing completion/address metadata")
        frame["__input_row"]=np.arange(len(frame))
        frame=frame.sort_values(["__ready_at","__input_row"],kind="stable").reset_index(drop=True)
        observed=None
        if self.package["variant"]=="context":
            if self.observation=="uniform_reference" and observation_column is None:
                raise ValueError("Uniform-reference model requires an explicit history observation column; query-only flows must not update history")
            if observation_column is not None:
                if observation_column not in frame:raise ValueError("Missing history observation column")
                observed=frame[observation_column].astype(str).str.lower().map({"true":True,"false":False,"1":True,"0":False})
                if observed.isna().any():raise ValueError("History observation flags must be true/false")
                observed=observed.to_numpy(dtype=bool)
            history=self.history.process(frame,observed)
            for column in history:frame[column]=history[column]
        x=self.package["transform"].transform(matrix(frame,columns,self.package["variant"]))
        probabilities=self.package["model"].predict_proba(x)
        raw=attack_probability(probabilities,self.package["classes"])
        p=self.package["calibrator"].predict(raw);scores=risk_score(p)
        event_ids=frame["__row_id"].astype(str).to_numpy() if "__row_id" in frame else signature(frame[columns]).astype(str)
        result=pd.DataFrame(dict(input_row=frame["__input_row"],row_id=event_ids,completion_time=frame["__ready_at"],
            predicted_class=np.asarray(self.package["classes"])[probabilities.argmax(1)],
            raw_attack_probability=raw,calibrated_attack_probability=p,risk_score=scores,
            action=ACTIONS[decide(scores,self.package["policy"])],model_sha256=self.artifact["artifact_sha256"],
            policy_version=sha256(self.root/"frozen_selection_manifest.json"),
            decision_recorded_utc=utc_now(),enforcement="simulation_only",outcome="not_measured"))
        return result.sort_values("input_row").reset_index(drop=True)

    def snapshot(self):
        return dict(schema_version=1,model_sha256=self.artifact["artifact_sha256"],
            observation=self.observation,history=self.history.snapshot())


def score_completed_csv(results,model_name,input_csv,output_csv,state_path=None,observation_column=None):
    target=Path(output_csv)
    if target.exists():raise ValueError("Scoring output already exists")
    if state_path and Path(state_path).resolve() in {Path(input_csv).resolve(),target.resolve()}:
        raise ValueError("History state must have its own path")
    state_file=Path(state_path) if state_path else None
    state=json.loads(state_file.read_text()) if state_file and state_file.exists() else None
    scorer=CompletedFlowScorer(results,model_name,state)
    records=pd.read_csv(input_csv,dtype={"__row_id":str})
    result=scorer.score_frame(records,observation_column)
    target.parent.mkdir(parents=True,exist_ok=True)
    result.to_csv(target,index=False)
    if state_file:write_json(state_file,scorer.snapshot())
    return len(result)
