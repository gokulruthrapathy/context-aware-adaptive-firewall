"""Offline completed-flow scoring with trusted locally generated artifacts."""
from pathlib import Path
import hashlib
import json
import joblib
import numpy as np
import pandas as pd
from .data import signature
from .features import causal_history,matrix
from .policy import attack_probability,risk_score,decide,ACTIONS


def score_completed_csv(results, model_name, input_csv, output_csv):
    root=Path(results)
    manifest=json.loads((root/"frozen_selection_manifest.json").read_text())
    matches=[r for r in manifest["artifacts"] if r["name"]==model_name]
    if len(matches)!=1:
        raise ValueError("Choose one model name from the frozen selection manifest")
    artifact=matches[0]
    path=root/"models"/(model_name+".joblib")
    if hashlib.sha256(path.read_bytes()).hexdigest()!=artifact["artifact_sha256"]:
        raise ValueError("Local model artifact changed")
    # A matching hash is not a sandbox. Use only a bundle you trust and generated.
    package=joblib.load(path)
    if package["policy"] is None:
        raise ValueError("No feasible policy was selected for this model")
    frame=pd.read_csv(input_csv)
    frame.columns=frame.columns.str.strip()
    if "__ready_at" not in frame:
        frame["__ready_at"]=pd.to_datetime(frame["Timestamp"],format="%d/%m/%Y %I:%M:%S %p",errors="raise")+pd.to_timedelta(frame["Flow Duration"],unit="us")
        frame["__src_ip"]=frame["Src IP"].astype(str)
        frame["__dst_ip"]=frame["Dst IP"].astype(str)
    else:
        frame["__ready_at"]=pd.to_datetime(frame["__ready_at"],errors="raise")
    frame["__input_row"]=np.arange(len(frame))
    frame=frame.sort_values(["__ready_at","__input_row"],kind="stable").reset_index(drop=True)
    if frame["__ready_at"].isna().any() or frame["Flow Duration"].lt(0).any():
        raise ValueError("Invalid completed-flow timing")
    if package["variant"]=="context":
        context=causal_history(frame)
        for column in context:
            frame[column]=context[column]
    x=package["transform"].transform(matrix(frame,package["base_columns"],package["variant"]))
    probabilities=package["model"].predict_proba(x)
    raw=attack_probability(probabilities,package["classes"])
    p=package["calibrator"].predict(raw)
    scores=risk_score(p)
    result=pd.DataFrame(dict(input_row=frame["__input_row"],completion_time=frame["__ready_at"],
        predicted_class=np.array(package["classes"])[probabilities.argmax(axis=1)],
        raw_attack_probability=raw,calibrated_attack_probability=p,risk_score=scores,
        action=ACTIONS[decide(scores,package["policy"])],enforcement="simulation_only"))
    if Path(output_csv).exists():
        raise ValueError("Scoring output already exists")
    Path(output_csv).parent.mkdir(parents=True,exist_ok=True)
    result.sort_values("input_row").to_csv(output_csv,index=False)
    return len(result)
