"""Reconcile saved predictions, denominators, probabilities and frozen artifacts."""
from pathlib import Path
import hashlib
import json
import numpy as np
import pandas as pd
from .policy import attack_probability,risk_score,decide,Thresholds,ACTIONS
from .metrics import policy_metrics


def verify_results(directory):
    root=Path(directory)
    manifest=json.loads((root/"frozen_selection_manifest.json").read_text())
    complete=json.loads((root/"run_complete.json").read_text())
    frozen=hashlib.sha256((root/"frozen_selection_manifest.json").read_bytes()).hexdigest()
    if complete["frozen_manifest_sha256"]!=frozen or manifest["test_used_for_selection"]:
        raise ValueError("Frozen manifest does not reconcile")
    h=hashlib.sha256()
    for path in sorted((root/"source_snapshot").glob("*.py")):
        h.update(path.name.encode());h.update(path.read_bytes())
    if h.hexdigest()!=manifest["code_sha256"]:
        raise ValueError("Source snapshot differs from frozen code hash")
    split=pd.read_csv(root/"split_manifest.csv.gz",dtype={"__row_id":str})
    if split["__row_id"].duplicated().any():
        raise ValueError("Split identities overlap")
    expected=set(split.loc[split["__split"].eq("test"),"__row_id"])
    for artifact in manifest["artifacts"]:
        # Relative location makes result folders movable without changing the manifest.
        model_file=root/"models"/(artifact["name"]+".joblib")
        if hashlib.sha256(model_file.read_bytes()).hexdigest()!=artifact["artifact_sha256"]:
            raise ValueError("Model artifact hash mismatch")
        name=artifact["name"]
        pred=pd.read_csv(root/(name+"_predictions.csv.gz"),dtype={"row_id":str})
        if pred["row_id"].duplicated().any() or set(pred["row_id"])!=expected:
            raise ValueError("Test row identities do not reconcile")
        label_lookup=split.set_index("__row_id")["__label"]
        if not np.array_equal(label_lookup.loc[pred["row_id"]].to_numpy(),pred["true_label"].to_numpy()):
            raise ValueError("Saved true labels differ from the split manifest")
        with np.load(root/(name+"_probabilities.npz"),allow_pickle=False) as data:
            if not np.array_equal(data["row_ids"],pred["row_id"].to_numpy()):
                raise ValueError("Probability rows do not align")
            raw=attack_probability(data["probabilities"],data["class_names"])
            if not np.allclose(raw,pred["raw_attack_probability"]):
                raise ValueError("Probability columns do not reconcile")
        scores=risk_score(pred["calibrated_attack_probability"])
        if not np.allclose(scores,pred["risk_score"]):
            raise ValueError("Risk scores do not reconcile")
        metrics=json.loads((root/"metrics"/(name+".json")).read_text())
        if metrics["selection_manifest_sha256"]!=frozen:
            raise ValueError("Metrics use another frozen selection")
        for kind,thresholds in [("fixed",Thresholds()),("selected",Thresholds(**artifact["policy"]) if artifact["policy"] else None)]:
            if thresholds is None:
                continue
            actions=decide(scores,thresholds)
            if not np.array_equal(ACTIONS[actions],pred[kind+"_action"]):
                raise ValueError("Saved actions do not reconcile")
            recomputed=policy_metrics(pred["true_label"].ne("BENIGN"),actions)
            for key,value in recomputed.items():
                saved=metrics[kind+"_policy"][key]
                if value is None:
                    if saved is not None: raise ValueError("Undefined rate mismatch")
                elif not np.isclose(value,saved,rtol=1e-12,atol=1e-12):
                    raise ValueError("Policy numerator/denominator mismatch: "+key)
            if kind=="selected":
                saved=pd.read_csv(root/(name+"_class_by_action.csv"),index_col=0)
                actual=pd.crosstab(pred["true_label"],pd.Series(ACTIONS[actions],name="action")).reindex(index=saved.index,columns=ACTIONS,fill_value=0)
                if not np.array_equal(saved[ACTIONS].to_numpy(),actual.to_numpy()):
                    raise ValueError("Class-by-action export mismatch")
    return dict(status="verified",models=len(manifest["artifacts"]),test_rows=len(expected),
        checked="model/source hashes, split IDs, labels, probability order, risk, actions, policy numerators and class-by-action totals")
