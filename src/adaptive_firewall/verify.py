"""Reconcile saved predictions, denominators, probabilities and frozen artifacts."""
from pathlib import Path
import hashlib
import json
import numpy as np
import pandas as pd
from .policy import attack_probability,risk_score,decide,Thresholds,ACTIONS
from .metrics import policy_metrics,classifier_metrics,with_intervals
from .provenance import sha256,read_predictions,evidence_manifest
from .policy import policy_order


def verify_results(directory,require_complete=True):
    root=Path(directory)
    manifest=json.loads((root/"frozen_selection_manifest.json").read_text())
    complete=json.loads((root/"run_complete.json").read_text()) if require_complete else None
    frozen=hashlib.sha256((root/"frozen_selection_manifest.json").read_bytes()).hexdigest()
    if (complete and complete["frozen_manifest_sha256"]!=frozen) or manifest["test_used_for_selection"]:
        raise ValueError("Frozen manifest does not reconcile")
    if manifest.get("schema_version",1)>=2:
        for file,key in [("config.json","config_sha256"),("split_manifest.csv.gz","split_manifest_sha256"),
                         ("validation_policy_candidates.csv","validation_candidates_sha256")]:
            if sha256(root/file)!=manifest[key]:raise ValueError("Frozen input/export changed: "+file)
        if complete and sha256(root/"evidence_manifest.json")!=complete["evidence_manifest_sha256"]:
            raise ValueError("Completion evidence manifest changed")
        evidence=json.loads((root/"evidence_manifest.json").read_text())
        if evidence!=evidence_manifest(root):raise ValueError("Completed evidence files changed or are missing")
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
        pred=read_predictions(root/(name+"_predictions.csv.gz"))
        if pred["row_id"].duplicated().any() or set(pred["row_id"])!=expected:
            raise ValueError("Test row identities do not reconcile")
        label_lookup=split.set_index("__row_id")["__label"]
        if not np.array_equal(label_lookup.loc[pred["row_id"]].to_numpy(),pred["true_label"].to_numpy()):
            raise ValueError("Saved true labels differ from the split manifest")
        with np.load(root/(name+"_probabilities.npz"),allow_pickle=False) as data:
            if not np.array_equal(data["row_ids"],pred["row_id"].to_numpy()):
                raise ValueError("Probability rows do not align")
            raw=attack_probability(data["probabilities"],data["class_names"])
            expected_prediction=data["class_names"][data["probabilities"].argmax(axis=1)]
            if not np.array_equal(expected_prediction,pred["predicted_label"]):
                raise ValueError("Classifier argmax does not match saved probability vectors")
            if not np.allclose(raw,pred["raw_attack_probability"]):
                raise ValueError("Probability columns do not reconcile")
        scores=risk_score(pred["calibrated_attack_probability"])
        if not np.allclose(scores,pred["risk_score"]):
            raise ValueError("Risk scores do not reconcile")
        metrics=json.loads((root/"metrics"/(name+".json")).read_text())
        if metrics["selection_manifest_sha256"]!=frozen:
            raise ValueError("Metrics use another frozen selection")
        recomputed_classifier=classifier_metrics(pred["true_label"],pred["predicted_label"],
            metrics["classifier"]["class_order"],pred["true_label"].ne("BENIGN"),pred["calibrated_attack_probability"].to_numpy())
        for key,value in recomputed_classifier.items():
            if key in metrics["classifier"]:_compare(value,metrics["classifier"][key],"classifier."+key)
        raw_brier=float(np.mean((pred["true_label"].ne("BENIGN").to_numpy()-raw)**2))
        _compare(raw_brier,metrics["classifier"]["raw_attack_brier"],"raw Brier")
        if "calibration" in artifact:
            info=artifact["calibration"]
            if info["method"]=="identity":calculated=raw
            else:
                from scipy.special import expit
                clipped=np.clip(raw,1e-6,1-1e-6)
                calculated=expit(info["slope"]*np.log(clipped/(1-clipped))+info["intercept"])
            if not np.allclose(calculated,pred["calibrated_attack_probability"],rtol=1e-12,atol=1e-12):
                raise ValueError("Calibration map does not reproduce exported probabilities")
        if manifest.get("schema_version",1)>=2:
            candidates=pd.read_csv(root/"validation_policy_candidates.csv",converters={k:float for k in ["monitor","rate_limit","block"]})
            candidates=candidates[(candidates.model==artifact["model"])&(candidates.seed==artifact["seed"])]
            for source,key in [("used","policy"),("raw","raw_policy")]:
                feasible=candidates[(candidates.score_source==source)&candidates.feasible]
                best=min(feasible.to_dict("records"),key=lambda r:policy_order(r,manifest["config"]["policy_objective"])) if len(feasible) else None
                expected_policy={k:best[k] for k in ["monitor","rate_limit","block"]} if best else None
                if expected_policy!=artifact[key]:raise ValueError("Selected policy does not match saved validation ranking")
        for kind,thresholds in [("fixed",Thresholds()),("selected",Thresholds(**artifact["policy"]) if artifact["policy"] else None)]:
            if thresholds is None:
                continue
            actions=decide(scores,thresholds)
            if not np.array_equal(ACTIONS[actions],pred[kind+"_action"]):
                raise ValueError("Saved actions do not reconcile")
            recomputed=policy_metrics(pred["true_label"].ne("BENIGN"),actions)
            for key,value in recomputed.items():
                if key not in metrics[kind+"_policy"]:continue
                saved=metrics[kind+"_policy"][key]
                if value is None:
                    if saved is not None: raise ValueError("Undefined rate mismatch")
                elif not np.isclose(value,saved,rtol=1e-12,atol=1e-12):
                    raise ValueError("Policy numerator/denominator mismatch: "+key)
            for key,value in with_intervals(recomputed).items():
                if key.endswith("_ci95"):_compare(value,metrics[kind+"_policy"][key],key)
            if kind=="selected":
                saved=pd.read_csv(root/(name+"_class_by_action.csv"),index_col=0)
                actual=pd.crosstab(pred["true_label"],pd.Series(ACTIONS[actions],name="action")).reindex(index=saved.index,columns=ACTIONS,fill_value=0)
                if not np.array_equal(saved[ACTIONS].to_numpy(),actual.to_numpy()):
                    raise ValueError("Class-by-action export mismatch")
    return dict(status="verified",models=len(manifest["artifacts"]),test_rows=len(expected),
        checked="model/source/evidence hashes, split identities, classifier argmax/metrics, calibration map when recorded, policy ranking, actions, denominators, intervals and class-by-action totals",
        limitation="Export consistency is not an independent retraining replication or proof of dataset ground truth")


def _compare(actual,expected,name):
    if isinstance(actual,dict):
        for key,value in actual.items():_compare(value,expected[key],name+"."+key)
    elif isinstance(actual,(list,tuple)):
        if len(actual)!=len(expected):raise ValueError("Metric shape mismatch: "+name)
        for a,b in zip(actual,expected):_compare(a,b,name)
    elif isinstance(actual,(float,int,np.number)):
        if not np.isclose(actual,expected,rtol=1e-10,atol=1e-12):raise ValueError("Metric mismatch: "+name)
    elif actual!=expected:raise ValueError("Metric mismatch: "+name)
