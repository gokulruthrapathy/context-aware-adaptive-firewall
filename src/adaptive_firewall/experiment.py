"""Freeze every model/calibrator/policy before opening the test labels for metrics."""
from pathlib import Path
import hashlib
import importlib.metadata
import json
import platform
import time
import joblib
import numpy as np
import pandas as pd
from threadpoolctl import threadpool_limits
from .data import load_prepared, write_json, SPLITS
from .features import causal_history, matrix, TrainOnlyTransform, HISTORY
from .models import fit_model, BinaryCalibrator
from .policy import attack_probability, risk_score, decide, select_policy, Thresholds, ACTIONS
from .metrics import classifier_metrics, policy_metrics, with_intervals, paired_bootstrap_f1
from .config import validate_config
from .history import FlowHistory
from .provenance import sha256, utc_now, environment, input_fingerprints, evidence_manifest
from .policy import policy_order


def code_hash():
    h=hashlib.sha256()
    for p in sorted(Path(__file__).parent.glob("*.py")):
        h.update(p.name.encode()); h.update(p.read_bytes())
    return h.hexdigest()


def run(config, prepared, output):
    config=validate_config(config)
    out=Path(output)
    if out.exists() and any(out.iterdir()):
        raise ValueError("Choose a new results directory to preserve previous run evidence")
    out.mkdir(parents=True,exist_ok=True)
    write_json(out/"run_status.json",dict(status="running",phase="preflight",started_utc=utc_now()))
    try:
        return _run(config,prepared,out)
    except Exception as exc:
        status=json.loads((out/"run_status.json").read_text())
        status.update(status="failed",failed_utc=utc_now(),error_type=type(exc).__name__,message=str(exc))
        write_json(out/"run_status.json",status)
        raise


def _phase(out,phase):
    status=json.loads((out/"run_status.json").read_text())
    status.update(phase=phase,updated_utc=utc_now())
    write_json(out/"run_status.json",status)


def _run(config,prepared,out):
    reference_path=(Path(prepared).parent/"temporal.csv.gz"
        if config["protocol"]=="random" and config["history_observation"]=="uniform_reference" else None)
    inputs=input_fingerprints(prepared,reference_path,config["require_preparation_manifest"])
    run_environment=environment(Path(__file__).resolve().parents[2])
    write_json(out/"input_manifest.json",inputs)
    write_json(out/"environment.json",run_environment)
    history=FlowHistory(**{k.removeprefix("history_"):config[k] for k in [
        "history_max_sources","history_max_events_per_source","history_max_total_events","history_max_pending_events"]})
    initial_code_hash=code_hash()
    snapshot=out/"source_snapshot"
    snapshot.mkdir()
    for p in Path(__file__).parent.glob("*.py"):
        (snapshot/p.name).write_bytes(p.read_bytes())
    write_json(out/"config.json",config)
    _phase(out,"history")
    frame=load_prepared(prepared,config.get("protocol","random"),config.get("binary",False))
    base_columns=json.loads((Path(prepared).parent/"data_audit.json").read_text())["base_columns"]
    if reference_path is not None:
        # Context observations come from an independently uniform sample, never
        # the class-capped training selection. Query-only rows do not update it.
        reference=load_prepared(reference_path)
        reference_ids=set(reference["__row_id"])
        combined=pd.concat([frame,reference],ignore_index=True).drop_duplicates("__row_id")
        combined=combined.sort_values(["__ready_at","__row_id"],kind="stable").reset_index(drop=True)
        histories=causal_history(combined,combined["__row_id"].isin(reference_ids).to_numpy(),state=history)
        histories.index=combined["__row_id"]
        frame[HISTORY]=histories.loc[frame["__row_id"],HISTORY].to_numpy()
    else:
        frame=pd.concat([frame,causal_history(frame,state=history)],axis=1)
    history_contract=dict(observation="uniform_reference" if reference_path else "cohort",
        limits=history.limits,strictly_earlier=True,equal_time_pending=True,
        evicted_sources=history.evicted_sources,truncated_events=history.truncated_events)
    write_json(out/"history_contract.json",history_contract)
    partitions={s:np.flatnonzero(frame["__split"].eq(s)) for s in SPLITS}
    labels=frame["__label"].to_numpy()
    # The train taxonomy defines model outputs. Unknown test classes remain explicit.
    classes=sorted(np.unique(labels[partitions["train"]]))
    if "BENIGN" not in classes or len(classes)<2:
        raise ValueError("Training partition needs BENIGN and at least one attack class")
    encoder={name:i for i,name in enumerate(classes)}
    yi=np.array([encoder.get(name,-1) for name in labels])
    is_attack=labels!="BENIGN"
    for split in ["calibration","policy"]:
        if np.unique(is_attack[partitions[split]]).size<2:
            raise ValueError(split+" partition lacks one binary class; protocol is not evaluable")
    identity_columns=["__row_id","__source","__ready_at","__split","__label"]
    identity_columns += [c for c in ["__raw_row","__flow_id","__original_label"] if c in frame]
    ids=frame[identity_columns].copy()
    ids.to_csv(out/"split_manifest.csv.gz",index=False)
    audit=json.loads((Path(prepared).parent/"data_audit.json").read_text())
    write_json(out/"data_audit.json",audit)
    split_summary={s:dict(rows=len(ix),labels=dict(pd.Series(labels[ix]).value_counts()),
        earliest=str(frame.iloc[ix]["__ready_at"].min()),latest=str(frame.iloc[ix]["__ready_at"].max())) for s,ix in partitions.items()}
    # Convert numpy integers for strict JSON output.
    for s in split_summary:
        split_summary[s]["labels"]={k:int(v) for k,v in split_summary[s]["labels"].items()}
    write_json(out/"split_summary.json",split_summary)
    suite=config.get("models",[{"name":"baseline_dnn","kind":"dnn","variant":"baseline"},
        {"name":"engineered_dnn","kind":"dnn","variant":"engineered"},
        {"name":"context_dnn","kind":"dnn","variant":"context"},
        {"name":"random_forest","kind":"random_forest","variant":"baseline"},
        {"name":"logistic","kind":"logistic","variant":"baseline"},
        {"name":"dummy","kind":"dummy","variant":"baseline"}])
    artifacts=[]
    all_policy_rows=[]
    comparison_policies={}
    policy_arguments=dict(benign_budget=config["benign_budget"],search=config["threshold_search"],
        objective=config["policy_objective"],containment_target=config["containment_target"],
        max_monitor_fraction=config["max_monitor_fraction"])
    with threadpool_limits(limits=config.get("threads",2)):
        _phase(out,"training_and_validation_selection")
        # PHASE 1: train, tune, calibrate, and select. No test scoring in this loop.
        for spec in suite:
            raw=matrix(frame,base_columns,spec["variant"])
            transform=TrainOnlyTransform().fit(raw.iloc[partitions["train"]])
            x={s:transform.transform(raw.iloc[ix]) for s,ix in partitions.items() if s!="test"}
            for seed in config.get("seeds",[17,42,99]):
                name=spec["name"]+"_seed"+str(seed)
                print("Training",name,flush=True)
                model,training=fit_model(spec["kind"],x["train"],yi[partitions["train"]],x["tune"],yi[partitions["tune"]],seed,config)
                model_classes=[classes[int(i)] for i in model.classes_]
                raw_cal=attack_probability(model.predict_proba(x["calibration"]),model_classes)
                calibrator=BinaryCalibrator(config["calibration"]).fit(raw_cal,is_attack[partitions["calibration"]],
                    min_per_class=config["min_calibration_per_class"],fallback=config["calibration_fallback"])
                raw_policy=attack_probability(model.predict_proba(x["policy"]),model_classes)
                p_policy=calibrator.predict(raw_policy)
                selected,rows=select_policy(risk_score(p_policy),is_attack[partitions["policy"]],**policy_arguments)
                raw_selected,raw_rows=select_policy(risk_score(raw_policy),is_attack[partitions["policy"]],**policy_arguments)
                training["calibration"]={"method":getattr(calibrator,"method_","unrestricted"),
                    "attack_support":calibrator.attack_support_,"benign_support":calibrator.benign_support_,
                    "slope":getattr(calibrator,"slope_",float(calibrator.model_.coef_.item()) if hasattr(calibrator,"model_") else None),
                    "intercept":getattr(calibrator,"intercept_",float(calibrator.model_.intercept_.item()) if hasattr(calibrator,"model_") else None),
                    "requested_method":calibrator.requested_method_,"fallback_reason":calibrator.fallback_reason_,
                    "boundary_solution":getattr(calibrator,"boundary_solution_",False),
                    "calibration_brier_raw":float(np.mean((is_attack[partitions["calibration"]]-raw_cal)**2)),
                    "calibration_brier_used":float(np.mean((is_attack[partitions["calibration"]]-calibrator.predict(raw_cal))**2))}
                frozen_comparisons=[]
                for source,candidates,primary in [("used",rows,selected),("raw",raw_rows,raw_selected)]:
                    for r in candidates:
                        all_policy_rows.append(dict(model=spec["name"],seed=seed,score_source=source,**r))
                    frozen_comparisons.append(dict(name=source+"_selected",score_source=source,
                        thresholds=vars(primary) if primary else None))
                    # Prespecified validation-only matched-containment comparisons.
                    for target in [.90,.95,.99]:
                        feasible=[r for r in candidates if r["attack_containment"]>=target
                            and r["benign_disruption"]<=config["benign_budget"]
                            and r["monitor_fraction"]<=config["max_monitor_fraction"]]
                        chosen=min(feasible,key=lambda r:policy_order(r,"min_disruption")) if feasible else None
                        frozen_comparisons.append(dict(name=f"{source}_target_{target:.2f}",score_source=source,
                            target=target,thresholds={k:chosen[k] for k in ["monitor","rate_limit","block"]} if chosen else None))
                comparison_policies[name]=frozen_comparisons
                package=dict(model=model,transform=transform,calibrator=calibrator,
                    classes=model_classes,base_columns=base_columns,variant=spec["variant"],
                    policy=selected,raw_policy=raw_selected,training=training,history_contract=history_contract)
                model_path=out/"models"/(name+".joblib")
                model_path.parent.mkdir(exist_ok=True)
                joblib.dump(package,model_path,compress=3)
                write_json(out/"training"/(name+".json"),training)
                artifacts.append(dict(name=name,model=spec["name"],seed=seed,kind=spec["kind"],
                    variant=spec["variant"],features=len(raw.columns),path="models/"+name+".joblib",
                    artifact_sha256=hashlib.sha256(model_path.read_bytes()).hexdigest(),
                    policy=vars(selected) if selected is not None else None,
                    raw_policy=vars(raw_selected) if raw_selected else None,
                    calibration=training["calibration"],comparison_policies=frozen_comparisons))
        pd.DataFrame(all_policy_rows).to_csv(out/"validation_policy_candidates.csv",index=False)
        if code_hash()!=initial_code_hash:
            raise ValueError("Source changed during training; discard this run and rerun with fixed source")
        if input_fingerprints(prepared,reference_path,config["require_preparation_manifest"])!=inputs:
            raise ValueError("Prepared inputs changed during training")
        manifest=dict(schema_version=2,code_sha256=initial_code_hash,python=platform.python_version(),
            packages={name:importlib.metadata.version(name) for name in ["numpy","pandas","scikit-learn","scipy","matplotlib","joblib"]},
            config=config,classes=classes,artifacts=artifacts,
            protocol=config.get("protocol","random"),test_used_for_selection=False,
            prior_test_exposure=config["prior_test_exposure"],independent_confirmation=(config["prior_test_exposure"]=="independent_confirmation"),
            frozen_utc=utc_now(),environment=run_environment,inputs=inputs,history_contract=history_contract,
            config_sha256=sha256(out/"config.json"),split_manifest_sha256=sha256(out/"split_manifest.csv.gz"),
            validation_candidates_sha256=sha256(out/"validation_policy_candidates.csv"),
            caveats=["Post-flow completed-record scoring, not prevention of packets already transmitted",
                "Rate-limit containment is an offline proxy, not measured mitigation",
                "History is based on retained sampled flows, not the full original capture",
                "Random protocol mixes capture times; temporal protocol is a separate forward-time test",
                "Exact-feature deduplication changes the original capture distribution"])
        write_json(out/"frozen_selection_manifest.json",manifest)
        frozen_hash=hashlib.sha256((out/"frozen_selection_manifest.json").read_bytes()).hexdigest()
        _phase(out,"frozen_test_evaluation")
        # PHASE 2: held-out evaluation. Frozen artifacts are never fitted again.
        ix=partitions["test"]
        y_test,attack_test=labels[ix],is_attack[ix]
        test_classes=sorted(set(classes)|set(y_test))
        summaries=[]
        policy_comparisons=[]
        predictions={}
        for entry in artifacts:
            print("Evaluating",entry["name"],flush=True)
            # Only deserialize artifacts produced in this run, after verifying their hash.
            path=out/entry["path"]
            if hashlib.sha256(path.read_bytes()).hexdigest()!=entry["artifact_sha256"]:
                raise ValueError("Model artifact changed after policy selection")
            package=joblib.load(path)
            test_features=matrix(frame.iloc[ix],base_columns,entry["variant"])
            start=time.perf_counter()
            xt=package["transform"].transform(test_features)
            probabilities=package["model"].predict_proba(xt)
            class_names=np.array(package["classes"])
            predicted=class_names[np.argmax(probabilities,axis=1)]
            raw_attack=attack_probability(probabilities,class_names)
            p_attack=package["calibrator"].predict(raw_attack)
            elapsed=time.perf_counter()-start
            metrics=classifier_metrics(y_test,predicted,test_classes,attack_test,p_attack)
            metrics["test_rows_with_unseen_training_class"]=int((yi[ix]==-1).sum())
            metrics["raw_attack_brier"]=float(np.mean((attack_test-raw_attack)**2))
            fixed_actions=decide(risk_score(p_attack),Thresholds())
            fixed=with_intervals(policy_metrics(attack_test,fixed_actions))
            selected_actions=None
            selected_metrics=None
            if package["policy"] is not None:
                selected_actions=decide(risk_score(p_attack),package["policy"])
                selected_metrics=with_intervals(policy_metrics(attack_test,selected_actions))
            comparison_actions={}
            for policy in entry["comparison_policies"]:
                thresholds=policy["thresholds"]
                result=dict(model=entry["model"],seed=entry["seed"],policy=policy["name"],
                    score_source=policy["score_source"],validation_target=policy.get("target"),feasible=thresholds is not None)
                if thresholds is not None:
                    scores=risk_score(raw_attack if policy["score_source"]=="raw" else p_attack)
                    actions=decide(scores,Thresholds(**thresholds))
                    comparison_actions[policy["name"]]=ACTIONS[actions]
                    result.update(with_intervals(policy_metrics(attack_test,actions)))
                policy_comparisons.append(result)
            details=dict(model=entry["model"],seed=entry["seed"],features=entry["features"],
                classifier=metrics,fixed_policy=fixed,selected_policy=selected_metrics,
                thresholds=entry["policy"],inference_seconds=elapsed,
                microseconds_per_flow=elapsed*1e6/len(ix),
                timing_scope="batch feature transformation + prediction + binary calibration; excludes flow extraction and history generation",
                selection_manifest_sha256=frozen_hash)
            write_json(out/"metrics"/(entry["name"]+".json"),details)
            prediction_frame=pd.DataFrame(dict(row_id=frame.iloc[ix]["__row_id"].to_numpy(),
                source=frame.iloc[ix]["__source"].to_numpy(),true_label=y_test,predicted_label=predicted,
                completion_time=frame.iloc[ix]["__ready_at"].to_numpy(),model_sha256=entry["artifact_sha256"],
                selection_manifest_sha256=frozen_hash,enforcement="simulation_only",outcome="not_measured",
                is_attack=attack_test,raw_attack_probability=raw_attack,calibrated_attack_probability=p_attack,
                risk_score=risk_score(p_attack),fixed_action=ACTIONS[fixed_actions]))
            for key,actions in comparison_actions.items():prediction_frame[key+"_action"]=actions
            if selected_actions is not None:
                prediction_frame["selected_action"]=ACTIONS[selected_actions]
                action_table=pd.crosstab(pd.Series(y_test,name="true_label"),pd.Series(ACTIONS[selected_actions],name="action")).reindex(columns=ACTIONS,fill_value=0)
                action_table.to_csv(out/(entry["name"]+"_class_by_action.csv"))
            prediction_frame.to_csv(out/(entry["name"]+"_predictions.csv.gz"),index=False)
            np.savez_compressed(out/(entry["name"]+"_probabilities.npz"),probabilities=probabilities,class_names=class_names,row_ids=prediction_frame["row_id"].to_numpy(dtype=str))
            predictions[(entry["model"],entry["seed"])]=predicted
            row=dict(model=entry["model"],seed=entry["seed"],features=entry["features"],
                accuracy=metrics["accuracy"],macro_precision=metrics["macro_precision"],macro_recall=metrics["macro_recall"],macro_f1=metrics["macro_f1"],
                attack_auroc=metrics["attack_auroc"],attack_average_precision=metrics["attack_average_precision"],attack_brier=metrics["attack_brier"],
                weighted_f1=metrics["weighted_f1"],supported_class_macro_f1=metrics["supported_class_macro_f1"],
                policy_feasible=selected_metrics is not None,calibration_method=entry["calibration"]["method"],
                training_seconds=package["training"]["seconds"],microseconds_per_flow=details["microseconds_per_flow"])
            if selected_metrics:
                row.update({k:selected_metrics[k] for k in ["attack_blocking","attack_containment","benign_false_block","benign_disruption","monitor_fraction","attack_allowed","attack_monitored","benign_monitored"]})
            summaries.append(row)
        summary=pd.DataFrame(summaries)
        summary.to_csv(out/"summary.csv",index=False)
        pd.DataFrame(policy_comparisons).to_csv(out/"policy_comparisons.csv",index=False)
        numeric=[c for c in summary.select_dtypes(include="number") if c!="seed"]
        summary.groupby("model")[numeric].agg(["mean","std"]).to_csv(out/"summary_across_seeds.csv")
        comparisons=[]
        for seed in config.get("seeds",[17,42,99]):
            if ("baseline_dnn",seed) in predictions:
                for comparison in ["engineered_dnn","context_dnn"]:
                    if (comparison,seed) not in predictions:
                        continue
                    for groups in [None,frame.iloc[ix]["__source"].to_numpy()]:
                        comparisons.append(dict(model_seed=seed,comparison=comparison,
                            **paired_bootstrap_f1(y_test,predictions[("baseline_dnn",seed)],predictions[(comparison,seed)],test_classes,
                                repeats=config.get("bootstrap_repeats",300),seed=seed,groups=groups)))
        write_json(out/"paired_comparisons.json",comparisons)
    from .plots import make_plots
    _phase(out,"plotting")
    make_plots(out)
    if code_hash()!=initial_code_hash or input_fingerprints(prepared,reference_path,config["require_preparation_manifest"])!=inputs:
        raise ValueError("Source or prepared input changed during evaluation")
    write_json(out/"evidence_manifest.json",evidence_manifest(out))
    from .verify import verify_results
    _phase(out,"verification")
    verification=verify_results(out,require_complete=False)
    write_json(out/"verification.json",verification)
    status=json.loads((out/"run_status.json").read_text())
    status.update(status="complete",phase="complete",completed_utc=utc_now())
    write_json(out/"run_status.json",status)
    write_json(out/"run_complete.json",dict(test_rows=len(ix),frozen_manifest_sha256=frozen_hash,
        evidence_manifest_sha256=sha256(out/"evidence_manifest.json"),models_evaluated=len(artifacts),
        status="complete",completed_utc=utc_now(),prior_test_exposure=config["prior_test_exposure"],
        independent_confirmation=manifest["independent_confirmation"]))
    return summary
