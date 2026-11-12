"""Validated, fully expanded experiment configuration; unknown keys are errors."""
from copy import deepcopy
import math
import re

DEFAULT_MODELS = [
    {"name": "baseline_dnn", "kind": "dnn", "variant": "baseline"},
    {"name": "engineered_dnn", "kind": "dnn", "variant": "engineered"},
    {"name": "context_dnn", "kind": "dnn", "variant": "context"},
    {"name": "random_forest", "kind": "random_forest", "variant": "baseline"},
    {"name": "logistic", "kind": "logistic", "variant": "baseline"},
    {"name": "dummy", "kind": "dummy", "variant": "baseline"},
]
DEFAULTS = dict(protocol="random", binary=False, calibration="monotonic",
    calibration_fallback="identity", min_calibration_per_class=100,
    threshold_search="validation_quantiles", policy_objective="max_containment",
    containment_target=.95, max_monitor_fraction=1., benign_budget=.05,
    seeds=[17,42,99], hidden_layers=[64,32], epochs=25, patience=5,
    min_delta=.0001, batch_size=256, learning_rate=.001, l2=.0001, trees=100,
    logistic_iterations=500, bootstrap_repeats=300, threads=2,
    history_observation="uniform_reference", history_max_sources=4096,
    history_max_events_per_source=10000, history_max_total_events=100000,
    history_max_pending_events=100000, models=DEFAULT_MODELS,
    study_status="exploratory development; independent confirmation pending",
    prior_test_exposure="development_reused", require_preparation_manifest=True)


def validate_config(config):
    if not isinstance(config, dict):
        raise ValueError("Configuration must be a JSON object")
    unknown=set(config)-set(DEFAULTS)
    if unknown:
        raise ValueError("Unknown configuration keys: "+", ".join(sorted(unknown)))
    out=deepcopy(DEFAULTS)
    out.update(deepcopy(config))
    choices={"protocol":{"random","temporal"}, "calibration":{"identity","monotonic","unrestricted"},
        "calibration_fallback":{"identity","error","none"},
        "threshold_search":{"validation_quantiles","fixed_grid"},
        "policy_objective":{"max_containment","min_disruption"},
        "history_observation":{"uniform_reference","cohort"},
        "prior_test_exposure":{"development_reused","new_rows_same_capture","independent_confirmation"}}
    for key, allowed in choices.items():
        if out[key] not in allowed:
            raise ValueError(f"Invalid {key}: {out[key]!r}")
    for key in ["binary","require_preparation_manifest"]:
        if type(out[key]) is not bool:
            raise ValueError(key+" must be a boolean")
    for key in ["min_calibration_per_class","epochs","patience","batch_size","trees",
                "logistic_iterations","bootstrap_repeats","threads","history_max_sources",
                "history_max_events_per_source","history_max_total_events","history_max_pending_events"]:
        if type(out[key]) is not int or out[key]<1:
            raise ValueError(key+" must be a positive integer")
    for key in ["benign_budget","containment_target","max_monitor_fraction"]:
        if type(out[key]) not in (int,float) or not math.isfinite(out[key]) or not 0<=out[key]<=1:
            raise ValueError(key+" must be finite and in [0,1]")
    for key in ["min_delta","learning_rate","l2"]:
        if type(out[key]) not in (int,float) or not math.isfinite(out[key]) or out[key]<0:
            raise ValueError(key+" must be finite and nonnegative")
    if out["learning_rate"]==0:
        raise ValueError("learning_rate must be positive")
    for key in ["seeds","hidden_layers"]:
        values=out[key]
        minimum=0 if key=="seeds" else 1
        if not isinstance(values,list) or not values or any(type(v) is not int or v<minimum for v in values):
            raise ValueError(key+" must be a nonempty integer list")
    if len(set(out["seeds"]))!=len(out["seeds"]):
        raise ValueError("Repeated seeds are not independent runs")
    if not isinstance(out["study_status"],str) or not out["study_status"].strip():
        raise ValueError("study_status must describe the experiment")
    specs=out["models"]
    if not isinstance(specs,list) or not specs:
        raise ValueError("models must be a nonempty list")
    names=[]
    for spec in specs:
        if not isinstance(spec,dict) or set(spec)!={"name","kind","variant"}:
            raise ValueError("Each model requires exactly name, kind and variant")
        if not isinstance(spec["name"],str) or not re.fullmatch(r"[a-z][a-z0-9_]*",spec["name"]):
            raise ValueError("Model names must be safe lowercase identifiers")
        if spec["kind"] not in {"dnn","random_forest","logistic","dummy"} or spec["variant"] not in {"baseline","engineered","context"}:
            raise ValueError("Invalid model kind or variant")
        names.append(spec["name"])
    if len(set(names))!=len(names):
        raise ValueError("Model names must be unique")
    return out
