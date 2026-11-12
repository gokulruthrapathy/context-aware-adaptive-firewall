"""A small synthetic fixture tests plumbing, never research performance."""
import json
import numpy as np
import pandas as pd
from adaptive_firewall.data import write_json
from adaptive_firewall.experiment import run
from adaptive_firewall.verify import verify_results
from adaptive_firewall.inference import score_completed_csv
from adaptive_firewall.provenance import register_prepared


def test_full_train_freeze_evaluate_export_workflow(tmp_path):
    rng=np.random.default_rng(8)
    n=140
    attack=np.arange(n)%2==0
    raw=pd.DataFrame({"Flow Duration":rng.uniform(1e3,1e6,n),
        "Total Fwd Packet":rng.integers(1,30,n).astype(float),
        "Total Bwd packets":rng.integers(0,20,n).astype(float),
        "Total Length of Fwd Packet":rng.uniform(10,1000,n),
        "Total Length of Bwd Packet":rng.uniform(0,1000,n),
        "SYN Flag Count":attack.astype(float),"Dst Port":np.where(attack,443,80).astype(float)})
    columns=list(raw.columns)
    raw["__label"]=np.where(attack,"ATTACK","BENIGN")
    raw["__src_ip"]="source"
    raw["__dst_ip"]="destination"
    raw["__source"]="synthetic_test_fixture"
    raw["__row_id"]=[str(i) for i in range(n)]
    raw["__ready_at"]=pd.date_range("2017-01-01",periods=n,freq="s")
    raw["__split"]=["train"]*80+["tune"]*10+["calibration"]*10+["policy"]*10+["test"]*30
    raw["__history_observed"]=True
    prepared=tmp_path/"prepared"
    prepared.mkdir()
    raw.to_csv(prepared/"random.csv.gz",index=False)
    raw.to_csv(prepared/"temporal.csv.gz",index=False)
    write_json(prepared/"data_audit.json",{"base_columns":columns,"dataset":"synthetic software test only"})
    register_prepared(prepared,origin="synthetic software test fixture")
    output=tmp_path/"results"
    result=run({"seeds":[17],"epochs":2,"patience":2,"bootstrap_repeats":3,"threads":1,
        "models":[{"name":"baseline_dnn","kind":"dnn","variant":"baseline"},
                  {"name":"engineered_dnn","kind":"dnn","variant":"engineered"},
                  {"name":"context_dnn","kind":"dnn","variant":"context"}]},prepared/"random.csv.gz",output)
    assert len(result)==3
    assert json.loads((output/"run_complete.json").read_text())["status"]=="complete"
    assert json.loads((output/"paired_comparisons.json").read_text())
    assert (output/"figures/context_confusion.png").exists()
    predictions=pd.read_csv(output/"context_dnn_seed17_predictions.csv.gz")
    assert len(predictions)==30 and predictions["row_id"].is_unique
    assert verify_results(output)["models"]==3
    assert score_completed_csv(output,"context_dnn_seed17",prepared/"random.csv.gz",tmp_path/"scored.csv",
        observation_column="__history_observed")==n
    # The fitted model sees identical history when a time group crosses batches.
    from adaptive_firewall.inference import CompletedFlowScorer
    whole=CompletedFlowScorer(output,"context_dnn_seed17").score_frame(raw,"__history_observed")
    scorer=CompletedFlowScorer(output,"context_dnn_seed17")
    first=scorer.score_frame(raw.iloc[:47],"__history_observed")
    restored=CompletedFlowScorer(output,"context_dnn_seed17",json.loads(json.dumps(scorer.snapshot())))
    second=restored.score_frame(raw.iloc[47:],"__history_observed")
    joined=pd.concat([first,second],ignore_index=True)
    np.testing.assert_allclose(whole.risk_score,joined.risk_score,rtol=1e-5,atol=1e-5)
    assert list(whole.action)==list(joined.action)
    # Altering derived metrics is detected even if model/probability blobs survive.
    metric_path=output/"metrics/baseline_dnn_seed17.json"
    saved=metric_path.read_bytes()
    changed=json.loads(saved);changed["classifier"]["accuracy"]=0
    write_json(metric_path,changed)
    import pytest
    with pytest.raises(ValueError,match="evidence"):
        verify_results(output)
    metric_path.write_bytes(saved)
    assert verify_results(output)["status"]=="verified"
