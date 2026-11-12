import numpy as np
import pandas as pd
import pytest
from adaptive_firewall.policy import Thresholds,attack_probability,risk_score,decide,select_policy
from adaptive_firewall.metrics import policy_metrics,binomial_interval,paired_bootstrap_f1
from adaptive_firewall.features import TrainOnlyTransform,engineered,causal_history,HISTORY
from adaptive_firewall.data import normalized_labels,signature,load_prepared
from adaptive_firewall.models import BinaryCalibrator


def test_action_equalities_and_invalid_values():
    np.testing.assert_array_equal(decide([0,24.999,25,59.999,60,78.999,79,100]),[0,0,1,1,2,2,3,3])
    for values in [[np.nan],[np.inf],[-1],[101]]:
        with pytest.raises(ValueError): decide(values)
    with pytest.raises(ValueError): Thresholds(60,25,79)


def test_probability_column_order_and_validation():
    p=[[.2,.7,.1]]
    assert attack_probability(p,["A","BENIGN","B"])[0]==pytest.approx(.3)
    with pytest.raises(ValueError): attack_probability(p,["A","B","C"])
    with pytest.raises(ValueError): attack_probability([[.5,.8]],["BENIGN","A"])
    with pytest.raises(ValueError): risk_score([float("nan")])


def test_policy_numerators_and_monitor_exclusion():
    y=[1,1,1,1,0,0,0,0]
    a=[0,1,2,3,0,1,2,3]
    result=policy_metrics(y,a)
    assert result["attack_blocked"]==1
    assert result["attack_contained"]==2
    assert result["benign_disrupted"]==2
    assert result["attack_containment"]==.5
    assert policy_metrics([],[])["attack_containment"] is None
    assert binomial_interval(0,0)==[None,None]
    assert binomial_interval(0,10)[0]==0


def test_policy_constraint_and_infeasibility():
    thresholds,rows=select_policy([1,2,80,90],[0,0,1,1],.0,grid=[Thresholds()])
    assert thresholds==Thresholds() and rows[0]["feasible"]
    thresholds,_=select_policy([99,99],[0,1],.0,grid=[Thresholds()])
    assert thresholds is None
    with pytest.raises(ValueError): select_policy([1,2],[False,False])


def test_validation_cutoffs_cover_small_probability_ranges():
    selected,_=select_policy([.001,.002,.008,.009],[False,False,True,True],benign_budget=0.)
    assert selected.rate_limit<.01
    assert policy_metrics([False,False,True,True],decide([.001,.002,.008,.009],selected))["attack_containment"]==1


def test_monotonic_calibration_never_reverses_risk_order():
    p=np.array([.1,.2,.3,.7,.8,.9])
    # A hostile calibration sample would make unrestricted logistic slope negative.
    calibrator=BinaryCalibrator().fit(p,np.array([True,True,True,False,False,False]))
    assert np.all(np.diff(calibrator.predict(p))>=0)
    assert calibrator.boundary_solution_


def test_preprocessing_fit_uses_training_only_and_preserves_order():
    train=pd.DataFrame({"Flow Bytes/s":[1.,2.,3.],"x":[2.,np.nan,4.]})
    transform=TrainOnlyTransform().fit(train)
    cap=transform.rate_caps_["Flow Bytes/s"]
    medians=transform.imputer_.statistics_.copy()
    test=pd.DataFrame({"Flow Bytes/s":[1e15],"x":[np.inf]})
    assert np.isfinite(transform.transform(test)).all()
    assert transform.rate_caps_["Flow Bytes/s"]==cap
    np.testing.assert_array_equal(transform.imputer_.statistics_,medians)
    with pytest.raises(ValueError): transform.transform(test[["x","Flow Bytes/s"]])


def tiny_flows():
    return pd.DataFrame({"Flow Duration":[0.,1e6,2e6],"Total Fwd Packet":[0.,2.,3.],
        "Total Bwd packets":[0.,1.,1.],"Total Length of Fwd Packet":[0.,200.,300.],
        "Total Length of Bwd Packet":[0.,100.,100.],"SYN Flag Count":[0.,1.,0.],
        "Dst Port":[80,443,80],"__ready_at":pd.to_datetime(["2017-01-01 00:00:00","2017-01-01 00:00:00","2017-01-01 00:00:01"]),
        "__src_ip":["s","s","s"],"__dst_ip":["d","d","d"]})


def test_engineering_zero_denominators_and_shape():
    result=engineered(tiny_flows())
    assert result.shape==(3,14)
    assert np.isfinite(result).all().all()
    assert result.iloc[0]["eng_bytes_per_packet"]==0
    assert result.iloc[1]["eng_bytes_per_second"]==300


def test_causal_history_excludes_current_tied_and_future_rows():
    data=tiny_flows()
    first=causal_history(data)
    assert list(first["ctx_source_flows_60s"])==[0,0,2]
    assert first.iloc[2]["ctx_seconds_since_previous"]==1
    data.loc[2,"Total Length of Fwd Packet"]=1e12
    second=causal_history(data)
    pd.testing.assert_frame_equal(first.iloc[:2],second.iloc[:2])
    # Labels are not read at all.
    data["__label"]=["ATTACK"]*3
    pd.testing.assert_frame_equal(second,causal_history(data))
    assert len(HISTORY)==8


def test_history_window_expiry_uses_seconds_independent_of_datetime_unit():
    data=tiny_flows()
    data.loc[2,"__ready_at"]=pd.Timestamp("2017-01-01 00:05:01")
    result=causal_history(data)
    assert result.iloc[2]["ctx_source_flows_300s"]==0
    assert result.iloc[2]["ctx_seconds_since_previous"]==300


def test_query_only_history_rows_do_not_update_reference_stream():
    data=tiny_flows()
    result=causal_history(data,update_mask=[True,False,True])
    assert result.iloc[2]["ctx_source_flows_60s"]==1
    assert result.iloc[2]["ctx_source_bytes_60s"]==0


def test_single_capture_does_not_produce_false_cluster_precision():
    result=paired_bootstrap_f1(["A","B"],["A","B"],["A","B"],["A","B"],groups=["only","only"],repeats=20)
    assert result["ci95"]==[None,None] and result["repeats"]==0


def test_labels_and_signature_exclude_label_information():
    labels=normalized_labels(pd.Series([" BENIGN ","DoS Hulk - Attempted","DoS Hulk"]))
    assert list(labels)==["BENIGN","BENIGN","DoS Hulk"]
    x=pd.DataFrame({"a":[1.,1.,2.],"b":[3.,3.,4.]})
    h=signature(x)
    assert h[0]==h[1] and h[0]!=h[2]


def test_deduplication_uses_the_saved_model_precision():
    x=pd.DataFrame({"x":[1.,np.nextafter(1.,2.)]})
    assert signature(x)[0]==signature(x)[1]


def test_paired_bootstrap_identical_predictions_zero_delta():
    result=paired_bootstrap_f1(["A","B"]*5,["A","B"]*5,["A","B"]*5,["A","B"],repeats=20)
    assert result["delta_macro_f1"]==0 and result["ci95"]==[0.,0.]


def test_temporal_boundaries_never_split_equal_times(tmp_path):
    times=pd.date_range("2017-01-01",periods=20,freq="s").repeat(2)
    x=pd.DataFrame({"__row_id":[str(i) for i in range(40)],"__ready_at":times,"__label":["BENIGN","A"]*20,"__source":"capture"})
    p=tmp_path/"prepared.csv"
    x.to_csv(p,index=False)
    data=load_prepared(p,"temporal",True)
    assert data.groupby("__ready_at")["__split"].nunique().max()==1
    previous=None
    for split in ["train","tune","calibration","policy","test"]:
        block=data.loc[data["__split"]==split,"__ready_at"]
        if previous is not None: assert previous<block.min()
        previous=block.max()
