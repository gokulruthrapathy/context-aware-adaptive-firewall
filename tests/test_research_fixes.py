import json
from pathlib import Path
import zipfile
import numpy as np
import pandas as pd
import pytest
from adaptive_firewall.config import validate_config
from adaptive_firewall.history import FlowHistory,HISTORY
from adaptive_firewall.features import causal_history
from adaptive_firewall.models import BinaryCalibrator
from adaptive_firewall.policy import select_policy,Thresholds
from adaptive_firewall.provenance import input_fingerprints,sha256
from test_core import tiny_flows


@pytest.mark.parametrize("config",[{"epoch":3},{"protocol":"typo"},{"binary":"false"},
    {"seeds":[1,1]},{"threads":0},{"l2":float("nan")},{"hidden_layers":[]},
    {"models":[{"name":"../escape","kind":"dnn","variant":"baseline"}]}])
def test_invalid_configuration_fails_closed(config):
    with pytest.raises(ValueError):validate_config(config)


def test_defaults_are_expanded_without_mutating_input():
    original={"seeds":[17]}
    a=validate_config(original);a["hidden_layers"].append(8)
    assert original=={"seeds":[17]}
    assert validate_config(original)["hidden_layers"]==[64,32]
    assert validate_config(original)["prior_test_exposure"]=="development_reused"


def test_reported_checkpoint_is_the_retained_min_delta_epoch(monkeypatch):
    import adaptive_firewall.models as module
    class Estimator:
        def __init__(self,**kwargs):self.epoch=0;self.loss_=1.
        def partial_fit(self,x,y,classes):self.epoch+=1;return self
        def predict_proba(self,x):return np.tile([.5,.5],(len(x),1))
    losses=iter([.5,.49995,.5001])
    monkeypatch.setattr(module,"MLPClassifier",Estimator)
    monkeypatch.setattr(module,"log_loss",lambda *a,**k:next(losses))
    model,info=module.fit_model("dnn",np.ones((4,2)),np.array([0,1,0,1]),
        np.ones((2,2)),np.array([0,1]),17,{"epochs":3,"patience":2,"min_delta":.0001})
    assert model.epoch==info["best_epoch"]==1
    assert info["minimum_loss_epoch"]==2


def test_low_support_calibration_uses_prespecified_identity_fallback():
    p=np.array([.05,.1,.8,.95]);y=np.array([0,0,1,1])
    cal=BinaryCalibrator().fit(p,y,min_per_class=100,fallback="identity")
    assert cal.method_=="identity" and "support" in cal.fallback_reason_
    np.testing.assert_array_equal(cal.predict(p),p)
    with pytest.raises(ValueError,match="support"):
        BinaryCalibrator().fit(p,y,min_per_class=100,fallback="error")


def test_target_policy_and_monitor_budget_expose_infeasibility():
    grid=[Thresholds(10,40,70),Thresholds(10,70,90)]
    policy,rows=select_policy([1,45,50,80],[0,0,1,1],.5,grid=grid,
        objective="min_disruption",containment_target=1.)
    assert policy==grid[0]
    policy,_=select_policy([1,45,50,80],[0,0,1,1],0.,grid=grid,
        objective="min_disruption",containment_target=1.)
    assert policy is None
    policy,_=select_policy([30,80],[0,1],0.,grid=[Thresholds()],max_monitor_fraction=0.)
    assert policy is None


def test_history_matches_strictly_earlier_oracle_across_batches():
    frame=pd.concat([tiny_flows()]*8,ignore_index=True)
    frame["__ready_at"]=pd.to_datetime("2017-01-01")+pd.to_timedelta(np.arange(24)//3,unit="us")
    frame["__src_ip"]=["a","b"]*12
    frame["__dst_ip"]=["x","y","z"]*8
    observed=np.arange(24)%4!=0
    whole=causal_history(frame,observed)
    state=FlowHistory();pieces=[]
    for start,end in [(0,2),(2,7),(7,13),(13,24)]:
        pieces.append(state.process(frame.iloc[start:end],observed[start:end]))
        state=FlowHistory.restore(json.loads(json.dumps(state.snapshot())))
    pd.testing.assert_frame_equal(whole,pd.concat(pieces))
    for i,row in frame.iterrows():
        prior=frame[(frame.__ready_at<row.__ready_at)&(frame.__src_ip==row.__src_ip)&observed]
        assert whole.iloc[i]["ctx_source_flows_60s"]==len(prior)
        assert whole.iloc[i]["ctx_source_same_destination_60s"]==int(prior.__dst_ip.eq(row.__dst_ip).sum())


def test_history_bounds_expiry_and_late_event_rejection():
    frame=pd.concat([tiny_flows()]*5,ignore_index=True)
    frame["__ready_at"]=pd.date_range("2017-01-01",periods=15,freq="s")
    frame["__src_ip"]=["a","b","c"]*5
    state=FlowHistory(max_sources=2,max_events_per_source=2,max_total_events=3,max_pending_events=2)
    state.process(frame)
    assert len(state.sources)<=2 and state.total_events<=3
    assert state.evicted_sources>0
    with pytest.raises(ValueError,match="Late"):
        state.process(frame.iloc[:1])
    later=frame.iloc[-1:].copy();later["__ready_at"]+=pd.Timedelta(seconds=301)
    result=state.process(later)
    assert result.iloc[0]["ctx_source_flows_300s"]==0
    assert len(state.sources)==0


def test_equal_time_pending_limit_is_explicit():
    frame=tiny_flows();state=FlowHistory(max_pending_events=1)
    with pytest.raises(ValueError,match="pending"):
        state.process(frame.iloc[:2])


def test_package_excludes_environments_and_every_prepared_version(tmp_path):
    import importlib.util
    module_path=Path(__file__).resolve().parents[1]/"scripts/package.py"
    spec=importlib.util.spec_from_file_location("package_script",module_path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    for name in [".venv/secret.txt","venv/library.py","data/raw/dataset.zip",
                 "data/prepared_v2/temporal.csv.gz","data/prepared/random.csv.gz",".git/config"]:
        assert not module.included(tmp_path/name,tmp_path)
    assert module.included(tmp_path/"notebooks/study.ipynb",tmp_path)
    assert module.included(tmp_path/"results/study/models/model.joblib",tmp_path)


def test_prepare_preserves_row_locator_and_rejects_overwrite(tmp_path,monkeypatch):
    import adaptive_firewall.data as data
    rng=np.random.default_rng(91);n=240
    source=pd.DataFrame({"Flow ID":["flow"+str(i) for i in range(n)],
        "Src IP":"192.0.2.1","Src Port":1000,"Dst IP":"192.0.2.2",
        "Timestamp":["01/01/2017 01:00:00 PM"]*n,"Label":["BENIGN","A"]*(n//2),
        "Dst Port":rng.integers(1,65535,n),"Flow Duration":np.arange(n)+1.,
        "Total Fwd Packet":rng.integers(1,100,n),"Total Bwd packets":1.,
        "Total Length of Fwd Packet":100.,"Total Length of Bwd Packet":50.,"SYN Flag Count":1.})
    archive=tmp_path/"source.zip"
    with zipfile.ZipFile(archive,"w") as z:z.writestr("capture.csv",source.to_csv(index=False))
    monkeypatch.setattr(data,"DATA_SHA256",sha256(archive))
    output=tmp_path/"prepared"
    data.prepare(archive,output,20,20,20,60,chunksize=25)
    frame=pd.read_csv(output/"random.csv.gz")
    for _,row in frame.iterrows():
        original=source.iloc[int(row.__raw_row)-1]
        assert original["Flow ID"]==row.__flow_id
        assert original["Flow Duration"]==row["Flow Duration"]
    assert input_fingerprints(output/"random.csv.gz",output/"temporal.csv.gz")
    with pytest.raises(ValueError,match="preserved"):
        data.prepare(archive,output)
    with (output/"random.csv.gz").open("ab") as stream:stream.write(b"tampered")
    with pytest.raises(ValueError,match="fingerprint"):
        input_fingerprints(output/"random.csv.gz")
