import json
import numpy as np
import pandas as pd
import pytest
from adaptive_firewall.data import write_json
from adaptive_firewall.provenance import register_prepared
from adaptive_firewall.experiment import run


def test_plot_failure_leaves_failed_run_without_completion(tmp_path,monkeypatch):
    import adaptive_firewall.plots as plots
    n=100
    frame=pd.DataFrame({"Flow Duration":np.arange(n)+1.,"Dst Port":80.,
        "Total Fwd Packet":2.,"Total Bwd packets":1.,
        "Total Length of Fwd Packet":100.,"Total Length of Bwd Packet":50.,"SYN Flag Count":1.})
    columns=list(frame)
    frame["__row_id"]=[str(i) for i in range(n)]
    frame["__ready_at"]=pd.date_range("2017-01-01",periods=n,freq="s")
    frame["__src_ip"]="source";frame["__dst_ip"]="destination";frame["__source"]="fixture"
    frame["__label"]=["BENIGN","ATTACK"]*(n//2)
    frame["__split"]=np.repeat(["train","tune","calibration","policy","test"],20)
    data=tmp_path/"prepared";data.mkdir()
    frame.to_csv(data/"random.csv.gz",index=False);frame.to_csv(data/"temporal.csv.gz",index=False)
    write_json(data/"data_audit.json",dict(base_columns=columns,dataset="synthetic test"))
    register_prepared(data,origin="synthetic test")
    def fail(*args):raise RuntimeError("intentional plot failure")
    monkeypatch.setattr(plots,"make_plots",fail)
    output=tmp_path/"failed"
    with pytest.raises(RuntimeError,match="intentional"):
        run(dict(seeds=[17],bootstrap_repeats=3,threads=1,
            models=[dict(name="dummy",kind="dummy",variant="baseline")]),data/"random.csv.gz",output)
    assert not (output/"run_complete.json").exists()
    assert json.loads((output/"run_status.json").read_text())["status"]=="failed"
