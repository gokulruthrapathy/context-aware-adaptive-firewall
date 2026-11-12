"""Figures come directly from saved metrics and predictions."""
from pathlib import Path
import json
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def save(fig,path):
    fig.savefig(str(path)+".png",dpi=180,bbox_inches="tight")
    fig.savefig(str(path)+".pdf",bbox_inches="tight")
    plt.close(fig)


def make_plots(directory):
    root=Path(directory)
    output=root/"figures"
    output.mkdir(exist_ok=True)
    summary=pd.read_csv(root/"summary.csv")
    means=summary.groupby("model")["macro_f1"].mean().sort_values()
    std=summary.groupby("model")["macro_f1"].std().fillna(0).reindex(means.index)
    fig,ax=plt.subplots(figsize=(8,4))
    ax.barh(means.index,means,xerr=std,color="#147d92",capsize=4)
    ax.set(xlim=(0,1),xlabel="Macro F1 (mean ± SD across seeds)",title="Held-out classifier comparison")
    save(fig,output/"macro_f1")
    if "benign_disruption" in summary:
        fig,ax=plt.subplots(figsize=(7,5))
        for name,g in summary.groupby("model"):
            ax.scatter(g["benign_disruption"]*100,g["attack_containment"]*100,label=name,s=45)
        ax.set(xlabel="Benign disruption (%)",ylabel="Attack containment proxy (%)",title="Held-out security–disruption trade-off")
        ax.legend(fontsize=8)
        save(fig,output/"test_policy_tradeoff")
    for file in sorted((root/"metrics").glob("*.json")):
        if "context_dnn" not in file.name:
            continue
        metrics=json.loads(file.read_text())
        cm=np.asarray(metrics["classifier"]["confusion_matrix"])
        denom=cm.sum(axis=1,keepdims=True)
        normalized=np.divide(cm,denom,out=np.zeros_like(cm,dtype=float),where=denom!=0)
        names=metrics["classifier"]["class_order"]
        fig,ax=plt.subplots(figsize=(9,8))
        im=ax.imshow(normalized,vmin=0,vmax=1,cmap="Blues")
        ax.set_xticks(range(len(names)),names,rotation=90,fontsize=7)
        ax.set_yticks(range(len(names)),names,fontsize=7)
        ax.set(xlabel="Predicted class",ylabel="True class",title=f"Context DNN seed {metrics['seed']}: row-normalized confusion matrix")
        fig.colorbar(im,ax=ax)
        save(fig,output/"context_confusion")
        pred=pd.read_csv(root/(file.stem+"_predictions.csv.gz"))
        fig,ax=plt.subplots(figsize=(5,5))
        p=pred["calibrated_attack_probability"].to_numpy()
        y=pred["is_attack"].to_numpy(dtype=float)
        bins=np.minimum((p*10).astype(int),9)
        valid=[i for i in range(10) if (bins==i).any()]
        ax.plot([0,1],[0,1],"--",color="gray")
        ax.plot([p[bins==i].mean() for i in valid],[y[bins==i].mean() for i in valid],"o-",color="#147d92")
        ax.set(xlim=(0,1),ylim=(0,1),xlabel="Mean used attack probability",ylabel="Observed attack fraction",title=f"Context seed {metrics['seed']}: probability reliability")
        save(fig,output/"context_calibration")
        break
    candidates=root/"validation_policy_candidates.csv"
    if candidates.exists():
        rows=pd.read_csv(candidates)
        if "score_source" in rows:
            fig,ax=plt.subplots(figsize=(8,5))
            for (model,source),group in rows.groupby(["model","score_source"]):
                if source!="raw" or model=="dummy":continue
                frontier=group.groupby("benign_disruption")["attack_containment"].max().sort_index()
                ax.plot(frontier.index*100,frontier.to_numpy()*100,label=model)
            ax.set(xlim=(0,10),ylim=(0,101),xlabel="Validation benign disruption (%)",
                ylabel="Validation containment proxy (%)",title="Validation raw-score candidates (seeds pooled descriptively)")
            ax.legend(fontsize=8)
            save(fig,output/"validation_policy_candidates")
