"""Build the human-readable evidence report from completed local experiments."""
from pathlib import Path
import json
import numpy as np
import pandas as pd

ROOT=Path(__file__).resolve().parents[1]


def table(headers,rows):
    return "| "+" | ".join(headers)+" |\n|"+"|".join(["---"]*len(headers))+"|\n"+"\n".join("| "+" | ".join(map(str,row))+" |" for row in rows)+"\n"


def mean_sd(values,percent=False):
    scale=100 if percent else 1
    return f"{values.mean()*scale:.2f} ± {values.std(ddof=1)*scale:.2f}"


def main():
    studies={"Randomized multiclass":"corrected_random","Chronological binary":"corrected_temporal"}
    audit=json.loads((ROOT/"data/prepared/data_audit.json").read_text())
    report=["# Executed results and journal-readiness assessment\n",
        "Prepared 12 November 2026. These are real public-data CPU experiments from a new implementation. They are not recovered results from the missing Team CSEUG49 code.\n",
        "**Status: completed exploratory development studies, not a submission-ready journal validation.** The corrected runs followed inspection of the diagnostic test outcomes. Their test partitions were held out from fitting within each run but reused during development. Fresh independent confirmation remains necessary.\n",
        "## Data audit\n",
        table(["Audit item","Observed count"],[(k,audit[k]) for k in ["raw_rows","invalid_rows","duplicate_feature_rows","conflicting_feature_signatures","unique_rows_after_conflict_exclusion"]]),
        "The pinned source is Engelen et al.'s corrected CICIDS2017 WTMC2021 archive. Attempted attack labels map to BENIGN. Exact feature-vector deduplication at float32 precision and conflicting-label exclusion change the original population. Uniform evaluation sampling therefore refers to the cleaned, deduplicated population. Training is class-capped.\n"]
    all_summary=[]
    study_tables=[]
    for title,folder in studies.items():
        root=ROOT/"results"/folder
        if not (root/"run_complete.json").exists():
            raise RuntimeError("Incomplete experiment: "+folder)
        summary=pd.read_csv(root/"summary.csv")
        summary["protocol"]=title
        all_summary.append(summary)
        splits=json.loads((root/"split_summary.json").read_text())
        report += ["## "+title+"\n",table(["Partition","Rows","Benign","Attack"],
            [(name,info["rows"],info["labels"].get("BENIGN",0),info["rows"]-info["labels"].get("BENIGN",0)) for name,info in splits.items()])]
        rows=[]
        for model,g in summary.groupby("model",sort=False):
            rows.append([model,mean_sd(g.accuracy,True),mean_sd(g.macro_f1),
                mean_sd(g.attack_blocking,True),mean_sd(g.attack_containment,True),
                mean_sd(g.benign_false_block,True),mean_sd(g.benign_disruption,True)])
        text=table(["Model","Accuracy %","Macro F1","Attack block %","Containment proxy %","Benign block %","Benign disruption %"],rows)
        study_tables.append((title,text))
        report += [text,"Values are mean ± sample SD across seeds 17, 42 and 99. They are not confidence intervals across independent datasets.\n"]
        means=summary.groupby("model").mean(numeric_only=True)
        delta=means.loc["context_dnn","macro_f1"]-means.loc["baseline_dnn","macro_f1"]
        report.append(f"Context-minus-baseline mean macro F1: **{delta:+.4f}**. This is an observed comparison, not a claim that context is universally better.\n")
        best_reference=means.loc["random_forest","macro_f1"]
        report.append(f"The conventional random-forest comparator has mean macro F1 **{best_reference:.4f}** in this protocol. Its inclusion prevents interpreting a DNN-only comparison as evidence of state-of-the-art performance.\n")
        boundary=[]
        for path in (root/"training").glob("*.json"):
            info=json.loads(path.read_text())
            if info.get("calibration",{}).get("boundary_solution"):
                boundary.append(path.stem)
        explanation=("Boundary solutions signal weak calibration information, not a successful probability-quality guarantee." if boundary else "No lower-bound solutions occurred here; that alone does not guarantee calibration on another traffic mix.")
        report.append(f"Monotonic calibration reached its lower slope bound in {len(boundary)} of {len(summary)} runs. Boundary fits: {', '.join(boundary) if boundary else 'none'}. {explanation}\n")
        brier_rows=[]
        for model in ["baseline_dnn","context_dnn","random_forest"]:
            raw=[];cal=[];auc=[]
            for path in (root/"metrics").glob(model+"_seed*.json"):
                metrics=json.loads(path.read_text())["classifier"]
                raw.append(metrics["raw_attack_brier"]);cal.append(metrics["attack_brier"]);auc.append(metrics["attack_auroc"])
            brier_rows.append([model,f"{np.mean(raw):.5f}",f"{np.mean(cal):.5f}",f"{np.mean(auc):.5f}"])
        report += [table(["Model","Raw binary Brier","Calibrated binary Brier","Calibrated AUROC"],brier_rows),
            "Lower Brier is better. Calibration can worsen after temporal/prevalence shift even when monotonicity preserves ordering.\n"]
        comparisons=json.loads((root/"paired_comparisons.json").read_text())
        report.append(table(["Comparison","Model seed","Resampling unit","Delta F1","95% paired interval"],
            [(r["comparison"]+" minus baseline",r["model_seed"],r["unit"],f"{r['delta_macro_f1']:+.4f}",
              "not estimable" if r["ci95"][0] is None else f"[{r['ci95'][0]:+.4f}, {r['ci95'][1]:+.4f}]") for r in comparisons]))
        report.append("Row intervals assume exchangeable flows. Capture-cluster intervals have at most five groups. An interval is deliberately omitted when only one capture file appears in the test period.\n")
        manifest=json.loads((root/"frozen_selection_manifest.json").read_text())
        pred=pd.read_csv(root/"context_dnn_seed17_predictions.csv.gz",dtype={"row_id":str},float_precision="round_trip")
        row=pred.loc[pred["true_label"].ne("BENIGN")].iloc[0]
        artifact=next(r for r in manifest["artifacts"] if r["name"]=="context_dnn_seed17")
        report += ["### One real flow through the saved decision path\n",
            f"The first attack-labeled record in the completion-sorted context-model test export has row ID `{row.row_id}`. Its true label is `{row.true_label}` and predicted class is `{row.predicted_label}`. The true label is used only for evaluation.\n",
            f"The saved class probability vector gives raw attack probability **{row.raw_attack_probability:.8f}**. The separately fitted monotonic mapping produces **{row.calibrated_attack_probability:.8f}**, so risk is **{row.risk_score:.8f}** on the 0–100 scale. Selected cutoffs are `{artifact['policy']}` and the exported action is **{row.selected_action}**.\n",
            "An attack assigned Block increments both attack-blocked and attack-contained numerators. Rate-limit increments only attack-contained. Allow or Monitor increments neither. The attack denominator increments for every attack record. A benign record instead contributes to the benign denominators and, if restricted/blocked, the relevant benign numerators.\n"]
        count_rows=[]
        for action in ["Allow","Monitor","Rate-limit","Block"]:
            count_rows.append([action,int((pred.selected_action.eq(action)&pred.true_label.ne("BENIGN")).sum()),
                int((pred.selected_action.eq(action)&pred.true_label.eq("BENIGN")).sum())])
        report += ["Context seed 17 action counts, directly from its prediction export:\n",table(["Action","Attack flows","Benign flows"],count_rows),
            "Monitoring is excluded from the disruption metric. A zero disruption rate can therefore coexist with substantial observation/alert workload. Actual monitoring cost is not measured.\n"]
        test_labels=set(splits["test"]["labels"])
        absent=sorted(set(manifest["classes"])-test_labels)
        report.append("Training taxonomy classes with zero test support: "+(", ".join(absent) if absent else "none")+". Macro F1 averages over the declared training/test label union, with zero-division behavior explicitly set to zero. Do not infer rare-class effectiveness without test support.\n")
        over=summary.loc[summary.benign_disruption>.05,["model","seed","benign_disruption"]]
        report.append("Held-out runs exceeding the 5% policy-validation disruption target: "+(", ".join(f"{r.model} seed {r.seed}: {100*r.benign_disruption:.2f}%" for r in over.itertuples()) if len(over) else "none in these evaluated samples")+". This is not a guarantee for a new traffic mix.\n")
    combined=pd.concat(all_summary,ignore_index=True)
    combined.to_csv(ROOT/"results/combined_summary.csv",index=False)
    report += ["## Retained diagnostic failure\n",
        "The initial chronological runs in `results/pilot_temporal` produced approximately 92–93% classifier accuracy for the learned models but zero selected-policy attack containment. Several unrestricted calibrators learned a negative slope from a calibration period with very few attacks, reversing their raw attack ranking. The coarse grid also could not select cutoffs below 30 despite much smaller observed risk scores.\n",
        "The corrected implementation constrains calibration to be nondecreasing and generates cutoff candidates from policy-validation scores. These changes were made after inspecting the diagnostic outcomes. The corrected numbers are development follow-ups, not independent confirmation. Initial runs and their source snapshots remain available. No claim of a successful novel method follows from this correction alone.\n",
        "## What is implemented\n",
        "The local package includes data acquisition and audits; data preparation; 14 flow-derived and eight causal sampled-history features; training-only transformations; baseline/engineered/context DNNs; conventional comparators; checkpoint selection; monotonic calibration; validation-only threshold search; frozen evaluation; per-flow probabilities and decisions; numerator-preserving policy metrics; three seeds; uncertainty analyses; figures; independent export reconciliation; and offline scoring of new completed-flow batches.\n",
        "## What is still required for a journal claim\n",
        "A specific, literature-positioned original contribution; a fresh independent dataset or capture after this development work; stronger rare-class and source/session-grouped evidence; full-stream history and timing validation; and a complete manuscript reviewed by all authors under a named journal's requirements. Actual live-enforcement and packet-level mitigation experiments are additionally required if the paper claims deployed firewall effectiveness. They are not required merely to describe a carefully scoped offline simulation.\n",
        "An RNN, LSTM or quantum model is not a publication requirement. Add an architecture only to test a justified hypothesis with a fair comparison. Do not report the original deck's 172,628-flow CSE-CIC-IDS2018 figures as results of this different dataset and new implementation.\n",
        "## Evidence locations\n",
        "Each completed result directory contains `frozen_selection_manifest.json`, `source_snapshot/`, `split_manifest.csv.gz`, `training/`, `metrics/`, `summary.csv`, seed summaries, `paired_comparisons.json`, model artifacts, class-by-action CSVs, per-flow predictions, probability vectors, figures and `verification.json`. The software check record is in `docs/TEST_RESULTS.md`.\n",
        "Descriptive timing values were collected on a shared Windows desktop during concurrent runs. They exclude capture, flow assembly, context generation and enforcement, and are not controlled end-to-end throughput benchmarks.\n"]
    text="\n".join(report)
    (ROOT/"RESULTS_AND_NEXT_STEPS.md").write_text(text,encoding="utf-8")
    paper=["# Causal Flow Context and Budget-Constrained Risk Policies: An Offline Development Study on Corrected CICIDS2017\n",
        "**Working manuscript draft. Not ready for submission. Author list, affiliations and corresponding author require confirmation.**\n",
        "## Abstract\n",
        f"We implement an auditable offline flow-classification and simulated-policy pipeline using a pinned corrected CICIDS2017 archive containing {audit['raw_rows']:,} input records. We compare a 78-feature multilayer neural baseline, 14 flow-derived additions, eight earlier completed-flow context statistics, and conventional classifiers. Separate records support checkpoint tuning, binary calibration and threshold selection under a 5% benign-disruption validation target. Randomized multiclass and chronological binary development experiments use three seeds. Initial diagnostics expose calibration rank reversal and inadequate cutoff coverage. Follow-up experiments constrain calibration to be monotonic and derive cutoff candidates from validation scores. The measured results below do not establish universal benefit from context, cross-network transfer or live mitigation. Because test outcomes informed development changes, fresh independent confirmation remains necessary.\n",
        "## 1. Introduction and scope\n",
        "Traffic classification and firewall effectiveness are separate claims. This study evaluates completed-flow class predictions and simulated action assignments. A Block output does not prove packet prevention, and assigning Rate-limit does not measure attack suppression. We examine whether causal source context improves a controlled classifier and whether a validation-constrained policy behaves consistently under chronological shift. The contribution at this stage is a transparent implementation and development analysis, rather than an established new learning algorithm or deployment result.\n",
        "## 2. Related work\n",
        "The original CICIDS2017 release [1] is widely used, but corrected extraction and labeling work [2,3] motivates explicit version and label provenance. Online traffic-context processing already appears in systems such as Kitsune [4]. Cross-dataset generalization studies [5] and recent contextual-flow reviews [6] emphasize that strong in-capture classification need not establish operational generalization. This working draft does not claim novelty over those methods. A full current related-work comparison and an independently supported contribution remain prerequisites for submission.\n",
        "## 3. Methods\n",
        "The archive is streamed, numeric infinities become missing values, malformed rows are excluded, attempted labels map to BENIGN, and exact float32 feature-vector duplicates and conflicting signatures are excluded. Randomized splits use feature-signature hashes, class-capped training and uniform cleaned-population evaluation samples. A separate uniform sample supports a chronological binary protocol. Neither protocol is an independent network. Full formulas, sampling rules and time boundaries are in `docs/METHODS.md`, `docs/FEATURES.md` and the saved split manifests.\n",
        "DNNs use ReLU layers of 64 and 32 units, Adam, learning rate 0.001, batch size 256, L2 coefficient 0.0001, a maximum of 25 epochs and external tuning-loss checkpoint selection. Seeds are 17,42,99. A 100-tree random forest, logistic regression and a prior-only classifier provide conventional references. Training-only medians, rate caps and standardization preserve split separation. Context uses strictly earlier completed flows in a uniform sampled observation stream and excludes tied/current flows.\n",
        "Raw attack probability equals one minus the BENIGN output probability. A dedicated monotonic binary logistic map estimates calibrated risk probabilities. Risk equals 100 times that estimate. Rate-limit and Block cutoffs search policy-validation quantiles under a benign-disruption point-estimate constraint. Monitor is a deterministic observation threshold and is not optimized for operational overhead. All artifacts freeze before test scoring within a run.\n",
        "Attack blocking counts attack Block/A. Containment counts attack (Rate-limit+Block)/A. Benign false-blocking counts benign Block/B. Disruption counts benign (Rate-limit+Block)/B. Monitor enters neither restriction numerator. These are action-assignment proxies. Classifier macro metrics use the declared label union and report support. Exact per-flow binomial intervals and paired row/capture bootstrap comparisons include their dependence limitations.\n",
        "## 4. Results\n"]
    for title,tab in study_tables:
        paper += ["### "+title+"\n",tab]
    paper += ["Tables show mean ± sample SD across three seeds. Detailed per-class support, raw/calibrated Brier scores, probability vectors, action counts and paired intervals are in `RESULTS_AND_NEXT_STEPS.md` and the result artifacts. These are exploratory follow-ups after diagnosis of the initial runs, not a fresh untouched test.\n",
        "## 5. Discussion and limitations\n",
        "A neural classifier's class accuracy is insufficient to validate its calibrated risk policy. A nonrepresentative calibration period can compress or distort scores; monotonicity prevents reversal but does not guarantee calibration under prevalence shift. A validation constraint is not a held-out or deployment guarantee. Context may help some outcomes and harm others, and conventional baselines must remain in the comparison. Zero-support rare classes and a single capture source in part of the temporal test limit inference. Full-flow timing, sampled history, deduplication-induced population change and port-based shortcuts constrain operational interpretation.\n",
        "## 6. Required confirmation before submission\n",
        "State a novel, falsifiable contribution against closely related current methods. Confirm it on a fresh independently collected network with compatible schemas and causal timing; add full-stream history and source/session-grouped evaluations; justify tuning budgets and uncertainty; and validate any claimed live enforcement in an isolated authorized testbed. Use the selected journal's current formatting and author requirements. No acceptance claim is made.\n",
        "## 7. Reproducibility and data/code availability\n",
        "The local research package includes exact dependencies, source snapshots, archive hash, command-line entry points, tests, manifests, model artifacts, predictions, numeric result tables and generated figures. The project repository is https://github.com/gokulruthrapathy/context-aware-adaptive-firewall. No DOI has been issued. Raw data remain under their creators' terms. The authors must choose a code license and public archive before making a formal availability statement.\n",
        "## Acknowledgment and AI-content disclosure draft\n",
        "OpenAI Codex assisted with implementation, tests, experiment orchestration, analysis and initial manuscript drafting. The human author team must independently verify the work, identify the final AI-assisted sections and approve the manuscript. This draft does not assert that such author verification has already occurred. Consult the selected IEEE journal's current disclosure policy [7].\n",
        "## References\n",
        "[1] I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, ‘Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization,’ ICISSP, 2018. https://doi.org/10.5220/0006639801080116\n",
        "[2] G. Engelen, V. Rimmer, and W. Joosen, ‘Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study,’ IEEE SPW, 2021. https://doi.org/10.1109/SPW53761.2021.00009\n",
        "[3] L. Liu, G. Engelen, T. Lynar, D. Essam, and W. Joosen, ‘Error Prevalence in NIDS datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018,’ IEEE CNS, 2022. https://intrusion-detection.distrinet-research.be/CNS2022/index.html\n",
        "[4] Y. Mirsky, T. Doitshman, Y. Elovici, and A. Shabtai, ‘Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection,’ NDSS, 2018. https://cris.bgu.ac.il/en/publications/kitsune-an-ensemble-of-autoencoders-for-online-network-intrusion-/\n",
        "[5] M. Cantone, C. Marrocco, and A. Bria, ‘On the Cross-Dataset Generalization of Machine Learning for Network Intrusion Detection,’ arXiv:2402.10974, 2024 preprint. https://arxiv.org/abs/2402.10974\n",
        "[6] A. El Mahdaouy, I. Ait Yahia, S. Oualil, and I. Berrada, ‘Deep Learning for Contextualized NetFlow-Based Network Intrusion Detection: Methods, Data, Evaluation and Deployment,’ arXiv:2602.05594, 2026 preprint. https://arxiv.org/abs/2602.05594\n",
        "[7] IEEE Author Center, ‘Submission and Peer Review Policies,’ accessed 12 November 2026. https://journals.ieeeauthorcenter.ieee.org/become-an-ieee-journal-author/publishing-ethics/guidelines-and-policies/submission-and-peer-review-policies/\n"]
    (ROOT/"paper").mkdir(exist_ok=True)
    (ROOT/"paper/manuscript.md").write_text("\n".join(paper),encoding="utf-8")
    print("Generated results report and evidence-limited manuscript draft")


if __name__=="__main__":
    main()
