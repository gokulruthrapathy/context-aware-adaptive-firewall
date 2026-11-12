# Causal Flow Context and Budget-Constrained Risk Policies: An Offline Development Study on Corrected CICIDS2017

**Historical version 0.1 draft; see docs/V2_WORKFLOW.md for subsequent development.**

**Working manuscript draft. Not ready for submission. Author list, affiliations and corresponding author require confirmation.**

## Abstract

We implement an auditable offline flow-classification and simulated-policy pipeline using a pinned corrected CICIDS2017 archive containing 2,100,814 input records. We compare a 78-feature multilayer neural baseline, 14 flow-derived additions, eight earlier completed-flow context statistics, and conventional classifiers. Separate records support checkpoint tuning, binary calibration and threshold selection under a 5% benign-disruption validation target. Randomized multiclass and chronological binary development experiments use three seeds. Initial diagnostics expose calibration rank reversal and inadequate cutoff coverage. Follow-up experiments constrain calibration to be monotonic and derive cutoff candidates from validation scores. The measured results below do not establish universal benefit from context, cross-network transfer or live mitigation. Because test outcomes informed development changes, fresh independent confirmation remains necessary.

## 1. Introduction and scope

Traffic classification and firewall effectiveness are separate claims. This study evaluates completed-flow class predictions and simulated action assignments. A Block output does not prove packet prevention, and assigning Rate-limit does not measure attack suppression. We examine whether causal source context improves a controlled classifier and whether a validation-constrained policy behaves consistently under chronological shift. The contribution at this stage is a transparent implementation and development analysis, rather than an established new learning algorithm or deployment result.

## 2. Related work

The original CICIDS2017 release [1] is widely used, but corrected extraction and labeling work [2,3] motivates explicit version and label provenance. Online traffic-context processing already appears in systems such as Kitsune [4]. Cross-dataset generalization studies [5] and recent contextual-flow reviews [6] emphasize that strong in-capture classification need not establish operational generalization. This working draft does not claim novelty over those methods. A full current related-work comparison and an independently supported contribution remain prerequisites for submission.

## 3. Methods

The archive is streamed, numeric infinities become missing values, malformed rows are excluded, attempted labels map to BENIGN, and exact float32 feature-vector duplicates and conflicting signatures are excluded. Randomized splits use feature-signature hashes, class-capped training and uniform cleaned-population evaluation samples. A separate uniform sample supports a chronological binary protocol. Neither protocol is an independent network. Full formulas, sampling rules and time boundaries are in `docs/METHODS.md`, `docs/FEATURES.md` and the saved split manifests.

DNNs use ReLU layers of 64 and 32 units, Adam, learning rate 0.001, batch size 256, L2 coefficient 0.0001, a maximum of 25 epochs and external tuning-loss checkpoint selection. Seeds are 17,42,99. A 100-tree random forest, logistic regression and a prior-only classifier provide conventional references. Training-only medians, rate caps and standardization preserve split separation. Context uses strictly earlier completed flows in a uniform sampled observation stream and excludes tied/current flows.

Raw attack probability equals one minus the BENIGN output probability. A dedicated monotonic binary logistic map estimates calibrated risk probabilities. Risk equals 100 times that estimate. Rate-limit and Block cutoffs search policy-validation quantiles under a benign-disruption point-estimate constraint. Monitor is a deterministic observation threshold and is not optimized for operational overhead. All artifacts freeze before test scoring within a run.

Attack blocking counts attack Block/A. Containment counts attack (Rate-limit+Block)/A. Benign false-blocking counts benign Block/B. Disruption counts benign (Rate-limit+Block)/B. Monitor enters neither restriction numerator. These are action-assignment proxies. Classifier macro metrics use the declared label union and report support. Exact per-flow binomial intervals and paired row/capture bootstrap comparisons include their dependence limitations.

## 4. Results

### Randomized multiclass

| Model | Accuracy % | Macro F1 | Attack block % | Containment proxy % | Benign block % | Benign disruption % |
|---|---|---|---|---|---|---|
| baseline_dnn | 99.12 ± 0.15 | 0.64 ± 0.03 | 99.88 ± 0.10 | 100.00 ± 0.00 | 0.64 ± 0.11 | 4.88 ± 0.23 |
| engineered_dnn | 99.17 ± 0.07 | 0.64 ± 0.02 | 99.88 ± 0.07 | 100.00 ± 0.00 | 0.61 ± 0.03 | 4.34 ± 0.21 |
| context_dnn | 99.23 ± 0.12 | 0.63 ± 0.02 | 99.82 ± 0.18 | 100.00 ± 0.00 | 0.47 ± 0.17 | 4.73 ± 0.15 |
| random_forest | 99.57 ± 0.01 | 0.73 ± 0.00 | 99.96 ± 0.07 | 100.00 ± 0.00 | 0.59 ± 0.18 | 4.12 ± 0.05 |
| logistic | 97.22 ± 0.00 | 0.53 ± 0.00 | 99.82 ± 0.00 | 99.97 ± 0.00 | 1.79 ± 0.00 | 4.70 ± 0.00 |
| dummy | 80.50 ± 0.00 | 0.06 ± 0.00 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.00 ± 0.00 |

### Chronological binary

| Model | Accuracy % | Macro F1 | Attack block % | Containment proxy % | Benign block % | Benign disruption % |
|---|---|---|---|---|---|---|
| baseline_dnn | 92.65 ± 0.28 | 0.93 ± 0.00 | 91.64 ± 0.24 | 92.51 ± 0.53 | 2.17 ± 1.38 | 4.05 ± 1.47 |
| engineered_dnn | 92.48 ± 0.00 | 0.92 ± 0.00 | 89.25 ± 1.86 | 89.98 ± 2.40 | 2.83 ± 0.13 | 4.68 ± 0.45 |
| context_dnn | 92.50 ± 0.01 | 0.92 ± 0.00 | 58.28 ± 50.47 | 87.38 ± 0.06 | 0.00 ± 0.00 | 0.00 ± 0.00 |
| random_forest | 92.43 ± 0.02 | 0.92 ± 0.00 | 99.77 ± 0.19 | 99.98 ± 0.01 | 1.07 ± 0.86 | 3.23 ± 0.61 |
| logistic | 92.25 ± 0.00 | 0.92 ± 0.00 | 88.25 ± 0.00 | 88.84 ± 0.00 | 1.31 ± 0.00 | 4.61 ± 0.00 |
| dummy | 39.43 ± 0.00 | 0.28 ± 0.00 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.00 ± 0.00 |

Tables show mean ± sample SD across three seeds. Detailed per-class support, raw/calibrated Brier scores, probability vectors, action counts and paired intervals are in `RESULTS_AND_NEXT_STEPS.md` and the result artifacts. These are exploratory follow-ups after diagnosis of the initial runs, not a fresh untouched test.

## 5. Discussion and limitations

A neural classifier's class accuracy is insufficient to validate its calibrated risk policy. A nonrepresentative calibration period can compress or distort scores; monotonicity prevents reversal but does not guarantee calibration under prevalence shift. A validation constraint is not a held-out or deployment guarantee. Context may help some outcomes and harm others, and conventional baselines must remain in the comparison. Zero-support rare classes and a single capture source in part of the temporal test limit inference. Full-flow timing, sampled history, deduplication-induced population change and port-based shortcuts constrain operational interpretation.

## 6. Required confirmation before submission

State a novel, falsifiable contribution against closely related current methods. Confirm it on a fresh independently collected network with compatible schemas and causal timing; add full-stream history and source/session-grouped evaluations; justify tuning budgets and uncertainty; and validate any claimed live enforcement in an isolated authorized testbed. Use the selected journal's current formatting and author requirements. No acceptance claim is made.

## 7. Reproducibility and data/code availability

The local research package includes exact dependencies, source snapshots, archive hash, command-line entry points, tests, manifests, model artifacts, predictions, numeric result tables and generated figures. The project repository is https://github.com/gokulruthrapathy/context-aware-adaptive-firewall. No DOI has been issued. Raw data remain under their creators' terms. The authors must choose a code license and public archive before making a formal availability statement.

## Acknowledgment and AI-content disclosure draft

OpenAI Codex assisted with implementation, tests, experiment orchestration, analysis and initial manuscript drafting. The human author team must independently verify the work, identify the final AI-assisted sections and approve the manuscript. This draft does not assert that such author verification has already occurred. Consult the selected IEEE journal's current disclosure policy [7].

## References

[1] I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, ‘Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization,’ ICISSP, 2018. https://doi.org/10.5220/0006639801080116

[2] G. Engelen, V. Rimmer, and W. Joosen, ‘Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study,’ IEEE SPW, 2021. https://doi.org/10.1109/SPW53761.2021.00009

[3] L. Liu, G. Engelen, T. Lynar, D. Essam, and W. Joosen, ‘Error Prevalence in NIDS datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018,’ IEEE CNS, 2022. https://intrusion-detection.distrinet-research.be/CNS2022/index.html

[4] Y. Mirsky, T. Doitshman, Y. Elovici, and A. Shabtai, ‘Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection,’ NDSS, 2018. https://cris.bgu.ac.il/en/publications/kitsune-an-ensemble-of-autoencoders-for-online-network-intrusion-/

[5] M. Cantone, C. Marrocco, and A. Bria, ‘On the Cross-Dataset Generalization of Machine Learning for Network Intrusion Detection,’ IEEE Access 12:144489-144508, 2024; DOI 10.1109/ACCESS.2024.3472907. https://arxiv.org/abs/2402.10974

[6] A. El Mahdaouy, I. Ait Yahia, S. Oualil, and I. Berrada, ‘Deep Learning for Contextualized NetFlow-Based Network Intrusion Detection: Methods, Data, Evaluation and Deployment,’ arXiv:2602.05594, 2026 preprint. https://arxiv.org/abs/2602.05594

[7] IEEE Author Center, ‘Submission and Peer Review Policies,’ accessed 12 November 2026. https://journals.ieeeauthorcenter.ieee.org/become-an-ieee-journal-author/publishing-ethics/guidelines-and-policies/submission-and-peer-review-policies/
