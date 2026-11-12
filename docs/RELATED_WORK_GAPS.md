# Related work and novelty assessment

This is a focused primary-source starting point, not an exhaustive systematic review. Do not assert that a contribution is the first of its kind from this search alone. Preprints are identified explicitly. No reported metric below is used as a directly comparable baseline because the protocols and datasets differ.

| Primary work | Relevance | What this project still must establish |
|---|---|---|
| Engelen, Rimmer and Joosen, *Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study*, IEEE SPW 2021. https://doi.org/10.1109/SPW53761.2021.00009 | Documents dataset/flow-generation issues and supplies the corrected archive used here | Exact archive version, label handling, audit and limitations must be reported. Data cleaning is not a new learning algorithm. |
| Liu et al., *Error Prevalence in NIDS datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018*, IEEE CNS 2022. https://intrusion-detection.distrinet-research.be/CNS2022/index.html | Later analysis and correction of both commonly used benchmarks | Repeat critical findings on the later release or justify the pinned older archive. A popular benchmark is not automatically reliable. |
| Mirsky et al., *Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection*, NDSS 2018. Author institution record: https://cris.bgu.ac.il/en/publications/kitsune-an-ensemble-of-autoencoders-for-online-network-intrusion-/ | Established online anomaly detection supported by traffic-channel feature extraction | Adding source history to a neural classifier alone does not establish novelty. A fair online comparison needs compatible observations and training assumptions. |
| Cantone, Marrocco and Bria, *On the Cross-Dataset Generalization of Machine Learning for Network Intrusion Detection*, IEEE Access 12:144489-144508, 2024; DOI 10.1109/ACCESS.2024.3472907. https://arxiv.org/abs/2402.10974 | Studies transfer across several flow datasets and distinguishes in-dataset results from cross-network generalization | A randomized CICIDS2017 test and a chronological CICIDS2017 test do not establish cross-network transfer. Implement explicit common-schema adapters for independent transfer. |
| El Mahdaouy, Ait Yahia, Oualil and Berrada, *Deep Learning for Contextualized NetFlow-Based Network Intrusion Detection: Methods, Data, Evaluation and Deployment*, arXiv:2602.05594, 2026 preprint. https://arxiv.org/abs/2602.05594 | Surveys temporal/relational context and operational evaluation issues | The field already studies contextual flow detection. Position a specific method or evaluation insight against closely related systems and use causal evidence. |

## A testable direction

Candidate hypothesis: **under a prespecified benign-disruption budget, calibrated causal context improves held-out attack blocking compared with the same classifier and policy without history, and the improvement survives chronological and independent-network tests.**

The implemented package measures baseline, flow engineering and sampled history under a controlled DNN architecture, includes conventional baselines, and evaluates chronological shift. It does not yet demonstrate the independent-network part. A negative or unstable result must narrow the hypothesis rather than be hidden. An offline evaluation paper can be appropriate without live enforcement if its contribution, experiments and claims are substantial and accurately scoped. Live firewall integration is required only for claims about actual enforcement or deployed mitigation.

## Concrete experiments still needed for a strong claim

- A separate network/capture with timestamps and source identifiers for causal history, plus an explicitly shared feature schema. Do not zero-fill incompatible schemas silently.
- Full-stream versus sampled-stream history, with windows and state costs measured on the same observation process.
- Fair tuning budgets and closely related contextual methods, not only architecture names such as RNN/LSTM.
- Service-port/source-session shortcut ablations and additional independent temporal periods.
- Benign-budget stability across traffic mixtures and uncertainty-aware policy constraints.

The package is a transparent experimental foundation. The author team must choose a contribution supported by its results and complete the relevant experiments before claiming journal-level novelty or generalization.
