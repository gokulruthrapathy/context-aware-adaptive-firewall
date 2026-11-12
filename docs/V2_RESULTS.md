# Version 0.2 CPU execution results

**Completed development reruns, not independent-network confirmation.**

Implementation commit: `4fcccb93f814dc8b6bc9f6fd38b1be9c8dd1578c`.
Run: `research_v2_20261112T052723Z_6ce995`.

All 10 notebook code cells executed successfully in Python 3.12.14 on the local Windows i7-12650H CPU (16 logical processors, 16 GB RAM; training limited to two threads). This was local execution of the notebook cells, not execution inside hosted Colab.

The notebook software check passed **35 tests in 11.61 seconds**. Both studies completed 18 model/seed bundles each, with plots, verification and evidence manifests. The original four studies remain intact and also passed the stronger current verifier. A 256-record demonstration preserved actions across a saved/restored history state.

The two study runs took approximately 3 minutes 14 seconds combined, including training, evaluation, plots and verification; data preparation, notebook setup, additional checks and ZIP export are excluded. These are shared-desktop elapsed times, not throughput benchmarks.

## Primary validation objective: maximize containment under 5% benign disruption

| Protocol | Model | Accuracy % | Macro F1 | Attack block % | Containment proxy % | Benign block % | Benign disruption % | Monitor % of all flows |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| random | baseline_dnn | 99.12 | 0.6412 | 99.88 | 100.00 | 0.64 | 4.88 | 1.56 |
| random | context_dnn | 99.23 | 0.6255 | 99.77 | 100.00 | 0.38 | 4.75 | 1.40 |
| random | dummy | 80.50 | 0.0595 | 0.00 | 0.00 | 0.00 | 0.00 | 100.00 |
| random | engineered_dnn | 99.17 | 0.6361 | 99.88 | 100.00 | 0.61 | 4.34 | 1.52 |
| random | logistic | 97.22 | 0.5325 | 99.82 | 99.97 | 1.79 | 4.70 | 3.57 |
| random | random_forest | 99.57 | 0.7263 | 99.96 | 100.00 | 0.59 | 4.12 | 2.76 |
| temporal | baseline_dnn | 92.65 | 0.9250 | 91.64 | 92.51 | 2.17 | 4.05 | 1.38 |
| temporal | context_dnn | 92.50 | 0.9236 | 87.55 | 87.62 | 0.00 | 0.07 | 0.06 |
| temporal | dummy | 39.43 | 0.2828 | 0.00 | 0.00 | 0.00 | 0.00 | 100.00 |
| temporal | engineered_dnn | 92.48 | 0.9234 | 89.25 | 89.98 | 2.83 | 4.68 | 1.52 |
| temporal | logistic | 92.25 | 0.9210 | 88.25 | 88.84 | 1.31 | 4.61 | 1.36 |
| temporal | random_forest | 92.43 | 0.9229 | 99.77 | 99.98 | 1.07 | 3.22 | 0.66 |

Values are means across seeds 17, 42 and 99 on the same protocol test rows. They are not independent-network replications. Random testing uses 19,948 records (3,889 attack / 16,059 benign); chronological testing uses 6,985 (4,231 attack / 2,754 benign). Macro F1 preserves the original 15-class random taxonomy, including four zero-support classes; supported-class and weighted diagnostics are separately exported.

## Alternative objective: minimize disruption with a 95% validation containment target

The same frozen models also have prespecified raw-score policies selected solely from policy-validation candidates. These policies minimize benign disruption, require at least 95% validation containment and retain the 5% validation disruption cap. A validation target does not enforce identical test containment between methods.

| Protocol | Model | Mean test containment proxy % | Mean test benign disruption % |
|---|---|---:|---:|
| random | baseline_dnn | 99.84 | 0.60 |
| random | context_dnn | 99.85 | 0.52 |
| random | engineered_dnn | 99.96 | 0.74 |
| random | logistic | 97.25 | 1.09 |
| random | random_forest | 99.91 | 0.39 |
| temporal | random_forest | 99.77 | 1.07 |

Only random forest met the chronological 95% validation target in all three seeds. The chronological DNNs, logistic regression and dummy were explicitly infeasible; no target policy was silently relaxed or chosen using test labels. Random-study dummy target policies were also infeasible.

For chronological random forest, the primary objective gives 99.98% test containment / 3.22% benign disruption. The 95%-validation-target alternative gives 99.77% / 1.07%. This illustrates the cost of chasing the last fraction of containment in this sample; it is not a population guarantee or a comparison at exactly identical test containment.

## Calibration and history diagnostics

All 18 chronological models used the prespecified identity fallback because calibration contained only 28 attack records, below the minimum of 100 per binary class. Their used-score Brier equals raw-score Brier: approximately 0.07082 baseline DNN, 0.07500 context DNN and 0.07247 random forest. Identity avoids an unsupported calibration fit; it does not prove calibrated probability quality under shift. No random-study model required fallback.

Both history contracts recorded zero source evictions and zero event truncations. Context still does not consistently outperform baseline or random forest. Incremental floating-point history arithmetic and the new source revision can change context-model optimization; historical outputs were preserved rather than replaced.

Independent checks reproduced **180** feasible frozen policy assignments and their attack/benign numerators directly from saved CSV probabilities, with no discrepancies. The runner separately verifies classifier metrics, calibration maps, primary validation ranking, confidence limits and evidence hashes. These are consistency checks, not independent retraining.

## Evidence

- Full results: `results/research_v2_20261112T052723Z_6ce995/`.
- `random/` and `temporal/`: source snapshots, input/environment manifests, model bundles, validation candidates, split manifests, training records, probabilities, predictions, policy comparisons, metrics, figures, verification and final completion markers.
- `software_tests.txt` / `installed_packages.txt`: actual executed test log and environment.
- `independent_policy_check.json`: additional policy reconciliation.
- `notebooks/Adaptive_Firewall_Executed_Local.ipynb`: all locally executed cells and outputs.

## Remaining before stronger publication claims

Fresh compatible independent traffic; representative tuning/calibration/policy periods; source/session grouping and sufficient independent capture groups; controlled context/port/history-density ablations; policy-difference uncertainty and service-impact measurements. No online drift adaptation, production enforcement or journal readiness is claimed.
