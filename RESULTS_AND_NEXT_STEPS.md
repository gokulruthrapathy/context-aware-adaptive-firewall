# Executed results and journal-readiness assessment

Prepared 12 November 2026. These are real public-data CPU experiments from a new implementation. They are not recovered results from the missing Team CSEUG49 code.

**Status: completed exploratory development studies, not a submission-ready journal validation.** The corrected runs followed inspection of the diagnostic test outcomes. Their test partitions were held out from fitting within each run but reused during development. Fresh independent confirmation remains necessary.

## Data audit

| Audit item | Observed count |
|---|---|
| raw_rows | 2100814 |
| invalid_rows | 31 |
| duplicate_feature_rows | 264812 |
| conflicting_feature_signatures | 4338 |
| unique_rows_after_conflict_exclusion | 1831633 |

The pinned source is Engelen et al.'s corrected CICIDS2017 WTMC2021 archive. Attempted attack labels map to BENIGN. Exact feature-vector deduplication at float32 precision and conflicting-label exclusion change the original population. Uniform evaluation sampling therefore refers to the cleaned, deduplicated population. Training is class-capped.

## Randomized multiclass

| Partition | Rows | Benign | Attack |
|---|---|---|---|
| train | 27658 | 4000 | 23658 |
| tune | 4993 | 4023 | 970 |
| calibration | 4990 | 3938 | 1052 |
| policy | 4986 | 4010 | 976 |
| test | 19948 | 16059 | 3889 |

| Model | Accuracy % | Macro F1 | Attack block % | Containment proxy % | Benign block % | Benign disruption % |
|---|---|---|---|---|---|---|
| baseline_dnn | 99.12 ± 0.15 | 0.64 ± 0.03 | 99.88 ± 0.10 | 100.00 ± 0.00 | 0.64 ± 0.11 | 4.88 ± 0.23 |
| engineered_dnn | 99.17 ± 0.07 | 0.64 ± 0.02 | 99.88 ± 0.07 | 100.00 ± 0.00 | 0.61 ± 0.03 | 4.34 ± 0.21 |
| context_dnn | 99.23 ± 0.12 | 0.63 ± 0.02 | 99.82 ± 0.18 | 100.00 ± 0.00 | 0.47 ± 0.17 | 4.73 ± 0.15 |
| random_forest | 99.57 ± 0.01 | 0.73 ± 0.00 | 99.96 ± 0.07 | 100.00 ± 0.00 | 0.59 ± 0.18 | 4.12 ± 0.05 |
| logistic | 97.22 ± 0.00 | 0.53 ± 0.00 | 99.82 ± 0.00 | 99.97 ± 0.00 | 1.79 ± 0.00 | 4.70 ± 0.00 |
| dummy | 80.50 ± 0.00 | 0.06 ± 0.00 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.00 ± 0.00 |

Values are mean ± sample SD across seeds 17, 42 and 99. They are not confidence intervals across independent datasets.

Context-minus-baseline mean macro F1: **-0.0142**. This is an observed comparison, not a claim that context is universally better.

The conventional random-forest comparator has mean macro F1 **0.7263** in this protocol. Its inclusion prevents interpreting a DNN-only comparison as evidence of state-of-the-art performance.

Monotonic calibration reached its lower slope bound in 0 of 18 runs. Boundary fits: none. No lower-bound solutions occurred here; that alone does not guarantee calibration on another traffic mix.

| Model | Raw binary Brier | Calibrated binary Brier | Calibrated AUROC |
|---|---|---|---|
| baseline_dnn | 0.00822 | 0.00344 | 0.99980 |
| context_dnn | 0.00646 | 0.00197 | 0.99989 |
| random_forest | 0.00510 | 0.00257 | 0.99985 |

Lower Brier is better. Calibration can worsen after temporal/prevalence shift even when monotonicity preserves ordering.

| Comparison | Model seed | Resampling unit | Delta F1 | 95% paired interval |
|---|---|---|---|---|
| engineered_dnn minus baseline | 17 | flow | -0.0147 | [-0.0311, +0.0001] |
| engineered_dnn minus baseline | 17 | capture file | -0.0147 | [-0.0285, +0.0049] |
| context_dnn minus baseline | 17 | flow | -0.0205 | [-0.0475, -0.0012] |
| context_dnn minus baseline | 17 | capture file | -0.0205 | [-0.0390, +0.0027] |
| engineered_dnn minus baseline | 42 | flow | -0.0038 | [-0.0288, +0.0166] |
| engineered_dnn minus baseline | 42 | capture file | -0.0038 | [-0.0217, +0.0380] |
| context_dnn minus baseline | 42 | flow | -0.0200 | [-0.0426, -0.0012] |
| context_dnn minus baseline | 42 | capture file | -0.0200 | [-0.0282, +0.0040] |
| engineered_dnn minus baseline | 99 | flow | +0.0031 | [-0.0147, +0.0189] |
| engineered_dnn minus baseline | 99 | capture file | +0.0031 | [-0.0089, +0.0155] |
| context_dnn minus baseline | 99 | flow | -0.0021 | [-0.0226, +0.0201] |
| context_dnn minus baseline | 99 | capture file | -0.0021 | [-0.0183, +0.0194] |

Row intervals assume exchangeable flows. Capture-cluster intervals have at most five groups. An interval is deliberately omitted when only one capture file appears in the test period.

### One real flow through the saved decision path

The first attack-labeled record in the completion-sorted context-model test export has row ID `1320100705183924090`. Its true label is `FTP-Patator` and predicted class is `FTP-Patator`. The true label is used only for evaluation.

The saved class probability vector gives raw attack probability **0.99990474**. The separately fitted monotonic mapping produces **0.99791048**, so risk is **99.79104825** on the 0–100 scale. Selected cutoffs are `{'monitor': 0.035695954377401744, 'rate_limit': 0.07139190875480349, 'block': 5.690699500566013}` and the exported action is **Block**.

An attack assigned Block increments both attack-blocked and attack-contained numerators. Rate-limit increments only attack-contained. Allow or Monitor increments neither. The attack denominator increments for every attack record. A benign record instead contributes to the benign denominators and, if restricted/blocked, the relevant benign numerators.

Context seed 17 action counts, directly from its prediction export:

| Action | Attack flows | Benign flows |
|---|---|---|
| Allow | 0 | 15021 |
| Monitor | 0 | 282 |
| Rate-limit | 4 | 663 |
| Block | 3885 | 93 |

Monitoring is excluded from the disruption metric. A zero disruption rate can therefore coexist with substantial observation/alert workload. Actual monitoring cost is not measured.

Training taxonomy classes with zero test support: Heartbleed, Infiltration, Web Attack - Sql Injection, Web Attack - XSS. Macro F1 averages over the declared training/test label union, with zero-division behavior explicitly set to zero. Do not infer rare-class effectiveness without test support.

Held-out runs exceeding the 5% policy-validation disruption target: baseline_dnn seed 42: 5.12%. This is not a guarantee for a new traffic mix.

## Chronological binary

| Partition | Rows | Benign | Attack |
|---|---|---|---|
| train | 41906 | 35163 | 6743 |
| tune | 6984 | 6978 | 6 |
| calibration | 6984 | 6956 | 28 |
| policy | 6984 | 4305 | 2679 |
| test | 6985 | 2754 | 4231 |

| Model | Accuracy % | Macro F1 | Attack block % | Containment proxy % | Benign block % | Benign disruption % |
|---|---|---|---|---|---|---|
| baseline_dnn | 92.65 ± 0.28 | 0.93 ± 0.00 | 91.64 ± 0.24 | 92.51 ± 0.53 | 2.17 ± 1.38 | 4.05 ± 1.47 |
| engineered_dnn | 92.48 ± 0.00 | 0.92 ± 0.00 | 89.25 ± 1.86 | 89.98 ± 2.40 | 2.83 ± 0.13 | 4.68 ± 0.45 |
| context_dnn | 92.50 ± 0.01 | 0.92 ± 0.00 | 58.28 ± 50.47 | 87.38 ± 0.06 | 0.00 ± 0.00 | 0.00 ± 0.00 |
| random_forest | 92.43 ± 0.02 | 0.92 ± 0.00 | 99.77 ± 0.19 | 99.98 ± 0.01 | 1.07 ± 0.86 | 3.23 ± 0.61 |
| logistic | 92.25 ± 0.00 | 0.92 ± 0.00 | 88.25 ± 0.00 | 88.84 ± 0.00 | 1.31 ± 0.00 | 4.61 ± 0.00 |
| dummy | 39.43 ± 0.00 | 0.28 ± 0.00 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.00 ± 0.00 | 0.00 ± 0.00 |

Values are mean ± sample SD across seeds 17, 42 and 99. They are not confidence intervals across independent datasets.

Context-minus-baseline mean macro F1: **-0.0015**. This is an observed comparison, not a claim that context is universally better.

The conventional random-forest comparator has mean macro F1 **0.9229** in this protocol. Its inclusion prevents interpreting a DNN-only comparison as evidence of state-of-the-art performance.

Monotonic calibration reached its lower slope bound in 13 of 18 runs. Boundary fits: baseline_dnn_seed17, baseline_dnn_seed42, baseline_dnn_seed99, context_dnn_seed17, context_dnn_seed99, engineered_dnn_seed17, engineered_dnn_seed42, engineered_dnn_seed99, logistic_seed17, logistic_seed42, logistic_seed99, random_forest_seed42, random_forest_seed99. Boundary solutions signal weak calibration information, not a successful probability-quality guarantee.

| Model | Raw binary Brier | Calibrated binary Brier | Calibrated AUROC |
|---|---|---|---|
| baseline_dnn | 0.07082 | 0.60087 | 0.95620 |
| context_dnn | 0.07501 | 0.46560 | 0.88226 |
| random_forest | 0.07247 | 0.59491 | 0.99932 |

Lower Brier is better. Calibration can worsen after temporal/prevalence shift even when monotonicity preserves ordering.

| Comparison | Model seed | Resampling unit | Delta F1 | 95% paired interval |
|---|---|---|---|---|
| engineered_dnn minus baseline | 17 | flow | -0.0049 | [-0.0064, -0.0032] |
| engineered_dnn minus baseline | 17 | capture file | -0.0049 | not estimable |
| context_dnn minus baseline | 17 | flow | -0.0046 | [-0.0062, -0.0029] |
| context_dnn minus baseline | 17 | capture file | -0.0046 | not estimable |
| engineered_dnn minus baseline | 42 | flow | +0.0000 | [+0.0000, +0.0000] |
| engineered_dnn minus baseline | 42 | capture file | +0.0000 | not estimable |
| context_dnn minus baseline | 42 | flow | +0.0001 | [-0.0004, +0.0007] |
| context_dnn minus baseline | 42 | capture file | +0.0001 | not estimable |
| engineered_dnn minus baseline | 99 | flow | +0.0000 | [+0.0000, +0.0000] |
| engineered_dnn minus baseline | 99 | capture file | +0.0000 | not estimable |
| context_dnn minus baseline | 99 | flow | +0.0000 | [-0.0007, +0.0007] |
| context_dnn minus baseline | 99 | capture file | +0.0000 | not estimable |

Row intervals assume exchangeable flows. Capture-cluster intervals have at most five groups. An interval is deliberately omitted when only one capture file appears in the test period.

### One real flow through the saved decision path

The first attack-labeled record in the completion-sorted context-model test export has row ID `428831923332548287`. Its true label is `ATTACK` and predicted class is `BENIGN`. The true label is used only for evaluation.

The saved class probability vector gives raw attack probability **0.00000000**. The separately fitted monotonic mapping produces **0.00400819**, so risk is **0.40081857** on the 0–100 scale. Selected cutoffs are `{'monitor': 0.20078989505987027, 'rate_limit': 0.40157979011974054, 'block': 25.0}` and the exported action is **Monitor**.

An attack assigned Block increments both attack-blocked and attack-contained numerators. Rate-limit increments only attack-contained. Allow or Monitor increments neither. The attack denominator increments for every attack record. A benign record instead contributes to the benign denominators and, if restricted/blocked, the relevant benign numerators.

Context seed 17 action counts, directly from its prediction export:

| Action | Attack flows | Benign flows |
|---|---|---|
| Allow | 0 | 0 |
| Monitor | 537 | 2754 |
| Rate-limit | 3694 | 0 |
| Block | 0 | 0 |

Monitoring is excluded from the disruption metric. A zero disruption rate can therefore coexist with substantial observation/alert workload. Actual monitoring cost is not measured.

Training taxonomy classes with zero test support: none. Macro F1 averages over the declared training/test label union, with zero-division behavior explicitly set to zero. Do not infer rare-class effectiveness without test support.

Held-out runs exceeding the 5% policy-validation disruption target: baseline_dnn seed 42: 5.05%, engineered_dnn seed 42: 5.12%. This is not a guarantee for a new traffic mix.

## Retained diagnostic failure

The initial chronological runs in `results/pilot_temporal` produced approximately 92–93% classifier accuracy for the learned models but zero selected-policy attack containment. Several unrestricted calibrators learned a negative slope from a calibration period with very few attacks, reversing their raw attack ranking. The coarse grid also could not select cutoffs below 30 despite much smaller observed risk scores.

The corrected implementation constrains calibration to be nondecreasing and generates cutoff candidates from policy-validation scores. These changes were made after inspecting the diagnostic outcomes. The corrected numbers are development follow-ups, not independent confirmation. Initial runs and their source snapshots remain available. No claim of a successful novel method follows from this correction alone.

## What is implemented

The local package includes data acquisition and audits; data preparation; 14 flow-derived and eight causal sampled-history features; training-only transformations; baseline/engineered/context DNNs; conventional comparators; checkpoint selection; monotonic calibration; validation-only threshold search; frozen evaluation; per-flow probabilities and decisions; numerator-preserving policy metrics; three seeds; uncertainty analyses; figures; independent export reconciliation; and offline scoring of new completed-flow batches.

## What is still required for a journal claim

A specific, literature-positioned original contribution; a fresh independent dataset or capture after this development work; stronger rare-class and source/session-grouped evidence; full-stream history and timing validation; and a complete manuscript reviewed by all authors under a named journal's requirements. Actual live-enforcement and packet-level mitigation experiments are additionally required if the paper claims deployed firewall effectiveness. They are not required merely to describe a carefully scoped offline simulation.

An RNN, LSTM or quantum model is not a publication requirement. Add an architecture only to test a justified hypothesis with a fair comparison. Do not report the original deck's 172,628-flow CSE-CIC-IDS2018 figures as results of this different dataset and new implementation.

## Evidence locations

Each completed result directory contains `frozen_selection_manifest.json`, `source_snapshot/`, `split_manifest.csv.gz`, `training/`, `metrics/`, `summary.csv`, seed summaries, `paired_comparisons.json`, model artifacts, class-by-action CSVs, per-flow predictions, probability vectors, figures and `verification.json`. The software check record is in `docs/TEST_RESULTS.md`.

Descriptive timing values were collected on a shared Windows desktop during concurrent runs. They exclude capture, flow assembly, context generation and enforcement, and are not controlled end-to-end throughput benchmarks.
