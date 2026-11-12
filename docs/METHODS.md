# Experimental methods and contracts

## Data preparation

The ZIP archive is streamed through pandas in 25,000-row chunks. No archive code is executed and no paths are extracted. SHA-256 must match the pinned release. Headers are stripped. Numeric fields parse with invalid values mapped to NaN, and infinite values become NaN. Rows with invalid timestamps, negative/missing duration, missing labels, repeated headers or fewer than half the numeric fields present are excluded. Remaining numeric missing values are imputed from training medians. Label `Attempted` variants map to BENIGN. Original and mapped label counts are saved.

Flow ID, source IP, source port, destination IP, timestamp and label are excluded from the 78 baseline predictors. Destination port and protocol remain, so shortcut learning from attack services remains a risk. `__ready_at = Timestamp + Flow Duration microseconds` defines completed-flow availability.

Deduplication uses a 64-bit pandas hash of the ordered numeric feature vector at the float32 precision saved for modeling, with labels and metadata excluded. A hash match is treated conservatively as a duplicate; a hash with conflicting labels is excluded entirely. Thus distinct real flows with identical feature vectors are collapsed. This deliberately changes the capture's distribution. Hash collisions are possible, although unlikely. The procedure does not prove removal of semantically similar sessions or near-duplicate traffic. Exact package versions are pinned because hashing and numeric parsing are part of the data contract.

For the randomized protocol, signature hash modulo 100 assigns 60% train and 10% each to tuning, calibration, policy and test partitions. Duplicate signatures cannot cross partitions. Priority sampling keeps at most 4,000 training rows per class, at most 5,000 each from tuning/calibration/policy, and 20,000 test rows. Natural-prevalence sampling here means uniform sampling **after** exact-feature deduplication and corruption filtering. It does not imply production prevalence. Selection does not inspect prediction quality. Very rare classes may have no test support.

An independent uniform priority reservoir of 70,000 deduplicated flows forms the temporal cohort. It is sorted by completion time and split contiguously at the 60th/70th/80th/90th percentiles, with equal timestamps assigned together. This is a distinct forward-time BENIGN/ATTACK experiment. Boundaries and all class counts are recorded. It is not an independent dataset and its particular periods may omit attacks from some partitions. Calibration/policy selection fail explicitly if either lacks benign or attack records.

## Features and transformations

All variants use the same row identities, labels and partition membership. Feature order is fixed and validated against the fitted schema. The baseline has 78 inputs; the engineered model adds 14 current-flow features; the history model adds eight context features, for 100 total inputs. No feature uses true attack labels or future model outcomes. For the randomized protocol, history updates come exclusively from the independent uniform temporal reservoir: additional class-capped training records are query-only and never update that observation stream. This prevents class-dependent training selection from manufacturing the reference history. For the temporal protocol, the uniform temporal cohort is itself the history stream.

Rate columns (names containing `/s` or `per_second`) are capped at the training 99.5th percentile, with a nonnegative lower bound. Medians and StandardScaler mean/variance fit on training only. All splits use those fitted values. Standardized values are clipped to [-20,20], a fixed transformation. All-empty training columns impute to zero. Transformations and column order are saved inside each local model artifact.

## Models

DNNs are scikit-learn MLPClassifier networks with two hidden layers of 64 and 32 ReLU units, Adam, learning rate 0.001, batch size 256 and L2 coefficient 0.0001. Binary output uses the library's logistic formulation and multiclass output its softmax formulation, trained with cross-entropy. Defaults for Adam parameters come from the pinned library. No dropout, RNN, LSTM, quantum circuit, SMOTE or online model update is claimed.

Each epoch calls `partial_fit` on training rows. The checkpoint with best external tuning cross-entropy is retained, with a maximum of 25 epochs and patience of five epochs. The minimum improvement is 0.0001. Unknown tuning classes are excluded from checkpoint loss and their count is logged. Training rows are class-capped, not class-weighted. Architecture is prespecified for a controlled pilot rather than exhaustively optimized.

Comparators: a 100-tree RandomForestClassifier (minimum leaf size 2, sqrt feature selection), LogisticRegression (C=1, maximum 500 iterations), and prior-only DummyClassifier. Three random seeds are prespecified: 17, 42 and 99. Deterministic or effectively deterministic baselines may repeat identical results, and these repeats are not independent data replications.

## Probabilities, calibration and risk

Class names are derived from the training taxonomy. Prediction columns follow the model's saved class order. `p_attack_raw = 1 - p_BENIGN`, summing all non-benign probability mass. Test labels absent from training remain explicit unknown classes in evaluation and have no output column. No ground-truth label enters the risk score.

On a separate calibration partition, monotonic binary logistic calibration maps the logit of the clipped raw attack probability to an estimated calibrated attack probability. Clipping is [0.000001,0.999999]. A two-parameter logistic fit uses L-BFGS-B, slope bounds [0.0001,100], intercept bounds [-50,50], mean binary log loss and slope penalty a²/(2N). Positive slope preserves risk ranking. A slope at the lower bound is explicitly recorded as a boundary solution rather than evidence of a reliable probability relationship. Both binary classes are required; their calibration supports are saved. It changes risk probabilities, not the multiclass argmax class. `risk = 100 * calibrated_attack_probability`, with no rounding, severity weight or additional history weight. History influences classifier inputs rather than entering a second score.

The retained initial diagnostic runs used unrestricted scikit-learn logistic calibration. Their chronological calibration sample caused negative slopes in several models, reversing risk ranking. Monotonic calibration prevents that reversal but cannot repair unrepresentative calibration data or guarantee probability accuracy after a traffic-prevalence shift.

## Action semantics

For thresholds m, r and b:

| Score | Action | What the implementation does |
|---|---|---|
| 0 <= score < m | Allow | Export the Allow decision |
| m <= score < r | Monitor | Export an observation flag |
| r <= score < b | Rate-limit | Export a simulated restriction decision |
| b <= score <= 100 | Block | Export a simulated block decision |

Invalid probabilities, thresholds or risk scores raise an error. They never silently become Allow. The reference cutoffs are 25/60/79, reflecting the deck's stated constants, but their application here uses a newly specified risk formula and does not reproduce the missing original program.

Current rate-limit and block candidates use 31 evenly spaced quantiles of **policy-validation risk scores**, plus the anchors 25/60/79/100 and the next representable score above the observed maximum toward 100. Only valid ordered cutoffs are included. This covers concentrated low-risk ranges rather than assuming a broad 0–100 spread. Monitor is not identified by the optimization objective, so its deterministic convention is min(25, rate_limit/2). This is a documented observation flag, not an optimized monitoring-workload policy. Candidate policies use only the policy partition. Select maximum attack containment subject to benign disruption <= 0.05, breaking ties by more attack blocking, then less benign false-blocking and less disruption, followed by cutoff order. No feasible candidate produces an explicit missing selected policy, not an implicit relaxation or a test-informed fallback. The fixed reference policy is evaluated separately.

The initial diagnostic runs retained in `results/pilot_*` used a coarse grid with rate-limit cutoffs at least 30 and fixed Monitor=25. That grid could not express useful decisions when calibrated scores were below 2. The current quantile-derived search addresses candidate coverage without consulting test scores during a run.

The 5% constraint is a point estimate on policy-validation data. It is neither a population guarantee nor a test constraint. Report the observed held-out rate even if it violates this target.

## Metrics

Let A be the number of attack flows and B the number of benign flows.

- Attack blocking = attack Block / A.
- Attack containment = attack (Rate-limit + Block) / A.
- Benign false-blocking = benign Block / B.
- Benign disruption = benign (Rate-limit + Block) / B.

Monitor contributes to neither containment nor disruption in these definitions. It still has operational cost, which is not measured. Empty denominators return null and exact confidence limits are null. Numerators and denominators accompany each rate. These metrics describe assignments, not actual prevented attacks or measured application damage.

Classifier accuracy counts exact class predictions. Macro precision/recall/F1 average equally over the union of training classes and observed test labels, including zero-support classes with zero-division behavior set to zero. Per-class support makes absent classes visible. Binary AUROC, average precision, Brier score and ECE use attack labels and calibrated attack probabilities. Raw Brier is also saved.

Policy confidence intervals use exact Clopper-Pearson limits under an independent-flow assumption. Paired bootstrap intervals compare baseline and each DNN feature variant on identical test rows, with 300 replicates and the same class set. Both row bootstrap and capture-file bootstrap are exported. Five or fewer capture clusters make the cluster intervals unstable; repeated seeds do not repair this.

## Frozen evaluation and artifacts

Every model, fitted transform, calibrator and selected policy is written first. Artifact hashes and the exact source-code hash are recorded in a frozen selection manifest before any held-out test scoring. Each local artifact's hash is verified before loading it. Never load third-party joblib files on trust.

Exports include split manifests, training histories, validation candidate tables, class probability vectors with class names and row IDs, calibrated probabilities, risk scores, fixed/selected actions, class-by-action counts, confusion matrices, per-class metrics, seed summaries, bootstrap comparisons, PNG/PDF figures and a run-complete marker. Absence of that marker means the experiment did not finish.

Timing covers batch feature transformation, model prediction and calibration. It excludes packet capture, flow assembly, history construction and live enforcement. It is not evidence of end-to-end cloud throughput or latency.

## Development provenance

Initial implementation runs reached test-prediction export but failed during bookkeeping export. Those incomplete runs were preserved privately under the task's work directory. Deduplication precision and history-reference sampling were corrected before the completed diagnostic runs in `results/pilot_*`. Inspection of those diagnostic test outcomes identified rank reversal under unrestricted calibration and inadequate cutoff-grid coverage. The current `results/corrected_*` runs apply monotonic calibration and validation-quantile candidates. Their model architecture and benign-budget target are unchanged. All diagnostic outcomes remain available, and the corrected studies are explicitly post-diagnosis development follow-ups on reused test partitions. They are not a fresh confirmatory evaluation, and their within-run freezing does not erase that fact. A fresh independent validation dataset is required before stronger publication claims.
