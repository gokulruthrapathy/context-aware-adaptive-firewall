# Adaptive firewall research package

This is a **new, locally implemented offline research pipeline**, not a recovery of the missing Team CSEUG49 source code. No original Python files were supplied. The presentation's numerical results are not reused as experimental evidence.

The code classifies **completed network flows** and assigns simulated Allow / Monitor / Rate-limit / Block actions. It does not parse live packets, change operating-system firewall rules, retrain itself in production, or demonstrate prevention of traffic already transmitted.

## Start here

- `RESEARCH_READINESS.md`: what remains before journal submission.
- `docs/METHODS.md`: precise experimental methods and action semantics.
- `docs/FEATURES.md`: feature names, equations, units and causal history.
- `docs/ORIGINAL_MATERIAL_REVIEW.md`: review of the supplied slides and filename screenshot.
- `results/corrected_random/` and `results/corrected_temporal/`: current development follow-up results when `run_complete.json` is present.
- `results/pilot_random/` and `results/pilot_temporal/`: retained initial diagnostic results with unrestricted calibration and a coarse cutoff grid. Do not pool them with the corrected runs as independent replications.
- `paper/manuscript.md`: evidence-limited manuscript draft, generated after the experiments.

## Reproduce in a new environment

For this existing local copy, the isolated environment is already installed. From the project directory you can use:

```powershell
& .\scripts\run_local.ps1 verify --results results/corrected_random
```

Python 3.11 or newer. The exact executed environment is in `requirements-lock.txt`; the original run used Python 3.12.14 on Windows and CPU training. Avoid installing into a shared system environment.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
.\.venv\Scripts\python.exe -m pip install -e . --no-deps
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m adaptive_firewall.cli download
.\.venv\Scripts\python.exe -m adaptive_firewall.cli prepare
.\.venv\Scripts\python.exe -m adaptive_firewall.cli run --config configs/pilot_random.json --prepared data/prepared/random.csv.gz --output results/random_reproduction
.\.venv\Scripts\python.exe -m adaptive_firewall.cli run --config configs/pilot_temporal.json --prepared data/prepared/temporal.csv.gz --output results/temporal_reproduction
```

If your Python network stack does not trust your organization's TLS certificate, configure its normal certificate trust. The supplied Windows fallback script uses the Windows trust store. Neither path disables TLS verification.

The raw archive already exists locally if the acquisition step completed. Do not redownload over it. The runner rejects a populated results directory so prior evidence is preserved. Default preparation streams the complete archive, retains class-capped training records, natural-prevalence samples for the other randomized partitions, and an independent uniform sample for the temporal study.

On Windows, if the Python downloader encounters a local certificate-trust issue, run `powershell -File scripts/download_windows.ps1` from the project folder. This uses normal Windows certificate verification and checks the same pinned archive hash.

After a completed experiment, independently reconcile the exported evidence:

```powershell
.\.venv\Scripts\python.exe -m adaptive_firewall.cli verify --results results/corrected_random
.\.venv\Scripts\python.exe -m adaptive_firewall.cli verify --results results/corrected_temporal
```

To score a new offline batch of completed flow records in the same schema using your own trusted bundle:

```powershell
.\.venv\Scripts\python.exe -m adaptive_firewall.cli score --results results/corrected_random --model context_dnn_seed17 --input completed_flows.csv --output scored_flows.csv
```

The `score` command starts history at the beginning of that batch and returns simulated actions only. Match the training observation density before interpreting its outputs. Do not load model bundles supplied by untrusted third parties.

## Data and provenance

Public source: [Engelen, Rimmer and Joosen's corrected CICIDS2017 release](https://intrusion-detection.distrinet-research.be/WTMC2021/tools_datasets.html), archive SHA-256:

`4d535da19795d85376ae1397d161329e3b06fc47d9a5a68cd9be2cd7ecee0f2a`

This is the WTMC2021 corrected release, **not** the later CNS2022 revision and **not** CSE-CIC-IDS2018. Both original and correction papers must be cited. Labels ending in `Attempted` are mapped to BENIGN, following the corrected-dataset authors' published recommendation. See the data audit for actual labels and counts. No assumption of exactly 15 modeled classes or the slide's 172,628 rows is built into the code.

Source, documentation, trained model bundles and all completed result artifacts are included in Git. Raw and prepared datasets, environments and caches are excluded; the verified download and preparation commands reproduce those data. The raw data remains under its creators' terms. No new license for third-party data is implied. Choose an appropriate license for the new project code with the project owners before public redistribution.

Git attributes preserve exact file bytes because the frozen manifests and source snapshots are verified by SHA-256. Do not normalize line endings in those saved evidence files.

## Evaluation discipline

- Feature-vector duplicates stay in one partition and are removed conservatively. Conflicting-label vectors are excluded entirely.
- Every model uses identical rows within its protocol.
- Imputation, rate caps and standardization fit on training data.
- Dedicated tuning, calibration and policy partitions precede final test evaluation.
- DNN checkpoints use tuning log loss. A separate monotonic binary Platt calibrator estimates attack probabilities on the calibration partition without reversing risk order.
- Policy selection maximizes validation containment under a 5% benign disruption point-estimate budget. Ties prefer more attack blocking, then fewer benign blocks and less disruption.
- Every model, calibrator and policy is saved and hashed before test scoring begins.
- Three seeds, conventional baselines, feature ablations, per-class reports, class-by-action counts, calibrated probabilities, paired comparisons and uncertainty intervals are exported.

The two studies share some underlying source flows and are **not independent datasets**. The temporal experiment collapses labels to BENIGN/ATTACK so new attack families can be evaluated as distribution shift. The random protocol is an in-capture diagnostic and does not establish deployment generalization.

The corrected studies follow diagnosis of the initial runs, including inspection of test outcomes. They are explicitly **development follow-ups on reused benchmark test partitions**, not fresh confirmation. All initial results are retained. A new independent validation set is still required for a stronger paper claim.

## Scope and limits

Flow-derived ratios are not evidence of temporal awareness. The context variant uses eight strictly earlier completed-flow statistics. Their history is built over the retained sampled stream, not all original flows. Raw source IPs are grouping keys only and are excluded from model input. Completed-flow detection has an observation delay and cannot support claims of first-packet prevention.

`attack_containment` counts both Rate-limit and Block. It is an **action-assignment proxy**, not measured attack suppression. A held-out benign disruption rate can exceed the validation budget under distribution shift. Per-flow confidence intervals assume independent flows, which is weak for correlated traffic. Capture-cluster bootstrap results have at most five groups, or fewer in the temporal test, and cannot establish broad generalization.

Do not present the package as journal-ready merely because its tests pass. Read the remaining research requirements.
