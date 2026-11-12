# Version 0.2: audit fixes and CPU / Colab workflow

Use `notebooks/Adaptive_Firewall_Research.ipynb` in Colab with a standard CPU runtime.
Run all cells in order. It installs the project, checks tests, downloads the pinned
public archive, prepares immutable cohorts, runs six models at three seeds in each
of two protocols, verifies exports, demonstrates persistent scoring state, and
exports a ZIP. It uses neither an account token nor Google Drive. Download the
export before the hosted runtime ends. Free hosted resources are not guaranteed:
https://research.google.com/colaboratory/faq.html

The same plain Python code cells can be validated locally with:

```powershell
$env:FIREWALL_REPO = (Get-Location).Path
python scripts/execute_notebook.py notebooks/Adaptive_Firewall_Research.ipynb --output ../Adaptive_Firewall_Executed_Local.ipynb
```

Use an isolated Python environment with `pip install -e ".[dev]"`. The notebook's
default compatible installation may differ from the archived exact local lock;
every new run saves actual package versions, source and environment-file hashes.
These are scikit-learn CPU models. Selecting a GPU does not accelerate them.

## Preserved history and new evidence

The original `pilot_*` and `corrected_*` directories and old prepared inputs are
historical evidence. New preparation uses `data/prepared_v2`; notebook results use
a unique `results/research_v2_<UTC>_<suffix>/random` and `/temporal` directory.
An occupied run or preparation directory is rejected. Failed runs retain a
`run_status.json` error and lack final `run_complete.json`. There is no automatic
resume: choose a new run identity after diagnosing the failure.

Current explicit configurations are `configs/research_random_v2.json` and
`configs/research_temporal_v2.json`. The old configs describe development history;
do not reinterpret an old run using changed defaults. Legacy cohorts can be
fingerprinted with `register-prepared`, but that records adoption of existing
bytes, not independent recovery of the original preparation.

## Fixed contracts

- Strict configuration keys and fully expanded defaults; no silent typo fallback.
- Preparation outputs include source CSV data-row number (header excluded), Flow ID,
  archive hash, preparation-code hash, and hashes of both cohorts and the audit.
- Every run verifies prepared bytes, copies identities and snapshots source, and
  freezes configuration, split and validation-candidate fingerprints before test.
- The checkpoint record now names the epoch actually retained under `min_delta`;
  `minimum_loss_epoch` separately records the absolute tuning-loss minimum.
- Bounded history expires inactive sources, maintains rolling aggregates, limits
  total/source/pending events, rejects late arrivals, and retains equal-time pending
  updates across batches. Truncations/evictions are counted and disclosed: capped
  history is approximate when those counts are nonzero.
- Uniform-reference models require explicit observation flags during scoring.
  Adding query-only rows never changes the observation stream implicitly. Temporal
  models use their chronological cohort as the observation stream.
- JSON scoring state is tied to the model hash and observation contract. State and
  CSV writes are not a transactional service; preserve inputs to recover after a
  crash. No network control is performed.
- Calibration falls back to identity when support is below 100 per binary class
  or a monotonic slope hits its lower bound. Identity is not advertised as calibrated
  probability. The rule is fixed before evaluation, and fallback reasons are saved.
- Raw-score policies, used-score policies and validation-selected 90/95/99%
  containment-target comparisons are frozen together. Infeasibility is explicit.
- Monitoring, malicious Allow/Monitor, weighted metrics and supported-class macro
  F1 are explicit additions; historical macro F1 semantics remain unchanged.
- Predictions include completion time, model/selection versions and an explicit
  `simulation_only` / `not_measured` outcome. These are auditable assignments, not
  prevention records.
- Final completion follows plotting, evidence hashing and stronger verification.
  Verification checks classifier metrics/argmax, recorded calibration maps, primary
  validation ranking, intervals and actions without deserializing model bundles.
- Packaging excludes Python environments, all prepared-data versions and caches.

## Persistent scoring

For an owned, trusted temporal-study bundle:

```powershell
python -m adaptive_firewall.cli score --results results/<run>/temporal --model context_dnn_seed17 --input first.csv --output first_scored.csv --state history.json
python -m adaptive_firewall.cli score --results results/<run>/temporal --model context_dnn_seed17 --input second.csv --output second_scored.csv --state history.json
```

Batches must arrive in nondecreasing completion order; equal timestamps may cross
batches. For a uniform-reference model, additionally supply
`--observation-column __history_observed` with explicit true/false flags. Supply the
reference events as well as query records; the scorer cannot reconstruct missing
observations. Raw input must match the trained CSV feature schema. A completed-flow
model still cannot prevent packets transmitted before completion.

## Interpretation and remaining research

The benchmark and its test periods were examined during earlier development. New
runs are explicitly marked `development_reused`; they are not independent-network
confirmation. The identity fallback fixes a known software decision rule but is
also a development choice informed by prior diagnostics. Positive results do not
erase that exposure. Fresh compatible traffic, grouped/temporal support, controlled
context ablations and independent uncertainty remain necessary for stronger claims.

No persistent drift detector, automatic policy promotion, operator feedback,
production policy rollback or network enforcement is claimed. Those remain scoped
research/deployment work; this release fixes the experimental and scoring foundation.
