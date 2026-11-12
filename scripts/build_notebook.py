"""Generate a plain-Python notebook usable in Colab and the local cell runner."""
from pathlib import Path
import json
import textwrap

ROOT=Path(__file__).resolve().parents[1]
cells=[]


def markdown(text):
    cells.append(dict(cell_type="markdown",id=f"cell-{len(cells):02d}",metadata={},
        source=textwrap.dedent(text).strip()+"\n"))


def code(text):
    cells.append(dict(cell_type="code",id=f"cell-{len(cells):02d}",metadata={},
        execution_count=None,outputs=[],source=textwrap.dedent(text).strip()+"\n"))


markdown("""
# Adaptive firewall: reproducible CPU research workflow

**Run in order with Runtime → Run all. Hardware accelerator: None (CPU).**

This notebook prepares the pinned corrected CICIDS2017 public dataset, runs software
tests, trains three DNN feature variants plus random forest/logistic/prior baselines,
and verifies saved probabilities and simulated policy decisions. It does not change
firewall rules or generate attacks. A GPU is not used by these scikit-learn models.

These are development experiments on a previously examined benchmark. New seeds or
reruns do not create independent confirmation. The 5% benign budget applies to policy
validation, not automatically to future traffic. Containment means assigned Rate-limit
or Block, not measured attack prevention. Original slide numbers are not reproduced.

No token, password, Google Drive mount, or paid runtime is required. Save the final ZIP:
Colab runtime storage is temporary. The historical checkpoints remain untouched.
""")
code("""
from pathlib import Path
from datetime import datetime, timezone
import importlib.util
import json, os, platform, subprocess, sys, uuid
try:
    import google.colab
    IN_COLAB = True
except ImportError:
    IN_COLAB = False

REPOSITORY = "https://github.com/gokulruthrapathy/context-aware-adaptive-firewall.git"
BRANCH = "research-fixes-colab"
REF = BRANCH  # For exact repetition, set the inspected commit SHA.
ROOT = Path(os.environ.get("FIREWALL_REPO", "/content/context-aware-adaptive-firewall"))
SEEDS = [17, 42, 99]
EPOCHS = 25
THREADS = min(2, os.cpu_count() or 1)
OBJECTIVE = "max_containment"  # Alternative: min_disruption (may be infeasible).
CONTAINMENT_TARGET = 0.95
MONITOR_BUDGET = 1.0  # Report all Monitor actions; choose a tighter limit before a new study.
USE_EXACT_LOCAL_LOCK = False  # Default installs compatible dependencies for Colab's Python.
RUN_TESTS = True
RUN_ID = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + uuid.uuid4().hex[:6]
RESULTS_ROOT = Path(os.environ.get("FIREWALL_RESULTS_ROOT", str(ROOT / "results")))
RUN_ROOT = RESULTS_ROOT / ("research_v2_" + RUN_ID)
PREPARED = ROOT / "data" / "prepared_v2"

def command(args, cwd=ROOT):
    print("Running:", " ".join(map(str,args)), flush=True)
    result = subprocess.run(list(map(str,args)), cwd=cwd, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout)
    if result.returncode:
        raise RuntimeError(f"Command failed with exit code {result.returncode}")
    return result.stdout

print({"colab": IN_COLAB, "python": platform.python_version(), "logical_cpus": os.cpu_count(),
       "threads": THREADS, "run_id": RUN_ID})
""")
markdown("""
## 1. Obtain source and install dependencies

The notebook clones the research branch if necessary. Reuse of an existing local
checkout does not reset it. Actual source, package versions and Git state are saved
with every run. Colab installs the project into its current Python; locally use a
dedicated environment. Exact local pins are optional because hosted Python changes.
""")
code("""
if not (ROOT / "pyproject.toml").exists():
    if ROOT.exists() and any(ROOT.iterdir()):
        raise ValueError("ROOT is occupied; choose an empty checkout location")
    ROOT.parent.mkdir(parents=True, exist_ok=True)
    command(["git", "clone", "--branch", BRANCH, "--single-branch", REPOSITORY, ROOT], cwd=ROOT.parent)
    if REF != BRANCH: command(["git", "checkout", REF])
os.chdir(ROOT)
if IN_COLAB:
    if USE_EXACT_LOCAL_LOCK:
        command([sys.executable, "-m", "pip", "install", "-r", "requirements-lock.txt"])
    command([sys.executable, "-m", "pip", "install", "-e", ".[dev]"])
sys.path.insert(0, str(ROOT / "src"))
from adaptive_firewall.provenance import environment, input_fingerprints, sha256
from adaptive_firewall.config import validate_config
print(json.dumps(environment(ROOT), indent=2))
""")
markdown("""
## 2. Test behavior before training

Synthetic tests check software behavior, not research accuracy. A failure stops
the notebook. Raw archive preparation, cross-batch history, checkpoint reporting,
policy infeasibility and incomplete-run behavior have dedicated regression checks.
""")
code("""
if RUN_TESTS:
    test_log = command([sys.executable, "-m", "pytest", "-q"])
else:
    test_log = "Tests explicitly skipped by notebook configuration."
    print(test_log)
""")
markdown("""
## 3. Acquire and fingerprint the public data

The archive download is approximately 334 MB and is checked against a pinned SHA-256.
Preparation reads the full archive in chunks and retains student-scale cohorts.
It rejects an occupied preparation directory. If interrupted, preserve that directory
and select a different PREPARED path. Existing valid preparations are hash-checked.
""")
code("""
from adaptive_firewall.data import DATA_SHA256
archive = ROOT / "data" / "raw" / "dataset.zip"
if not archive.exists():
    command([sys.executable, "-m", "adaptive_firewall.cli", "download", "--output", archive])
assert sha256(archive) == DATA_SHA256, "Unexpected archive bytes; do not train"
if not (PREPARED / "preparation_manifest.json").exists():
    command([sys.executable, "-m", "adaptive_firewall.cli", "prepare",
             "--archive", archive, "--output", PREPARED])
print(json.dumps(input_fingerprints(PREPARED / "random.csv.gz", PREPARED / "temporal.csv.gz"), indent=2))
audit = json.loads((PREPARED / "data_audit.json").read_text())
print({k: audit[k] for k in ["raw_rows", "invalid_rows", "duplicate_feature_rows",
                             "conflicting_feature_signatures", "unique_rows_after_conflict_exclusion"]})
""")
markdown("""
## 4. Freeze the experiment settings

Three seeds and six estimators are used per protocol. Fit/tuning, calibration, policy
selection and test records are separate within each run. Random multiclass and
chronological binary results must not be pooled as independent datasets.

Calibration uses identity scores if either calibration class has fewer than 100
records or the monotonic fit reaches its lower slope bound. This is a prespecified
fallback, not a claim that raw scores are calibrated. Raw-score policies are always
exported as controls. Validation-only 90/95/99% containment-target comparisons expose
infeasible targets; do not choose your final method from their test results.
""")
code("""
configs = {}
for protocol in ["random", "temporal"]:
    config = json.loads((ROOT / "configs" / f"research_{protocol}_v2.json").read_text())
    config.update(seeds=SEEDS, epochs=EPOCHS, threads=THREADS, policy_objective=OBJECTIVE,
                  containment_target=CONTAINMENT_TARGET, max_monitor_fraction=MONITOR_BUDGET)
    configs[protocol] = validate_config(config)
    print(protocol, json.dumps(configs[protocol], indent=2))
assert not RUN_ROOT.exists(), "Use a new RUN_ID; do not overwrite prior evidence"
RUN_ROOT.mkdir(parents=True)
(RUN_ROOT / "software_tests.txt").write_text(test_log, encoding="utf-8")
(RUN_ROOT / "installed_packages.txt").write_text(
    subprocess.check_output([sys.executable, "-m", "pip", "freeze"], text=True), encoding="utf-8")
""")
markdown("""
## 5. Train and evaluate sequentially

Each model, calibrator, validation policy and raw-score control is frozen before test
scoring. No runtime firewall access is involved. Runs complete only after plots,
evidence hashes and export verification succeed. CPU training is intentional.
""")
code("""
from adaptive_firewall.experiment import run
import pandas as pd
study_paths = {}
for protocol in ["random", "temporal"]:
    prepared = PREPARED / ("random.csv.gz" if protocol == "random" else "temporal.csv.gz")
    destination = RUN_ROOT / protocol
    result = run(configs[protocol], prepared, destination)
    study_paths[protocol] = destination
    print(protocol, "completed:", len(result), "model/seed bundles")
""")
markdown("""
## 6. Independently reconcile exported evidence

Verification checks files and calculations without reloading model bundles. It does
not establish independent retraining or validate the dataset creators' ground truth.
Inspect split support and calibration fallback records before interpreting accuracy.
""")
code("""
from adaptive_firewall.verify import verify_results
for protocol, directory in study_paths.items():
    print(protocol, json.dumps(verify_results(directory), indent=2))
    print("Partitions:", (directory / "split_summary.json").read_text())
    records = [json.loads(p.read_text())["calibration"] for p in sorted((directory / "training").glob("*.json"))]
    print("Identity fallbacks:", sum(bool(r["fallback_reason"]) for r in records), "/", len(records))
""")
markdown("""
## 7. Read results, policy controls and figures

Accuracy and policy rates are different outcomes. Macro F1 retains zero-support
training classes; supported-class macro F1 is a separately named diagnostic.
Monitor workload is shown explicitly. Tables are descriptive means across seeds,
not confidence intervals across independent networks. All actions are simulated.
""")
code("""
summaries = pd.concat([pd.read_csv(path / "summary.csv").assign(protocol=protocol)
                       for protocol, path in study_paths.items()], ignore_index=True)
columns = ["accuracy", "macro_f1", "weighted_f1", "supported_class_macro_f1", "attack_containment",
           "attack_blocking", "benign_disruption", "benign_false_block", "monitor_fraction"]
columns = [c for c in columns if c in summaries]
means = summaries.groupby(["protocol", "model"])[columns].mean()
print(means.to_string(float_format=lambda v: f"{v:.5f}"))
summaries.to_csv(RUN_ROOT / "combined_summary.csv", index=False)
comparisons = pd.concat([pd.read_csv(path / "policy_comparisons.csv").assign(protocol=protocol)
                        for protocol, path in study_paths.items()], ignore_index=True)
print("Feasibility counts:")
print(comparisons.groupby(["protocol", "model", "policy"])["feasible"].sum().to_string())
comparisons.to_csv(RUN_ROOT / "all_policy_comparisons.csv", index=False)
if IN_COLAB:
    from IPython.display import display, Image
    display(means)
    for protocol, path in study_paths.items():
        print(protocol)
        for name in ["macro_f1", "test_policy_tradeoff", "validation_policy_candidates", "context_calibration"]:
            figure = path / "figures" / (name + ".png")
            if figure.exists(): display(Image(filename=str(figure)))
""")
markdown("""
## 8. Demonstrate persistent scoring state

This small chronological prefix is a software demonstration, not an extra performance
experiment. New-history models preserve equal-time pending observations across
batches. Random-study models additionally require an explicit reference-observation
flag; they reject an implicit change to a full-stream observation process.
""")
code("""
from adaptive_firewall.data import load_prepared
from adaptive_firewall.inference import score_completed_csv
from threadpoolctl import threadpool_limits
import numpy as np
demo = RUN_ROOT / "state_demo"
demo.mkdir()
prefix = load_prepared(PREPARED / "temporal.csv.gz", "temporal", True).iloc[:256]
prefix.to_csv(demo / "whole_input.csv", index=False)
prefix.iloc[:127].to_csv(demo / "first_input.csv", index=False)
prefix.iloc[127:].to_csv(demo / "second_input.csv", index=False)
model_name = "context_dnn_seed" + str(SEEDS[0])
manifest = json.loads((study_paths["temporal"] / "frozen_selection_manifest.json").read_text())
has_policy = next(a for a in manifest["artifacts"] if a["name"] == model_name)["policy"] is not None
if has_policy:
    with threadpool_limits(limits=THREADS):
        score_completed_csv(study_paths["temporal"], model_name, demo / "whole_input.csv", demo / "whole.csv")
        score_completed_csv(study_paths["temporal"], model_name, demo / "first_input.csv", demo / "first.csv", demo / "state.json")
        score_completed_csv(study_paths["temporal"], model_name, demo / "second_input.csv", demo / "second.csv", demo / "state.json")
    whole = pd.read_csv(demo / "whole.csv", dtype={"row_id": str})
    pieces = pd.concat([pd.read_csv(demo / name, dtype={"row_id": str}) for name in ["first.csv", "second.csv"]], ignore_index=True)
    assert list(whole.row_id) == list(pieces.row_id)
    np.testing.assert_allclose(whole.risk_score, pieces.risk_score, atol=1e-5, rtol=1e-5)
    assert list(whole.action) == list(pieces.action)
    print("Persistent-state demonstration passed for", len(whole), "completed flows")
else:
    print("Demonstration skipped: the prespecified policy objective was infeasible for this model")
""")
markdown("""
## 9. Export evidence and preserve it

The ZIP contains this run's models, predictions, manifests, figures, tests log and
environment, together with source/configuration needed to repeat it. Raw data are
excluded; the download identity is recorded. Download before the Colab session ends.

Before publication: reserve compatible independent traffic, predefine selection and
operating points, verify rare-class support, and evaluate measured service impact if
claiming enforcement. No fresh independent-network confirmation is claimed here.
""")
code("""
import zipfile
export_path = ROOT.parent / ("firewall_results_" + RUN_ID + ".zip")
with zipfile.ZipFile(export_path, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=3) as bundle:
    for directory in ["src", "configs", "tests", "notebooks", "docs"]:
        for path in sorted((ROOT / directory).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                bundle.write(path, "project/" + path.relative_to(ROOT).as_posix())
    for name in ["README.md", "pyproject.toml", "requirements-lock.txt"]:
        bundle.write(ROOT / name, "project/" + name)
    for path in sorted(RUN_ROOT.rglob("*")):
        if path.is_file(): bundle.write(path, "run/" + path.relative_to(RUN_ROOT).as_posix())
with zipfile.ZipFile(export_path) as bundle:
    assert bundle.testzip() is None
print("Results directory:", RUN_ROOT)
print("Export:", export_path, "bytes:", export_path.stat().st_size, "sha256:", sha256(export_path))
if IN_COLAB:
    from IPython.display import FileLink, display
    display(FileLink(str(export_path)))
    # If your browser cannot follow the link, run:
    # from google.colab import files
    # files.download(str(export_path))
""")

def main():
    notebook=dict(nbformat=4,nbformat_minor=5,cells=cells,metadata={
        "kernelspec":{"display_name":"Python 3","language":"python","name":"python3"},
        "language_info":{"name":"python","version":"3.12"},
        "colab":{"name":"Adaptive_Firewall_Research.ipynb","provenance":[]}})
    target=ROOT/"notebooks/Adaptive_Firewall_Research.ipynb"
    target.parent.mkdir(exist_ok=True)
    target.write_text(json.dumps(notebook,indent=1,ensure_ascii=False),encoding="utf-8")
    print(target)


if __name__=="__main__":main()
