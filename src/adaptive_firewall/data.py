"""Stream a pinned public archive without extracting or executing its contents."""
from pathlib import Path
from collections import Counter
import hashlib
import json
import zipfile
import numpy as np
import pandas as pd

DATA_URL = "https://intrusion-detection.distrinet-research.be/WTMC2021/Dataset/dataset.zip"
DATA_SHA256 = "4d535da19795d85376ae1397d161329e3b06fc47d9a5a68cd9be2cd7ecee0f2a"
META = {"Flow ID", "Src IP", "Src Port", "Dst IP", "Timestamp", "Label"}
SPLITS = ["train", "tune", "calibration", "policy", "test"]


def write_json(path, value):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False), encoding="utf-8")


def normalized_labels(labels):
    labels = labels.astype(str).str.strip()
    # Explicit new-study decision, following the corrected-dataset authors' advice.
    return labels.mask(labels.str.contains("Attempted", case=False, regex=False), "BENIGN")


def signature(features):
    """Conservative exact feature-vector identity, excluding labels and metadata."""
    # Match the precision saved for modeling. Distinct float64 records that
    # collapse to one float32 vector must not leak across partitions.
    canonical=features.astype(np.float32).replace([np.inf,-np.inf],np.nan)
    return pd.util.hash_pandas_object(canonical, index=False).to_numpy(dtype=np.uint64)


def bounded_sample(old, new, limit):
    joined = new if old is None else pd.concat([old, new], ignore_index=True)
    return joined.nsmallest(limit, "__priority").copy() if len(joined) > limit else joined


def prepare(archive, output, train_per_class=4000, holdout_size=5000,
            test_size=20000, temporal_size=70000, chunksize=25000):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    with open(archive, "rb") as f:
        sha = hashlib.file_digest(f, "sha256").hexdigest()
    if sha != DATA_SHA256:
        raise ValueError("Archive SHA-256 differs from the pinned corrected CICIDS2017 release")
    audit = dict(dataset="Engelen et al. corrected CICIDS2017, WTMC2021 archive",
        source_url=DATA_URL, sha256=sha, attempted_label_policy="map to BENIGN",
        sampling="Class-capped train; uniform priority samples in other hash partitions",
        split="feature-signature hash modulo 100: 60/10/10/10/10",
        context_scope="Previous completed flows in the retained sampled stream, not the full traffic history",
        raw_rows=0, invalid_rows=0, duplicate_feature_rows=0,
        conflicting_feature_signatures=0, files=[], raw_labels=Counter(), cleaned_labels=Counter())
    seen, conflicts, pools, training = {}, set(), {}, {}
    temporal_pool = None
    base_columns = None
    with zipfile.ZipFile(archive) as z:
        for name in sorted(n for n in z.namelist() if n.lower().endswith(".csv")):
            audit["files"].append(dict(name=name, uncompressed_bytes=z.getinfo(name).file_size))
            print("Reading", name, flush=True)
            with z.open(name) as f:
                for chunk in pd.read_csv(f, chunksize=chunksize, low_memory=False, encoding="utf-8", encoding_errors="replace"):
                    chunk.columns = chunk.columns.str.strip()
                    audit["raw_rows"] += len(chunk)
                    audit["raw_labels"].update(chunk["Label"].astype(str).str.strip())
                    cols = [c for c in chunk if c not in META]
                    if base_columns is None:
                        base_columns = cols
                    if cols != base_columns:
                        raise ValueError("Archive files have inconsistent feature ordering")
                    x = chunk[cols].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
                    y = normalized_labels(chunk["Label"])
                    ts = pd.to_datetime(chunk["Timestamp"].str.strip(), format="%d/%m/%Y %I:%M:%S %p", errors="coerce")
                    good = ts.notna() & x["Flow Duration"].ge(0) & y.ne("nan") & y.ne("Label") & x.notna().mean(axis=1).ge(.5)
                    audit["invalid_rows"] += int((~good).sum())
                    x, y, ts = x.loc[good], y.loc[good], ts.loc[good]
                    hashes = signature(x)
                    keep = []
                    for i, (h, label) in enumerate(zip(hashes, y)):
                        key = int(h)
                        if key in seen:
                            audit["duplicate_feature_rows"] += 1
                            if seen[key] != label:
                                conflicts.add(str(key))
                            continue
                        seen[key] = label
                        keep.append(i)
                    if not keep:
                        continue
                    x, y, ts, hashes = x.iloc[keep], y.iloc[keep], ts.iloc[keep], hashes[keep]
                    rows = x.astype(np.float32).copy()
                    rows["__label"] = y.to_numpy()
                    rows["__source"] = name
                    rows["__src_ip"] = chunk.loc[x.index, "Src IP"].astype(str).to_numpy()
                    rows["__dst_ip"] = chunk.loc[x.index, "Dst IP"].astype(str).to_numpy()
                    rows["__ready_at"] = (ts + pd.to_timedelta(x["Flow Duration"], unit="us")).to_numpy()
                    rows["__row_id"] = [str(int(h)) for h in hashes]
                    rows["__priority"] = (hashes // np.uint64(100)).astype(np.float64)
                    bucket = hashes % np.uint64(100)
                    rows["__split"] = np.select([bucket < 60, bucket < 70, bucket < 80, bucket < 90], SPLITS[:4], default="test")
                    audit["cleaned_labels"].update(y)
                    temporal_pool = bounded_sample(temporal_pool, rows, temporal_size)
                    for split, group in rows.groupby("__split"):
                        if split == "train":
                            for label, class_rows in group.groupby("__label"):
                                training[label] = bounded_sample(training.get(label), class_rows, train_per_class)
                        else:
                            pools[split] = bounded_sample(pools.get(split), group, test_size if split == "test" else holdout_size)
    # All occurrences of a conflicting feature vector are excluded from every pool.
    random_pool = pd.concat([*training.values(), *pools.values()], ignore_index=True)
    random_pool = random_pool.loc[~random_pool["__row_id"].isin(conflicts)].copy()
    temporal_pool = temporal_pool.loc[~temporal_pool["__row_id"].isin(conflicts)].copy()
    if random_pool["__row_id"].duplicated().any():
        raise AssertionError("Duplicate signatures survived preparation")
    audit["conflicting_feature_signatures"] = len(conflicts)
    audit["first_occurrence_labels_before_conflict_exclusion"] = dict(audit["cleaned_labels"])
    audit["cleaned_labels"] = Counter(label for h,label in seen.items() if str(h) not in conflicts)
    audit["unique_rows_after_conflict_exclusion"] = sum(audit["cleaned_labels"].values())
    audit["base_columns"] = base_columns
    audit["random_sample_counts"] = {s: dict(Counter(g["__label"])) for s, g in random_pool.groupby("__split")}
    audit["temporal_sample_counts"] = dict(Counter(temporal_pool["__label"]))
    audit["raw_labels"], audit["cleaned_labels"] = dict(audit["raw_labels"]), dict(audit["cleaned_labels"])
    audit["caps"] = dict(train_per_class=train_per_class, holdout_size=holdout_size, test_size=test_size, temporal_size=temporal_size)
    random_pool.to_csv(output / "random.csv.gz", index=False)
    temporal_pool.to_csv(output / "temporal.csv.gz", index=False)
    write_json(output / "data_audit.json", audit)
    print("Prepared", len(random_pool), "random-protocol rows and", len(temporal_pool), "temporal-pool rows", flush=True)
    return audit


def load_prepared(path, protocol="random", binary=False):
    frame = pd.read_csv(path, dtype={"__row_id": str})
    frame["__ready_at"] = pd.to_datetime(frame["__ready_at"])
    frame = frame.sort_values(["__ready_at", "__row_id"], kind="stable").reset_index(drop=True)
    if frame["__row_id"].duplicated().any():
        raise ValueError("Prepared dataset contains duplicate row IDs")
    if protocol == "temporal":
        # Contiguous complete time groups; ties never cross a partition boundary.
        boundaries = frame["__ready_at"].quantile([.6, .7, .8, .9]).tolist()
        if len(set(boundaries)) != 4:
            raise ValueError("Insufficient distinct timestamps for a temporal protocol")
        frame["__split"] = np.select([frame["__ready_at"] <= b for b in boundaries], SPLITS[:4], default="test")
    if binary:
        frame["__label"] = np.where(frame["__label"].eq("BENIGN"), "BENIGN", "ATTACK")
    for name in SPLITS:
        if not frame["__split"].eq(name).any():
            raise ValueError("Empty partition: " + name)
    return frame
