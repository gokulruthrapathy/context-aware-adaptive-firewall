"""Portable identities for inputs, run environments and completed evidence."""
from pathlib import Path
import hashlib
import json
import os
import platform
import subprocess
import tempfile
from datetime import datetime, timezone


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream,"sha256").hexdigest()


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path, value):
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    text=json.dumps(value,indent=2,allow_nan=False)
    with tempfile.NamedTemporaryFile(mode="w",encoding="utf-8",dir=path.parent,
            prefix="."+path.name,suffix=".tmp",delete=False) as stream:
        temporary=Path(stream.name)
        stream.write(text)
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def environment(root):
    def git(*args):
        try:
            return subprocess.check_output(["git", "-C",str(root),*args],text=True,
                stderr=subprocess.DEVNULL,timeout=10).strip()
        except (OSError,subprocess.SubprocessError):
            return None
    memory={}
    if os.name=="nt":
        import ctypes
        class Memory(ctypes.Structure):
            _fields_=[("length",ctypes.c_ulong),("load",ctypes.c_ulong)]+[(name,ctypes.c_ulonglong) for name in
                ["total_phys","avail_phys","total_page","avail_page","total_virtual","avail_virtual","avail_extended"]]
        info=Memory();info.length=ctypes.sizeof(info)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(info)):
            memory=dict(physical_memory_bytes=info.total_phys,available_memory_bytes_at_start=info.avail_phys)
    elif Path("/proc/meminfo").exists():
        values={line.split(":")[0]:int(line.split()[1])*1024 for line in Path("/proc/meminfo").read_text().splitlines()}
        memory=dict(physical_memory_bytes=values.get("MemTotal"),available_memory_bytes_at_start=values.get("MemAvailable"))
    git_status=git("status","--porcelain")
    return dict(recorded_utc=utc_now(),python=platform.python_version(),platform=platform.platform(),
        machine=platform.machine(),processor=platform.processor(),logical_cpus=os.cpu_count(),
        git_commit=git("rev-parse","HEAD"),git_branch=git("branch","--show-current"),
        git_dirty=bool(git_status) if git_status is not None else None,**memory,
        environment_files={p.name:sha256(p) for p in [Path(root)/"pyproject.toml",Path(root)/"requirements-lock.txt"] if p.exists()})


def input_fingerprints(prepared, reference=None, require_manifest=True):
    path=Path(prepared)
    files={"prepared":path,"audit":path.parent/"data_audit.json"}
    if reference is not None:
        files["history_reference"]=Path(reference)
    preparation=path.parent/"preparation_manifest.json"
    if not preparation.exists() and require_manifest:
        raise ValueError("Missing preparation_manifest.json; prepare to a new directory or explicitly register legacy inputs")
    if preparation.exists():
        declared=json.loads(preparation.read_text(encoding="utf-8"))
        for item in files.values():
            expected=declared["files"].get(item.name)
            if expected is None or sha256(item)!=expected:
                raise ValueError("Prepared input fingerprint mismatch: "+item.name)
        files["preparation_manifest"]=preparation
    return {key:dict(file=p.name,sha256=sha256(p),bytes=p.stat().st_size) for key,p in files.items()}


def register_prepared(directory, origin="legacy inputs registered after original runs"):
    root=Path(directory)
    target=root/"preparation_manifest.json"
    if target.exists():
        raise ValueError("Preparation manifest already exists; preserve it")
    required=[root/"random.csv.gz",root/"temporal.csv.gz",root/"data_audit.json"]
    if not all(p.is_file() for p in required):
        raise ValueError("Both cohorts and data_audit.json are required")
    result=dict(schema_version=1,created_utc=utc_now(),origin=origin,
        files={p.name:sha256(p) for p in required})
    atomic_json(target,result)
    return result


def read_predictions(path):
    # Python's float parser preserves exported nextafter boundaries without
    # pandas' deprecated float_precision option.
    fields=["raw_attack_probability","calibrated_attack_probability","risk_score"]
    import pandas as pd
    return pd.read_csv(path,dtype={"row_id":str},converters={k:float for k in fields})


def evidence_manifest(directory):
    root=Path(directory)
    excluded={"run_complete.json","run_status.json","verification.json","evidence_manifest.json"}
    return {p.relative_to(root).as_posix():sha256(p) for p in sorted(root.rglob("*"))
            if p.is_file() and p.name not in excluded}
