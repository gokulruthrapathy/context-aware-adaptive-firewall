"""Package source and evidence without datasets, environments or caches."""
from pathlib import Path
import argparse
import hashlib
import json
import zipfile


def included(path,root):
    parts=path.relative_to(root).parts
    if any(p in {".venv","venv","env","__pycache__",".pytest_cache",".git",".ipynb_checkpoints"}
           or p.endswith(".egg-info") for p in parts):return False
    if len(parts)>1 and parts[0]=="data" and (parts[1]=="raw" or parts[1].startswith("prepared")):
        return False
    return path.name!="PACKAGE_MANIFEST.json"


def main():
    root=Path(__file__).resolve().parents[1]
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",type=Path,default=root.parent/"firewall-research-v2.zip")
    args=parser.parse_args()
    destination=args.output.resolve()
    if destination.exists():raise FileExistsError("Choose a new package path; existing archives are preserved")
    if destination.is_relative_to(root):raise ValueError("Write package outside its source directory")
    files=sorted(p for p in root.rglob("*") if p.is_file() and included(p,root))
    manifest={p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    (root/"PACKAGE_MANIFEST.json").write_text(json.dumps(manifest,indent=2),encoding="utf-8")
    files.append(root/"PACKAGE_MANIFEST.json")
    with zipfile.ZipFile(destination,"x",compression=zipfile.ZIP_DEFLATED,compresslevel=3) as archive:
        for path in files:archive.write(path,arcname=str(Path(root.name)/path.relative_to(root)))
    with zipfile.ZipFile(destination) as archive:
        bad=archive.testzip()
        if bad:raise ValueError("Invalid package member: "+bad)
    print(json.dumps(dict(file=str(destination),bytes=destination.stat().st_size,members=len(files),
        sha256=hashlib.sha256(destination.read_bytes()).hexdigest()),indent=2))


if __name__=="__main__":main()
