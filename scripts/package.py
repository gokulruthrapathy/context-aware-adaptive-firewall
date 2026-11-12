"""Package code, documents, trusted local models and results, excluding raw data."""
from pathlib import Path
import hashlib
import json
import zipfile

root=Path(__file__).resolve().parents[1]
destination=root.parent/"firewall-research.zip"
if destination.exists():
    raise FileExistsError("Choose another package path rather than overwriting a deliverable")

def included(path):
    parts=path.relative_to(root).parts
    if any(p in {"__pycache__",".pytest_cache",".git"} or p.endswith(".egg-info") for p in parts):
        return False
    if parts[:2] in [("data","raw"),("data","prepared")]:
        return False
    return path.name!="PACKAGE_MANIFEST.json"

(root/"PACKAGE_CONTENTS.md").write_text(
    "# Package contents\n\nThe ZIP includes source code, tests, exact dependency pins, documentation, manuscript draft, all four completed study outputs, source snapshots, trusted locally trained model bundles, probabilities, per-flow decisions, result figures and verification records.\n\n"
    "It excludes raw and prepared datasets, Python environments, caches and generated package metadata. In the original local folder, the downloaded archive and prepared cohorts remain under data/. To reproduce after moving the ZIP, use the documented download/prepare commands.\n\n"
    "The corrected studies are development follow-ups on reused benchmark partitions; the retained pilot studies show their diagnostic predecessors. They must not be pooled as independent datasets or independent confirmation.\n\n"
    "PACKAGE_MANIFEST.json records SHA-256 fingerprints of all included files except the manifest itself. The GitHub target is https://github.com/gokulruthrapathy/context-aware-adaptive-firewall. No journal submission has been performed.\n",encoding="utf-8")
files=sorted(p for p in root.rglob("*") if p.is_file() and included(p))
manifest={str(p.relative_to(root)).replace("\\","/"):hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
(root/"PACKAGE_MANIFEST.json").write_text(json.dumps(manifest,indent=2),encoding="utf-8")
files.append(root/"PACKAGE_MANIFEST.json")
with zipfile.ZipFile(destination,"x",compression=zipfile.ZIP_DEFLATED,compresslevel=3) as archive:
    for path in files:
        archive.write(path,arcname=str(Path(root.name)/path.relative_to(root)))
with zipfile.ZipFile(destination) as archive:
    bad=archive.testzip()
    if bad: raise ValueError("Invalid package member: "+bad)
print(json.dumps({"file":str(destination),"bytes":destination.stat().st_size,"members":len(files),
    "sha256":hashlib.sha256(destination.read_bytes()).hexdigest()},indent=2))
