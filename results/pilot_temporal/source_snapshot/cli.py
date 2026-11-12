from pathlib import Path
import argparse
import hashlib
import json
import urllib.request
from .data import prepare, DATA_URL, DATA_SHA256


def main():
    parser=argparse.ArgumentParser(description="Offline adaptive firewall research")
    sub=parser.add_subparsers(dest="command",required=True)
    d=sub.add_parser("download")
    d.add_argument("--output",default="data/raw/dataset.zip")
    p=sub.add_parser("prepare")
    p.add_argument("--archive",default="data/raw/dataset.zip")
    p.add_argument("--output",default="data/prepared")
    p.add_argument("--train-per-class",type=int,default=4000)
    p.add_argument("--holdout-size",type=int,default=5000)
    p.add_argument("--test-size",type=int,default=20000)
    p.add_argument("--temporal-size",type=int,default=70000)
    r=sub.add_parser("run")
    r.add_argument("--config",required=True)
    r.add_argument("--prepared",required=True)
    r.add_argument("--output",required=True)
    v=sub.add_parser("verify")
    v.add_argument("--results",required=True)
    s=sub.add_parser("score")
    s.add_argument("--results",required=True)
    s.add_argument("--model",required=True)
    s.add_argument("--input",required=True)
    s.add_argument("--output",required=True)
    args=parser.parse_args()
    if args.command=="download":
        output=Path(args.output)
        if output.exists():
            raise ValueError("Download target already exists")
        output.parent.mkdir(parents=True,exist_ok=True)
        temporary=output.with_suffix(".partial")
        urllib.request.urlretrieve(DATA_URL,temporary)
        with temporary.open("rb") as f:
            digest=hashlib.file_digest(f,"sha256").hexdigest()
        if digest!=DATA_SHA256:
            raise ValueError("Downloaded bytes do not match pinned SHA-256")
        temporary.rename(output)
        print(output)
    elif args.command=="prepare":
        prepare(args.archive,args.output,args.train_per_class,args.holdout_size,args.test_size,args.temporal_size)
    elif args.command=="run":
        from .experiment import run
        result=run(json.loads(Path(args.config).read_text()),args.prepared,args.output)
        print(result.to_string(index=False))
    elif args.command=="verify":
        from .verify import verify_results
        print(json.dumps(verify_results(args.results),indent=2))
    else:
        from .inference import score_completed_csv
        print("Scored completed flows:",score_completed_csv(args.results,args.model,args.input,args.output))


if __name__=="__main__":
    main()
