"""Execute plain Python notebook cells locally, retaining standard .ipynb outputs.

This validates the same cells in a Python process, not a hosted Colab runtime.
"""
from pathlib import Path
import argparse
import contextlib
import io
import json
import time
import traceback


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("notebook",type=Path)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():raise ValueError("Choose a new executed-notebook path")
    notebook=json.loads(args.notebook.read_text(encoding="utf-8"))
    namespace={"__name__":"__main__"}
    count=0
    notebook["metadata"]["local_validation"]={"method":"plain Python execution of the notebook's code cells",
        "hosted_colab_executed":False}
    for cell in notebook["cells"]:
        if cell["cell_type"]!="code":continue
        count+=1;cell["execution_count"]=count;cell["outputs"]=[]
        source="".join(cell["source"]) if isinstance(cell["source"],list) else cell["source"]
        print(f"Executing notebook code cell {count}: {source.splitlines()[0]}",flush=True)
        begin=time.perf_counter();buffer=io.StringIO();error=None
        try:
            with contextlib.redirect_stdout(buffer),contextlib.redirect_stderr(buffer):
                exec(compile(source,f"notebook-cell-{count}","exec"),namespace)
        except Exception as exc:
            error=exc
            cell["outputs"].append(dict(output_type="error",ename=type(exc).__name__,evalue=str(exc),
                traceback=traceback.format_exc().splitlines()))
        if buffer.getvalue():cell["outputs"].insert(0,dict(output_type="stream",name="stdout",text=buffer.getvalue()))
        cell["metadata"]["local_execution_seconds"]=time.perf_counter()-begin
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(notebook,indent=1,ensure_ascii=False),encoding="utf-8")
        print(buffer.getvalue()[-3500:],flush=True)
        if error:raise error
    print(f"Executed all {count} code cells successfully. Saved {args.output}",flush=True)


if __name__=="__main__":main()
