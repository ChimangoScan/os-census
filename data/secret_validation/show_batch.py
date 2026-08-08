"""Print sample.jsonl records [lo, hi) for the human reviewer to read and verdict.

Read-only display helper: for each record in that index range it prints the
scanner, rule, file, the (possibly multi-line) secret value/context and the
entropy score, if any. Produces no output file; the reviewer reads this and
then runs record.py to persist a verdict. Run from inside
data/secret_validation/ (paths are relative). Scratch tooling used once to
build the committed verdicts.jsonl, not part of the reproduce.sh path.

Usage: show_batch.py <lo> <hi>
"""
import json,sys
lo=int(sys.argv[1]); hi=int(sys.argv[2])
rows=[json.loads(l) for l in open('sample.jsonl')]
for i,o in enumerate(rows):
    if i<lo or i>=hi: continue
    print(f"[{i}] id={o['id']} | {o['scanner']} | rule={o['rule']} | verified={o.get('verified')}")
    print(f"     file={o['file']}")
    v=o['value'].replace('\n','\\n')
    print(f"     value={v}")
    if o.get('context'):
        c=o['context'].replace('\n','\\n')
        print(f"     ctx={c}")
    if o.get('entropy') is not None:
        print(f"     entropy={o['entropy']}")
