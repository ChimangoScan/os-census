"""Append the human reviewer's TP/FP/AMB verdicts for data/secret_validation/sample.jsonl.

Interactive helper: for each stdin line "index|verdict|reason" it looks up
sample.jsonl[index] and appends one verdict record to verdicts.jsonl. It does
NOT classify anything itself — the verdict is decided by the human reading the
sample (see show_batch.py) and typed in on stdin. Run from inside
data/secret_validation/ (paths are relative). This is scratch tooling used
once to build the committed verdicts.jsonl, not part of the reproduce.sh path.

Usage: record.py <start_index>  (start_index is informational only; each
stdin line still carries its own explicit index)
"""
import json,sys
rows=[json.loads(l) for l in open('sample.jsonl')]
out=open('verdicts.jsonl','a')
for line in sys.stdin:
    line=line.rstrip('\n')
    if not line.strip(): continue
    parts=line.split('|',2)
    idx=int(parts[0]); verdict=parts[1].strip(); reason=parts[2].strip()
    o=rows[idx]
    out.write(json.dumps({"index":idx,"id":o['id'],"scanner":o['scanner'],"image":o['image'],"rule":o['rule'],"file":o['file'],"verdict":verdict,"reason":reason},ensure_ascii=False)+"\n")
out.close()
