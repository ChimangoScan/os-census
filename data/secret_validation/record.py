import json,sys
# usage: record.py <start_index>  then reads stdin lines "offset verdict reason"
# verdict: TP/FP/AMB
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
