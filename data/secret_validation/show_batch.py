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
