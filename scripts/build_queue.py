#!/usr/bin/env python3
"""Monta a fila de scan (data/jobs_unique.jsonl) a partir do pull da API do
Docker Hub (data/hub_tags.jsonl + data/hub_repos.jsonl).

- filtra imagens amd64/linux
- deduplica por digest (bytes idênticos = 1 job; tags viram metadado)
- ordena em round-robin entre repos, alternando recente<->antigo dentro do repo
  (protege a análise de defasagem com poucas rodadas)
- emite no formato que o source JSONL do multiscan entende: {"image","name","weight",...}
  weight decrescente = ordem de scan (o coordenador reivindica por weight desc)
"""
import json, collections, re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime.now(timezone.utc)

def age_days(ts):
    if not ts: return None
    try: return (NOW - datetime.fromisoformat(ts.replace("Z", "+00:00"))).days
    except Exception: return None

def slug(s): return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_")

# pull_count por repo
pull = {}
for line in (ROOT/"data/hub_repos.jsonl").read_text().splitlines():
    r = json.loads(line); pull[f"{r['namespace']}/{r['name']}"] = r.get("pull_count")

# agrupa tags amd64/linux por (repo, digest) -> imagem única
uniq = collections.OrderedDict()
no_amd64 = collections.Counter()
for line in (ROOT/"data/hub_tags.jsonl").read_text().splitlines():
    o = json.loads(line); repo = f"{o['_ns']}/{o['_name']}"
    amd = [im for im in o.get("images", [])
           if im.get("architecture") == "amd64" and im.get("os") == "linux" and im.get("digest")]
    if not amd:
        no_amd64[repo] += 1; continue
    im = amd[0]; key = (repo, im["digest"])
    u = uniq.setdefault(key, {"repo": repo, "ns": o["_ns"], "name_repo": o["_name"],
                              "amd64_digest": im["digest"], "size": im.get("size"),
                              "pull_count": pull.get(repo), "tags": [], "ages": []})
    u["tags"].append(o["name"])
    a = age_days(im.get("last_pushed"))
    if a is not None: u["ages"].append(a)

imgs = list(uniq.values())
for u in imgs:
    u["age_days"] = min(u["ages"]) if u["ages"] else None      # publicação mais recente do digest
    u["repr_tag"] = sorted(u["tags"])[0]
    u["n_tags"] = len(u["tags"])

# round-robin: por repo ordena por idade (novo->velho) e intercala frente/trás
def interleave(lst):
    lst = sorted(lst, key=lambda u: (u["age_days"] if u["age_days"] is not None else 10**9))
    out = []; i, k = 0, len(lst) - 1
    while i <= k:
        out.append(lst[i])
        if i != k: out.append(lst[k])
        i += 1; k -= 1
    return out

byrepo = collections.defaultdict(list)
for u in imgs: byrepo[u["repo"]].append(u)
seqs = {r: interleave(v) for r, v in byrepo.items()}
ordered = []
for passo in range(max(len(v) for v in seqs.values())):
    for r in sorted(seqs):
        if passo < len(seqs[r]): ordered.append((passo, seqs[r][passo]))

total = len(ordered)
out_path = ROOT/"data/jobs_unique.jsonl"
with out_path.open("w") as f:
    for gi, (passo, u) in enumerate(ordered):
        ref = (f"{u['name_repo']}@{u['amd64_digest']}" if u["ns"] == "library"
               else f"{u['ns']}/{u['name_repo']}@{u['amd64_digest']}")
        name = slug(f"{u['name_repo']}_{u['repr_tag']}_{u['amd64_digest'][7:15]}")
        f.write(json.dumps({
            "image": ref, "name": name, "weight": total - gi,    # weight desc = ordem
            "repo": u["repo"], "repr_tag": u["repr_tag"], "tags": u["tags"], "n_tags": u["n_tags"],
            "amd64_digest": u["amd64_digest"], "size": u["size"],
            "age_days": u["age_days"], "pull_count": u["pull_count"], "round": passo + 1,
        }) + "\n")

print(f"imagens únicas (jobs): {total} -> {out_path.relative_to(ROOT)}")
ages = [u["age_days"] for _, u in ordered if u["age_days"] is not None]
print(f"idade (dias): min {min(ages)} | mediana {sorted(ages)[len(ages)//2]} | max {max(ages)}")
print("por repo:", {r: len(v) for r, v in sorted(byrepo.items(), key=lambda x: -len(x[1]))})
if no_amd64: print("tags sem amd64 (puladas):", dict(no_amd64))
