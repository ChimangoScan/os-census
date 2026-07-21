#!/usr/bin/env python3
"""Agrega os report.json em data/analysis/per_image.csv e imprime um resumo das
RQs. Roda em dados parciais (a cada momento do scan). stdlib only.
"""
import json, csv, glob, statistics, collections, os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = Path(os.environ.get("OSCENSUS_OUT") or ROOT/"scan-out"/"out_so")
ANA = Path(__file__).resolve().parent.parent / "data/analysis"
ANA.mkdir(parents=True, exist_ok=True)
SCA = {"trivy", "grype", "osv", "clair"}

rows = []
sca_sets = collections.defaultdict(set)   # scanner -> {(image,cve)}  p/ divergencia (RQ3)
for rj in glob.glob(str(OUT / "*/report.json")):
    try: r = json.load(open(rj))
    except Exception: continue
    m = r.get("target", {}).get("meta", {})
    inv = {i["scanner"]: i for i in r.get("invocations", [])}
    def sev(scn):  # dict severidade do scanner
        return (inv.get(scn, {}) or {}).get("findings_by_severity", {}) or {}
    pkgvuln = collections.Counter()
    for scn in SCA:
        for s, n in sev(scn).items(): pkgvuln[s] += n
    img = r.get("target", {}).get("image", "")
    # divergencia SCA: cada finding pkg-vuln com cve -> conjunto por scanner
    for f in r.get("findings", []):
        if f.get("category") == "pkg-vuln" and f.get("scanner") in SCA:
            cid = f.get("id") or (f.get("cves") or [None])[0]
            if cid and str(cid).startswith("CVE"):
                sca_sets[f["scanner"]].add((img, cid))   # CVE-level: justo entre esquemas de nome de pacote
    rows.append({
        "image": img, "repo": m.get("repo", "?"), "age_days": m.get("age_days"),
        "pull_count": m.get("pull_count"), "size_mb": round((m.get("size") or 0)/1e6, 1),
        "n_tags": m.get("n_tags"),
        "packages": (inv.get("syft", {}) or {}).get("findings", 0),
        "vuln_critical": pkgvuln.get("critical", 0), "vuln_high": pkgvuln.get("high", 0),
        "vuln_medium": pkgvuln.get("medium", 0), "vuln_low": pkgvuln.get("low", 0),
        "vuln_total": sum(pkgvuln.values()),
        "secrets": (inv.get("trufflehog", {}) or {}).get("findings", 0)
                   + (inv.get("gitleaks", {}) or {}).get("findings", 0),
        "misconfig": (inv.get("dockle", {}) or {}).get("findings", 0)
                     + (inv.get("checkov", {}) or {}).get("findings", 0),
        "malware": (inv.get("clamav", {}) or {}).get("findings", 0)
                   + (inv.get("yarahunter", {}) or {}).get("findings", 0),
    })

if not rows:
    print("ainda sem report.json"); raise SystemExit

cols = list(rows[0].keys())
with (ANA / "per_image.csv").open("w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=cols); w.writeheader(); w.writerows(rows)

import gzip
with gzip.open(ANA / "rq3_sca_sets.json.gz", "wt") as f:
    json.dump({s: sorted(v) for s, v in sca_sets.items()}, f)

print(f"=== {len(rows)} imagens analisadas -> data/analysis/per_image.csv ===\n")

# RQ1: postura por repo (média de críticas+altas, pacotes)
print("RQ1 — postura por repo (n imgs | críticas+altas médias | pacotes médios):")
by = collections.defaultdict(list)
for r in rows: by[r["repo"]].append(r)
for repo, v in sorted(by.items(), key=lambda x: -statistics.mean([i["vuln_critical"]+i["vuln_high"] for i in x[1]])):
    ch = statistics.mean([i["vuln_critical"]+i["vuln_high"] for i in v])
    pk = statistics.mean([i["packages"] for i in v])
    print(f"  {repo:24} {len(v):>4} | {ch:6.1f} | {pk:6.0f}")

# RQ2: idade vs vulnerabilidades (buckets de defasagem)
print("\nRQ2 — defasagem (idade) x vuln_total médio:")
buckets = [(0,180,"0-6m"),(180,365,"6-12m"),(365,730,"1-2a"),(730,1460,"2-4a"),(1460,99999,"4a+")]
for lo,hi,lbl in buckets:
    g=[r["vuln_total"] for r in rows if r["age_days"] is not None and lo<=r["age_days"]<hi]
    if g: print(f"  {lbl:6} n={len(g):>4}  vuln_total médio={statistics.mean(g):7.1f}")

# RQ3: divergência SCA (Jaccard par-a-par sobre (img,cve,pkg))
print("\nRQ3 — divergência SCA (Jaccard par-a-par de (imagem,cve,pacote)):")
present=[s for s in ["trivy","grype","osv","clair"] if sca_sets.get(s)]
for i,a in enumerate(present):
    for b in present[i+1:]:
        A,B=sca_sets[a],sca_sets[b]; u=len(A|B)
        print(f"  {a}∩{b}: Jaccard={len(A&B)/u if u else 0:.2f}  ({a}={len(A)}, {b}={len(B)}, ∩={len(A&B)})")

# RQ5: mínima = mais segura? (pacotes x vuln_total)
print("\nRQ5 — pacotes x vuln_total (amostra ordenada por pacotes):")
for r in sorted(rows, key=lambda x: x["packages"])[:3] + sorted(rows, key=lambda x: -x["packages"])[:3]:
    print(f"  {r['repo']:20} pkgs={r['packages']:>5} vuln_total={r['vuln_total']:>5}")
