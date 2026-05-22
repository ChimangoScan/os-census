#!/usr/bin/env python3
"""Figuras do paper: UM painel horizontal 1x4 (altura minima) a partir de
data/analysis/per_image.csv e dos report.json.
Rodar:  uv run --with matplotlib python make_figs.py
"""
import csv, json, glob, collections, os, statistics as _st
from pathlib import Path
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent
CSV = str(ROOT / "data/analysis/per_image.csv")
_legacy = Path("/mnt/win_ssd/scanners-data/out_so")
OUT = str(os.environ.get("OSCENSUS_OUT") or (_legacy if _legacy.exists() else ROOT/"scan-out"/"out_so"))
FIG = str(Path(__file__).resolve().parent / "figures")
plt.rcParams.update({"font.size": 7, "axes.grid": True, "grid.alpha": 0.25,
                     "axes.axisbelow": True, "savefig.bbox": "tight",
                     "axes.titlesize": 7.5, "xtick.labelsize": 6, "ytick.labelsize": 6})

def short(r): return r.split("/")[-1]
rows = list(csv.DictReader(open(CSV)))
for r in rows:
    for k in ("age_days","packages","vuln_critical","vuln_high","vuln_total"):
        try: r[k] = float(r[k]) if r[k] not in ("","None") else None
        except: r[k] = None

fig, ax = plt.subplots(1, 4, figsize=(13.2, 2.05))

# (a) RQ1: media criticas+altas por distro (top 11), com +-SD e n
by = collections.defaultdict(list)
for r in rows:
    if r["vuln_critical"] is not None and r["vuln_high"] is not None:
        by[short(r["repo"])].append(r["vuln_critical"]+r["vuln_high"])
agg = sorted(((k, sum(v)/len(v), (_st.pstdev(v) if len(v)>1 else 0), len(v)) for k,v in by.items()), key=lambda x:x[1])[-11:]
labels=[k for k,_,_,_ in agg]; means=[m for _,m,_,_ in agg]; sds=[s for _,_,s,_ in agg]; ns=[n for _,_,_,n in agg]
lo = [min(s, m) for m, s in zip(means, sds)]   # capa barra de erro inferior em 0
ax[0].barh(labels, means, xerr=[lo, sds], color="#b2182b", error_kw=dict(elinewidth=0.6, ecolor="#777"))
for i,(m,n) in enumerate(zip(means,ns)): ax[0].text(m, i, f"  n={n}", va="center", fontsize=4.5, color="#333")
ax[0].set_xlim(left=0)
ax[0].set_xlabel("mean crit+high / img (±SD)"); ax[0].set_title("(a) Posture by distro",loc="left")

# (b) RQ2: staleness, com +-SD por bucket
bk=[(0,180,"0-6m"),(180,365,"6-12m"),(365,730,"1-2y"),(730,1460,"2-4y"),(1460,1e9,"4y+")]
xs,ys,es=[],[],[]
for lo,hi,lb in bk:
    g=[r["vuln_total"] for r in rows if r["age_days"] is not None and r["vuln_total"] is not None and lo<=r["age_days"]<hi]
    if g: xs.append(lb); ys.append(sum(g)/len(g)); es.append(_st.pstdev(g) if len(g)>1 else 0)
loe = [min(e, y) for y, e in zip(ys, es)]   # capa barra inferior em 0
ax[1].errorbar(xs,ys,yerr=[loe, es],fmt="o-",color="#2166ac",lw=2,capsize=2,elinewidth=0.7); ax[1].set_ylabel("mean vulns (±SD)")
ax[1].set_ylim(bottom=0)
ax[1].set_title("(b) Staleness ρ=0.16",loc="left"); ax[1].tick_params(axis="x",rotation=30)

# (c) RQ5: pacotes x vulns
px=[r["packages"] for r in rows if r["packages"] and r["vuln_total"] is not None]
py=[r["vuln_total"] for r in rows if r["packages"] and r["vuln_total"] is not None]
ax[2].scatter(px,py,s=5,alpha=0.25,color="#1a9850",edgecolors="none")
ax[2].set_xscale("symlog"); ax[2].set_yscale("symlog")
ax[2].set_xlim(left=0); ax[2].set_ylim(bottom=0)   # sem regiao negativa
ax[2].set_xlabel("packages"); ax[2].set_ylabel("vulns"); ax[2].set_title("(c) Minimal safer?",loc="left")

# (d) RQ3: Jaccard 4 engines SCA, por (imagem, CVE) -- justo entre esquemas de
# nome de pacote (Clair usa pacote-fonte; Trivy/Grype, binario)
SCA=["trivy","grype","osv","clair"]; sets={s:set() for s in SCA}
for rj in glob.glob(f"{OUT}/*/report.json"):
    try: r=json.load(open(rj))
    except: continue
    img=r.get("target",{}).get("image","")
    for f in r.get("findings",[]):
        if f.get("category")=="pkg-vuln" and f.get("scanner") in sets:
            cid=f.get("id") or (f.get("cves") or [None])[0]
            if cid and str(cid).startswith("CVE"): sets[f["scanner"]].add((img,cid))
M=[[ (len(sets[a]&sets[b])/len(sets[a]|sets[b]) if (sets[a]|sets[b]) else 0) for b in SCA] for a in SCA]
im=ax[3].imshow(M,cmap="YlOrRd",vmin=0,vmax=1)
ax[3].set_xticks(range(4)); ax[3].set_yticks(range(4))
_nm={"trivy":"Trivy","grype":"Grype","osv":"OSV","clair":"Clair"}
ax[3].set_xticklabels([_nm[s] for s in SCA], rotation=30); ax[3].set_yticklabels([_nm[s] for s in SCA])
for i in range(4):
    for j in range(4):
        ax[3].text(j,i,f"{M[i][j]:.2f}",ha="center",va="center",fontsize=6,
                   color="white" if M[i][j]>0.5 else "black")
ax[3].set_title("(d) CVE agreement (Jaccard)",loc="left"); ax[3].grid(False)

fig.tight_layout(pad=0.4, w_pad=0.8)
fig.savefig(f"{FIG}/fig_panels.pdf"); plt.close(fig)
print("fig_panels.pdf ok | SCA sizes:", {s:len(v) for s,v in sets.items()})

# ---------- Figura 2 (RQ4): nao-pulaveis (schema legado) por distro ----------
import sqlite3
DB = os.environ.get("OSCENSUS_DB") or str(ROOT / "work/os.db")
try:
    c = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    tot = collections.Counter(); skp = collections.Counter(); pulls = {}
    for stt, tj in c.execute("SELECT status,target_json FROM jobs"):
        try:
            d = json.loads(tj); m = d.get("meta") or {}; rp = (m.get("repo") or "?").split("/")[-1]
        except Exception: rp, m = "?", {}
        tot[rp] += 1
        if stt == "skipped": skp[rp] += 1
        if m.get("pull_count") and rp not in pulls: pulls[rp] = m["pull_count"]
    c.close()
    reps = [r for r in tot if tot[r] >= 20]
    unp = {r: 100*skp[r]/tot[r] for r in reps}
    f2, a2 = plt.subplots(1, 3, figsize=(11.5, 2.15))
    it = sorted(reps, key=lambda r: unp[r])
    a2[0].barh(it, [unp[r] for r in it], color="#7b3294")
    a2[0].set_xlabel("% un-pullable"); a2[0].set_title("(a) Legacy schema", loc="left"); a2[0].tick_params(axis="y", labelsize=5.5)
    it2 = sorted([r for r in reps if pulls.get(r)], key=lambda r: pulls[r])
    a2[1].barh(it2, [pulls[r] for r in it2], color="#1b7837"); a2[1].set_xscale("log")
    a2[1].set_xlabel("repository pulls"); a2[1].set_title("(b) Popularity", loc="left"); a2[1].tick_params(axis="y", labelsize=5.5)
    rc = [r for r in reps if pulls.get(r)]
    a2[2].scatter([unp[r] for r in rc], [pulls[r] for r in rc], s=14, color="#762a83", edgecolors="none")
    a2[2].set_yscale("log"); a2[2].set_xlabel("% un-pullable"); a2[2].set_ylabel("pulls")
    a2[2].set_title("(c) Popular & legacy", loc="left")
    f2.tight_layout(pad=0.4, w_pad=0.9); f2.savefig(f"{FIG}/fig_eol.pdf"); plt.close(f2)
    print("fig_eol.pdf ok (3 panels)")
except Exception as e:
    print("fig_eol skip:", e)
