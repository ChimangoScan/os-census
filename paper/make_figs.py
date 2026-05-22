#!/usr/bin/env python3
"""Figuras do paper: UM painel horizontal 1x4 (altura minima) a partir de
data/analysis/per_image.csv e dos report.json.
Rodar:  uv run --with matplotlib python make_figs.py
"""
import csv, json, glob, collections, os
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

# (a) RQ1: media criticas+altas por distro (top 11)
by = collections.defaultdict(list)
for r in rows:
    if r["vuln_critical"] is not None and r["vuln_high"] is not None:
        by[short(r["repo"])].append(r["vuln_critical"]+r["vuln_high"])
st = sorted(((k,sum(v)/len(v)) for k,v in by.items()), key=lambda x:x[1])[-11:]
ax[0].barh([k for k,_ in st],[m for _,m in st],color="#b2182b")
ax[0].set_xlabel("mean crit+high / img"); ax[0].set_title("(a) Posture by distro",loc="left")

# (b) RQ2: staleness
bk=[(0,180,"0-6m"),(180,365,"6-12m"),(365,730,"1-2y"),(730,1460,"2-4y"),(1460,1e9,"4y+")]
xs,ys=[],[]
for lo,hi,lb in bk:
    g=[r["vuln_total"] for r in rows if r["age_days"] is not None and r["vuln_total"] is not None and lo<=r["age_days"]<hi]
    if g: xs.append(lb); ys.append(sum(g)/len(g))
ax[1].plot(xs,ys,"o-",color="#2166ac",lw=2); ax[1].set_ylabel("mean vulns")
ax[1].set_title("(b) Staleness",loc="left"); ax[1].tick_params(axis="x",rotation=30)

# (c) RQ5: pacotes x vulns
px=[r["packages"] for r in rows if r["packages"] and r["vuln_total"] is not None]
py=[r["vuln_total"] for r in rows if r["packages"] and r["vuln_total"] is not None]
ax[2].scatter(px,py,s=5,alpha=0.25,color="#1a9850",edgecolors="none")
ax[2].set_xscale("symlog"); ax[2].set_yscale("symlog")
ax[2].set_xlabel("packages"); ax[2].set_ylabel("vulns"); ax[2].set_title("(c) Minimal safer?",loc="left")

# (d) RQ3: Jaccard 4 engines SCA
SCA=["trivy","grype","osv","clair"]; sets={s:set() for s in SCA}
for rj in glob.glob(f"{OUT}/*/report.json"):
    try: r=json.load(open(rj))
    except: continue
    img=r.get("target",{}).get("image","")
    for f in r.get("findings",[]):
        if f.get("category")=="pkg-vuln" and f.get("scanner") in sets:
            cid=f.get("id") or (f.get("cves") or [None])[0]
            if cid: sets[f["scanner"]].add((img,cid,f.get("package")))
M=[[ (len(sets[a]&sets[b])/len(sets[a]|sets[b]) if (sets[a]|sets[b]) else 0) for b in SCA] for a in SCA]
im=ax[3].imshow(M,cmap="YlOrRd",vmin=0,vmax=1)
ax[3].set_xticks(range(4)); ax[3].set_yticks(range(4))
ax[3].set_xticklabels([s[:3].capitalize() for s in SCA]); ax[3].set_yticklabels([s[:3].capitalize() for s in SCA])
for i in range(4):
    for j in range(4):
        ax[3].text(j,i,f"{M[i][j]:.2f}",ha="center",va="center",fontsize=6,
                   color="white" if M[i][j]>0.5 else "black")
ax[3].set_title("(d) SCA Jaccard",loc="left"); ax[3].grid(False)

fig.tight_layout(pad=0.4, w_pad=0.8)
fig.savefig(f"{FIG}/fig_panels.pdf"); plt.close(fig)
print("fig_panels.pdf ok | SCA sizes:", {s:len(v) for s,v in sets.items()})
