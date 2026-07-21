#!/usr/bin/env python3
"""Figuras: uma figura 1x4 por RQ (linha horizontal, altura minima).
Saidas: fig_rq1..fig_rq5, fig_repro em figures/.
Rodar:  uv run --with matplotlib,numpy python scripts/make_figs.py
"""
import csv, json, glob, collections, os, sqlite3, re, statistics as st
from pathlib import Path
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent
CSV  = str(ROOT / "data/analysis/per_image.csv")
FIG  = str(ROOT / "figures")
OUT  = str(os.environ.get("OSCENSUS_OUT") or ROOT/"scan-out"/"out_so")
DB   = os.environ.get("OSCENSUS_DB") or str(ROOT / "work/os.db")
plt.rcParams.update({"font.size": 9, "axes.grid": True, "grid.alpha": 0.25, "axes.axisbelow": True,
                     "savefig.bbox": "tight", "axes.titlesize": 9.5, "xtick.labelsize": 8, "ytick.labelsize": 8})
FS = (12.6, 2.25)   # 1x4 horizontal, baixo

def short(r): return (r or "?").split("/")[-1]
def fnum(x):
    try: return float(x)
    except: return None

rows = list(csv.DictReader(open(CSV)))
for r in rows:
    for k in ("age_days","pull_count","packages","vuln_critical","vuln_high","vuln_medium","vuln_low",
              "vuln_total","secrets","misconfig","malware"):
        r[k] = fnum(r.get(k))

# agrega por distro (>=10 imgs)
byd = collections.defaultdict(list)
for r in rows: byd[short(r["repo"])].append(r)
distros = [d for d in byd if len(byd[d]) >= 10]

def dmean(d, fn):
    v = [fn(r) for r in byd[d] if fn(r) is not None]
    return st.mean(v) if v else 0

# ----------------------------------------------------------------- RQ1
fig, ax = plt.subplots(1, 4, figsize=FS)
ch = sorted(distros, key=lambda d: dmean(d, lambda r: (r["vuln_critical"] or 0)+(r["vuln_high"] or 0)))[-11:]
ax[0].barh(ch, [dmean(d, lambda r:(r["vuln_critical"] or 0)+(r["vuln_high"] or 0)) for d in ch], color="#b2182b")
ax[0].set_xlabel("mean crit+high"); ax[0].set_title("(a) Crit+high / distro", loc="left"); ax[0].set_xlim(left=0); ax[0].tick_params(axis="y", labelsize=7.5)
# (b) composicao de severidade (% empilhado) p/ top distros por total
tt = sorted(distros, key=lambda d: dmean(d, lambda r:r["vuln_total"]))[-9:]
sev = ["vuln_critical","vuln_high","vuln_medium","vuln_low"]; cols=["#67000d","#ef3b2c","#fc9272","#fee0d2"]
bot=[0]*len(tt)
for s,c in zip(sev,cols):
    vals=[dmean(d, lambda r,s=s:r[s]) for d in tt]
    tot=[max(dmean(d, lambda r:r["vuln_total"]),1) for d in tt]
    pct=[100*v/t for v,t in zip(vals,tot)]
    ax[1].barh(tt,pct,left=bot,color=c,label=s.split("_")[1]); bot=[b+p for b,p in zip(bot,pct)]
ax[1].set_xlabel("% of findings"); ax[1].set_title("(b) Severity mix", loc="left"); ax[1].tick_params(axis="y", labelsize=7.5); ax[1].legend(fontsize=6, ncol=2, loc="lower right")
# (c) % com >=1 critica por distro
pc = sorted(distros, key=lambda d: 100*sum(1 for r in byd[d] if (r["vuln_critical"] or 0)>0)/len(byd[d]))[-11:]
ax[2].barh(pc, [100*sum(1 for r in byd[d] if (r["vuln_critical"] or 0)>0)/len(byd[d]) for d in pc], color="#d94801")
ax[2].set_xlabel("% with >=1 critical"); ax[2].set_title("(c) Critical prevalence", loc="left"); ax[2].set_xlim(0,100); ax[2].tick_params(axis="y", labelsize=7.5)
# (d) mean total vulns por distro
tv = sorted(distros, key=lambda d: dmean(d, lambda r:r["vuln_total"]))[-11:]
ax[3].barh(tv, [dmean(d, lambda r:r["vuln_total"]) for d in tv], color="#08519c")
ax[3].set_xlabel("mean total vulns"); ax[3].set_title("(d) Total / distro", loc="left"); ax[3].set_xlim(left=0); ax[3].tick_params(axis="y", labelsize=7.5)
fig.tight_layout(pad=0.4, w_pad=0.8); fig.savefig(f"{FIG}/fig_rq1.pdf"); plt.close(fig); print("fig_rq1 ok")

# ----------------------------------------------------------------- RQ2 (1x4)
fig, ax = plt.subplots(1, 4, figsize=FS)
bk=[(0,180,"0-6m"),(180,365,"6-12m"),(365,730,"1-2y"),(730,1460,"2-4y"),(1460,1e9,"4y+")]
def bucket(col):
    xs,ys,es=[],[],[]
    for lo,hi,lb in bk:
        g=[r[col] for r in rows if r["age_days"] is not None and r[col] is not None and lo<=r["age_days"]<hi]
        if g: xs.append(lb); ys.append(st.mean(g)); es.append(st.pstdev(g) if len(g)>1 else 0)
    return xs,ys,es
xs,ys,es=bucket("vuln_total"); lo=[min(e,y) for y,e in zip(ys,es)]
ax[0].errorbar(xs,ys,yerr=[lo,es],fmt="o-",color="#2166ac",lw=2,capsize=2,elinewidth=.7); ax[0].set_ylim(bottom=0)
ax[0].set_ylabel("mean total"); ax[0].set_title("(a) Total vs age (rho=0.27)", loc="left"); ax[0].tick_params(axis="x",rotation=30)
xs2,ys2,_=bucket("vuln_critical"); xh,yh,_=bucket("vuln_high")
ax[1].plot(xs2,ys2,"o-",label="crit",color="#67000d"); ax[1].plot(xh,yh,"s-",label="high",color="#ef3b2c")
ax[1].set_ylim(bottom=0); ax[1].set_ylabel("mean"); ax[1].set_title("(b) Crit/high vs age", loc="left"); ax[1].tick_params(axis="x",rotation=30); ax[1].legend(fontsize=7)
ag=[r["age_days"]/365 for r in rows if r["age_days"] is not None and r["vuln_total"] is not None]
vt=[r["vuln_total"] for r in rows if r["age_days"] is not None and r["vuln_total"] is not None]
ax[2].scatter(ag,vt,s=5,alpha=.2,color="#2166ac",edgecolors="none"); ax[2].set_ylim(bottom=0); ax[2].set_xlim(left=0)
ax[2].set_xlabel("age (years)"); ax[2].set_ylabel("total"); ax[2].set_title("(c) Per-image", loc="left")
pcb=[]
for lo_,hi_,lb in bk:
    g=[r for r in rows if r["age_days"] is not None and lo_<=r["age_days"]<hi_]
    if g: pcb.append((lb,100*sum(1 for r in g if (r["vuln_critical"] or 0)>0)/len(g)))
ax[3].plot([a for a,_ in pcb],[b for _,b in pcb],"o-",color="#d94801"); ax[3].set_ylim(0,100)
ax[3].set_ylabel("% with >=1 crit"); ax[3].set_title("(d) Critical vs age", loc="left"); ax[3].tick_params(axis="x",rotation=30)
fig.tight_layout(pad=0.4, w_pad=0.8); fig.savefig(f"{FIG}/fig_rq2.pdf"); plt.close(fig); print("fig_rq2 ok")

# ----------------------------------------------------------------- RQ3
# Le os report.json brutos se existirem; senao usa o dump pre-computado
# (data/analysis/rq3_sca_sets.json.gz) -> reproducao sem precisar do scan bruto.
SCA=["trivy","grype","osv","clair"]; sets={s:set() for s in SCA}
_reports=glob.glob(f"{OUT}/*/report.json")
if _reports:
    for rj in _reports:
        try: r=json.load(open(rj))
        except: continue
        img=r.get("target",{}).get("image","")
        for f in r.get("findings",[]):
            if f.get("category")=="pkg-vuln" and f.get("scanner") in sets:
                cid=f.get("id") or (f.get("cves") or [None])[0]
                if cid and str(cid).startswith("CVE"): sets[f["scanner"]].add((img,cid))
else:
    import gzip
    dump=ROOT/"data/analysis/rq3_sca_sets.json.gz"
    with gzip.open(dump,"rt") as fi:
        for s,pairs in json.load(fi).items(): sets[s]={tuple(p) for p in pairs}
    print(f"RQ3: usando dump pre-computado ({dump.name})")
# Normaliza o identificador para o CVE-id canonico antes de cruzar os conjuntos:
# o Clair grava metade das entradas como o nome completo do vuln
# ("CVE-XXXX-YYYY on Ubuntu 20.04 ..."), que sem normalizar nunca cruza com os
# CVE-ids limpos dos demais engines e inflaria artificialmente a divergencia.
_CVE=re.compile(r"CVE-\d{4}-\d+")
for s in SCA:
    sets[s]={(img,_CVE.search(str(c)).group(0)) for (img,c) in sets[s] if _CVE.search(str(c))}
_nm={"trivy":"Trivy","grype":"Grype","osv":"OSV","clair":"Clair"}
fig, ax = plt.subplots(1, 4, figsize=FS)
M=[[ (len(sets[a]&sets[b])/len(sets[a]|sets[b]) if (sets[a]|sets[b]) else 0) for b in SCA] for a in SCA]
im=ax[0].imshow(M,cmap="YlOrRd",vmin=0,vmax=1); ax[0].set_xticks(range(4)); ax[0].set_yticks(range(4))
ax[0].set_xticklabels([_nm[s] for s in SCA],rotation=30); ax[0].set_yticklabels([_nm[s] for s in SCA])
for i in range(4):
    for j in range(4): ax[0].text(j,i,f"{M[i][j]:.2f}",ha="center",va="center",fontsize=7,color="white" if M[i][j]>.5 else "black")
ax[0].set_title("(a) Jaccard (CVE)", loc="left"); ax[0].grid(False)
ax[1].bar([_nm[s] for s in SCA],[len(sets[s]) for s in SCA],color="#7b3294"); ax[1].set_yscale("log")
ax[1].set_ylabel("image-CVE pairs"); ax[1].set_title("(b) Coverage", loc="left"); ax[1].tick_params(axis="x",rotation=30)
allp=collections.Counter()
for s in SCA:
    for k in sets[s]: allp[k]+=1
hist=collections.Counter(allp.values())
ax[2].bar([1,2,3,4],[hist.get(i,0) for i in (1,2,3,4)],color="#238b45"); ax[2].set_yscale("log")
ax[2].set_xlabel("# scanners agreeing"); ax[2].set_xticks([1,2,3,4]); ax[2].set_ylabel("CVE-image pairs"); ax[2].set_title("(c) Agreement", loc="left")
uniq=[]
for s in SCA:
    others=set().union(*[sets[o] for o in SCA if o!=s]) if any(o!=s for o in SCA) else set()
    uniq.append(len(sets[s]-others))
ax[3].bar([_nm[s] for s in SCA],uniq,color="#b2182b"); ax[3].set_yscale("log")
ax[3].set_ylabel("unique pairs"); ax[3].set_title("(d) Scanner-only", loc="left"); ax[3].tick_params(axis="x",rotation=30)
fig.tight_layout(pad=0.4, w_pad=0.9); fig.savefig(f"{FIG}/fig_rq3.pdf"); plt.close(fig)
print("fig_rq3 ok | sizes:", {s:len(v) for s,v in sets.items()})

# ----------------------------------------------------------------- RQ4 (fila: skip + pulls)
# Le work/os.db se existir; senao o extrato versionado data/analysis/job_status.csv.gz
# (gerado por scripts/export_job_status.py) -> reproducao sem a fila original.
fig, ax = plt.subplots(1, 4, figsize=FS)
try:
    tot=collections.Counter(); skp=collections.Counter(); pulls={}
    if os.path.exists(DB):
        c=sqlite3.connect(f"file:{DB}?mode=ro",uri=True)
        jobs=[]
        for stt,tj in c.execute("SELECT status,target_json FROM jobs"):
            try: d=json.loads(tj); m=d.get("meta") or {}
            except: m={}
            jobs.append((short(m.get("repo")) if m else "?", stt, m.get("pull_count")))
        c.close()
    else:
        import gzip
        with gzip.open(ROOT/"data/analysis/job_status.csv.gz","rt") as fi:
            jobs=[(short(r["repo"]), r["status"], fnum(r["pull_count"])) for r in csv.DictReader(fi)]
        print("RQ4: usando extrato pre-computado (job_status.csv.gz)")
    for rp,stt,pc in jobs:
        tot[rp]+=1
        if stt=="skipped": skp[rp]+=1
        if pc and rp not in pulls: pulls[rp]=pc
    reps=[r for r in tot if tot[r]>=20]; unp={r:100*skp[r]/tot[r] for r in reps}
    it=sorted(reps,key=lambda r:unp[r])
    ax[0].barh(it,[unp[r] for r in it],color="#7b3294"); ax[0].set_xlabel("% un-pullable"); ax[0].set_title("(a) Legacy schema",loc="left"); ax[0].tick_params(axis="y",labelsize=7.5)
    it2=sorted([r for r in reps if pulls.get(r)],key=lambda r:pulls[r])
    ax[1].barh(it2,[pulls[r] for r in it2],color="#1b7837"); ax[1].set_xscale("log"); ax[1].set_xlabel("repo pulls"); ax[1].set_title("(b) Popularity",loc="left"); ax[1].tick_params(axis="y",labelsize=7.5)
    its=sorted(reps,key=lambda r:skp[r])
    ax[2].barh(its,[skp[r] for r in its],color="#54278f"); ax[2].set_xlabel("un-pullable count"); ax[2].set_title("(c) Absolute",loc="left"); ax[2].tick_params(axis="y",labelsize=7.5)
    rc=[r for r in reps if pulls.get(r)]
    ax[3].scatter([unp[r] for r in rc],[pulls[r] for r in rc],s=14,color="#762a83",edgecolors="none"); ax[3].set_yscale("log")
    ax[3].set_xlabel("% un-pullable"); ax[3].set_ylabel("pulls"); ax[3].set_title("(d) Popular & legacy",loc="left")
    fig.tight_layout(pad=0.4, w_pad=0.9); fig.savefig(f"{FIG}/fig_rq4.pdf"); plt.close(fig); print("fig_rq4 ok")
except Exception as e:
    print("fig_rq4 skip:", e)

# ----------------------------------------------------------------- RQ5 (1x4)
fig, ax = plt.subplots(1, 4, figsize=FS)
px=[r["packages"] for r in rows if r["packages"] and r["vuln_total"] is not None]
py=[r["vuln_total"] for r in rows if r["packages"] and r["vuln_total"] is not None]
ax[0].scatter(px,py,s=5,alpha=.25,color="#1a9850",edgecolors="none"); ax[0].set_xscale("symlog"); ax[0].set_yscale("symlog")
ax[0].set_xlim(left=0); ax[0].set_ylim(bottom=0); ax[0].set_xlabel("packages"); ax[0].set_ylabel("total vulns"); ax[0].set_title("(a) Packages vs vulns", loc="left")
# (b) regressao multipla padronizada: idade vs pacotes (driver dominante)
def _pear(xs,ys):
    n=len(xs); mx=sum(xs)/n; my=sum(ys)/n
    sx=(sum((x-mx)**2 for x in xs))**.5; sy=(sum((y-my)**2 for y in ys))**.5
    return sum((x-mx)*(y-my) for x,y in zip(xs,ys))/(sx*sy) if sx and sy else 0
trip=[(r["packages"],r["age_days"],r["vuln_total"]) for r in rows if r["packages"] and r["age_days"] is not None and r["vuln_total"] is not None]
P=[t[0] for t in trip]; A=[t[1] for t in trip]; Vv=[t[2] for t in trip]
ry1=_pear(Vv,P); ry2=_pear(Vv,A); r12=_pear(P,A); den=(1-r12*r12) or 1
b_pkg=(ry1-ry2*r12)/den; b_age=(ry2-ry1*r12)/den
ax[1].bar(["age","packages"],[b_age,b_pkg],color=["#2166ac","#1a9850"]); ax[1].axhline(0,color="k",lw=.5)
ax[1].set_ylabel("standardized $\\beta$"); ax[1].set_title("(b) Drivers of vuln. load", loc="left")
# (c) popularidade: pulls vs vulns (popularidade nao protege)
pu=[(r["pull_count"],r["vuln_total"]) for r in rows if r["pull_count"] and r["vuln_total"] is not None]
ax[2].scatter([p for p,_ in pu],[v for _,v in pu],s=5,alpha=.25,color="#b2182b",edgecolors="none")
ax[2].set_xscale("symlog"); ax[2].set_xlim(left=0); ax[2].set_ylim(bottom=0)
ax[2].set_xlabel("pulls"); ax[2].set_ylabel("total vulns"); ax[2].set_title("(c) Popularity vs vulns", loc="left")
# (d) vulns/package por distro
vpp=sorted(distros,key=lambda d: dmean(d, lambda r:(r["vuln_total"] or 0)/r["packages"] if r["packages"] else 0))[-11:]
ax[3].barh(vpp,[dmean(d, lambda r:(r["vuln_total"] or 0)/r["packages"] if r["packages"] else 0) for d in vpp],color="#6a51a3")
ax[3].set_xlabel("vulns / package"); ax[3].set_title("(d) Density / distro", loc="left"); ax[3].set_xlim(left=0); ax[3].tick_params(axis="y",labelsize=7.5)
fig.tight_layout(pad=0.4, w_pad=0.8); fig.savefig(f"{FIG}/fig_rq5.pdf"); plt.close(fig); print(f"fig_rq5 ok (b_age={b_age:.2f} b_pkg={b_pkg:.2f})")

# ----------------------------------------------------------------- Reproducoes (prior vs ours)
def _frac(pred, dom):
    v=[r for r in rows if dom(r)]; return 100*sum(1 for r in v if pred(r))/len(v) if v else 0
hs =_frac(lambda r:((r["vuln_critical"] or 0)+(r["vuln_high"] or 0))>0, lambda r:r["vuln_total"] is not None)
sec=_frac(lambda r:(r["secrets"] or 0)>0, lambda r:r["secrets"] is not None)
kv =_frac(lambda r:(r["vuln_total"] or 0)>0, lambda r:r["vuln_total"] is not None)
labels=["Shu '17\n(high-sev)","Dahlmanns '23\n(secrets, raw)","Dr.Docker '25\n(known-vuln)"]
prior=[80.0,8.5,93.7]; ours=[hs,sec,kv]; xs=[0,1,2]; w=0.38
fig, ax = plt.subplots(figsize=(4.7,2.3))
ax.bar([x-w/2 for x in xs],prior,w,label="reported",color="#9ecae1",edgecolor="#3182bd",lw=.4)
ax.bar([x+w/2 for x in xs],ours,w,label="ours",color="#08519c")
ax.set_xticks(xs); ax.set_xticklabels(labels,fontsize=7); ax.set_ylabel("% of images"); ax.set_ylim(0,108)
ax.legend(fontsize=7.5,loc="upper center"); ax.set_title("(a) Prior reported vs ours", loc="left")
for x,v in zip(xs,prior): ax.text(x-w/2,v+1.5,f"{v:g}",ha="center",fontsize=6.5)
for x,v in zip(xs,ours):  ax.text(x+w/2,v+1.5,f"{v:.0f}",ha="center",fontsize=6.5)
fig.tight_layout(pad=0.4); fig.savefig(f"{FIG}/fig_repro.pdf"); plt.close(fig); print(f"fig_repro ok (hs={hs:.0f} sec={sec:.0f} kv={kv:.0f})")

# ----------------------------------------------------------------- fig_repro2
# Reproduz 4 plots classicos de trabalhos anteriores no NOSSO corpus:
# (a) Shu'17 Fig.4 CDF de vulns/imagem; (b) Ibrahim'20 Fig.17 / Wist'21 Fig.3 vulns por distro (box);
# (c) Boles'24 Fig.3 diferenca por-imagem (Grype-Trivy); (d) Wist'21 Fig.6 pulls vs vulns (rho).
import numpy as _np, gzip as _gz
def _spear(a, b):
    a = _np.asarray(a, float); b = _np.asarray(b, float)
    ra = _np.argsort(_np.argsort(a)); rb = _np.argsort(_np.argsort(b))
    return float(_np.corrcoef(ra, rb)[0, 1])
fig, ax = plt.subplots(1, 4, figsize=FS)
# (a) CDF de vulns/imagem
vt = sorted(r["vuln_total"] for r in rows if r["vuln_total"] is not None)
ax[0].plot(vt, [(i+1)/len(vt) for i in range(len(vt))], color="#08519c", lw=1.3)
ax[0].axvline(st.median(vt), color="#d95f02", ls="--", lw=.7)
ax[0].set_xscale("symlog"); ax[0].set_xlabel("vulns / image"); ax[0].set_ylabel("CDF")
ax[0].set_title(f"(a) CDF, median {st.median(vt):.0f} [Shu'17]", loc="left")
# (b) box por distro (top 9 por mediana)
topd = sorted(distros, key=lambda d: st.median([r["vuln_total"] for r in byd[d] if r["vuln_total"] is not None]))[-9:]
ax[1].boxplot([[r["vuln_total"] for r in byd[d] if r["vuln_total"] is not None] for d in topd],
              showfliers=False, widths=.6)
ax[1].set_xticklabels(topd, rotation=40, ha="right", fontsize=7); ax[1].set_yscale("log")
ax[1].set_ylabel("vulns / image"); ax[1].set_title("(b) vulns by distro [Ibrahim'20]", loc="left")
# (c) Grype - Trivy por imagem
_S = json.load(_gz.open(ROOT/"data/analysis/rq3_sca_sets.json.gz", "rt"))
def _cnt(scan):
    c = collections.Counter()
    for img, _ in _S[scan]: c[img] += 1
    return c
_g, _t = _cnt("grype"), _cnt("trivy")
_diff = [_g.get(i, 0) - _t.get(i, 0) for i in (set(_g) | set(_t))]
ax[2].hist(_diff, bins=70, color="#7b3294"); ax[2].axvline(0, color="k", lw=.6)
ax[2].set_xlabel("Grype $-$ Trivy (CVEs/image)"); ax[2].set_ylabel("images")
ax[2].set_title(f"(c) Grype$>$Trivy in {100*sum(1 for d in _diff if d>0)/len(_diff):.0f}% [Boles'24]", loc="left")
# (d) pulls vs vulns
_p = [(r["pull_count"], r["vuln_total"]) for r in rows if r["pull_count"] and r["vuln_total"] is not None]
ax[3].scatter([x for x,_ in _p], [y for _,y in _p], s=3, alpha=.18, color="#238b45", edgecolors="none")
ax[3].set_xscale("log"); ax[3].set_xlabel("pull count"); ax[3].set_ylabel("vulns / image")
ax[3].set_title(f"(d) pulls vs vulns $\\rho$={_spear([x for x,_ in _p],[y for _,y in _p]):.2f} [Wist'21]", loc="left")
fig.tight_layout(pad=0.4, w_pad=0.9); fig.savefig(f"{FIG}/fig_repro2.pdf"); plt.close(fig)
print(f"fig_repro2 ok (n={len(vt)}, pulls-rho shown)")
