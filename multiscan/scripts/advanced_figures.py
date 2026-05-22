#!/usr/bin/env python3
"""Advanced cross-scanner analyses for the paper, on top of paper_figures.py.

Produces, into the figures directory with an ``adv_`` prefix:
  adv_venn_sca         3-set Venn of the SCA axis (grype/trivy/osv)
  adv_upset_<axis>     UpSet plots (Lex et al. 2014) for the larger axes
  adv_shapley          Shapley-value coverage attribution, per scanner
  adv_clusters         HDBSCAN clustering of the 130 containers
  adv_dendro           hierarchical clustering of scanners (Jaccard distance)
  adv_tversky_sca      Tversky asymmetric containment, SCA axis
and prints a table of robust agreement coefficients (Fleiss kappa,
Krippendorff alpha, Gwet AC1) per axis.

All paths are CLI-configurable; nothing is hardcoded. By default the corpus is
read from ``out/_corpus`` (relative to the repository root) and figures are
written to ``out/_corpus/figures``. Override with ``--corpus`` / ``--out``.
"""
from __future__ import annotations
import argparse, collections, gzip, itertools, json, math, sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

import figstyle

ROOT = Path(__file__).resolve().parent.parent
# CORPUS / FIG are bound by main() from the CLI; module-level defaults keep the
# helper functions importable for tests.
CORPUS = ROOT / "out" / "_corpus"
FIG = CORPUS / "figures"

plt.rcParams.update({"font.size": 9, "font.family": "serif",
                     "axes.spines.top": False, "axes.spines.right": False,
                     "figure.dpi": 150, "savefig.bbox": "tight"})

AXIS_LABEL = {"pkg-vuln": "package vuln (SCA)", "sbom-component": "SBOM",
              "secret": "secrets", "other": "SAST", "image-config": "image config",
              "malware": "malware", "web-vuln": "web (DAST)", "network-vuln": "network"}


def _norm_path(p: str) -> str:
    p = (p or "").strip().lower()
    for pre in ("/scan/", "/scan"):
        if p.startswith(pre):
            p = p[len(pre):]; break
    h, s, t = p.rpartition(":")
    return (h if s and t.isdigit() else p).lstrip("/")


def key(d: dict) -> tuple:
    c = d.get("category", "")
    cv = d.get("cves") or []
    if c in ("pkg-vuln", "network-vuln"):
        return (c, (cv[0] if cv else d.get("id") or "").strip().lower())
    if c == "sbom-component":
        return (c, (d.get("package") or "").strip().lower())
    if c in ("secret", "other", "malware"):
        return (c, _norm_path(d.get("location") or ""))
    if c == "web-vuln":
        return (c, (d.get("id") or d.get("title") or "").lower(),
                (d.get("endpoint") or "").lower())
    return (c, (d.get("id") or d.get("title") or "").strip().lower())


def findings_path() -> Path:
    """Corpus findings file, accepting either a plain or gzip-compressed dataset
    (the released dataset ships ``findings.jsonl.gz`` to fit common size caps)."""
    plain = CORPUS / "findings.jsonl"
    return plain if plain.is_file() else CORPUS / "findings.jsonl.gz"


def open_findings():
    p = findings_path()
    return gzip.open(p, "rt") if p.suffix == ".gz" else open(p)


def load():
    """ax[category][scanner] -> set of (target, key);  by_target[target][category] too."""
    ax = collections.defaultdict(lambda: collections.defaultdict(set))
    with open_findings() as fh:
        for ln in fh:
            ln = ln.strip()
            if not ln:
                continue
            try:
                d = json.loads(ln)
            except json.JSONDecodeError:
                continue
            c = d.get("category", "?")
            ax[c][d.get("scanner", "?")].add((d.get("target_name", "?"), key(d)))
    return ax


def save(fig, name):
    fig.savefig(FIG / f"{name}.pdf")
    plt.close(fig)
    print(f"  {name}.pdf")


# ---- Venn -----------------------------------------------------------------
def fig_venn(axsets):
    from matplotlib_venn import venn3
    sd = axsets.get("pkg-vuln", {})
    order = [s for s in ("grype", "trivy", "osv") if s in sd]
    if len(order) != 3:
        print("  (skip venn: SCA axis needs 3 tools)"); return
    fig, ax = plt.subplots(figsize=(4.0, 3.2))
    v = venn3([sd[s] for s in order], set_labels=order, ax=ax)
    for rid, s in zip(("100", "010", "001"), order):
        p = v.get_patch_by_id(rid)
        if p:
            p.set_color(figstyle.color(s)); p.set_alpha(0.55)
    ax.set_title("SCA axis: shared and exclusive CVEs")
    save(fig, "adv_venn_sca")


def fig_venn_grid(axsets):
    """Venn diagrams for the axes that have actual inter-tool overlap, placed
    side by side. Axes whose scanners share nothing (web, SAST, image config,
    network) are omitted: a Venn of disjoint sets carries no information.
    matplotlib-venn labels the sets outside the circles, so there is no legend
    to overlap the diagram."""
    from matplotlib_venn import venn2, venn3
    panels = [("sbom-component", ["cdxgen", "syft"]),
              ("pkg-vuln", ["grype", "trivy", "osv"]),
              ("secret", ["whispers", "trufflehog", "gitleaks"])]
    fig, axes = plt.subplots(1, 3, figsize=(8.4, 2.9))
    for ax, (axis, scs) in zip(axes, panels):
        sd = axsets.get(axis, {})
        scs = [s for s in scs if s in sd]
        sets = [sd[s] for s in scs]
        # equal-size circles (real counts go on the labels) so extreme size
        # disparity does not shrink a circle into an unreadable dot
        if len(scs) == 2:
            a, b = sets
            real = {"10": len(a - b), "11": len(a & b), "01": len(b - a)}
            v = venn2(subsets=(1, 1, 1), set_labels=scs, ax=ax)
            ids = ("10", "01")
        else:
            a, b, c = sets
            real = {"100": len(a - b - c), "010": len(b - a - c),
                    "001": len(c - a - b), "110": len((a & b) - c),
                    "101": len((a & c) - b), "011": len((b & c) - a),
                    "111": len(a & b & c)}
            v = venn3(subsets=(1,) * 7, set_labels=scs, ax=ax)
            ids = ("100", "010", "001")
        for rid, n in real.items():
            lbl = v.get_label_by_id(rid)
            if lbl:
                lbl.set_text(f"{n:,}")
                # shrink count labels so long numbers stay inside the region
                lbl.set_fontsize(6.5 if len(rid) == 3 else 7.5)
        for sl in (v.set_labels or []):
            if sl:
                sl.set_fontsize(8.5)
        for rid, s in zip(ids, scs):
            p = v.get_patch_by_id(rid)
            if p:
                p.set_color(figstyle.color(s)); p.set_alpha(0.62)
        ax.set_title(AXIS_LABEL.get(axis, axis), fontsize=9)
    save(fig, "adv_venn_grid")


def _draw_upset(container, axis, sd, topn):
    """Draw a hand-rolled UpSet (size bars + membership matrix) into a Figure
    or SubFigure. Scales to any tool count with no relative-size distortion."""
    el2sc = collections.defaultdict(set)
    for s, ks in sd.items():
        for el in ks:
            el2sc[el].add(s)
    combos = collections.Counter(frozenset(v) for v in el2sc.values())
    items = combos.most_common(topn)
    scanners = sorted(sd, key=lambda s: -len(sd[s]))
    axb, axm = container.subplots(
        2, 1, sharex=True,
        gridspec_kw={"height_ratios": [2.0, 1.3], "hspace": 0.06})
    axb.bar(range(len(items)), [n for _, n in items], color="#5577aa", width=0.6)
    for i, (_, n) in enumerate(items):
        axb.text(i, n, f"{n:,}", ha="center", va="bottom", fontsize=6)
    axb.set_yscale("log"); axb.tick_params(labelsize=6)
    axb.spines["bottom"].set_visible(False)
    axb.set_title(AXIS_LABEL.get(axis, axis), fontsize=9)
    for xi, (combo, _) in enumerate(items):
        for yi, s in enumerate(scanners):
            axm.scatter(xi, yi, s=34,
                        color=figstyle.color(s) if s in combo else "#dddddd", zorder=2)
        ys = [yi for yi, s in enumerate(scanners) if s in combo]
        if len(ys) > 1:
            axm.plot([xi, xi], [min(ys), max(ys)], color="#555555", lw=1.4, zorder=1)
    axm.set_yticks(range(len(scanners)))
    axm.set_yticklabels(scanners, fontsize=6.5)
    axm.set_xticks([]); axm.set_ylim(-0.6, len(scanners) - 0.4)
    axm.invert_yaxis()
    for sp in axm.spines.values():
        sp.set_visible(False)


def fig_upset_grid(axsets):
    """One UpSet panel per axis: the per-axis answer to a whole-battery Venn,
    which is undefined since scanners of different axes share no findings."""
    order = [a for a in ("sbom-component", "pkg-vuln", "image-config", "secret",
                          "other", "web-vuln", "network-vuln")
             if len(axsets.get(a, {})) >= 2]
    fig = plt.figure(figsize=(7.8, 8.6))
    subs = fig.subfigures(4, 2).ravel()
    for i, axis in enumerate(order):
        _draw_upset(subs[i], axis, axsets[axis], topn=8)
    for j in range(len(order), len(subs)):
        subs[j].subplots().axis("off")
    save(fig, "adv_upset_grid")


def fig_upset(axsets, axis, name, topn=12):
    sd = axsets.get(axis, {})
    if len(sd) < 3:
        print(f"  (skip upset {axis}: <3 tools)"); return
    fig = plt.figure(figsize=(6.2, 3.9))
    _draw_upset(fig, axis, sd, topn)
    save(fig, name)


# ---- Shapley --------------------------------------------------------------
def shapley(sets: dict) -> dict:
    """Shapley value of each scanner for the coalition game v(C)=|union of C|."""
    scs = list(sets)
    n = len(scs)
    cache = {}

    def v(coal):
        k = frozenset(coal)
        if k not in cache:
            cache[k] = len(set().union(*[sets[s] for s in coal])) if coal else 0
        return cache[k]

    sv = {s: 0.0 for s in scs}
    for s in scs:
        others = [x for x in scs if x != s]
        for r in range(len(others) + 1):
            w = math.factorial(r) * math.factorial(n - r - 1) / math.factorial(n)
            for C in itertools.combinations(others, r):
                sv[s] += w * (v(list(C) + [s]) - v(list(C)))
    return sv


def fig_shapley(axsets):
    rows = []  # (scanner, axis, shapley_pct)
    for c, sd in axsets.items():
        if len(sd) < 2:
            continue
        sv = shapley(sd)
        tot = sum(sv.values()) or 1
        for s, val in sv.items():
            rows.append((s, c, val / tot * 100))
    rows.sort(key=lambda x: x[2])
    fig, ax = plt.subplots(figsize=(5.6, 4.2))
    ax.barh([f"{s}  ({AXIS_LABEL.get(c, c)})" for s, c, _ in rows],
            [v for _, _, v in rows], color=[figstyle.color(s) for s, c, _ in rows])
    for i, (_, _, v) in enumerate(rows):
        ax.text(v + 1, i, f"{v:.0f}", va="center", fontsize=6.3)
    ax.set_xlabel("Shapley value: fair share (%) of the axis's distinct findings")
    ax.set_xlim(0, max(v for *_, v in rows) + 8)
    plt.yticks(fontsize=6.3)
    save(fig, "adv_shapley")
    return rows


# ---- agreement coefficients ----------------------------------------------
def agreement_coeffs(axsets):
    """Per axis: Fleiss kappa, Krippendorff alpha, Gwet AC1 on the binary
    scanner x finding matrix (item = a distinct finding in the axis union)."""
    import krippendorff
    out = []
    for c, sd in sorted(axsets.items()):
        n = len(sd)
        if n < 2:
            continue
        mult = collections.Counter()
        for s, ks in sd.items():
            for el in ks:
                mult[el] += 1
        counts = np.array(list(mult.values()))          # n1 per item
        m = len(counts)
        n1 = counts.astype(float)
        n0 = n - n1
        # observed pairwise agreement
        pa = np.mean((n1 * (n1 - 1) + n0 * (n0 - 1)) / (n * (n - 1)))
        pi1 = np.mean(n1 / n)
        pe_fleiss = pi1 ** 2 + (1 - pi1) ** 2
        kappa = (pa - pe_fleiss) / (1 - pe_fleiss) if pe_fleiss < 1 else 0.0
        pe_gwet = 2 * pi1 * (1 - pi1)
        ac1 = (pa - pe_gwet) / (1 - pe_gwet) if pe_gwet < 1 else 0.0
        # Krippendorff alpha on a (raters x items) 0/1 matrix, subsampled if huge
        scs = list(sd)
        idx = list(range(m))
        if m > 20000:
            rng = np.random.default_rng(0)
            idx = sorted(rng.choice(m, 20000, replace=False))
        elems = list(mult.keys())
        sub = [elems[i] for i in idx]
        rel = np.zeros((n, len(sub)), dtype=int)
        for ri, s in enumerate(scs):
            ks = sd[s]
            for ci, el in enumerate(sub):
                rel[ri, ci] = 1 if el in ks else 0
        try:
            alpha = krippendorff.alpha(reliability_data=rel,
                                       level_of_measurement="nominal")
        except Exception:
            alpha = float("nan")
        out.append((AXIS_LABEL.get(c, c), n, m, kappa, alpha, ac1))
    return out


def fig_agreement_coeffs(axsets):
    """Grouped bars of the three chance-corrected agreement coefficients per
    axis (the visual form of the agreement table)."""
    data = sorted(agreement_coeffs(axsets), key=lambda r: r[3])
    labels = [r[0] for r in data]
    x = np.arange(len(labels))
    w = 0.26
    fig, ax = plt.subplots(figsize=(6.0, 3.0))
    ax.bar(x - w, [r[3] for r in data], w, label=r"Fleiss $\kappa$", color="#c0504d")
    ax.bar(x, [r[4] for r in data], w, label=r"Krippendorff $\alpha$", color="#e0a030")
    ax.bar(x + w, [r[5] for r in data], w, label="Gwet AC1", color="#4a8c5a")
    ax.axhline(0, color="#333333", linewidth=0.8)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=25, ha="right", fontsize=8)
    ax.set_ylabel("chance-corrected agreement")
    ax.legend(fontsize=8, frameon=False, ncol=3)
    save(fig, "adv_agreement_coeffs")


# ---- HDBSCAN clustering of containers -------------------------------------
def fig_clusters(axsets):
    from sklearn.cluster import HDBSCAN
    from sklearn.decomposition import PCA
    from sklearn.preprocessing import StandardScaler
    axes = [a for a in AXIS_LABEL if a in axsets]
    targets = sorted({t for sd in axsets.values() for ks in sd.values() for t, _ in ks})
    feat = []
    for t in targets:
        row = []
        for a in axes:
            sd = axsets[a]
            mult = collections.Counter()
            for s, ks in sd.items():
                for tt, k in ks:
                    if tt == t:
                        mult[k] += 1
            tot = len(mult)
            multi = sum(1 for v in mult.values() if v >= 2)
            row.append(multi / tot if tot else 0.0)        # multi-tool agreement frac
            row.append(math.log1p(tot))                    # finding volume
        feat.append(row)
    X = StandardScaler().fit_transform(np.array(feat))
    lab = HDBSCAN(min_cluster_size=5, min_samples=3).fit_predict(X)
    xy = PCA(n_components=2, random_state=0).fit_transform(X)
    fig, ax = plt.subplots(figsize=(5.0, 3.4))
    for cl in sorted(set(lab)):
        m = lab == cl
        ax.scatter(xy[m, 0], xy[m, 1], s=22,
                   label=("noise" if cl == -1 else f"cluster {cl}"),
                   color="#bbbbbb" if cl == -1 else None)
    ax.set_xlabel("PCA 1"); ax.set_ylabel("PCA 2")
    ax.legend(fontsize=7, frameon=False)
    ax.set_title("Containers clustered by cross-scanner agreement profile")
    save(fig, "adv_clusters")
    nclust = len({c for c in lab if c != -1})
    print(f"  HDBSCAN: {nclust} clusters, {(lab == -1).sum()}/{len(lab)} noise")
    return lab, targets


# ---- dendrogram -----------------------------------------------------------
def fig_dendro(axsets):
    from scipy.cluster.hierarchy import linkage, dendrogram
    from scipy.spatial.distance import squareform
    scs = sorted({s for sd in axsets.values() for s in sd},
                 key=lambda s: next(c for c, sd in axsets.items() if s in sd))
    sset = {}
    for c, sd in axsets.items():
        for s, ks in sd.items():
            sset.setdefault(s, set()).update(ks)
    n = len(scs)
    D = np.zeros((n, n))
    for i in range(n):
        for j in range(i + 1, n):
            a, b = sset[scs[i]], sset[scs[j]]
            u = len(a | b)
            jac = len(a & b) / u if u else 0.0
            D[i, j] = D[j, i] = 1 - jac
    Z = linkage(squareform(D), method="average")
    fig, ax = plt.subplots(figsize=(5.8, 3.4))
    dendrogram(Z, labels=scs, ax=ax, leaf_font_size=6.5,
               color_threshold=0.999)
    ax.set_ylabel("1 - Jaccard")
    ax.set_title("Scanner similarity (hierarchical clustering)")
    plt.xticks(rotation=80)
    save(fig, "adv_dendro")


# ---- Tversky --------------------------------------------------------------
def fig_tversky(axsets):
    sd = axsets.get("pkg-vuln", {})
    order = [s for s in ("grype", "trivy", "osv") if s in sd]
    if len(order) < 2:
        return
    n = len(order)
    M = np.zeros((n, n))
    for i, a in enumerate(order):
        for j, b in enumerate(order):
            A = sd[a]
            M[i, j] = len(A & sd[b]) / len(A) if A else 0.0
    fig, ax = plt.subplots(figsize=(3.4, 3.0))
    im = ax.imshow(M, cmap="YlGnBu", vmin=0, vmax=1)
    ax.set_xticks(range(n)); ax.set_yticks(range(n))
    ax.set_xticklabels(order); ax.set_yticklabels(order)
    for i in range(n):
        for j in range(n):
            ax.text(j, i, f"{M[i, j]:.2f}", ha="center", va="center",
                    color="white" if M[i, j] > 0.55 else "black", fontsize=8)
    ax.set_title("Tversky containment\n(row's findings also seen by column)")
    fig.colorbar(im, fraction=0.046, pad=0.04)
    save(fig, "adv_tversky_sca")


def _parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", type=Path, default=CORPUS,
                    help="directory holding findings.jsonl / metrics.csv "
                         f"(default: {CORPUS.relative_to(ROOT)})")
    ap.add_argument("--out", type=Path, default=None,
                    help="directory for the generated PDF figures "
                         "(default: <corpus>/figures)")
    return ap.parse_args(argv)


def main(argv=None):
    global CORPUS, FIG
    args = _parse_args(argv)
    CORPUS = args.corpus
    FIG = args.out if args.out is not None else CORPUS / "figures"
    if not findings_path().is_file():
        print(f"error: corpus not found at {CORPUS}/findings.jsonl[.gz]", file=sys.stderr)
        return 1
    FIG.mkdir(parents=True, exist_ok=True)
    print("loading corpus ...")
    axsets = load()
    print(f"axes: {sorted(axsets)}")
    fig_venn(axsets)
    fig_venn_grid(axsets)
    fig_upset_grid(axsets)
    rows = fig_shapley(axsets)
    fig_dendro(axsets)
    fig_tversky(axsets)
    fig_clusters(axsets)
    fig_agreement_coeffs(axsets)
    print("\nShapley coverage attribution (fair share %):")
    for s, c, v in sorted(rows, key=lambda x: (x[1], -x[2])):
        print(f"  {AXIS_LABEL.get(c, c):20s} {s:14s} {v:5.1f}%")
    print("\nRobust agreement coefficients per axis:")
    print(f"  {'axis':22s} {'tools':>5s} {'items':>9s} {'Fleiss k':>9s} {'Kripp a':>8s} {'Gwet AC1':>9s}")
    for axis, n, m, k, a, ac1 in agreement_coeffs(axsets):
        print(f"  {axis:22s} {n:>5d} {m:>9d} {k:>9.3f} {a:>8.3f} {ac1:>9.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
