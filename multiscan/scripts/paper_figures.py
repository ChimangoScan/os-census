#!/usr/bin/env python3
"""Polished, standardized figures for the paper.

Curated subset of the analysis (see figures.py for the full exploratory set):
overview, SCA-axis Jaccard, agreement tiers, saturation, exclusivity, cost.

All paths are CLI-configurable; nothing is hardcoded. By default the corpus is
read from ``out/_corpus`` (relative to the repository root) and figures are
written to ``out/_corpus/figures``. Override with ``--corpus`` / ``--out``::

    python scripts/paper_figures.py --corpus results/_corpus --out results/figures
"""
from __future__ import annotations
import argparse, collections, csv, gzip, itertools, json, statistics, sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator

import figstyle

ROOT = Path(__file__).resolve().parent.parent
# CORPUS / FIG are bound by main() from the CLI; module-level defaults keep the
# helper functions importable for tests.
CORPUS = ROOT / "out" / "_corpus"
FIG = CORPUS / "figures"

plt.rcParams.update({
    "font.size": 10, "font.family": "serif", "axes.titlesize": 10,
    "axes.spines.top": False, "axes.spines.right": False,
    "figure.dpi": 150, "savefig.bbox": "tight", "axes.grid": False,
})
C = {"static": "#3a6ea5", "dynamic": "#c25a3a", "accent": "#4a8c5a",
     "bar": "#5577aa", "warn": "#cc8844"}
AXIS_LABEL = {"pkg-vuln": "package vuln (SCA)", "sbom-component": "SBOM",
              "secret": "secrets", "other": "SAST", "image-config": "image config",
              "malware": "malware", "web-vuln": "web (DAST)", "network-vuln": "network"}
DYNAMIC = {"web-vuln", "network-vuln"}


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
    rows = []
    with open_findings() as fh:
        for ln in fh:
            ln = ln.strip()
            if ln:
                try:
                    d = json.loads(ln)
                except json.JSONDecodeError:
                    continue
                rows.append((d.get("scanner", "?"), d.get("category", "?"),
                             key(d), d.get("target_name", "?")))
    return rows


def jacc(a, b):
    u = a | b
    return len(a & b) / len(u) if u else 0.0


def save(fig, name):
    fig.savefig(FIG / f"{name}.pdf")
    plt.close(fig)
    print(f"  {name}.pdf")


def fig_overview(rows):
    by = collections.Counter(c for _, c, _, _ in rows)
    items = by.most_common()
    fig, ax = plt.subplots(figsize=(5.0, 2.3))
    ax.bar([AXIS_LABEL.get(c, c) for c, _ in items], [n for _, n in items],
           color=[C["dynamic"] if c in DYNAMIC else C["static"] for c, _ in items])
    ax.set_yscale("log"); ax.set_ylabel("findings (log scale)")
    for i, (_, n) in enumerate(items):
        ax.text(i, n, f"{n:,}", ha="center", va="bottom", fontsize=7)
    plt.xticks(rotation=25, ha="right")
    ax.legend(handles=[plt.Rectangle((0, 0), 1, 1, color=C["static"]),
                       plt.Rectangle((0, 0), 1, 1, color=C["dynamic"])],
              labels=["static", "dynamic"], fontsize=8, frameon=False)
    save(fig, "fig_overview")


def per_axis_sets(rows):
    ax = collections.defaultdict(lambda: collections.defaultdict(set))
    for s, c, k, t in rows:
        ax[c][s].add((t, k))
    return ax


def fig_jaccard(axsets):
    """Pairwise Jaccard heatmap, one panel per axis. Showing every axis (not
    just SCA) is the point: SBOM, SCA and secrets carry colour, the rest are
    all-zero off-diagonal, i.e. their tools are disjoint."""
    order = [a for a in ("sbom-component", "pkg-vuln", "secret", "other",
                          "image-config", "web-vuln", "network-vuln")
             if len(axsets.get(a, {})) >= 2]
    cols = 4
    nrows = (len(order) + cols - 1) // cols
    fig, axes = plt.subplots(nrows, cols, figsize=(3.2 * cols, 3.0 * nrows),
                             constrained_layout=True)
    axes = axes.ravel()
    im = None
    for i, a in enumerate(order):
        sd = axsets[a]
        sc = sorted(sd, key=lambda s: -len(sd[s]))
        M = [[jacc(sd[x], sd[y]) for y in sc] for x in sc]
        ax = axes[i]
        im = ax.imshow(M, cmap="YlGnBu", vmin=0, vmax=1)
        ax.set_xticks(range(len(sc))); ax.set_yticks(range(len(sc)))
        ax.set_xticklabels(sc, rotation=45, ha="right", fontsize=6.5)
        ax.set_yticklabels(sc, fontsize=6.5)
        for x in range(len(sc)):
            for y in range(len(sc)):
                ax.text(y, x, f"{M[x][y]:.2f}", ha="center", va="center",
                        color="white" if M[x][y] > 0.55 else "black", fontsize=6)
        ax.set_title(AXIS_LABEL.get(a, a), fontsize=9)
    for j in range(len(order), len(axes)):
        axes[j].axis("off")
    if im is not None:
        fig.colorbar(im, ax=axes.tolist(), fraction=0.022, pad=0.02)
    save(fig, "fig_jaccard")


def fig_agreement(axsets):
    axes = [a for a in ["pkg-vuln", "secret", "other", "sbom-component",
                        "image-config", "web-vuln"] if len(axsets.get(a, {})) >= 2]
    fig, ax = plt.subplots(figsize=(5.0, 2.4))
    cols = ["#c0504d", "#e0a030", "#4a8c5a"]
    bottoms = [0.0] * len(axes)
    for tier, color, lab in zip((1, 2, 3), cols, ("1 tool", "2 tools", "3+ tools")):
        vals = []
        for a in axes:
            kc = collections.Counter()
            for s in axsets[a]:
                for el in axsets[a][s]:
                    kc[el] += 1
            tot = len(kc) or 1
            vals.append(sum(1 for v in kc.values() if min(v, 3) == tier) / tot * 100)
        ax.bar([AXIS_LABEL.get(a, a) for a in axes], vals, bottom=bottoms,
               color=color, label=lab)
        bottoms = [b + v for b, v in zip(bottoms, vals)]
    ax.set_ylabel("% of distinct findings"); ax.set_ylim(0, 100)
    ax.legend(fontsize=8, frameon=False, ncol=3, loc="upper center",
              bbox_to_anchor=(0.5, 1.18))
    plt.xticks(rotation=25, ha="right")
    save(fig, "fig_agreement_tiers")


def fig_saturation(rows):
    by = collections.defaultdict(set)
    for s, c, k, t in rows:
        by[s].add((t, c, k))
    rem = dict(by)
    covered, order, curve = set(), [], []
    while rem:
        best = max(rem, key=lambda s: len(rem[s] - covered))
        covered |= rem.pop(best)
        order.append(best); curve.append(len(covered))
    total = curve[-1]
    xs = list(range(1, len(curve) + 1))
    fig, ax = plt.subplots(figsize=(6.6, 2.7))
    ax.plot(xs, curve, "o-", color=C["accent"], ms=4)
    ax.fill_between(xs, curve, color=C["accent"], alpha=0.12)
    # % of the final total covered so far, labelled the first time each whole
    # percentage is reached, so the flat tail is not a wall of "100%".
    # Truncate (not round) so "100%" appears only on the genuine final dot,
    # never as a rounded-up 99.x%.
    last = None
    for x, y in zip(xs, curve):
        pct = int(100 * y / total)
        if pct != last:
            ax.annotate(f"{pct}%", (x, y),
                        textcoords="offset points", xytext=(0, 6),
                        ha="center", fontsize=7, color="#333333")
            last = pct
    ax.set_xlabel("number of scanners (greedy order)")
    ax.set_ylabel("cumulative unique findings")
    ax.set_xlim(0.4, len(curve) + 0.6)
    ax.set_ylim(0, total * 1.12)
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))   # whole scanners only
    ax.yaxis.set_major_formatter(lambda v, _: f"{int(v):,}")
    save(fig, "fig_saturation")


def fig_exclusivity(axsets):
    excl = {}
    for c, sd in axsets.items():
        if len(sd) < 2:
            continue
        for s, ks in sd.items():
            others = set().union(*(v for o, v in sd.items() if o != s))
            excl[(s, c)] = len(ks - others) / max(len(ks), 1) * 100
    items = sorted(excl.items(), key=lambda kv: -kv[1])[::-1]
    fig, ax = plt.subplots(figsize=(4.4, 0.18 * len(items) + 0.6))
    vals = [v for _, v in items]
    ax.barh([f"{s} ({AXIS_LABEL.get(c, c)})" for (s, c), _ in items], vals,
            color=[figstyle.color(s) for (s, c), _ in items])
    for i, v in enumerate(vals):                       # label every bar
        ax.text(min(v + 2, 99), i, f"{v:.0f}%", va="center", fontsize=6)
    ax.set_xlabel("% findings exclusive to the tool (within axis)")
    ax.set_xlim(0, 100)
    plt.yticks(fontsize=6.5)
    save(fig, "fig_exclusivity")


def fig_cost():
    p = CORPUS / "metrics.csv"
    if not p.is_file():
        return
    rt = collections.defaultdict(list)
    for r in csv.DictReader(open(p, newline="")):
        try:                                    # ignore zero/blank wall time
            w = float(r.get("wall_seconds") or 0)
            if w > 0:
                rt[r["scanner"]].append(w)
        except (ValueError, KeyError):
            pass
    rt = {s: v for s, v in rt.items() if v}
    order = sorted(rt, key=lambda s: statistics.median(rt[s]))
    fig, ax = plt.subplots(figsize=(5.8, 4.6))
    bp = ax.boxplot([rt[s] for s in order], vert=False, tick_labels=order,
                    showfliers=False, patch_artist=True, widths=0.62,
                    boxprops=dict(color="#555555"),
                    medianprops=dict(color="black"))
    for patch, s in zip(bp["boxes"], order):
        patch.set_facecolor(figstyle.color(s))
    ax.set_xscale("log")
    ax.set_xticks([1, 10, 60, 600])
    ax.set_xticklabels(["1 s", "10 s", "1 min", "10 min"])
    ax.xaxis.set_minor_locator(plt.NullLocator())
    ax.set_xlabel("per-container wall time (log scale)")
    ax.margins(y=0.01)
    plt.yticks(fontsize=6.3)
    save(fig, "fig_cost")


def fig_coverage(axsets):
    """Per scanner: coverage = share of its axis's distinct findings it reports."""
    items = []
    for c, sd in axsets.items():
        if not sd:
            continue
        union = set().union(*sd.values())
        U = len(union) or 1
        for s, ks in sd.items():
            items.append((s, c, len(ks) / U * 100))
    items.sort(key=lambda x: x[2])
    fig, ax = plt.subplots(figsize=(5.8, 4.3))
    ax.barh([f"{s}  ({AXIS_LABEL.get(c, c)})" for s, c, _ in items],
            [v for _, _, v in items],
            color=[figstyle.color(s) for s, c, _ in items])
    for i, (_, _, v) in enumerate(items):
        ax.text(v + 1, i, f"{v:.0f}", va="center", fontsize=6.5)
    ax.set_xlabel("coverage: % of the axis's distinct findings reported by the tool")
    ax.set_xlim(0, 105)
    ax.margins(y=0.01)
    plt.yticks(fontsize=6.3)
    save(fig, "fig_coverage")


def fig_scatter(axsets):
    """Each scanner placed by what it covers against what it uniquely adds:
    x = share of its axis it reports, y = share of its own findings that no
    axis-mate reports. Top-right is broad and unique; bottom-left is narrow
    and redundant. One point per (scanner, axis), coloured by axis."""
    pts = []
    for c, sd in axsets.items():
        if len(sd) < 2:
            continue
        union = set().union(*sd.values())
        U = len(union) or 1
        for s, ks in sd.items():
            if not ks:
                continue
            others = set().union(*(v for o, v in sd.items() if o != s))
            pts.append((s, c, len(ks) / U * 100, len(ks - others) / len(ks) * 100))
    fig, ax = plt.subplots(figsize=(5.6, 4.0))
    cmap = plt.get_cmap("tab10")
    for i, a in enumerate(sorted({c for _, c, _, _ in pts})):
        ap = [(s, cov, exc) for s, c, cov, exc in pts if c == a]
        ax.scatter([p[1] for p in ap], [p[2] for p in ap], s=45, color=cmap(i),
                   label=AXIS_LABEL.get(a, a), edgecolor="white",
                   linewidth=0.5, zorder=3)
        for s, cov, exc in ap:
            ax.annotate(s, (cov, exc), fontsize=5, xytext=(3, 3),
                        textcoords="offset points")
    ax.set_xlabel("coverage: % of the axis's distinct findings the tool reports")
    ax.set_ylabel("exclusivity: % of the tool's findings no axis-mate reports")
    ax.set_xlim(-3, 106)
    ax.set_ylim(-3, 106)
    ax.legend(fontsize=6.5, frameon=False, ncol=2)
    save(fig, "fig_scatter")


def fig_per_scanner(rows):
    """Total findings reported by each scanner (log scale): the companion to
    fig_cost, what each tool reports beside what it costs to run."""
    by = collections.Counter(s for s, _, _, _ in rows)
    order = sorted(by, key=lambda s: by[s])
    fig, ax = plt.subplots(figsize=(4.6, 0.20 * len(order) + 0.5))
    vals = [by[s] for s in order]
    ax.barh(order, vals, color=[figstyle.color(s) for s in order])
    for i, v in enumerate(vals):
        ax.text(v, i, f" {v:,}", va="center", fontsize=6)
    ax.set_xscale("log")
    ax.set_xlabel("findings reported (log scale)")
    ax.margins(y=0.01)
    plt.yticks(fontsize=6.5)
    save(fig, "fig_per_scanner")


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
    rows = load()
    print(f"{len(rows):,} findings -> {FIG}")
    axsets = per_axis_sets(rows)
    fig_overview(rows)
    fig_jaccard(axsets)
    fig_agreement(axsets)
    fig_scatter(axsets)
    fig_saturation(rows)
    fig_exclusivity(axsets)
    fig_coverage(axsets)
    fig_per_scanner(rows)
    fig_cost()
    return 0


if __name__ == "__main__":
    sys.exit(main())
