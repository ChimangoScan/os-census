#!/usr/bin/env python3
"""Generate the multiscan comparison figures and statistics from the
consolidated corpus (out/_corpus/). Scope: agreement, coverage, cost — see
docs/COMPARISON.md and docs/ANALYSIS.md. No accuracy / ground truth.

Usage: python scripts/figures.py [corpus_dir] [out_dir]
"""
from __future__ import annotations
import csv, itertools, json, sys, collections
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent
CORPUS = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "out" / "_corpus"
FIGDIR = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "figures"
DYNAMIC_CATS = {"web-vuln", "network-vuln"}
SEV_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


# ── data loading ────────────────────────────────────────────────────────────

def _norm_path(p: str) -> str:
    """Normalize a file path across scanners: drop the /scan rootfs-mount
    prefix and any trailing :line, so file-level findings line up."""
    p = (p or "").strip().lower()
    for pre in ("/scan/", "/scan"):
        if p.startswith(pre):
            p = p[len(pre):]
            break
    head, sep, tail = p.rpartition(":")
    if sep and tail.isdigit():
        p = head
    return p.lstrip("/")


def _key(d: dict) -> tuple:
    """Axis-aware cross-scanner identity of a finding (see docs/COMPARISON.md
    normalization rules). Agreement is later computed over (target, key)."""
    cat = d.get("category", "")
    cves = d.get("cves") or []
    if cat in ("pkg-vuln", "network-vuln"):     # SCA / network -> canonical CVE id
        return (cat, (cves[0] if cves else d.get("id") or "").strip().lower())
    if cat == "sbom-component":                 # SBOM -> package name
        return (cat, (d.get("package") or "").strip().lower())
    if cat in ("secret", "other", "malware"):   # secrets/SAST/malware -> file path
        return (cat, _norm_path(d.get("location") or ""))
    if cat == "web-vuln":                       # DAST -> id + endpoint
        return (cat, (d.get("id") or d.get("title") or "").strip().lower(),
                (d.get("endpoint") or "").strip().lower())
    return (cat, (d.get("id") or d.get("title") or "").strip().lower())


def load_findings(path: Path):
    rows = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            rows.append((d.get("scanner", "?"), d.get("category", "?"),
                         (d.get("severity") or "unknown"), _key(d),
                         d.get("target_name", "?")))
    return rows


def load_metrics(path: Path):
    if not path.is_file():
        return []
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))


# ── statistics ──────────────────────────────────────────────────────────────

def jaccard(a: set, b: set) -> float:
    u = a | b
    return len(a & b) / len(u) if u else 0.0


def fleiss_kappa(item_counts: list[tuple[int, int]]) -> float:
    """item_counts: per finding, (n_raters_that_found, n_raters_total)."""
    if not item_counts:
        return 0.0
    N = len(item_counts)
    n = item_counts[0][1]
    if n < 2:
        return 0.0
    p_found = sum(f for f, _ in item_counts) / (N * n)
    p_not = 1.0 - p_found
    Pe = p_found ** 2 + p_not ** 2
    Pbar = sum((f * f + (n - f) * (n - f) - n) / (n * (n - 1))
               for f, _ in item_counts) / N
    return (Pbar - Pe) / (1.0 - Pe) if Pe < 1.0 else 1.0


# ── figures ─────────────────────────────────────────────────────────────────

def fig_category_phase(rows, out):
    by = collections.Counter((c, "dynamic" if c in DYNAMIC_CATS else "static")
                              for _, c, _, _, _ in rows)
    cats = sorted({c for c, _ in by}, key=lambda c: -sum(
        v for (cc, _), v in by.items() if cc == c))
    fig, ax = plt.subplots(figsize=(9, 5))
    for ph, color in (("static", "#3b6"), ("dynamic", "#36b")):
        ax.bar(cats, [by.get((c, ph), 0) for c in cats], label=ph, color=color,
               bottom=[by.get((c, "static"), 0) if ph == "dynamic" else 0 for c in cats])
    ax.set_yscale("log"); ax.set_ylabel("findings (log)"); ax.legend()
    ax.set_title("F1 — findings by category and phase")
    plt.xticks(rotation=30, ha="right"); _save(fig, out / "F1_category_phase.png")


def fig_severity(rows, out):
    by = collections.Counter((c, s) for _, c, s, _, _ in rows)
    cats = sorted({c for c, _ in by})
    fig, ax = plt.subplots(figsize=(9, 5))
    bottom = [0] * len(cats)
    for s in SEV_ORDER:
        vals = [by.get((c, s), 0) for c in cats]
        ax.bar(cats, vals, bottom=bottom, label=s)
        bottom = [b + v for b, v in zip(bottom, vals)]
    ax.set_yscale("log"); ax.set_ylabel("findings (log)"); ax.legend(fontsize=8)
    ax.set_title("F2 — severity distribution by category")
    plt.xticks(rotation=30, ha="right"); _save(fig, out / "F2_severity.png")


def fig_per_container(rows, out):
    by = collections.Counter(t for _, _, _, _, t in rows)
    vals = sorted(by.values(), reverse=True)
    fig, ax = plt.subplots(figsize=(9, 4))
    ax.bar(range(len(vals)), vals, color="#46a")
    ax.set_yscale("log"); ax.set_xlabel("container (rank)")
    ax.set_ylabel("findings (log)")
    ax.set_title(f"F3 — per-container finding count ({len(vals)} containers)")
    _save(fig, out / "F3_per_container.png")


def fig_count_spread(rows, out):
    by = collections.Counter(s for s, _, _, _, _ in rows)
    items = sorted(by.items(), key=lambda kv: -kv[1])
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar([s for s, _ in items], [v for _, v in items], color="#a64")
    ax.set_yscale("log"); ax.set_ylabel("findings (log)")
    ax.set_title("F10 — total findings per scanner")
    plt.xticks(rotation=60, ha="right"); _save(fig, out / "F10_count_spread.png")


def fig_exclusivity(rows, out, stats):
    """Per scanner: fraction of its findings whose key is unique to it, within
    its category."""
    by_cat = collections.defaultdict(lambda: collections.defaultdict(set))
    for s, c, _, k, t in rows:
        by_cat[c][s].add((t, k))
    excl = {}                                   # (scanner, category) -> (uniq, total)
    for c, sc in by_cat.items():
        if len(sc) < 2:
            continue
        for s, keys in sc.items():
            others = set().union(*(v for o, v in sc.items() if o != s))
            excl[(s, c)] = (len(keys - others), len(keys))
    items = sorted(excl.items(), key=lambda kv: -(kv[1][0] / max(kv[1][1], 1)))
    fig, ax = plt.subplots(figsize=(11, 5))
    ax.bar([f"{s}·{c}" for (s, c), _ in items],
           [v[0] / max(v[1], 1) * 100 for _, v in items], color="#964")
    ax.set_ylabel("% exclusive findings")
    ax.set_title("F8 — per-scanner exclusivity (within axis)")
    plt.xticks(rotation=70, ha="right", fontsize=7)
    _save(fig, out / "F8_exclusivity.png")
    stats["exclusivity"] = {f"{s}·{c}": {"exclusive": v[0], "total": v[1]}
                            for (s, c), v in excl.items()}


def fig_jaccard_and_agreement(rows, out, stats):
    """F5 Jaccard heatmap + F6 agreement histogram + Fleiss kappa, per category."""
    by_cat = collections.defaultdict(lambda: collections.defaultdict(set))
    for s, c, _, k, t in rows:
        by_cat[c][s].add((t, k))
    stats["jaccard"] = {}
    stats["fleiss_kappa"] = {}
    for c, sc in sorted(by_cat.items()):
        scanners = sorted(sc)
        if len(scanners) < 2:
            continue
        # F5 — Jaccard heatmap
        M = [[jaccard(sc[a], sc[b]) for b in scanners] for a in scanners]
        fig, ax = plt.subplots(figsize=(1.1 * len(scanners) + 2,
                                        1.1 * len(scanners) + 1))
        im = ax.imshow(M, cmap="viridis", vmin=0, vmax=1)
        ax.set_xticks(range(len(scanners))); ax.set_yticks(range(len(scanners)))
        ax.set_xticklabels(scanners, rotation=60, ha="right")
        ax.set_yticklabels(scanners)
        for i in range(len(scanners)):
            for j in range(len(scanners)):
                ax.text(j, i, f"{M[i][j]:.2f}", ha="center", va="center",
                        color="w" if M[i][j] < 0.6 else "k", fontsize=7)
        fig.colorbar(im, fraction=0.046)
        ax.set_title(f"F5 — pairwise Jaccard · {c}")
        _save(fig, out / f"F5_jaccard_{c}.png")
        stats["jaccard"][c] = {f"{a}|{b}": round(jaccard(sc[a], sc[b]), 4)
                               for a, b in itertools.combinations(scanners, 2)}
        # F6 — agreement histogram + Fleiss kappa
        key_count = collections.Counter()
        for s in scanners:
            for k in sc[s]:
                key_count[k] += 1
        hist = collections.Counter(min(v, 3) for v in key_count.values())
        fig, ax = plt.subplots(figsize=(5, 4))
        labels = {1: "1 tool", 2: "2 tools", 3: "3+ tools"}
        ax.bar([labels[i] for i in (1, 2, 3)],
               [hist.get(i, 0) for i in (1, 2, 3)], color=["#c44", "#ca4", "#4a4"])
        ax.set_ylabel("findings"); ax.set_title(f"F6 — agreement · {c}")
        _save(fig, out / f"F6_agreement_{c}.png")
        kappa = fleiss_kappa([(v, len(scanners)) for v in key_count.values()])
        stats["fleiss_kappa"][c] = round(kappa, 4)


def fig_saturation(rows, out, stats):
    """F13 — greedy cumulative unique-finding curve as scanners are added."""
    by_scanner = collections.defaultdict(set)
    for s, c, _, k, t in rows:
        by_scanner[s].add((t, k))
    remaining = dict(by_scanner)
    covered, order, curve = set(), [], []
    while remaining:
        best = max(remaining, key=lambda s: len(remaining[s] - covered))
        covered |= remaining.pop(best)
        order.append(best); curve.append(len(covered))
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.plot(range(1, len(curve) + 1), curve, "o-", color="#2a7")
    ax.set_xticks(range(1, len(order) + 1))
    ax.set_xticklabels(order, rotation=60, ha="right", fontsize=7)
    ax.set_ylabel("cumulative unique findings")
    ax.set_xlabel("scanners added (greedy order)")
    ax.set_title("F13 — coverage saturation curve")
    _save(fig, out / "F13_saturation.png")
    stats["saturation_order"] = order
    stats["saturation_curve"] = curve


def fig_coverage_matrix(rows, out):
    """F12 — scanner x container: did the scanner produce >=1 finding."""
    scanners = sorted({s for s, _, _, _, _ in rows})
    targets = sorted({t for _, _, _, _, t in rows})
    has = {(s, t) for s, _, _, _, t in rows}
    M = [[1 if (s, t) in has else 0 for t in targets] for s in scanners]
    fig, ax = plt.subplots(figsize=(min(0.18 * len(targets) + 2, 24),
                                    0.32 * len(scanners) + 1))
    ax.imshow(M, cmap="Greens", aspect="auto", vmin=0, vmax=1)
    ax.set_yticks(range(len(scanners))); ax.set_yticklabels(scanners, fontsize=7)
    ax.set_xticks([]); ax.set_xlabel(f"{len(targets)} containers")
    ax.set_title("F12 — coverage matrix (>=1 finding)")
    _save(fig, out / "F12_coverage_matrix.png")


def fig_cost(metrics, out, stats):
    """F18 runtime, F19 memory, F20 findings-vs-time, F22 error rate."""
    if not metrics:
        return
    rt = collections.defaultdict(list)
    mem = collections.defaultdict(list)
    nf = collections.defaultdict(int)
    status = collections.defaultdict(collections.Counter)
    for m in metrics:
        s = m.get("scanner", "?")
        try:
            rt[s].append(float(m.get("wall_seconds") or 0))
            mem[s].append(float(m.get("peak_mem_mb") or 0))
            nf[s] += int(m.get("findings") or 0)
        except ValueError:
            pass
        status[s][m.get("status", "?")] += 1
    order = sorted(rt, key=lambda s: -sorted(rt[s])[len(rt[s]) // 2] if rt[s] else 0)
    # F18 runtime box
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.boxplot([rt[s] for s in order], tick_labels=order, showfliers=False)
    ax.set_yscale("log"); ax.set_ylabel("wall seconds (log)")
    ax.set_title("F18 — runtime per scanner")
    plt.xticks(rotation=60, ha="right"); _save(fig, out / "F18_runtime.png")
    # F19 memory box
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.boxplot([mem[s] for s in order], tick_labels=order, showfliers=False)
    ax.set_ylabel("peak memory (MB)")
    ax.set_title("F19 — peak memory per scanner")
    plt.xticks(rotation=60, ha="right"); _save(fig, out / "F19_memory.png")
    # F20 findings vs total wall time
    fig, ax = plt.subplots(figsize=(7, 6))
    for s in order:
        ax.scatter(sum(rt[s]) / 60.0, nf[s], s=40)
        ax.annotate(s, (sum(rt[s]) / 60.0, nf[s]), fontsize=6)
    ax.set_xlabel("total wall time (min)"); ax.set_ylabel("findings")
    ax.set_xscale("log"); ax.set_yscale("symlog")
    ax.set_title("F20 — findings vs runtime")
    _save(fig, out / "F20_findings_vs_time.png")
    # F22 status / error rate
    statuses = sorted({st for c in status.values() for st in c})
    fig, ax = plt.subplots(figsize=(10, 5))
    bottom = [0] * len(order)
    for st in statuses:
        vals = [status[s].get(st, 0) for s in order]
        ax.bar(order, vals, bottom=bottom, label=st)
        bottom = [b + v for b, v in zip(bottom, vals)]
    ax.set_ylabel("invocations"); ax.legend(fontsize=8)
    ax.set_title("F22 — invocation status per scanner")
    plt.xticks(rotation=60, ha="right"); _save(fig, out / "F22_status.png")
    stats["cost"] = {s: {"runs": len(rt[s]),
                         "wall_total_min": round(sum(rt[s]) / 60.0, 1),
                         "wall_median_s": round(sorted(rt[s])[len(rt[s]) // 2], 1)
                         if rt[s] else 0,
                         "status": dict(status[s])} for s in order}


def fig_venn_upset(rows, out):
    """F7 — set overlap per axis: a Venn diagram for 2-3 tools, an UpSet plot
    for more (Venn is unreadable beyond 3 sets)."""
    try:
        from matplotlib_venn import venn2, venn3
        from upsetplot import UpSet, from_contents
    except ImportError:
        print("  (skip F7 — install the 'analysis' extra: matplotlib-venn, upsetplot)")
        return
    by_cat = collections.defaultdict(lambda: collections.defaultdict(set))
    for s, c, _, k, t in rows:
        by_cat[c][s].add((t, k))
    for c, sc in sorted(by_cat.items()):
        scanners = sorted(sc)
        n = len(scanners)
        if n < 2:
            continue
        if n <= 3:
            fig, ax = plt.subplots(figsize=(6.5, 6))
            sets = [sc[s] for s in scanners]
            (venn2 if n == 2 else venn3)(sets, set_labels=tuple(scanners), ax=ax)
            ax.set_title(f"F7 — set overlap · {c}")
            _save(fig, out / f"F7_venn_{c}.png")
        else:
            try:
                data = from_contents({s: sc[s] for s in scanners})
                fig = plt.figure(figsize=(3 + n, 6))
                UpSet(data, sort_by="cardinality", show_counts=True).plot(fig=fig)
                fig.suptitle(f"F7 — set overlap (UpSet) · {c}")
                fig.savefig(out / f"F7_upset_{c}.png", dpi=120)
                plt.close(fig)
                print(f"  wrote F7_upset_{c}.png")
            except Exception as e:
                plt.close("all")
                print(f"  (skip F7 upset for {c}: {type(e).__name__})")


def _save(fig, path: Path):
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)
    print(f"  wrote {path.name}")


def write_report_md(rows, metrics, stats, out: Path):
    """Human-readable Markdown companion to the figures + stats.json."""
    cat = collections.Counter(c for _, c, _, _, _ in rows)
    sev = collections.Counter(v for _, _, v, _, _ in rows)
    per_scanner = collections.Counter(s for s, _, _, _, _ in rows)
    scanner_cats = collections.defaultdict(set)
    for s, c, _, _, _ in rows:
        scanner_cats[s].add(c)
    targets = {t for _, _, _, _, t in rows}
    L = ["# multiscan — corpus statistics", "",
         "Generated by `scripts/figures.py` from `out/_corpus/`. Scope:",
         "agreement, coverage, cost (see `docs/COMPARISON.md`). The PNG figures",
         "(`F1`…`F22`) and machine-readable `stats.json` sit alongside this file.", "",
         "## Overview", "",
         f"- findings: **{len(rows):,}**",
         f"- scanner invocations: **{len(metrics):,}**",
         f"- containers: **{len(targets)}**",
         f"- scanners producing findings: **{len(per_scanner)}**", "",
         "## Findings by category (F1)", "",
         "| category | findings | phase |", "|---|--:|---|"]
    for c, n in cat.most_common():
        L.append(f"| {c} | {n:,} | {'dynamic' if c in DYNAMIC_CATS else 'static'} |")
    L += ["", "## Findings by severity (F2)", "", "| severity | findings |", "|---|--:|"]
    for s in SEV_ORDER:
        if sev.get(s):
            L.append(f"| {s} | {sev[s]:,} |")
    L += ["", "## Findings per scanner (F10)", "",
          "| scanner | axes | findings |", "|---|---|--:|"]
    for s, n in per_scanner.most_common():
        L.append(f"| {s} | {', '.join(sorted(scanner_cats[s]))} | {n:,} |")
    L += ["", "## Agreement per axis (F5/F6)", "",
          "Pairwise Jaccard of normalized finding sets, keyed by (container,",
          "finding); Fleiss' kappa is chance-corrected agreement.", ""]
    for c in sorted(stats.get("jaccard", {})):
        L.append(f"### {c}  ·  Fleiss κ = {stats['fleiss_kappa'].get(c)}")
        L += ["", "| pair | Jaccard |", "|---|--:|"]
        for pair, v in sorted(stats["jaccard"][c].items(), key=lambda kv: -kv[1]):
            L.append(f"| {pair} | {v} |")
        L.append("")
    L += ["## Exclusivity (F8)", "",
          "Findings reported by no other tool in the axis.", "",
          "| scanner · axis | exclusive | total | % |", "|---|--:|--:|--:|"]
    for k, v in sorted(stats.get("exclusivity", {}).items(),
                       key=lambda kv: -(kv[1]["exclusive"] / max(kv[1]["total"], 1))):
        pct = v["exclusive"] / max(v["total"], 1) * 100
        L.append(f"| {k} | {v['exclusive']:,} | {v['total']:,} | {pct:.1f}% |")
    L += ["", "## Coverage saturation (F13)", "",
          "Cumulative unique findings as scanners are added in greedy order.", "",
          "| # | scanner added | cumulative unique |", "|--:|---|--:|"]
    for i, (s, c) in enumerate(zip(stats.get("saturation_order", []),
                                   stats.get("saturation_curve", [])), 1):
        L.append(f"| {i} | {s} | {c:,} |")
    L += ["", "## Cost per scanner (F18/F22)", "",
          "| scanner | runs | wall total (min) | wall median (s) | status |",
          "|---|--:|--:|--:|---|"]
    for s, v in sorted(stats.get("cost", {}).items(),
                       key=lambda kv: -kv[1]["wall_total_min"]):
        st = ", ".join(f"{k}:{n}" for k, n in v["status"].items())
        L.append(f"| {s} | {v['runs']} | {v['wall_total_min']} | "
                 f"{v['wall_median_s']} | {st} |")
    (out / "STATISTICS.md").write_text("\n".join(L) + "\n")
    print("  wrote STATISTICS.md")


# ── main ────────────────────────────────────────────────────────────────────

def main() -> int:
    findings_path = CORPUS / "findings.jsonl"
    if not findings_path.is_file():
        print(f"error: {findings_path} not found", file=sys.stderr)
        return 1
    FIGDIR.mkdir(parents=True, exist_ok=True)
    print(f"loading {findings_path} ...")
    rows = load_findings(findings_path)
    metrics = load_metrics(CORPUS / "metrics.csv")
    print(f"{len(rows):,} findings, {len(metrics):,} invocations -> {FIGDIR}")
    stats: dict = {"findings": len(rows), "invocations": len(metrics)}
    fig_category_phase(rows, FIGDIR)
    fig_severity(rows, FIGDIR)
    fig_per_container(rows, FIGDIR)
    fig_count_spread(rows, FIGDIR)
    fig_exclusivity(rows, FIGDIR, stats)
    fig_jaccard_and_agreement(rows, FIGDIR, stats)
    fig_saturation(rows, FIGDIR, stats)
    fig_coverage_matrix(rows, FIGDIR)
    fig_venn_upset(rows, FIGDIR)
    fig_cost(metrics, FIGDIR, stats)
    (FIGDIR / "stats.json").write_text(json.dumps(stats, indent=2))
    print(f"  wrote stats.json")
    write_report_md(rows, metrics, stats, FIGDIR)
    return 0


if __name__ == "__main__":
    sys.exit(main())
