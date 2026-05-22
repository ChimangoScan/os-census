#!/usr/bin/env python3
"""Consolidate per-target ``report.json`` files into a single corpus.

Builds ``<corpus>/{findings.jsonl,metrics.csv}`` from the per-container
``report.json`` files produced by the harness. Two layouts are supported:

* ``--from-collect`` (default) the uniform-hardware cluster re-run. Each
  container is scanned across three phases whose reports are gathered under
  ``collect/``::

      static  phase: collect/static/<host>/out-staticrr/<container>/report.json
      statfix phase: collect/statfix/<host>/out-statfix/<container>/report.json
      dynamic phase: collect/dynamic/<host>/out-dynfull/<container>/report.json

  The three phase reports for a container are merged: ``out-staticrr`` supplies
  every static scanner, except that ``whispers``/``pip-audit``/``govulncheck``
  errored there (their custom images were not yet built) and are taken from the
  ``out-statfix`` re-run instead; ``out-dynfull`` supplies the dynamic scanners.
  This is the layout that produced the dataset in the paper.

* ``--from-out DIR`` a flat output directory ``DIR/<container>/report.json``,
  i.e. the layout written directly by ``scanners run`` on a single machine.
  This is what the reduced reproduction (``scripts/reproduce-reduced.sh``)
  uses, so the analysis scripts can run without a cluster. No merge is needed
  (one machine ran every scanner into one report).

In both layouts ``find-sec-bugs`` and ``dependency-check`` are dropped: they
were excluded from the study battery, leaving 32 scanners (OpenVAS included).

Nothing is hardcoded: the repository root is derived from this file's location,
and every input/output path is a CLI argument. The previous corpus, if any, is
kept aside as ``findings_prev.jsonl``.

Examples::

    python scripts/consolidate.py                       # cluster re-run -> out/_corpus
    python scripts/consolidate.py --from-out results/out --corpus results/_corpus
"""
from __future__ import annotations
import argparse
import collections
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from scanners.findings.openvas_import import import_openvas   # noqa: E402
from scanners.models import Target                            # noqa: E402

METRIC_COLS = ["scanner", "target_name", "target_image", "target_ip", "mode",
               "wall_seconds", "exit_code", "status", "peak_cpu_pct",
               "peak_mem_mb", "findings"]

# Scanners excluded from the analysed battery and dropped from every corpus:
# find-sec-bugs and dependency-check (slow, marginal coverage); arachni, whose
# EOL (2020) browser-based crawler cannot run on current systems (0 requests).
DROP_SCANNERS = {"find-sec-bugs", "dependency-check", "arachni"}
# Scanners re-run in the statfix phase: their authoritative results live in the
# out-statfix reports, not the out-staticrr ones (where they errored because
# their custom images had not been built yet).
STATFIX_SCANNERS = {"whispers", "pip-audit", "govulncheck"}
# Scanner re-run in the dynweb phase: nuclei errored in the dynamic phase (its
# image lacked the template repo), so its results are taken from out-dynweb.
DYNWEB_SCANNERS = {"nuclei"}

# whispers' "comment" and "file-known" rules flag every code comment and every
# recognised filename; they are not secrets and make up ~99% of whispers' raw
# output. They are excluded from the corpus (the whispers adapter drops them at
# the source too; this is the safety net for reports collected before the fix).
WHISPERS_NOISE = {"comment", "file-known"}

# Report keys copied verbatim into a merged report.
_META_KEYS = ("target", "started_at", "finished_at", "scanned_image_digest",
              "container_ip", "open_ports", "http_endpoints")


def _keep_finding(f: dict) -> bool:
    """False for whispers' comment/file-known pseudo-findings (not real secrets)."""
    return not (f.get("scanner") == "whispers" and f.get("id") in WHISPERS_NOISE)


def _load_report(rj: Path) -> dict | None:
    """Read one report.json, returning None (with a note) on a bad file."""
    try:
        return json.loads(rj.read_text())
    except (OSError, ValueError) as e:
        print(f"  bad report {rj}: {e}")
        return None


def reports_from_collect(collect: Path, phase: str, outdir: str) -> dict[str, dict]:
    """container -> report.json dict, from the sharded cluster layout
    ``collect/<phase>/<host>/<outdir>/<container>/report.json``."""
    out: dict[str, dict] = {}
    for rj in sorted((collect / phase).glob(f"*/{outdir}/*/report.json")):
        rep = _load_report(rj)
        if rep is not None:
            out[rj.parent.name] = rep
    return out


def reports_from_out(out_dir: Path) -> dict[str, dict]:
    """container -> report.json dict, from a flat ``<out_dir>/<container>/report.json``
    layout (one machine, written directly by ``scanners run``)."""
    out: dict[str, dict] = {}
    for rj in sorted(out_dir.glob("*/report.json")):
        rep = _load_report(rj)
        if rep is not None:
            out[rj.parent.name] = rep
    return out


def load_targets(inventory: Path) -> dict[str, Target]:
    """Read the CSV inventory into a {container-name: Target} map."""
    out: dict[str, Target] = {}
    with open(inventory) as fh:
        for r in csv.DictReader(fh):
            t = Target(image=r["image"], name=r["container"], ip=(r.get("ip") or None))
            out[t.name] = t
    return out


def filter_report(rep: dict) -> dict:
    """Return a copy of *rep* with the dropped scanners removed (used for the
    flat one-machine layout, where no cross-phase merge is needed)."""
    out = {k: rep.get(k) for k in _META_KEYS}
    out["invocations"] = [i for i in rep.get("invocations", [])
                          if i.get("scanner") not in DROP_SCANNERS]
    out["findings"] = [f for f in rep.get("findings", [])
                       if f.get("scanner") not in DROP_SCANNERS and _keep_finding(f)]
    return out


def merge_report(staticrr: dict | None, statfix: dict | None,
                 dynfull: dict | None, dynweb: dict | None) -> dict:
    """Merge a container's cluster-phase reports into one.

    out-staticrr contributes every static scanner except the statfix set and
    the dropped set; out-statfix contributes the statfix set; out-dynfull
    contributes the dynamic scanners except nuclei; out-dynweb contributes
    nuclei. find-sec-bugs, dependency-check and arachni are dropped everywhere."""
    base = staticrr or statfix or dynfull or dynweb or {}
    merged = {k: base.get(k) for k in _META_KEYS}
    inv: list[dict] = []
    find: list[dict] = []

    def take(rep: dict | None, keep) -> None:
        if not rep:
            return
        for i in rep.get("invocations", []):
            if keep(i.get("scanner")):
                inv.append(i)
        for f in rep.get("findings", []):
            if keep(f.get("scanner")) and _keep_finding(f):
                find.append(f)

    take(staticrr, lambda s: s not in DROP_SCANNERS and s not in STATFIX_SCANNERS)
    take(statfix, lambda s: s in STATFIX_SCANNERS)
    take(dynfull, lambda s: s not in DROP_SCANNERS and s not in DYNWEB_SCANNERS)
    take(dynweb, lambda s: s in DYNWEB_SCANNERS)
    merged["invocations"] = inv
    merged["findings"] = find
    return merged


def write_corpus(corpus: Path, reports: dict[str, dict],
                 *, openvas_dir: Path | None,
                 targets: dict[str, Target]) -> tuple[int, int, list[str]]:
    """Write ``findings.jsonl`` + ``metrics.csv`` under *corpus*; return the
    (report-finding count, openvas-finding count, sorted scanner list)."""
    corpus.mkdir(parents=True, exist_ok=True)
    findings = corpus / "findings.jsonl"
    if findings.exists():
        findings.rename(corpus / "findings_prev.jsonl")

    n_find = n_ov = 0
    scanners: set[str] = set()
    metrics: list[dict] = []
    with open(findings, "w") as out:
        for container, rep in sorted(reports.items()):
            tname = (rep.get("target") or {}).get("name", container)
            per_scanner = collections.Counter()
            for f in rep.get("findings", []):
                out.write(json.dumps(f) + "\n")
                n_find += 1
                if f.get("scanner"):
                    scanners.add(f["scanner"])
                    per_scanner[f["scanner"]] += 1
            for inv in rep.get("invocations", []):
                row = {k: inv.get(k, "") for k in METRIC_COLS}
                if not row["target_name"]:
                    row["target_name"] = tname
                # recompute the finding count from the (filtered/merged) corpus
                # so metrics.csv always agrees with findings.jsonl
                row["findings"] = per_scanner.get(inv.get("scanner"), 0)
                metrics.append(row)
                if inv.get("scanner"):
                    scanners.add(inv["scanner"])
        # OpenVAS the network axis. Folded in only when a directory is given.
        if openvas_dir is not None and openvas_dir.is_dir():
            ip_map = {t.ip: t for t in targets.values() if t.ip}
            ov_containers: list[str] = []
            for f in import_openvas(openvas_dir, ip_map):
                fj = f.to_json()
                out.write(json.dumps(fj) + "\n")
                n_ov += 1
                ov_containers.append(fj.get("target_name", ""))
            scanners.add("openvas")
            # OpenVAS runs outside the engine, so it has no per-invocation
            # timing; record one metric row per scanned container, its wall
            # time being the duration of the batch it was scanned in (the
            # eight hosts of a batch are scanned concurrently). Batch
            # durations come from batch_seconds.txt beside the reports.
            bs = openvas_dir / "batch_seconds.txt"
            durs = []
            if bs.is_file():
                durs = [float(x) for x in bs.read_text().split() if x.strip()]
            for i, c in enumerate(sorted(set(ov_containers))):
                metrics.append({"scanner": "openvas", "target_name": c,
                                "mode": "network", "status": "ok",
                                "wall_seconds": durs[i % len(durs)] if durs else "",
                                "findings": ov_containers.count(c)})

    with open(corpus / "metrics.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=METRIC_COLS, extrasaction="ignore")
        w.writeheader()
        for r in metrics:
            w.writerow(r)
    return n_find, n_ov, sorted(scanners)


def _parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--from-collect", action="store_true", default=True,
                     help="merge the sharded cluster re-run under collect/ (default)")
    src.add_argument("--from-out", type=Path, metavar="DIR",
                     help="read a flat <DIR>/<container>/report.json layout instead "
                          "(the layout `scanners run` writes on one machine)")
    ap.add_argument("--collect-dir", type=Path, default=ROOT / "collect",
                    help="root of the sharded re-run layout (default: ./collect)")
    ap.add_argument("--corpus", type=Path, default=ROOT / "out" / "_corpus",
                    help="output directory for findings.jsonl / metrics.csv "
                         "(default: ./out/_corpus)")
    ap.add_argument("--inventory", type=Path, default=ROOT / "data" / "inventory" / "d1.csv",
                    help="CSV inventory used for IP<->target correlation "
                         "(default: ./data/inventory/d1.csv)")
    ap.add_argument("--openvas-dir", type=Path, default=None,
                    help="directory of OpenVAS reports to fold in as the network "
                         "axis (default: omitted)")
    return ap.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)
    targets = load_targets(args.inventory)

    if args.from_out is not None:
        raw = reports_from_out(args.from_out)
        reports = {c: filter_report(r) for c, r in raw.items()}
        src_desc = f"flat layout {args.from_out}"
    else:
        staticrr = reports_from_collect(args.collect_dir, "static", "out-staticrr")
        statfix = reports_from_collect(args.collect_dir, "statfix", "out-statfix")
        dynfull = reports_from_collect(args.collect_dir, "dynamic", "out-dynfull")
        dynweb = reports_from_collect(args.collect_dir, "dynweb", "out-dynweb")
        containers = sorted(set(staticrr) | set(statfix) | set(dynfull) | set(dynweb))
        reports = {c: merge_report(staticrr.get(c), statfix.get(c),
                                   dynfull.get(c), dynweb.get(c))
                   for c in containers}
        src_desc = (f"sharded re-run {args.collect_dir} "
                    f"(staticrr={len(staticrr)} statfix={len(statfix)} "
                    f"dynfull={len(dynfull)} dynweb={len(dynweb)})")

    n_find, n_ov, scanners = write_corpus(
        args.corpus, reports, openvas_dir=args.openvas_dir, targets=targets)

    findings = args.corpus / "findings.jsonl"
    print(f"consolidated ({src_desc}) -> {findings}")
    print(f"  findings: {n_find:,} from reports + {n_ov:,} OpenVAS "
          f"= {n_find + n_ov:,}")
    print(f"  containers: {len(reports)}")
    print(f"  scanners ({len(scanners)}): {', '.join(scanners)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
