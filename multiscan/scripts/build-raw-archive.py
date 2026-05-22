#!/usr/bin/env python3
"""Assemble the per-container raw scanner-output archive.

Input  layout: <pull>/<host>/out-{staticrr,statfix,dynfull,dynweb}/<container>/<scanner>/
Output layout: <out>/<container>/<scanner>/   (native scanner files only)

The archive is organized purely by container. Each scanner is taken from its
authoritative phase: the static scanners from out-staticrr, except
whispers/pip-audit/govulncheck (which errored there and are taken from the
out-statfix re-run); the dynamic scanners from out-dynfull, except nuclei
(taken from the out-dynweb re-run).

Files are hard-linked when input and output share a filesystem, so the archive
costs no extra disk. Nothing is hardcoded: both paths are CLI arguments.

Usage: build-raw-archive.py <pull-dir> <out-dir>
"""
from __future__ import annotations
import os
import shutil
import sys
from pathlib import Path

STATFIX = {"whispers", "pip-audit", "govulncheck"}
DYNWEB = {"nuclei"}

# (phase outdir, predicate: keep this scanner from this phase?). Order matters:
# the first phase to provide a scanner directory wins. out-dynweb is listed
# before out-dynfull so the corrected nuclei re-run wins where it exists, while
# out-dynfull supplies nuclei (and every other dynamic scanner) elsewhere.
PHASES = [
    ("out-staticrr", lambda s: s not in STATFIX),
    ("out-statfix", lambda s: s in STATFIX),
    ("out-dynweb", lambda s: s in DYNWEB),
    ("out-dynfull", lambda s: True),
]


def _copy(src: Path, dst: Path) -> None:
    """Hard-link the tree if possible, else copy."""
    try:
        shutil.copytree(src, dst, copy_function=os.link)
    except OSError:
        shutil.copytree(src, dst)


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    pull, out = Path(sys.argv[1]), Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    containers: set[str] = set()
    for host in sorted(p for p in pull.iterdir() if p.is_dir()):
        for outdir, keep in PHASES:
            phase = host / outdir
            if not phase.is_dir():
                continue
            for cdir in sorted(p for p in phase.iterdir() if p.is_dir()):
                containers.add(cdir.name)
                dest = out / cdir.name
                for scanner in sorted(p for p in cdir.iterdir() if p.is_dir()):
                    if keep(scanner.name) and not (dest / scanner.name).exists():
                        _copy(scanner, dest / scanner.name)
    n_scan = sum(1 for c in out.iterdir() if c.is_dir()
                 for _ in (c.iterdir()))
    print(f"assembled {len(containers)} containers, {n_scan} scanner dirs -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
