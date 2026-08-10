#!/usr/bin/env python3
"""Incrementally gzip-compresses the outputs of images already 'done', to fit
on disk without losing data. Safe: only touches dirs whose job is 'done' in the
queue and files with mtime > 120s (does not catch an in-progress scan). Keeps
report.json raw (small, used by the dashboard/analysis). Idempotent — can run
every cycle.
"""
import gzip, shutil, sqlite3, time, sys, os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB = Path(os.environ.get("OSCENSUS_DB") or ROOT / "work/os.db")
OUT = Path(os.environ.get("OSCENSUS_OUT") or ROOT/"scan-out"/"out_so")
EXfiles = {"report.json"}
NOW = time.time()

def done_names():
    """Return the set of job names whose status is 'done' in the queue DB.

    Read-only query against DB (`work/os.db` by default). Used to decide which
    scan-output directories are safe to gzip: only images the coordinator has
    finished, never one still being scanned.
    """
    c = sqlite3.connect(f"file:{DB}?mode=ro", uri=True, timeout=20)
    try: return {r[0] for r in c.execute("SELECT name FROM jobs WHERE status='done'")}
    finally: c.close()

def main():
    """Gzip every eligible raw scanner-output file under OUT in place.

    Eligible = file belongs to a directory whose job is 'done' (done_names()),
    is not report.json (kept raw for analyze.py/make_figs.py), is not already
    .gz, and has an mtime older than 120s (skips files a still-running scan may
    still be writing). Deletes the raw file after compressing; safe to re-run
    since already-.gz files are skipped. Does not affect any paper number —
    it only shrinks disk usage of the working scan-out/ tree.
    """
    if not OUT.exists(): print("out_so does not exist yet"); return
    names = done_names()
    n_gz = saved = 0
    for d in OUT.iterdir():
        if not d.is_dir() or d.name not in names: continue
        for f in d.rglob("*"):
            if not f.is_file() or f.suffix == ".gz" or f.name in EXfiles: continue
            if NOW - f.stat().st_mtime < 120: continue            # may still be writing
            raw = f.stat().st_size
            with f.open("rb") as fi, gzip.open(str(f) + ".gz", "wb", compresslevel=6) as fo:
                shutil.copyfileobj(fi, fo)
            saved += raw - (Path(str(f) + ".gz").stat().st_size); f.unlink(); n_gz += 1
    print(f"[{time.strftime('%H:%M:%S')}] compressed {n_gz} files, ~{saved/1024**2:.0f} MB saved")

if __name__ == "__main__":
    main()
