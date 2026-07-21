#!/usr/bin/env python3
"""Exporta o status da fila (work/os.db) para data/analysis/job_status.csv.gz,
a base versionada da RQ4 (imagens un-pullable / legacy schema). stdlib only.
Rodar:  OSCENSUS_DB=/caminho/os.db python3 scripts/export_job_status.py
"""
import csv, gzip, json, os, sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB = os.environ.get("OSCENSUS_DB") or str(ROOT / "work/os.db")
OUT = ROOT / "data/analysis/job_status.csv.gz"

c = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
with gzip.open(OUT, "wt", newline="") as f:
    w = csv.writer(f)
    w.writerow(["image", "repo", "status", "pull_count"])
    for stt, tj in c.execute("SELECT status, target_json FROM jobs"):
        d = json.loads(tj)
        m = d.get("meta") or {}
        w.writerow([d.get("image", ""), m.get("repo", "?"), stt, m.get("pull_count") or ""])
c.close()
print(f"{OUT} escrito")
