#!/usr/bin/env python3
"""Compacta (gzip) incrementalmente as saídas das imagens já 'done', pra caber
em disco sem perder dado. Seguro: só toca dirs cujo job está 'done' na fila e
arquivos com mtime > 120s (não pega scan em andamento). Mantém report.json cru
(pequeno, usado pelo dashboard/análise). Idempotente — pode rodar a cada ciclo.
"""
import gzip, shutil, sqlite3, time, sys, os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB = Path(os.environ.get("OSCENSUS_DB") or ROOT / "work/os.db")
OUT = Path(os.environ.get("OSCENSUS_OUT") or ROOT/"scan-out"/"out_so")
EXfiles = {"report.json"}
NOW = time.time()

def done_names():
    c = sqlite3.connect(f"file:{DB}?mode=ro", uri=True, timeout=20)
    try: return {r[0] for r in c.execute("SELECT name FROM jobs WHERE status='done'")}
    finally: c.close()

def main():
    if not OUT.exists(): print("out_so ainda não existe"); return
    names = done_names()
    n_gz = saved = 0
    for d in OUT.iterdir():
        if not d.is_dir() or d.name not in names: continue
        for f in d.rglob("*"):
            if not f.is_file() or f.suffix == ".gz" or f.name in EXfiles: continue
            if NOW - f.stat().st_mtime < 120: continue            # ainda pode estar escrevendo
            raw = f.stat().st_size
            with f.open("rb") as fi, gzip.open(str(f) + ".gz", "wb", compresslevel=6) as fo:
                shutil.copyfileobj(fi, fo)
            saved += raw - (Path(str(f) + ".gz").stat().st_size); f.unlink(); n_gz += 1
    print(f"[{time.strftime('%H:%M:%S')}] compactados {n_gz} arquivos, ~{saved/1024**2:.0f} MB economizados")

if __name__ == "__main__":
    main()
