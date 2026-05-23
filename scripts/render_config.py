#!/usr/bin/env python3
"""Gera config/os.yaml com os caminhos corretos para ESTE clone, sem edicao
manual. Caminhos de saida/cache: env OSCENSUS_OUT/OSCENSUS_CACHE, senao
scan-out/ dentro do repo.
Rodar:  python3 scripts/render_config.py
"""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
def pick(env, rel):
    return os.environ.get(env) or str(ROOT / rel)

OUT   = pick("OSCENSUS_OUT",   "scan-out/out_so")
CACHE = pick("OSCENSUS_CACHE", "scan-out/cache_so")
for d in (OUT, CACHE, str(ROOT/"work")):
    Path(d).mkdir(parents=True, exist_ok=True)

cfg = f"""# Gerado por scripts/render_config.py (NAO editar a mao; rode o script).
queue:
  backend: sqlite
  sqlite_path: {ROOT}/work/os.db
source:
  type: jsonl
  path: {ROOT}/data/jobs_unique.jsonl
scanners:
  registry: {ROOT}/config/scanners.yaml
  only: [syft, cdxgen, trivy, grype, osv, clair, dockle, checkov,
         trufflehog, gitleaks, detect-secrets, whispers, clamav, yarahunter]
  static: true
  dynamic: false
output:
  dir: {OUT}
  cache_dir: {CACHE}
  keep_image_tarball: false
  skip_done: true
workers:
  count: 1            # 1 pull por vez por maquina (limite de rede)
  scan_timeout: 1800
runtime:
  remove_image_after: true
  max_image_mb: 2000
  prune_every: 25
  scan_parallelism: 4
  pull_retries: 4
  pull_backoff: 30
  dockerhub_accounts: {ROOT}/config/accounts.json
"""
(ROOT / "config/os.yaml").write_text(cfg)
print(f"config/os.yaml gerado. out={OUT} cache={CACHE}")
