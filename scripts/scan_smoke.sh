#!/usr/bin/env bash
# Claim 3 em versao reduzida: escaneia SMOKE_N imagens do corpus (default 10,
# uma fatia round-robin -> ~10 distros diferentes) com os MESMOS 14 scanners
# do censo, numa fila e saida proprias (nao toca o censo). Requisitos: Docker,
# python3, uv. Credencial Docker Hub e opcional (config/accounts.json).
set -euo pipefail
cd "$(dirname "$0")/.."
N="${SMOKE_N:-10}"
UV="${UV:-uv}"
SMOKE="$PWD/scan-out/smoke"
mkdir -p "$SMOKE" work
head -n "$N" data/jobs_unique.jsonl > "$SMOKE/jobs.jsonl"

ACCOUNTS=""
[ -f config/accounts.json ] && ACCOUNTS="$PWD/config/accounts.json"
cat > config/smoke_scan.yaml <<EOF
# Gerado por scripts/scan_smoke.sh (nao editar; nao versionado).
queue:
  backend: sqlite
  sqlite_path: $PWD/work/smoke.db
source:
  type: jsonl
  path: $SMOKE/jobs.jsonl
scanners:
  registry: $PWD/config/scanners.yaml
  only: [syft, cdxgen, trivy, grype, osv, clair, dockle, checkov,
         trufflehog, gitleaks, detect-secrets, whispers, clamav, yarahunter]
  static: true
  dynamic: false
output:
  dir: $SMOKE/out
  cache_dir: $SMOKE/cache
  keep_image_tarball: false
  skip_done: true
workers:
  count: 1
  scan_timeout: 1800
runtime:
  remove_image_after: true
  max_image_mb: 2000
  prune_every: 25
  scan_parallelism: 4
  pull_retries: 4
  pull_backoff: 30
  dockerhub_accounts: $ACCOUNTS
EOF

docker image inspect multiscan/whispers:1 >/dev/null 2>&1 || \
  printf 'FROM python:3.12.10-alpine3.21\nRUN pip install --no-cache-dir whispers==2.4.0\nENTRYPOINT ["whispers"]\n' \
  | docker build -q -t multiscan/whispers:1 -

( cd multiscan && "$UV" run scanners prepare --only clair --config ../config/smoke_scan.yaml )
( cd multiscan && "$UV" run scanners seed --config ../config/smoke_scan.yaml \
               && "$UV" run scanners run  --config ../config/smoke_scan.yaml )

GOT=$(find "$SMOKE/out" -maxdepth 2 -name report.json | wc -l)
echo "[scan-smoke] $GOT/$N imagens com report.json em $SMOKE/out"
SMOKE_OUT="$SMOKE/out" python3 - <<'PY'
import glob, json, os, collections
per = collections.Counter(); imgs = 0
for rj in glob.glob(os.environ["SMOKE_OUT"] + "/*/report.json"):
    r = json.load(open(rj)); imgs += 1
    for i in r.get("invocations", []):
        per[i["scanner"]] += 1
print(f"[scan-smoke] {imgs} reports; invocacoes por scanner:",
      dict(sorted(per.items())))
PY
test "$GOT" -ge "$((N * 8 / 10))"   # sucesso: >=80% (imagens legacy-schema do corpus podem ser skipped)
echo "[scan-smoke] OK"
