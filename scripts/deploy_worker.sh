#!/bin/bash
# Deploys a remote OS-census worker onto a remote host, consistent with the local one:
# multiscan engine + scanners.yaml (clair --image-ref) + matcher.db + whispers.
# The worker consumes the queue via the local coordinator (port 8918) over a reverse tunnel.
# Usage: bash deploy_worker.sh <host>     (run from the local PC; requires ssh <host> and ssh -R)
set -e
H="$1"; [ -z "$H" ] && { echo "usage: deploy_worker.sh <host>"; exit 1; }
COORD=8918
ROOT="$(cd "$(dirname "$0")/.." && pwd)"          # repo root (auto)
LOCAL_REPO="${OSCENSUS_ENGINE:-$ROOT/multiscan}"  # engine: submodule by default
LOCAL_CFG="$ROOT/config"
MATCHER="${OSCENSUS_MATCHER:-${OSCENSUS_CACHE:-$ROOT/scan-out/cache_so}/clair/matcher.db}"
RD=os-worker   # remote dir (relative to home)

echo "[$H] 1. dirs"
ssh "$H" "mkdir -p ~/$RD/{cache/clair,out,work}"

echo "[$H] 2. engine + configs (rsync)"
rsync -az --delete --exclude '.venv' --exclude '.git' --exclude '__pycache__' "$LOCAL_REPO/" "$H:~/$RD/multiscan/"
rsync -az "$LOCAL_CFG/scanners.yaml" "$H:~/$RD/scanners.yaml"
rsync -az "$LOCAL_CFG/accounts.json" "$H:~/$RD/accounts.json"

echo "[$H] 3. clair matcher.db (~1GB, LAN)"
rsync -az "$MATCHER" "$H:~/$RD/cache/clair/matcher.db"

echo "[$H] 4. worker config (http backend -> coordinator via tunnel; 1 pull/machine)"
HOME_R=$(ssh "$H" 'echo $HOME')
ssh "$H" "cat > ~/$RD/config.yaml" <<EOF
queue:
  backend: http
  url: http://localhost:$COORD
source:
  type: txt
  path: $HOME_R/$RD/empty.txt
scanners:
  registry: $HOME_R/$RD/scanners.yaml
  only: [syft, cdxgen, trivy, grype, osv, clair, dockle, checkov, trufflehog, gitleaks, detect-secrets, whispers, clamav, yarahunter]
  static: true
  dynamic: false
output:
  dir: $HOME_R/$RD/out
  cache_dir: $HOME_R/$RD/cache
  keep_image_tarball: false
workers:
  count: 1          # 1 pull at a time per machine (network limit)
  scan_timeout: 1800
runtime:
  remove_image_after: true
  max_image_mb: 2000
  scan_parallelism: 4
  dockerhub_accounts: $HOME_R/$RD/accounts.json
EOF
ssh "$H" "touch ~/$RD/empty.txt"

echo "[$H] 5. uv (install if missing)"
ssh "$H" 'command -v uv >/dev/null || (curl -LsSf https://astral.sh/uv/install.sh | sh)'

echo "[$H] 6. build whispers"
ssh "$H" 'd=$(mktemp -d); printf "FROM python:3.12.10-alpine3.21\nRUN pip install --no-cache-dir whispers==2.4.0\nENTRYPOINT [\"whispers\"]\n" > $d/Dockerfile; docker build -q -t multiscan/whispers:1 $d >/dev/null && echo whispers-ok'

echo "[$H] 7. reverse tunnel PC->$H (coordinator)"
pkill -f "R $COORD:localhost:$COORD $H" 2>/dev/null || true
sleep 1
ssh -f -N -o ServerAliveInterval=30 -o ExitOnForwardFailure=yes -R $COORD:localhost:$COORD "$H" || echo "WARNING: tunnel may already exist"

echo "[$H] 8. start worker (nohup)"
ssh "$H" "cd ~/$RD/multiscan && nohup \$HOME/.local/bin/uv run scanners run --config ~/$RD/config.yaml > ~/$RD/worker.log 2>&1 & echo started pid \$!"
echo "[$H] DEPLOY OK"
