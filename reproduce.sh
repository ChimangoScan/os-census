#!/usr/bin/env bash
# Reproduction of the multi-scanner census of the Linux OS base images of Docker Hub.
# One command per path:
#
#   ./reproduce.sh           FROM THE COMMITTED DATA: regenerate every figure from
#   (or ./reproduce.sh data) the pre-computed data versioned in data/
#                            (per_image.csv + rq3_sca_sets.json.gz), then verify
#                            every paper number. No scan, no network.
#
#   ./reproduce.sh analysis  Re-derive the committed aggregates from the raw
#                            per-image reports (downloaded from the release and
#                            sha256-verified), then run the same figures + verify.
#
#   ./reproduce.sh scan-smoke  Run the real 14-scanner pipeline on 10 corpus images.
#
#   ./reproduce.sh all       THE WHOLE STUDY from scratch: crawl the Docker Hub API
#                            -> queue -> scan (14 scanners) -> analysis -> figures.
#                            Weeks of scanning; needs Docker and a Docker Hub token.
#
# Requirements: python3, uv (https://docs.astral.sh/uv/); `analysis` also needs
# curl + zstd (it downloads the dataset from the release if absent); `scan-smoke`
# and `all` need Docker.
set -euo pipefail
cd "$(dirname "$0")"
MODE="${1:-figures}"
UV="${UV:-uv}"

DATASET_URL="https://github.com/ChimangoScan/os-census/releases/download/dataset-v1/os-census-per-image-reports.tar.zst"
DATASET_SHA256="184e823e663a563608e0f0398a7aa095d533a41aefc1e7f7df30b8086909d963"

ensure_dataset() {  # make sure the report.json files are present; download from the release and verify sha256 if not
  local out="${OSCENSUS_OUT:-$PWD/scan-out/out_so}"
  if [ -n "$(find "$out" -maxdepth 2 -name report.json -print -quit 2>/dev/null)" ]; then
    echo "[reproduce] dataset already present in $out"; return
  fi
  echo "[reproduce] dataset absent; downloading from the release (~138 MB; 8.6 GB extracted)"
  mkdir -p scan-out
  if ! curl -L --fail -o scan-out/reports.tar.zst "$DATASET_URL"; then
    echo "[reproduce] direct URL unavailable; resolving through the API endpoint"
    local aurl
    aurl=$(curl -s https://api.github.com/repos/ChimangoScan/os-census/releases/tags/dataset-v1 \
      | python3 -c "import json,sys;print([a['url'] for a in json.load(sys.stdin)['assets'] if a['name']=='os-census-per-image-reports.tar.zst'][0])")
    curl -L --fail -H "Accept: application/octet-stream" -o scan-out/reports.tar.zst "$aurl"
  fi
  echo "$DATASET_SHA256  scan-out/reports.tar.zst" | sha256sum -c -
  tar --zstd -xf scan-out/reports.tar.zst -C scan-out
  rm scan-out/reports.tar.zst
  export OSCENSUS_OUT="$PWD/scan-out/out_so"
}

figures() {
  echo "[reproduce] figures from the pre-computed data (data/)"
  "$UV" run --with matplotlib,numpy python scripts/make_figs.py
  echo "[reproduce] OK -> figures/*.pdf"
}

verify() {
  echo "[reproduce] checking every paper number against the data (expected/paper_values.json)"
  python3 scripts/verify_values.py
}

case "$MODE" in
  data|figures)  figures; verify ;;
  verify)        verify ;;
  analysis)
    ensure_dataset
    echo "[reproduce] re-aggregating report.json -> data/analysis/per_image.csv"
    python3 scripts/analyze.py
    figures; verify ;;
  all|full)
    echo "[reproduce] whole study: crawl -> queue -> scan -> analysis -> figures"
    python3 scripts/crawl_hub.py                       # Docker Hub API -> data/hub_*.jsonl
    python3 scripts/build_queue.py                     # -> data/jobs_unique.jsonl
    python3 scripts/render_config.py                   # -> config/os.yaml (paths of this clone)
    ( cd multiscan && "$UV" run scanners seed --config ../config/os.yaml \
                   && "$UV" run scanners run  --config ../config/os.yaml )
    python3 scripts/analyze.py                         # -> data/analysis/per_image.csv
    figures; verify ;;
  scan-smoke)
    echo "[reproduce] reduced scan pipeline: scanning ${SMOKE_N:-10} images with the 14 scanners"
    bash scripts/scan_smoke.sh ;;
  *) echo "usage: $0 [data|analysis|verify|scan-smoke|all]   (data=figures+verify; scan-smoke=scan pipeline on 10 images; all=the whole study)"; exit 1 ;;
esac
