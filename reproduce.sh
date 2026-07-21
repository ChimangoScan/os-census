#!/usr/bin/env bash
# Reproducao do censo multi-scanner das imagens base de SO do Docker Hub.
# Um comando por coisa:
#
#   ./reproduce.sh           SO COM OS DADOS: regenera TODAS as figuras a partir
#   (ou ./reproduce.sh data) dos dados pre-computados versionados em data/
#                            (per_image.csv + rq3_sca_sets.json.gz). Nao roda scan.
#
#   ./reproduce.sh all       ESTUDO INTEIRO do zero: crawl da API -> fila -> scan
#                            (14 scanners) -> analise -> as mesmas figuras.
#                            Demorado; precisa de Docker e token Docker Hub.
#
#   ./reproduce.sh analysis  (intermediario) report.json brutos -> per_image.csv -> figuras.
#
# Requisitos: python3, uv (https://docs.astral.sh/uv/); analysis precisa de
# curl + zstd (baixa o dataset da release se ausente); full precisa de Docker.
set -euo pipefail
cd "$(dirname "$0")"
MODE="${1:-figures}"
UV="${UV:-uv}"

DATASET_URL="https://github.com/ChimangoScan/os-census/releases/download/dataset-v1/os-census-per-image-reports.tar.zst"
DATASET_SHA256="184e823e663a563608e0f0398a7aa095d533a41aefc1e7f7df30b8086909d963"

ensure_dataset() {  # garante os report.json; baixa da release e verifica sha256 se ausentes
  local out="${OSCENSUS_OUT:-$PWD/scan-out/out_so}"
  if [ -n "$(find "$out" -maxdepth 2 -name report.json -print -quit 2>/dev/null)" ]; then
    echo "[reproduce] dataset presente em $out"; return
  fi
  echo "[reproduce] dataset ausente; baixando da release (~138 MB; 8.6 GB extraido)"
  mkdir -p scan-out
  if ! curl -L --fail -o scan-out/reports.tar.zst "$DATASET_URL"; then
    echo "[reproduce] URL direta indisponivel; resolvendo pelo endpoint da API"
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
  echo "[reproduce] figuras a partir dos dados pre-computados (data/)"
  "$UV" run --with matplotlib,numpy python scripts/make_figs.py
  echo "[reproduce] OK -> figures/*.pdf"
}

verify() {
  echo "[reproduce] verificando cada numero do paper contra os dados (expected/paper_values.json)"
  python3 scripts/verify_values.py
}

case "$MODE" in
  data|figures)  figures; verify ;;
  verify)        verify ;;
  analysis)
    ensure_dataset
    echo "[reproduce] reagregando report.json -> data/analysis/per_image.csv"
    python3 scripts/analyze.py
    figures; verify ;;
  all|full)
    echo "[reproduce] estudo completo: crawl -> fila -> scan -> analise -> figuras"
    python3 scripts/crawl_hub.py                       # API Docker Hub -> data/hub_*.jsonl
    python3 scripts/build_queue.py                     # -> data/jobs_unique.jsonl
    python3 scripts/render_config.py                   # -> config/os.yaml (paths deste clone)
    ( cd multiscan && "$UV" run scanners seed --config ../config/os.yaml \
                   && "$UV" run scanners run  --config ../config/os.yaml )
    python3 scripts/analyze.py                         # -> data/analysis/per_image.csv
    figures; verify ;;
  scan-smoke)
    echo "[reproduce] claim 3 reduzido: escaneando ${SMOKE_N:-10} imagens com os 14 scanners"
    bash scripts/scan_smoke.sh ;;
  *) echo "uso: $0 [data|analysis|verify|scan-smoke|all]   (data=figuras+verify; scan-smoke=pipeline de scan em 10 imagens; all=estudo inteiro)"; exit 1 ;;
esac
