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
# Requisitos: python3, uv (https://docs.astral.sh/uv/). O modo full precisa de Docker.
set -euo pipefail
cd "$(dirname "$0")"
MODE="${1:-figures}"
UV="${UV:-uv}"

figures() {
  echo "[reproduce] figuras a partir dos dados pre-computados (data/)"
  "$UV" run --with matplotlib,numpy python scripts/make_figs.py
  echo "[reproduce] OK -> figures/*.pdf"
}

case "$MODE" in
  data|figures)  figures ;;
  analysis)
    echo "[reproduce] reagregando report.json -> data/analysis/per_image.csv"
    python3 scripts/analyze.py
    figures ;;
  all|full)
    echo "[reproduce] estudo completo: crawl -> fila -> scan -> analise -> figuras"
    python3 scripts/crawl_hub.py                       # API Docker Hub -> data/hub_*.jsonl
    python3 scripts/build_queue.py                     # -> data/jobs_unique.jsonl
    python3 scripts/render_config.py                   # -> config/os.yaml (paths deste clone)
    ( cd multiscan && "$UV" run scanners seed --config ../config/os.yaml \
                   && "$UV" run scanners run  --config ../config/os.yaml )
    python3 scripts/analyze.py                         # -> data/analysis/per_image.csv
    figures ;;
  *) echo "uso: $0 [data|analysis|all]   (data=so figuras dos dados; all=estudo inteiro)"; exit 1 ;;
esac
