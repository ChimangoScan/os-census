#!/usr/bin/env bash
# Reproducao do censo multi-scanner das imagens base de SO do Docker Hub.
#
#   ./reproduce.sh figures   (padrao) Regenera TODAS as figuras a partir dos
#                            dados pre-computados versionados em data/
#                            (per_image.csv + rq3_sca_sets.json.gz). Nao roda scan.
#   ./reproduce.sh analysis  Reagrega os report.json brutos -> per_image.csv
#                            e imprime o resumo das RQs (precisa do scan feito).
#   ./reproduce.sh full      Estudo inteiro: crawl da API -> fila -> scan com os
#                            14 scanners -> analise -> figuras. Demorado; precisa
#                            de Docker e de um token Docker Hub em config/accounts.json.
#
# Requisitos: python3, uv (https://docs.astral.sh/uv/). O modo full precisa de Docker.
set -euo pipefail
cd "$(dirname "$0")"
MODE="${1:-figures}"
UV="${UV:-uv}"

figures() {
  echo "[reproduce] figuras a partir dos dados pre-computados (data/)"
  "$UV" run --with matplotlib,numpy python paper/make_figs.py
  echo "[reproduce] OK -> paper/figures/*.pdf"
}

case "$MODE" in
  figures)  figures ;;
  analysis)
    echo "[reproduce] reagregando report.json -> data/analysis/per_image.csv"
    python3 scripts/analyze.py
    figures ;;
  full)
    echo "[reproduce] estudo completo: crawl -> fila -> scan -> analise -> figuras"
    python3 scripts/crawl_hub.py                       # API Docker Hub -> data/hub_*.jsonl
    python3 scripts/build_queue.py                     # -> data/jobs_unique.jsonl
    python3 scripts/render_config.py                   # -> config/os.yaml (paths deste clone)
    ( cd multiscan && "$UV" run scanners seed --config ../config/os.yaml \
                   && "$UV" run scanners run  --config ../config/os.yaml )
    python3 scripts/analyze.py                         # -> data/analysis/per_image.csv
    figures ;;
  *) echo "uso: $0 [figures|analysis|full]"; exit 1 ;;
esac
