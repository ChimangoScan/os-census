#!/usr/bin/env bash
# Verify Claim C4: runtime characterization and per-axis recommendation.
set -euo pipefail
source "$(dirname "$(readlink -f "$0")")/lib-claims.sh"
claims_setup

rule
echo "CLAIM C4   Runtime characterization and per-axis recommendation"
rule
echo "  Per-scanner wall time spans more than two orders of magnitude; the"
echo "  Shapley value attributes a fair coverage share to each tool per axis."
echo
echo "  Observed Shapley attribution (CORPUS=${CORPUS}):"
grep -A24 "Shapley coverage attribution" "${FIGDIR}/analysis.txt" 2>/dev/null \
  | sed 's/^/    /' || echo "    (see ${FIGDIR}/analysis.txt)"
echo
echo "  Artifacts: ${FIGDIR}/fig_cost.pdf      (per-container wall time)"
echo "             ${FIGDIR}/adv_shapley.pdf   (Shapley coverage attribution)"
echo
echo "  Expected:  runtime spans seconds to ~15 min per container; on SCA the"
echo "             Shapley split is balanced (Grype ~40%, Trivy ~36%,"
echo "             OSV-Scanner ~21%, govulncheck ~3%)."
rule
