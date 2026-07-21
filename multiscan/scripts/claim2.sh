#!/usr/bin/env bash
# Verify Claim C2: cross-family measurement of coverage and overlap.
set -euo pipefail
source "$(dirname "$(readlink -f "$0")")/lib-claims.sh"
claims_setup

rule
echo "CLAIM C2   Cross-family coverage and overlap"
rule
echo "  A large share of each tool's findings is exclusive to it in every axis;"
echo "  the closest mainstream SCA pair agrees on only ~33% of CVEs; chance-"
echo "  corrected agreement is negative in every multi-tool axis."
echo
echo "  Observed agreement coefficients (CORPUS=${CORPUS}):"
grep -A9 -i "agreement coefficients" "${FIGDIR}/analysis.txt" 2>/dev/null \
  | sed 's/^/    /' || echo "    (see ${FIGDIR}/analysis.txt)"
echo
echo "  Artifacts: ${FIGDIR}/adv_agreement_coeffs.pdf  (Fleiss k / Kripp. a / Gwet AC1)"
echo "             ${FIGDIR}/adv_venn_grid.pdf          (finding overlap)"
echo
echo "  Expected:  Fleiss' kappa negative for every multi-tool axis; Gwet's AC1"
echo "             positive for secrets and web."
rule
