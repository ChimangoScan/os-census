#!/usr/bin/env bash
# Verify Claim C3: coverage and complementarity.
set -euo pipefail
source "$(dirname "$(readlink -f "$0")")/lib-claims.sh"
claims_setup

rule
echo "CLAIM C3   Coverage and complementarity"
rule
echo "  Per-tool exclusivity is high, yet axis coverage is concentrated and the"
echo "  marginal value of each added scanner falls off sharply (saturation)."
echo
echo "  Artifacts: ${FIGDIR}/fig_exclusivity.pdf  (per-tool exclusive share)"
echo "             ${FIGDIR}/fig_saturation.pdf   (cumulative-unique-finding curve)"
echo
echo "  Expected:  the three mainstream SCA tools are each 38-42% exclusive;"
echo "             the saturation curve rises steeply then flattens, the first"
echo "             handful of scanners capturing most distinct findings."
rule
