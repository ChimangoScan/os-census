#!/usr/bin/env bash
# Verify Claim C1: a released, citable multi-scanner dataset.
set -euo pipefail
source "$(dirname "$(readlink -f "$0")")/lib-claims.sh"
claims_setup

n=$(corpus_findings)
rule
echo "CLAIM C1   A released, citable multi-scanner dataset"
rule
echo "  130 vulnerable containers x 31 open-source scanners across 8 axes."
echo
echo "  Observed (CORPUS=${CORPUS}): ${n} normalized findings"
echo "  Artifact:  ${FIGDIR}/fig_overview.pdf  (findings by analysis axis)"
echo
echo "  Expected:  on the full bundled dataset, 1,427,789 findings with every"
echo "             one of the 8 axes non-empty. A reduced corpus yields fewer"
echo "             findings but the same by-axis shape."
rule
