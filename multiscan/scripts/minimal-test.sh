#!/usr/bin/env bash
# =============================================================================
# Multiscan minimal test, one command
# =============================================================================
# Runs the real pipeline against two corpus containers (one base OS image and
# one deliberately vulnerable web app) and produces observable normalized
# findings. Everything is written under a single local directory; nothing else
# on the machine is touched.
#
# Usage:
#   bash scripts/minimal-test.sh
#
# Configuration (all optional, every value has a default):
#   CONTAINERS=alpine37,dvwa        comma-separated containers to scan
#   RESULTS_DIR=results-minimal     output directory (under the repo)
#   INVENTORY_SRC=data/inventory/d1-reduced.csv   inventory to pick from
# =============================================================================
set -euo pipefail

# locate the repository root (this script lives in scripts/)
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

CONTAINERS="${CONTAINERS:-alpine37,dvwa}"
RESULTS_DIR="${RESULTS_DIR:-results-minimal}"
INVENTORY_SRC="${INVENTORY_SRC:-data/inventory/d1-reduced.csv}"

[ -f "${INVENTORY_SRC}" ] || { echo "error: inventory not found: ${INVENTORY_SRC}" >&2; exit 1; }

mkdir -p "${RESULTS_DIR}"
MINI="${RESULTS_DIR}/inventory.csv"

# build the inventory: the CSV header plus the chosen containers
head -1 "${INVENTORY_SRC}" > "${MINI}"
pattern=$(printf '%s' "${CONTAINERS}" | tr ',' '|')
grep -E ",(${pattern})," "${INVENTORY_SRC}" >> "${MINI}" || true

n=$(($(wc -l < "${MINI}") - 1))
echo "minimal test: ${n} container(s) [${CONTAINERS}] -> ${MINI}"
[ "${n}" -ge 1 ] || { echo "error: no containers matched '${CONTAINERS}' in ${INVENTORY_SRC}" >&2; exit 1; }

# run the full pipeline against just those containers, all output under RESULTS_DIR
INVENTORY="${MINI}" RESULTS_DIR="${RESULTS_DIR}" bash scripts/reproduce-reduced.sh
