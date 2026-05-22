#!/usr/bin/env bash
# =============================================================================
# Multiscan, fully-automatic one-command reproduction
# =============================================================================
# One script, two ways to reproduce the paper:
#
#   (A) FROM THE PIPELINE  (default)
#       bash scripts/reproduce-reduced.sh
#       Runs the COMPLETE artifact pipeline end-to-end on a REDUCED corpus
#       (about 10 representative containers), so an SBC artifact reviewer can
#       reproduce the methodology and figures on a single laptop in roughly an
#       hour, without the multi-day cluster job the full 130-container study
#       needs. Steps: install uv, sync the engine, build the analysis venv,
#       build the local scanner images, run the scanner battery, consolidate
#       the per-container reports, generate every figure.
#
#   (B) FROM A READY DATASET  (no scanning, a few minutes)
#       CORPUS=dataset bash scripts/reproduce-reduced.sh
#       Skips all scanning and consolidation: takes an already-consolidated
#       corpus and regenerates every figure from it. The released dataset
#       ships in dataset/ (findings.jsonl.gz + metrics.csv); a plain
#       findings.jsonl is accepted too.
#
# Both ways are idempotent and resumable: re-running skips work already done
# (uv sync is a no-op, the harness resumes per scanner via output.skip_done,
# image builds are layer-cached). Re-run after an interruption.
#
# Configuration (all optional; nothing hardcoded that you cannot override):
#   CORPUS=path/to/_corpus            ready corpus dir; enables mode (B)
#   INVENTORY=path/to/inventory.csv   target list (default: data/inventory/d1-reduced.csv)
#   RESULTS_DIR=path/to/results       output root (default: results)
#   WORKERS=N                         parallel targets (default: 2)
#   SCAN_PARALLELISM=N                scanners per target (default: 2)
#   SCAN_TIMEOUT=SECONDS              per-scanner wall cap (default: 900)
#   SKIP_BUILD=1                      skip the local image build step
#   SKIP_SCAN=1                       reuse an existing run, only re-consolidate and plot
# Or pass the inventory as the first positional argument:
#   bash scripts/reproduce-reduced.sh data/inventory/smoke.csv
# =============================================================================
set -euo pipefail

# --- locate the repository root (this script lives in scripts/) --------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

# --- configuration (env vars / positional arg; every value has a default) ----
CORPUS="${CORPUS:-}"
INVENTORY="${1:-${INVENTORY:-data/inventory/d1-reduced.csv}}"
RESULTS_DIR="${RESULTS_DIR:-results}"
WORKERS="${WORKERS:-2}"
SCAN_PARALLELISM="${SCAN_PARALLELISM:-2}"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-900}"
SKIP_BUILD="${SKIP_BUILD:-0}"
SKIP_SCAN="${SKIP_SCAN:-0}"

# derived paths, all under RESULTS_DIR, so a reviewer can wipe one directory
OUT_DIR="${RESULTS_DIR}/out"               # per-container report.json tree
CORPUS_DIR="${RESULTS_DIR}/_corpus"        # consolidated findings.jsonl + metrics.csv
FIG_DIR="${RESULTS_DIR}/figures"           # generated PDF figures
WORK_DIR="${RESULTS_DIR}/work"             # the SQLite work queue
CACHE_DIR="${RESULTS_DIR}/cache"           # shared scanner caches
RUN_CONFIG="${RESULTS_DIR}/reduced-config.yaml"

# mode (B): a ready corpus was supplied, skip scanning and consolidation
DATASET_MODE=0
if [ -n "${CORPUS}" ]; then
  DATASET_MODE=1
  CORPUS_DIR="${CORPUS}"
fi

step() { printf '\n\033[1;34m==>\033[0m \033[1m%s\033[0m\n' "$1"; }
info() { printf '    %s\n' "$1"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$1" >&2; exit 1; }

# --- 0. pre-flight checks ----------------------------------------------------
step "Pre-flight checks"
if [ "${DATASET_MODE}" = 1 ]; then
  info "mode      : reproduce from a ready dataset (no scanning)"
  if [ -s "${CORPUS_DIR}/findings.jsonl" ]; then
    info "corpus    : ${CORPUS_DIR}/findings.jsonl"
  elif [ -s "${CORPUS_DIR}/findings.jsonl.gz" ]; then
    info "corpus    : ${CORPUS_DIR}/findings.jsonl.gz (gzip-compressed)"
  else
    die "CORPUS=${CORPUS_DIR} has no findings.jsonl or findings.jsonl.gz"
  fi
else
  info "mode      : reproduce from the pipeline"
  [ -f "${INVENTORY}" ] || die "inventory not found: ${INVENTORY}"
  command -v docker >/dev/null 2>&1 || die "docker is required but not installed"
  docker info >/dev/null 2>&1 || die "the Docker daemon is not reachable (start it, or add your user to the 'docker' group)"
  info "inventory : ${INVENTORY} ($(($(wc -l < "${INVENTORY}") - 1)) containers)"
  info "docker    : $(docker --version)"
fi
info "results   : ${RESULTS_DIR}/"

# --- 1. install uv if absent (official installer; no system pip is touched) --
step "Ensuring uv is installed"
if ! command -v uv >/dev/null 2>&1; then
  info "uv not found, installing via the official installer"
  curl -LsSf https://astral.sh/uv/install.sh | sh
  # the installer drops uv into ~/.local/bin (or $XDG_BIN_HOME / $CARGO_HOME)
  export PATH="${HOME}/.local/bin:${HOME}/.cargo/bin:${PATH}"
  command -v uv >/dev/null 2>&1 || die "uv install succeeded but uv is not on PATH; open a new shell and re-run"
fi
info "uv        : $(uv --version)"

# --- 2. create the engine environment ---------------------------------------
step "Installing the scanning engine (uv sync)"
# uv manages an isolated .venv with the pinned Python 3.12 + PyYAML; the system
# Python is never modified, so the PEP 668 'externally-managed-environment'
# error simply cannot occur.
uv sync

# --- 3. create the analysis environment -------------------------------------
step "Installing the analysis dependencies"
ANALYSIS_VENV=".venv-analysis"
if [ ! -x "${ANALYSIS_VENV}/bin/python" ]; then
  uv venv "${ANALYSIS_VENV}"
fi
# matplotlib + numpy/scipy/scikit-learn for the figures and statistics;
# matplotlib-venn for the Venn panels; krippendorff for the agreement table.
uv pip install --quiet --python "${ANALYSIS_VENV}/bin/python" \
  "matplotlib>=3.7" "numpy>=1.26" "scipy>=1.11" "scikit-learn>=1.3" \
  "matplotlib-venn>=1.1" "krippendorff>=0.6"
ANALYSIS_PY="${ANALYSIS_VENV}/bin/python"

if [ "${DATASET_MODE}" = 0 ]; then
  # --- 4. build the locally-built scanner images -----------------------------
  if [ "${SKIP_BUILD}" = "1" ]; then
    step "Building local scanner images (skipped: SKIP_BUILD=1)"
  else
    step "Building the locally-built scanner images"
    info "some scanners have no maintained upstream image; building from docker/"
    bash scripts/build-images.sh
  fi

  # --- 5. write the run configuration ----------------------------------------
  # The reduced run gets its own self-contained config so the script never
  # edits a file the user owns and never collides with config/config.yaml.
  step "Writing the reduced-run configuration"
  mkdir -p "${RESULTS_DIR}"
  cat > "${RUN_CONFIG}" <<YAML
# Auto-generated by scripts/reproduce-reduced.sh, safe to delete.
# Reduced reproduction config: a small representative inventory, modest
# resources, all outputs under ${RESULTS_DIR}/.
queue:
  backend: sqlite
  sqlite_path: ${WORK_DIR}/queue.db
source:
  type: csv
  path: ${INVENTORY}
  image_column: image
  name_column: container
  ip_column: ip
  meta_columns: [category, port, risk]
scanners:
  registry: config/scanners.yaml
  static: true
  dynamic: true
output:
  dir: ${OUT_DIR}
  cache_dir: ${CACHE_DIR}
  keep_image_tarball: false
  skip_done: true
workers:
  count: ${WORKERS}
  scan_timeout: ${SCAN_TIMEOUT}
runtime:
  scan_parallelism: ${SCAN_PARALLELISM}
  remove_image_after: true
  max_image_mb: 12000
YAML
  info "wrote ${RUN_CONFIG}"

  # --- 6. run the harness ----------------------------------------------------
  if [ "${SKIP_SCAN}" = "1" ]; then
    step "Running the harness (skipped: SKIP_SCAN=1, reusing ${OUT_DIR})"
    [ -d "${OUT_DIR}" ] || die "SKIP_SCAN=1 but no prior run found at ${OUT_DIR}"
  else
    step "Seeding the work queue"
    uv run scanners seed -c "${RUN_CONFIG}"

    step "Running the scanner battery (static + dynamic phases)"
    info "this pulls scanner and target images on first run, be patient"
    info "the run is resumable: if it is interrupted, re-run this script"
    uv run scanners run -c "${RUN_CONFIG}" -v

    step "Scan queue status"
    uv run scanners status -c "${RUN_CONFIG}"
  fi

  # --- 7. consolidate the per-container reports into a corpus ----------------
  step "Consolidating per-container reports into a corpus"
  "${ANALYSIS_PY}" scripts/consolidate.py \
    --from-out "${OUT_DIR}" \
    --corpus "${CORPUS_DIR}" \
    --inventory "${INVENTORY}"
  [ -s "${CORPUS_DIR}/findings.jsonl" ] || \
    die "consolidation produced no findings, inspect ${OUT_DIR}/*/report.json"
else
  step "Using the supplied corpus (scanning and consolidation skipped)"
  info "corpus : ${CORPUS_DIR}"
fi

# --- 8. generate the figures ------------------------------------------------
step "Generating the paper figures"
"${ANALYSIS_PY}" scripts/paper_figures.py --corpus "${CORPUS_DIR}" --out "${FIG_DIR}"
# advanced_figures.py needs >=2 tools per axis; on the reduced corpus some
# panels are skipped automatically. A failure there must not abort the run.
"${ANALYSIS_PY}" scripts/advanced_figures.py --corpus "${CORPUS_DIR}" --out "${FIG_DIR}" \
  || info "advanced_figures.py: some panels skipped on the reduced corpus (expected)"

# --- done -------------------------------------------------------------------
step "Done"
if [ -f "${CORPUS_DIR}/findings.jsonl" ]; then
  findings_file="${CORPUS_DIR}/findings.jsonl"
  n_findings=$(wc -l < "${findings_file}")
else
  findings_file="${CORPUS_DIR}/findings.jsonl.gz"
  n_findings=$(gzip -dc "${findings_file}" | wc -l)
fi
n_figures=$(find "${FIG_DIR}" -name '*.pdf' 2>/dev/null | wc -l)
info "corpus  : ${findings_file} (${n_findings} normalized findings)"
info "metrics : ${CORPUS_DIR}/metrics.csv"
info "figures : ${n_figures} PDF figure(s) in ${FIG_DIR}/"
printf '\n\033[1;32mresults in %s/\033[0m\n' "${RESULTS_DIR}"
