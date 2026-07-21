#!/usr/bin/env bash
# Common setup for the per-claim verification scripts (scripts/claim1..4.sh).
# Sourced, not executed directly.
#
# Configuration (all optional):
#   CORPUS=dataset            corpus to verify against (default: bundled dataset)
#   FIGDIR=results-claims     where figures + the analysis log are written

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

CORPUS="${CORPUS:-dataset}"
FIGDIR="${FIGDIR:-results-claims}"
ANALYSIS_VENV="${ANALYSIS_VENV:-.venv-analysis}"

rule() { printf -- '----------------------------------------------------------------\n'; }

# Ensure the analysis environment exists and the figures are generated once
# from CORPUS. Idempotent: regenerates only if CORPUS changed.
claims_setup() {
  command -v uv >/dev/null 2>&1 || { echo "error: uv is required; see README > Installation" >&2; exit 1; }
  if [ ! -x "${ANALYSIS_VENV}/bin/python" ]; then
    echo "setting up the analysis environment ..."
    uv venv "${ANALYSIS_VENV}" >/dev/null
    uv pip install --quiet --python "${ANALYSIS_VENV}/bin/python" \
      "matplotlib>=3.7" "numpy>=1.26" "scipy>=1.11" "scikit-learn>=1.3" \
      "matplotlib-venn>=1.1" "krippendorff>=0.6"
  fi
  PY="${ANALYSIS_VENV}/bin/python"

  if [ ! -f "${CORPUS}/findings.jsonl" ] && [ ! -f "${CORPUS}/findings.jsonl.gz" ]; then
    echo "error: no corpus at '${CORPUS}/'. Set CORPUS= (e.g. CORPUS=dataset)," >&2
    echo "       or run scripts/reproduce-reduced.sh first." >&2
    exit 1
  fi

  mkdir -p "${FIGDIR}"
  if [ "$(cat "${FIGDIR}/.corpus" 2>/dev/null || true)" != "${CORPUS}" ]; then
    echo "generating figures from CORPUS=${CORPUS} (one-time) ..."
    "${PY}" scripts/paper_figures.py --corpus "${CORPUS}" --out "${FIGDIR}" >/dev/null
    "${PY}" scripts/advanced_figures.py --corpus "${CORPUS}" --out "${FIGDIR}" \
      > "${FIGDIR}/analysis.txt" 2>/dev/null || true
    printf '%s' "${CORPUS}" > "${FIGDIR}/.corpus"
  fi
}

# findings count of the corpus
corpus_findings() {
  if [ -f "${CORPUS}/findings.jsonl" ]; then
    wc -l < "${CORPUS}/findings.jsonl"
  else
    gzip -dc "${CORPUS}/findings.jsonl.gz" | wc -l
  fi
}
