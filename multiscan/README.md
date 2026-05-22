# Multiscan: What Open-Source Security Scanners Find

Artifact for the paper **"What Open-Source Security Scanners Find: A
Measurement Study of 31 Tools over 130 Vulnerable Containers"**.

**Abstract.** For every security question a container raises (known CVEs in
dependencies, embedded secrets, software bill of materials, insecure code,
image hardening, malware, and web or network exposure) practitioners can
choose from many open-source scanners. Prior studies measure what those
scanners report one tool family at a time, on disjoint corpora and with
disjoint methods. Multiscan runs a battery of 31 open-source scanners spanning
eight analysis axes over a single corpus of 130 vulnerable containers, with one
Docker-only harness and one normalization, and measures the tools uniformly
along three dimensions: coverage, overlap, and runtime. This artifact contains
the harness that produced the dataset, the consolidated dataset itself, the
analysis code that turns it into the paper's figures, and the corpus inventory.

---

## Repository structure

```
multiscan/
├── src/scanners/        the scanning engine (Python 3.12 + PyYAML)
│   ├── adapters/        one module per scanner: builds its argv, parses its output
│   ├── dockerctl/       Docker lifecycle: pull, run, monitor, export rootfs
│   ├── jobqueue/        restartable work queue (SQLite, or HTTP coordinator)
│   ├── pipeline/        the worker loop that drives a scan
│   ├── findings/        normalized finding schema + corpus store + OpenVAS import
│   ├── sources/         target-inventory readers (csv / jsonl / txt)
│   └── cli.py           the `scanners` command-line entry point
├── config/              run configs + scanners.yaml (the scanner registry)
├── data/inventory/      corpus inventories: d1.csv (130), d1-reduced.csv (10)
├── data/openvas/        OpenVAS network-scan baseline, vendored in-repo
├── dataset/             the consolidated dataset (see dataset/README.md)
├── docker/              Dockerfiles for the locally-built scanner images
├── scripts/             analysis + reproduction (reproduce-reduced.sh is the entry point)
├── docs/                methodology and install/reproduce guides
├── tests/               unit tests for the engine
└── pyproject.toml       project metadata + dependencies (uv-managed)
```

---

## Badges considered (Selos considerados)

This artifact is submitted for the four SBC quality seals:

| Seal | Name | How this artifact satisfies it |
|------|------|--------------------------------|
| **SeloD** | Available (Disponível)    | Public versioned repository; the consolidated dataset ships in `dataset/`. |
| **SeloF** | Functional (Funcional)    | The *Minimal test* runs the real pipeline, a genuine scan of two containers producing observable normalized findings. |
| **SeloS** | Sustainable (Sustentável) | Modular engine with a documented CLI and config; reconfiguration needs no source editing. |
| **SeloR** | Reproducible (Reprodutível) | `scripts/reproduce-reduced.sh` reproduces the methodology end-to-end on one machine. |

---

## Basic information (Informações básicas)

`multiscan` is a **Docker-only harness**: every scanner runs as a pinned
container image, so nothing is installed on the host and a run reproduces on
any machine with a Docker daemon. The engine pulls each target image once,
hands the static scanners the saved tarball and exported root filesystem,
brings the container up on an isolated network for the dynamic scanners,
records per-invocation timing, and normalizes every output to one schema while
keeping each scanner's raw native output verbatim.

**Execution environment.** x86-64 Linux with a running Docker daemon. The CPU
must support the `x86-64-v3` instruction set (AVX2; any CPU from ~2015 onward),
required by one scanner image (cdxgen).

**Experimental infrastructure (SeloR).** The full study was executed on a
cluster of identical commodity nodes:

| Component | Value |
|-----------|-------|
| Nodes             | cluster of identical x86-64 Linux machines |
| CPU               | Intel Core i7-9700, 8 cores @ 3.0 GHz (no SMT) |
| RAM               | 32 GB per node |
| Disk              | local SSD, ≥ 500 GB free for the full run |
| Container runtime | Docker Engine 24+ |
| Engine language   | Python 3.12 |

**Run parameters (SeloR).** The harness is deterministic given the same inputs,
except for two unavoidable sources of variation: upstream image content behind
moving tags, and scanner-internal vulnerability-database snapshots. Every
parameter that governs a run lives in the run config and on the CLI; nothing is
hardcoded:

| Parameter | Config key | Default | Effect |
|-----------|-----------|---------|--------|
| Scan timeout     | `workers.scan_timeout`     | 1200 s | per-scanner wall-time cap |
| Worker count     | `workers.count`            | 4      | targets scanned concurrently |
| Scan parallelism | `runtime.scan_parallelism` | 4      | scanners run concurrently per target |
| Resume           | `output.skip_done`         | true   | a scanner with existing output is reused, not re-run |

**Hardware requirements.**

| Use case | CPU | RAM | Disk | Wall time |
|---|---|---|---|---|
| Minimal test | 2 cores | 4 GB | ~15 GB | ~5-10 min |
| Reduced reproduction (10 containers) | 2 cores | 8 GB | ~40 GB | ~1-2 h |
| Figures from the bundled dataset | 2 cores | 4 GB | ~5 GB | ~10 min |
| Full study (130 containers × 31 scanners) | a cluster | 8-core / 32 GB nodes | ~500 GB | multi-day |

The full study is a multi-day cluster job and is **not** reproducible in
artifact-review time. The artifact therefore ships a **reduced version**, a
10-container inventory and a one-command script, that reproduces the *whole
methodology* (collection, consolidation, figures) on a single machine in about
an hour, and the **bundled dataset** for reproducing the figures directly.

---

## Dependencies (Dependências)

- **Docker Engine ≥ 24**, `git`, `bash`, `curl`. Any Docker Engine ≥ 24 and a
  recent `uv` reproduce the artifact.
- **Python and every Python dependency** are managed by
  [`uv`](https://docs.astral.sh/uv/), installed automatically by the
  reproduction script if absent. **No system `pip`** is used, so the PEP 668
  *externally-managed-environment* error cannot occur.
- **Engine dependencies:** the Python standard library plus PyYAML. The
  **analysis** dependencies (matplotlib, numpy, scipy, scikit-learn,
  matplotlib-venn, krippendorff) are the `analysis` extra in `pyproject.toml`
  and install into a *separate* virtual environment so the engine stays
  standard-library + PyYAML. Exact versions of both are pinned in `uv.lock`.
- **Scanner images:** 31 scanners. Most are pinned public images from Docker
  Hub / GHCR; the rest have no maintained upstream image and are built from
  pinned Dockerfiles under `docker/`. The full list and version pins are in
  `config/scanners.yaml`.
- **Corpus images:** the 130 D1 target containers are public images referenced
  in `data/inventory/d1.csv` (the reduced corpus uses `d1-reduced.csv`), pulled
  on demand from Docker Hub. Anonymous pulls are rate-limited (~100 / 6 h); the
  minimal test and the reduced reproduction stay under this limit. For the full
  scan, place credentials in a git-ignored `accounts.json`.
- **Bundled dataset (SeloD):** the consolidated corpus ships in `dataset/`
  (`findings.jsonl.gz`, 1,427,789 normalized findings; `metrics.csv`, the
  per-run timing). See [`dataset/README.md`](dataset/README.md) for the schema.

---

## Security concerns (Preocupações com segurança)

**This artifact runs deliberately vulnerable software and dual-use security
tools. Read this section before executing it.**

- The corpus containers are **intentionally vulnerable or outdated**: known
  exploitable images (DVWA, Juice Shop, bWAPP, Mutillidae, Metasploitable),
  proof-of-concept images for specific CVEs (Log4Shell, CVE-2021-41773,
  SambaCry, GhostCat), and production software pinned to old releases.
- Several scanners are **offensive / dual-use** tools (nuclei, sqlmap, nmap,
  jaeles, OpenVAS) that actively probe and attack the target.

**Mitigations built into the artifact.** The harness brings every target up on
an **isolated Docker bridge network** and **publishes no container port to the
host**; scanners reach targets container-to-container only. Target containers
run hardened by default (`cap_drop ALL`, `no-new-privileges`, read-only
rootfs) and under memory and PID limits.

**What the reviewer must do.** Run the artifact on a disposable machine or VM,
on a network you control. **Never expose the vulnerable containers or the
OpenVAS server to the public internet.** Tear the lab down after evaluation
(`docker rm -f` any leftover containers; delete the `results/` directory).

---

## Installation (Instalação)

```bash
git clone <repository-url>
cd multiscan
uv sync                          # isolated .venv with Python 3.12 + PyYAML
bash scripts/build-images.sh     # build the locally-built scanner images (~5 min)
uv run scanners --help           # verify: prints the sub-commands
```

`scripts/reproduce-reduced.sh` performs every step above automatically
(including installing `uv`), so for artifact review you can skip straight to
**Experiments**.

---

## Minimal test (Teste mínimo)

One command runs the **real pipeline** against two corpus containers (one base
OS image, one deliberately vulnerable web app) and produces observable
normalized findings:

```bash
bash scripts/minimal-test.sh
```

Everything is written under `results-minimal/` in the repository; nothing else
on the machine is touched. Expected time: ~5-10 minutes (mostly image pulls on
the first run); resources: ~4 GB RAM, ~15 GB disk. To scan a different pair,
set `CONTAINERS`, e.g. `CONTAINERS=alpine37,juice-shop bash scripts/minimal-test.sh`.

**Expected output.** `scanners status` reports `2/2 processed`, `failed=0`.
Each container yields `results-minimal/out/<container>/report.json` with an
`invocations` list (one entry per scanner, with `wall_seconds` and a `findings`
count) and a `findings` list of normalized findings. The script consolidates
the reports into `findings.jsonl` and emits the figures. Non-empty,
schema-consistent findings confirm the harness works end-to-end.

---

## Experiments (Experimentos)

A single script, `scripts/reproduce-reduced.sh`, is the only entry point a
reviewer needs. It reproduces the paper **two ways**:

1. **From the pipeline** (default): runs the *entire methodology* (collection,
   consolidation, figures) on a 10-container inventory, on one machine, in
   about an hour. Recommended for artifact review.
2. **From the bundled dataset**: with `CORPUS=` pointing at a ready corpus, it
   skips all scanning and regenerates every figure in minutes.

```bash
# (1) from the pipeline
bash scripts/reproduce-reduced.sh

# (2) from the bundled dataset (no Docker, no scanning)
CORPUS=dataset bash scripts/reproduce-reduced.sh
```

The script is idempotent and resumable; re-run it after an interruption.
Override any path or parameter with an environment variable (nothing is
hardcoded), e.g. the full study on one machine:

```bash
INVENTORY=data/inventory/d1.csv RESULTS_DIR=results-full \
WORKERS=4 SCAN_PARALLELISM=4 SCAN_TIMEOUT=1800 \
    bash scripts/reproduce-reduced.sh
```

It prints `results in results/`, containing per-target `report.json` (pipeline
mode), the consolidated `findings.jsonl` + `metrics.csv`, and every figure as a
PDF under `results/figures/`.

The four claims below map to the paper's contributions. The reduced corpus
spans all eight axes, so the *shape* of every claim is observable; the exact
magnitudes come from the bundled dataset (run mode 2).

### Claim 1: A released, citable multi-scanner dataset (C1)

130 vulnerable containers scanned by 31 tools across eight axes, 1,427,789
normalized findings. `scripts/consolidate.py` builds the corpus and
`paper_figures.py` produces `fig_overview.pdf`, the by-axis finding breakdown
(Figure 1), with every axis non-empty. Runtime ~1 min, ~2 GB RAM.

### Claim 2: Cross-family measurement of coverage and overlap (C2)

A large share of each tool's findings is exclusive to it in every axis; the
closest mainstream SCA tools report the same CVE only ~33 % of the time;
chance-corrected agreement is negative in every multi-tool axis.
`advanced_figures.py` prints the κ / α / AC1 coefficients and produces
`adv_agreement_coeffs.pdf` (Figure 2) and `adv_venn_grid.pdf` (Figure 3).
Runtime ~5 min on the full corpus, ~3 GB RAM.

### Claim 3: Coverage and complementarity (C3)

Per-tool exclusivity is high in every axis, yet the marginal value of each
added scanner falls off sharply. `paper_figures.py` produces
`fig_exclusivity.pdf` (Figure 4) and `fig_saturation.pdf` (Figure 5): the
cumulative-coverage curve flattens after the first handful of scanners.
Runtime ~3 min, ~3 GB RAM.

### Claim 4: Runtime characterization and per-axis recommendation (C4)

Per-scanner wall time spans more than two orders of magnitude; this distils
into a per-axis recommended scanner set. `paper_figures.py` produces
`fig_cost.pdf` (Figure 6, reads `metrics.csv`) and `advanced_figures.py`
produces `adv_shapley.pdf` with the per-axis coverage attribution. Runtime
~5 min, ~3 GB RAM.

### Re-running the full collection (optional, multi-day)

To re-scan the whole corpus on a cluster: install on every node, point
`config/multiscan.yaml` at `data/inventory/d1.csv`, and use the HTTP
coordinator so workers share one queue. `docs/REPRODUCE.md` and
`docs/cluster.md` document this in full.

---

## License

This artifact is released under the **MIT License**, see [`LICENSE`](LICENSE).
The corpus container images and the scanner images remain under their
respective upstream licenses.
