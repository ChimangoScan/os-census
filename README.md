# os-census: a multi-scanner census of the Linux OS base images of Docker Hub

Reproduction artifact for the paper *"A Multi-Scanner Census of the Linux
Operating-System Base Images of Docker Hub"*. It measures the **5,606** unique
`amd64` images of the **20** Linux distributions in Docker Hub's *Operating
systems* category with **14** open-source scanners, and finds that the
vulnerability count varies by an order of magnitude across distributions and
tracks image age rather than size or popularity, that about **one in twelve**
historically published images can no longer be pulled by a current Docker
Engine, and that the four package-vulnerability engines show low pairwise
agreement (best pair Jaccard **0.36**).

> Paper: SBSeg 2026. Authors: Cristhian Kapelinski, Diego Kreutz (UNIPAMPA).

[![artifact](https://github.com/ChimangoScan/os-census/actions/workflows/artifact.yml/badge.svg)](https://github.com/ChimangoScan/os-census/actions/workflows/artifact.yml)

Continuous integration runs the reviewer's own path on a clean runner, weekly
and on demand, so the badge above is a live statement that the 5 figures and all
65 checked paper numbers still reproduce on a machine with none of the authors'
state.

## Estrutura do readme.md

Sections of this document:

| Section | Description |
|---|---|
| [Selos considerados](#selos-considerados) | Which seals the artifact targets and why |
| [Informações básicas](#informações-básicas) | Reference machine and requirements |
| [Dependências](#dependências) | Pinned tools, and how the dataset is fetched |
| [Preocupações com segurança](#preocupações-com-segurança) | What the artifact touches |
| [Instalação](#instalação) | Clone; nothing else for the main path |
| [Teste mínimo](#teste-mínimo) | One command, ~10 s |
| [Experimentos](#experimentos) | Claim #1 (main, ~15 min) and Claim #2 (optional, long) |
| [LICENSE](#license) | MIT |
| [How to cite](#how-to-cite) | The paper reference and the machine-readable `CITATION.cff` |

How the repository is organized:

| Path | Contents |
|---|---|
| `reproduce.sh` | The only entry point: `data` (default), `analysis`, `scan-smoke`, `all` |
| `scripts/` | Stdlib-only steps: `crawl_hub.py`, `build_queue.py`, `analyze.py`, `make_figs.py`, `verify_values.py` |
| `data/` | Committed inputs and aggregates: the crawl (`hub_*.jsonl`), the queue, `analysis/per_image.csv`, and the manual-validation samples |
| `expected/` | `paper_values.json` — every number asserted in the paper, with its source section |
| `figures/` | The regenerated PDFs, exactly as embedded in the paper |
| `multiscan/` | The vendored scan engine: one adapter per scanner, job queue, workers |
| `config/` | `scanners.yaml` (image references and invocations); `accounts.json` is gitignored |
| `docs/` | `LAYOUT.md` (data provenance) and `REPRODUCIBILITY_REPORT.md` (generated verification table) |

## Selos considerados

- **Disponível (SeloD)**: public repository + versioned release with the full
  dataset and checksums.
- **Funcional (SeloF)**: the minimal test regenerates every figure and checks
  every paper number in ~10 s, offline, from the committed data.
- **Sustentável (SeloS)**: small stdlib-only scripts (`scripts/`), documented
  layout (`docs/`), vendored scan engine (`multiscan/`), no dead code.
- **Reprodutível (SeloR)**: `./reproduce.sh` re-derives **all 65 numbers**
  asserted in the paper and all 5 figures from versioned data
  (`expected/paper_values.json`; exact match, exit code gated);
  `./reproduce.sh analysis` re-derives them from the raw per-image dataset,
  auto-downloaded and sha256-verified from the release.

## Informações básicas

Reference machine — every time in this README was measured on it, except where
a claim states otherwise:

| Item | Reference value |
|---|---|
| OS | Linux (any distro with Python 3.10+) |
| CPU/RAM | AMD Ryzen 5 8600G, 30 GB RAM (any 4-core/8 GB machine works) |
| Disk | ~1 GB for the repo; +9 GB only for `analysis` mode (raw dataset) |
| GPU | not needed |
| Software | `python3`, [`uv`](https://docs.astral.sh/uv/); `curl`+`zstd` for `analysis`; Docker only for the optional re-scan |

## Dependências

- Analysis/figures: Python 3 stdlib + `matplotlib`/`numpy`, resolved
  automatically by `uv run` at first use (no manual install).
- Dataset: attached to the [GitHub release](../../releases/tag/dataset-v1),
  checksums in `SHA256SUMS`. `reproduce.sh analysis` downloads and verifies it
  automatically — nothing to fetch by hand.
  - `os-census-per-image-reports.tar.zst` (131 MB, 8.6 GB extracted): the
    consolidated dataset: one `report.json` with the normalized findings of all
    14 scanners, for each of the 5,142 images that produced one (the corpus has
    5,606; 463 are un-pullable and one completed job wrote no report — see
    `docs/REPRODUCIBILITY_REPORT.md`).
  - `os-census-raw-outputs.tar.zst.part-*` (6 parts, 10.2 GB): the verbatim raw
    output of every scanner run, published for inspection. Reassemble with
    `cat os-census-raw-outputs.tar.zst.part-* | tar --zstd -x`. Its members are
    already individually gzipped, which is why it compresses far less than the
    per-image archive.
- Optional re-scan: Docker Engine 24+, a Docker Hub token, and the vendored
  engine in `multiscan/` (image references and invocations in
  `config/scanners.yaml`; see `SETUP.md`).

## Preocupações com segurança

- Everything runs locally; the main path is offline (no network).
- `analysis` mode downloads one read-only archive from the GitHub release.
- The optional re-scan pulls public images from Docker Hub; the token is read
  from `config/accounts.json` (gitignored, never committed).

## Instalação

```bash
git clone https://github.com/ChimangoScan/os-census && cd os-census
```

Nothing else: `uv run` resolves the plotting dependencies on first use (~30 s).

## Teste mínimo

One command (~10 s), offline, no Docker:

```bash
./reproduce.sh
```

It regenerates the paper's 5 figures from the committed data and re-derives
every number the paper asserts, checking each one against
`expected/paper_values.json`.

Expected: `fig_rq1 ok` ... `fig_repro2 ok`, the verification table (one row per
number: name, paper section, expected, obtained, PASS), and the final line
`**65 PASS / 0 FAIL / 0 SKIP**` (exit code 0). Figures land in `figures/*.pdf`
and the table is also written to `docs/REPRODUCIBILITY_REPORT.md`.

Expected resources: <1 GB RAM, no extra disk.

## Experimentos

### Claim #1 (main) — every paper number and figure re-derives from the raw multi-scanner dataset

```bash
./reproduce.sh analysis
```

- **Expected time:** ~15 min on the reference machine (131 MB download + 8.6 GB
  extract + re-aggregation of 5,142 reports); dominated by the download, so a
  slower link takes proportionally longer.
- **Expected resources:** ~9 GB disk, <2 GB RAM.
- **Expected result:** `data/analysis/per_image.csv` and the RQ3 sets are
  rebuilt from the raw `report.json` files, identical to the committed ones,
  followed by the same 5 figures and the same
  `**65 PASS / 0 FAIL / 0 SKIP**` as the minimal test — this is what makes the
  committed aggregates auditable rather than trusted.

### Claim #2 (optional) — the scan pipeline itself, reduced

**Optional, and not needed for any seal.** Claim #1 already re-derives every
number and figure in the paper from the raw dataset; this claim only exercises
the collection side — the pipeline that produced that dataset — and it is long
(see the time below). Run it only if you want to see the scanners execute.

10 corpus images scanned by all 14 scanners into an isolated queue and output
directory; the census state in `data/` is not touched.

```bash
./reproduce.sh scan-smoke
```

- **Expected time — strongly hardware- and link-dependent.** Measured at
  **~90 min on an 8-core AMD Ryzen 7 9700X** with a fast connection. On a
  slower or more contended machine, or a slower link, expect **10–20 h**. Most
  of the run is the one-time Clair database preparation and the pull of the 14
  scanner images, so it is bound by network bandwidth and CPU far more than by
  the 10 images themselves; scanning fewer images (`SMOKE_N=3 ./reproduce.sh
  scan-smoke`) therefore saves much less time than it looks.
- **Expected resources:** Docker; ~15 GB disk for the scanner images. A Docker
  Hub token in `config/accounts.json` is optional.
- **Expected result:** the run ends with
  `[scan-smoke] 10/10 images with report.json in <repo>/scan-out/smoke/out`,
  then a line listing the invocations per scanner (10 for each of the 14
  scanners), then `[scan-smoke] OK`. The per-image reports are under
  `scan-out/smoke/out/`. What this claim asserts is the **verdict and the
  per-scanner invocation counts**, not the wall-clock time. Finding counts will
  not match the census: the scanners resolve current vulnerability databases,
  while the census is the immutable record of when it ran (see
  `docs/REPRODUCIBILITY_REPORT.md`).
- **Cleanup:** the extracted-filesystem cache is written by containers as root;
  remove it with

```bash
docker run --rm -v "$PWD/scan-out:/s" alpine rm -rf /s/smoke
```

Beyond the two claims, the whole census can be re-run from scratch with
`./reproduce.sh all`: it crawls the Docker Hub API, rebuilds the queue of 5,606
images, runs the 14 scanners and then re-enters Claim #1. This takes **weeks of
scanning** and needs Docker plus a Docker Hub token; see
[`SETUP.md`](SETUP.md) for the one-time scanner preparation and the distributed
workers.

## LICENSE

[MIT](LICENSE).

## How to cite

Cite the paper, not the repository:

> Kapelinski, C. and Kreutz, D. (2026). A Multi-Scanner Census of the Linux Operating-System Base Images of Docker Hub. In *Anais do XXVII Simpósio Brasileiro de Segurança da Informação e de Sistemas Computacionais (SBSeg 2026)*. Sociedade Brasileira de Computação.

```bibtex
@inproceedings{kapelinski2026,
  author    = {Kapelinski, Cristhian and Kreutz, Diego},
  title     = {A Multi-Scanner Census of the Linux Operating-System Base Images of Docker Hub},
  booktitle = {Anais do XXVII Simpósio Brasileiro de Segurança da Informação e de Sistemas Computacionais (SBSeg 2026)},
  year      = {2026},
  publisher = {Sociedade Brasileira de Computação},
}
```

[`CITATION.cff`](CITATION.cff) carries the same metadata in machine-readable form, so GitHub's
"Cite this repository" button and tools such as Zenodo pick it up automatically.
