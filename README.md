# os-census: a multi-scanner census of the Linux OS base images of Docker Hub

Reproduction artifact for the paper *"A Multi-Scanner Census of the Linux Operating-System Base Images of Docker Hub"*. It measures the **5,606** unique `amd64` images of the **20** Linux distributions in Docker Hub's *Operating systems* category with **14** open-source scanners, and finds that the vulnerability count varies by an order of magnitude across distributions and tracks image age rather than size or popularity, that about **one in twelve** historically published images can no longer be pulled by a current Docker Engine, and that the four package-vulnerability engines show low pairwise agreement (best pair Jaccard **0.36**).

> Paper: SBSeg 2026. Authors: Cristhian Kapelinski, Diego Kreutz (UNIPAMPA).

> **For the artifact evaluation, this README is the only file you need to read.** The other Markdown files in the repository are complementary: they document internals and go deeper than the review requires.

Continuous integration ([`.github/workflows/artifact.yml`](.github/workflows/artifact.yml)) runs the reviewer's own path on a clean runner, on every push and weekly, regenerating the 5 figures and re-checking all 65 paper numbers on a machine with none of the authors' state.

## README structure

| Section | Description |
|---|---|
| [Considered badges](#considered-badges) | Which badges the artifact targets and why |
| [Basic information](#basic-information) | Reference machine and requirements |
| [Dependencies](#dependencies) | Pinned tools, and how the dataset is fetched |
| [Security concerns](#security-concerns) | What the artifact touches |
| [Installation](#installation) | Clone; nothing else for the main path |
| [Minimal test](#minimal-test) | One command, ~10 s |
| [Experiments](#experiments) | Claim #1 (main, ~15 min) and Claim #2 (optional, long) |
| [Cleaning up](#cleaning-up) | One command removes what a run created |
| [LICENSE](#license) | MIT |
| [How to cite](#how-to-cite) | The paper reference and the machine-readable `CITATION.cff` |

How the repository is organized:

| Path | Contents |
|---|---|
| [`reproduce.sh`](reproduce.sh) | The only entry point: `data` (default), `analysis`, `scan-smoke`, `all` |
| [`scripts/`](scripts/) | Stdlib-only steps: `crawl_hub.py`, `build_queue.py`, `analyze.py`, `make_figs.py`, `verify_values.py` |
| [`data/`](data/) | Committed inputs and aggregates: the crawl (`hub_*.jsonl`), the queue, `analysis/per_image.csv`, and the manual-validation samples |
| [`expected/`](expected/) | `paper_values.json`, every number asserted in the paper, with its source section |
| [`figures/`](figures/) | `fig_rq1`–`fig_rq5`, the 5 PDFs exactly as embedded in the paper, plus `fig_repro`/`fig_repro2` (replications of prior work on this corpus, not in the paper) |
| [`multiscan/`](multiscan/) | The vendored scan engine: one adapter per scanner, job queue, workers |
| [`config/`](config/) | `scanners.yaml` (image references and invocations) and [`accounts.example.json`](config/accounts.example.json); the real `accounts.json` is gitignored |
| [`cleanup.sh`](cleanup.sh) | Removes everything a run created |
| [`docs/`](docs/) | `LAYOUT.md` (data provenance) and `REPRODUCIBILITY_REPORT.md` (generated verification table) |

## Considered badges

- **Disponível (SeloD)**: public repository + versioned release with the full dataset and checksums.
- **Funcional (SeloF)**: the minimal test regenerates every figure and checks every paper number in ~10 s, offline, from the committed data.
- **Sustentável (SeloS)**: small stdlib-only scripts (`scripts/`), documented layout (`docs/`), vendored scan engine (`multiscan/`), no dead code.
- **Reprodutível (SeloR)**: `./reproduce.sh` re-derives **all 65 numbers** asserted in the paper and all 5 figures from versioned data (`expected/paper_values.json`; exact match, exit code gated); `./reproduce.sh analysis` re-derives them from the raw per-image dataset, auto-downloaded and sha256-verified from the release.

## Basic information

Reference machine: every time in this README was measured on it, except where a claim states otherwise:

| Item | Reference value |
|---|---|
| OS | Linux (any distro with Python 3.10+) |
| CPU/RAM | AMD Ryzen 5 8600G, 30 GB RAM (any 4-core/8 GB machine works) |
| Disk | depends on the mode; see the table right below |
| GPU | not needed |
| Software | `python3`, [`uv`](https://docs.astral.sh/uv/); `curl`+`zstd` for `analysis`; Docker only for the optional re-scan |

Disk is the one requirement that varies a lot between modes, so size the machine for the mode you intend to run. Measured with `du` on the reference machine, cumulative (each row includes the ones above it):

| Mode | Disk | What takes it |
|---|---|---|
| clone | ~65 MB | 33 MB checkout + 29 MB git history |
| [minimal test](#minimal-test) (default) | **~250 MB** | the above + ~150 MB for the `matplotlib`/`numpy` environment `uv` caches on first use |
| [Claim #1](#claim-1-main-every-paper-number-and-figure-re-derives-from-the-raw-multi-scanner-dataset) (`analysis`) | **~9 GB** | the above + the dataset: a 131 MB download that becomes 8.6 GB extracted |
| [Claim #2](#claim-2-optional-the-scan-pipeline-itself-reduced) (`scan-smoke`, optional) | **~24 GB** | the above + ~15 GB of scanner images and the Clair database |

[`./cleanup.sh`](#cleaning-up) releases everything in the rows below the clone.

## Dependencies

- Host tools, by mode. `reproduce.sh` checks the ones its mode needs before doing any work and prints the install command for the package manager it finds.

  | Mode | Needs |
  |---|---|
  | clone | `git` |
  | `verify` | `python3` |
  | no argument (default), `data`, `figures` | `python3`, `uv` |
  | `analysis` (Claim #1) | the above plus `curl`, `tar`, `zstd`, `sha256sum` |
  | `scan-smoke` (Claim #2) | the above plus **Docker**, with the daemon usable without `sudo` |

  ```bash
  sudo apt-get update && sudo apt-get install -y git python3 curl tar zstd coreutils docker.io util-linux-extra   # Debian, Ubuntu
  sudo dnf install -y git python3 curl tar zstd coreutils docker util-linux                                       # Fedora, RHEL
  sudo pacman -Sy --needed git python curl tar zstd coreutils docker util-linux                                   # Arch
  sudo zypper install -y git python3 curl tar zstd coreutils docker util-linux                                    # openSUSE
  curl -LsSf https://astral.sh/uv/install.sh | sh   # uv, then: export PATH="$HOME/.local/bin:$PATH"
  ```

  Docker package names differ between distributions; the [upstream instructions](https://docs.docker.com/engine/install/) are authoritative.

  Only `scan-smoke` needs the Docker daemon usable without `sudo`:

  ```bash
  sudo usermod -aG docker "$USER" && newgrp docker
  ```

  `newgrp` applies the new group to the current shell, so no logout is needed. It lives in `util-linux-extra` on recent Ubuntu (the package is in the `apt-get` line above; a desktop install does not always have it) and in `util-linux` elsewhere. If it is still missing, log out and back in instead, which has the same effect.

- Analysis/figures: Python 3 stdlib + `matplotlib`/`numpy`, resolved automatically by `uv run` at first use (no manual install).
- Dataset: attached to the [GitHub release](../../releases/tag/dataset-v1), checksums in `SHA256SUMS`. `reproduce.sh analysis` downloads and verifies it automatically, with nothing to fetch by hand.
  - `os-census-per-image-reports.tar.zst` (131 MB, 8.6 GB extracted): the consolidated dataset: one `report.json` with the normalized findings of all 14 scanners, for each of the 5,142 images that produced one (the corpus has 5,606; 463 are un-pullable and one completed job wrote no report, see `docs/REPRODUCIBILITY_REPORT.md`).
  - `os-census-raw-outputs.tar.zst.part-*` (6 parts, 10.2 GB): the verbatim raw output of every scanner run, published for inspection. Reassemble with `cat os-census-raw-outputs.tar.zst.part-* | tar --zstd -x`. Its members are already individually gzipped, which is why it compresses far less than the per-image archive.
- Optional re-scan: Docker Engine 24+, a Docker Hub token, and the vendored engine in `multiscan/` (image references and invocations in `config/scanners.yaml`; see `SETUP.md`).

## Security concerns

- Everything runs locally; the main path is offline (no network).
- `analysis` mode downloads one read-only archive from the GitHub release.
- The optional re-scan pulls public images from Docker Hub; the token is read from `config/accounts.json`, which is gitignored and never committed. The committed [`config/accounts.example.json`](config/accounts.example.json) shows the expected shape (a list of `{username, password}` used round-robin, so the free tier's per-account pull limit does not stop a long run) and carries placeholders only. It is optional: with no `accounts.json` the pipeline pulls anonymously, which is enough for the 10 images of Claim #2.

  ```bash
  cp config/accounts.example.json config/accounts.json   # then edit in a Docker Hub access token
  ```

## Installation

```bash
git clone https://github.com/ChimangoScan/os-census && cd os-census
```

Nothing else: `uv run` resolves the plotting dependencies on first use (~30 s).

## Minimal test

One command (~10 s), offline, no Docker:

```bash
./reproduce.sh
```

It regenerates the paper's 5 figures from the committed data (plus 2 extra ones, see [`figures/`](figures/)) and re-derives every number the paper asserts, checking each one against `expected/paper_values.json`.

Expected: one `fig_… ok` line per figure, from `fig_rq1 ok` to `fig_repro2 ok`, then the verification table (columns `check`, `paper source`, `expected`, `obtained`, `result`, one row per number), then the final line `**65 PASS / 0 FAIL / 0 SKIP**` (exit code 0). Figures land in `figures/*.pdf` and the table is also written to [`docs/REPRODUCIBILITY_REPORT.md`](docs/REPRODUCIBILITY_REPORT.md).

Expected resources: ~1 GB RAM (measured peak 938 MB); the only disk it adds is the ~150 MB `matplotlib`/`numpy` environment `uv` caches on first use (~250 MB in total with the clone, see [Basic information](#basic-information)).

## Experiments

### Claim #1 (main): every paper number and figure re-derives from the raw multi-scanner dataset

```bash
./reproduce.sh analysis
```

- **Expected time:** ~15 min on the reference machine (131 MB download + 8.6 GB extract + re-aggregation of 5,142 reports); dominated by the download, so a slower link takes proportionally longer.
- **Expected resources:** ~8.6 GB more disk for the extracted dataset (~9 GB in total, see [Basic information](#basic-information)), <2 GB RAM.
- **Expected result:** `data/analysis/per_image.csv` and the RQ3 sets are rebuilt from the raw `report.json` files, followed by the same 5 figures and the same `**65 PASS / 0 FAIL / 0 SKIP**` as the minimal test. This is what makes the committed aggregates auditable rather than trusted.
- **How to check the rebuild matched:** the aggregation writes in a fixed order, so a correct re-run reproduces the committed files **byte for byte**:

```bash
git status --porcelain data/analysis/
```

  Nothing listed means the rebuild is identical to what is committed. (The figures under `figures/` do change on every run: matplotlib stamps a creation date into the PDF. Their content does not.)

### Claim #2 (optional): the scan pipeline itself, reduced

**Optional, and not needed for any badge.** Claim #1 already re-derives every number and figure in the paper from the raw dataset; this claim only exercises the collection side, the pipeline that produced that dataset, and it is long (see the time below). Run it only if you want to see the scanners execute.

10 corpus images scanned by all 14 scanners into an isolated queue and output directory; the census state in `data/` is not touched.

```bash
./reproduce.sh scan-smoke
```

- **Expected time, strongly hardware- and link-dependent.** Measured at **~90 min on an 8-core AMD Ryzen 7 9700X** with a fast connection. On a slower or more contended machine, or a slower link, expect **10–20 h**. Most of the run is the one-time Clair database preparation and the pull of the 14 scanner images, so it is bound by network bandwidth and CPU far more than by the 10 images themselves; scanning fewer images (`SMOKE_N=3 ./reproduce.sh scan-smoke`) therefore saves much less time than it looks.
- **Expected resources:** Docker; ~15 GB more disk for the 14 scanner images and the Clair database (~24 GB in total, see [Basic information](#basic-information)). A Docker Hub token in `config/accounts.json` is optional; without it the images are pulled anonymously, which is enough for 10 images.
- **Expected result:** the run ends with `[scan-smoke] 10/10 images with report.json in <repo>/scan-out/smoke/out`, then a line listing the invocations per scanner (10 for each of the 14 scanners), then `[scan-smoke] OK`. The per-image reports are under `scan-out/smoke/out/`. What this claim asserts is the **verdict and the per-scanner invocation counts**, not the wall-clock time. Finding counts will not match the census: the scanners resolve current vulnerability databases, while the census is the immutable record of when it ran (see `docs/REPRODUCIBILITY_REPORT.md`).
- **Cleanup:** the extracted-filesystem cache is written by containers as root, so `./cleanup.sh` (see *Cleaning up*) removes it through a throwaway container.

Beyond the two claims, the whole census can be re-run from scratch with `./reproduce.sh all`: it crawls the Docker Hub API, rebuilds the queue of 5,606 images, runs the 14 scanners and then re-enters Claim #1. This takes **weeks of scanning** and needs Docker plus a Docker Hub token; see [`SETUP.md`](SETUP.md) for the one-time scanner preparation and the distributed workers.

## Cleaning up

One command removes everything a run created, the extracted 8.6 GB dataset, the environment and the scan output. It never touches anything tracked by git.

```bash
./cleanup.sh
```

Pass `--dry-run` to list what would go without removing it. The scanner images that the optional re-scan pulls are third-party and are kept by default; `./cleanup.sh --images` removes those too.

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

[`CITATION.cff`](CITATION.cff) carries the same metadata in machine-readable form, so GitHub's "Cite this repository" button and tools such as Zenodo pick it up automatically.
