# os-census: a multi-scanner census of the Linux OS base images of Docker Hub

Reproduction artifact for the paper *"A Multi-Scanner Census of the Linux
Operating-System Base Images of Docker Hub"*. It measures the **5,606** unique
`amd64` images of the **20** Linux distributions in Docker Hub's *Operating
systems* category with **14** open-source scanners, and finds that the
vulnerability count varies by an order of magnitude across distributions, that
about **one in twelve** historical images no longer installs on a modern
Docker, and that the four package-vulnerability engines show low pairwise
agreement (best pair Jaccard **0.36**).

> Paper: SBSeg 2026. Authors: Cristhian Kapelinski, Diego Kreutz (UNIPAMPA).

## README structure

| Section | Description |
|---|---|
| [Considered badges](#considered-badges) | Which seals the artifact targets and why |
| [Basic information](#basic-information) | Reference machine and requirements |
| [Dependencies](#dependencies) | Pinned tools and how inputs are fetched |
| [Security concerns](#security-concerns) | What the artifact touches |
| [Installation](#installation) | Clone; nothing else to install for the main path |
| [Minimal test](#minimal-test) | One command, ~10 s |
| [Experiments](#experiments) | One command per claim, with times |
| [Dataset](#dataset) | Release assets and how to use them |
| [License](#license) | MIT |

## Considered badges

- **Disponível (SeloD)**: public repository + versioned release with the full
  dataset and checksums.
- **Funcional (SeloF)**: the minimal test regenerates every figure and checks
  every paper number in ~10 s, offline, from the committed data.
- **Sustentável (SeloS)**: small stdlib-only scripts (`scripts/`), documented
  layout (`docs/`), vendored pinned scan engine (`multiscan/`), no dead code.
- **Reprodutível (SeloR)**: `./reproduce.sh` re-derives **all 60 numbers**
  asserted in the paper and all 5 figures from versioned data
  (`expected/paper_values.json`; exact match, exit code gated);
  `./reproduce.sh analysis` re-derives them from the raw per-image dataset,
  auto-downloaded and sha256-verified from the release.

## Basic information

| Item | Reference value |
|---|---|
| OS | Linux (any distro with Python 3.10+) |
| CPU/RAM | AMD Ryzen 5 8600G, 30 GB RAM (any 4-core/8 GB machine works) |
| Disk | ~1 GB for the repo; +9 GB only for `analysis` mode (raw dataset) |
| GPU | not needed |
| Software | `python3`, [`uv`](https://docs.astral.sh/uv/); `curl`+`zstd` for `analysis`; Docker only for the optional full re-scan |

## Dependencies

- Analysis/figures: Python 3 stdlib + `matplotlib`/`numpy`, resolved
  automatically by `uv run` at first use (no manual install).
- Raw dataset (only for `analysis` mode): auto-downloaded from the GitHub
  release by `reproduce.sh` and verified against a pinned sha256.
- Full re-scan (optional): Docker Engine 24+, a Docker Hub token, and the
  vendored engine in `multiscan/` (scanner versions pinned in
  `config/scanners.yaml`; see `SETUP.md`).

## Security concerns

- Everything runs locally; the main path is offline (no network).
- `analysis` mode downloads one read-only archive from the GitHub release.
- The optional full re-scan pulls public images from Docker Hub; the token is
  read from `config/accounts.json` (gitignored, never committed).

## Installation

```bash
git clone https://github.com/ChimangoScan/os-census
cd os-census
```

Nothing else: `uv run` resolves the plotting dependencies on first use (~30 s).

## Minimal test

One command (~10 s):

```bash
./reproduce.sh
```

Expected: `fig_rq1 ok` ... `fig_repro2 ok`, the verification table, and the
final line `**60 PASS / 0 FAIL / 0 SKIP**` (exit code 0). Figures land in
`figures/*.pdf`.

## Experiments

**Main claim — every number and figure in the paper reproduces from the data**
(~10 s, offline, <1 GB RAM):

```bash
./reproduce.sh
```

Expected result: all 5 paper figures regenerated and the 60 checks in
`expected/paper_values.json` (corpus sizes; RQ1 per-distribution means; RQ2
age buckets and Spearman ρ=0.27; RQ3 Jaccards and engine coverages; RQ4
un-pullable rates; RQ5 regression betas; secret/malware validation) all PASS.
The table is also written into `docs/REPRODUCIBILITY_REPORT.md`.

**Claim 2 — the committed aggregates derive from the raw multi-scanner
dataset** (~15 min: 138 MB download + 8.6 GB extract + re-aggregation of
5,142 reports; ~9 GB disk):

```bash
./reproduce.sh analysis
```

Expected result: `data/analysis/per_image.csv` and the RQ3 sets are rebuilt
from the raw `report.json` files (identical to the committed ones), then the
same figures and the same `60 PASS / 0 FAIL`.

**Claim 3 (optional, not required for the seals) — the whole census from
scratch** (days of scanning; Docker + Docker Hub token):

```bash
./reproduce.sh all
```

Crawls the Docker Hub API, rebuilds the queue (5,606 images), runs the 14
scanners and re-enters Claim 2. See `SETUP.md` for the one-time scanner prep
and distributed workers.

## Dataset

Attached to the [GitHub release](../../releases/tag/dataset-v1) (checksums in
`SHA256SUMS`):

- `os-census-per-image-reports.tar.zst` (138 MB, 8.6 GB extracted): the
  consolidated dataset — 5,142 per-image `report.json` with the normalized
  findings of all 14 scanners. `reproduce.sh analysis` fetches it
  automatically; to use it manually: `tar --zstd -xf` it and point
  `OSCENSUS_OUT` at the extracted `out_so/`.
- `os-census-raw-outputs.tar.zst.part-*` (6 parts, 10.2 GB, 19 GB extracted):
  the verbatim raw output of every scanner run. Reassemble with
  `cat os-census-raw-outputs.tar.zst.part-* | tar --zstd -x`.

Repository layout and data provenance: `docs/LAYOUT.md`. Known limitations and
the auto-generated verification table: `docs/REPRODUCIBILITY_REPORT.md`.

## License

[MIT](LICENSE).
