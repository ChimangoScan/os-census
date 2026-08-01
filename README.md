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
> Artifact evaluation:
> [submission](https://doc-artefatos.github.io/sbseg2026/subinstrucoes.html) ·
> [review](https://doc-artefatos.github.io/sbseg2026/revinstrucoes.html).

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
| [Experimentos](#experimentos) | One command per claim, with times |
| [LICENSE](#license) | MIT |

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
- **Reprodutível (SeloR)**: `./reproduce.sh` re-derives **all 62 numbers**
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

One command (~10 s):

```bash
./reproduce.sh
```

Expected: `fig_rq1 ok` ... `fig_repro2 ok`, the verification table, and the
final line `**62 PASS / 0 FAIL / 0 SKIP**` (exit code 0). Figures land in
`figures/*.pdf`.

## Experimentos

### Claim #1 (main) — every number and figure in the paper reproduces from the data

```bash
./reproduce.sh
```

- **Expected time:** ~10 s, offline.
- **Expected resources:** <1 GB RAM, no extra disk.
- **Expected result:** all 5 paper figures regenerated and the 62 checks in
  `expected/paper_values.json` (corpus sizes; RQ1 per-distribution means; RQ2
  age buckets and Spearman ρ=0.27; RQ3 Jaccards and engine coverages; RQ4
  un-pullable rates; RQ5 regression betas; secret/malware validation) all PASS,
  ending in `62 PASS / 0 FAIL / 0 SKIP`. The table is also written to
  `docs/REPRODUCIBILITY_REPORT.md`.

### Claim #2 — the committed aggregates derive from the raw multi-scanner dataset

```bash
./reproduce.sh analysis
```

- **Expected time:** ~15 min (131 MB download + 8.6 GB extract + re-aggregation
  of 5,142 reports).
- **Expected resources:** ~9 GB disk, <2 GB RAM.
- **Expected result:** `data/analysis/per_image.csv` and the RQ3 sets are
  rebuilt from the raw `report.json` files, identical to the committed ones,
  followed by the same figures and the same `62 PASS / 0 FAIL`.

### Claim #3 — the scan pipeline itself, reduced

10 corpus images scanned by all 14 scanners into an isolated queue and output
directory; the census state in `data/` is not touched.

```bash
./reproduce.sh scan-smoke
```

- **Expected time:** **27 min measured on an 8-core AMD Ryzen 7 9700X** (not
  the reference machine above), most of it the one-time Clair database
  preparation and the scanner image pulls.
- **Expected resources:** Docker; ~15 GB disk for the scanner images. A Docker
  Hub token in `config/accounts.json` is optional.
- **Expected result:** `[scan-smoke] 10/10 imagens com report.json` and one
  invocation of each of the 14 scanners per image, under `scan-out/smoke/out/`.
  The extracted-filesystem cache is written by containers as root; clean it
  with `docker run --rm -v "$PWD/scan-out:/s" alpine rm -rf /s/smoke`.

Beyond the three claims, the whole census can be re-run from scratch with
`./reproduce.sh all`: it crawls the Docker Hub API, rebuilds the queue of 5,606
images, runs the 14 scanners and re-enters Claim #2. This takes **weeks of
scanning** and needs Docker plus a Docker Hub token; see `SETUP.md` for the
one-time scanner preparation and the distributed workers.

## LICENSE

[MIT](LICENSE).
