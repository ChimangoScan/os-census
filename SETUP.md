# Setup / Reproduction

This artifact provides the OS-specific configuration, corpus and analysis; the
scan engine is the `multiscan` submodule. Below is the full path from a clean
clone to figures.

## 0. Prerequisites
- Docker (Engine 24+), Python 3.12, [`uv`](https://docs.astral.sh/uv/), `git`.
- A Docker Hub account access token (to avoid anonymous pull rate limits).

## 1. Clone
```bash
git clone https://github.com/ChimangoScan/os-census
cd os-census          # the scan engine is vendored in ./multiscan
```

## 2. Generate the run config (paths are automatic)
The scripts derive the repo root from their own location, so no path editing is
needed. Scan output goes to `./scan-out/` by default; point it at a larger
scratch directory with `OSCENSUS_OUT` / `OSCENSUS_CACHE` if you like. Generate
the engine config for this clone:
```bash
# optional: export OSCENSUS_OUT=/big/scratch/out_so OSCENSUS_CACHE=/big/scratch/cache_so
python3 scripts/render_config.py     # writes config/os.yaml with this clone's paths
```

## 3. Docker Hub credentials
```bash
printf '[{"username":"YOUR_USER","password":"YOUR_TOKEN"}]' > config/accounts.json
```
(`config/accounts.json` is gitignored and never committed.)

## 4. One-time scanner prep
```bash
# whispers has no official image; build the one the registry expects
printf 'FROM python:3.12.10-alpine3.21\nRUN pip install --no-cache-dir whispers==2.4.0\nENTRYPOINT ["whispers"]\n' | docker build -t multiscan/whispers:1 -
# Clair needs its matcher DB (~1 GB) downloaded once
cd multiscan && uv run scanners prepare --only clair --config ../config/os.yaml && cd ..
```

## 5. Build the queue and run the census
```bash
python3 scripts/build_queue.py                    # -> data/jobs_unique.jsonl (5,606 images)
cd multiscan
uv run scanners seed --config ../config/os.yaml   # load the queue
uv run scanners run  --config ../config/os.yaml   # scan (single host)
cd ..
```
Distributed runs (coordinator + reverse-tunnelled workers) use
`scripts/deploy_worker.sh <host>`; see the script header.

## 6. Analyse and plot
```bash
python3 scripts/analyze.py                         # -> data/analysis/per_image.csv + RQ summaries
uv run --with matplotlib python paper/make_figs.py # -> paper/figures/fig_panels.pdf
```

## 7. Live progress (optional)
```bash
python3 scripts/dashboard.py 8911   # http://localhost:8911
```

The full consolidated per-image dataset is released separately on acceptance.
