# Multi-Scanner Census of Linux OS Base Images on Docker Hub

Reproduction artifact for the short paper *"How Secure Is Your Base? A Recent
Multi-Scanner Census of Linux Operating-System Images on Docker Hub"*.

This repository holds the pipeline configuration, the corpus definition, the
vendored scan engine (`multiscan/`), and the analysis/figure scripts. The full
consolidated dataset (the per-image reports of all 14 scanners over the census)
is released separately **on acceptance**.

## What it measures

A census of the **Linux operating-system base images** Docker Hub lists under
its *Operating systems* category: 20 repositories (alpine, ubuntu, debian,
centos, busybox, amazonlinux, fedora, oraclelinux, rockylinux, almalinux,
photon, archlinux, tumbleweed, leap, kali-rolling, mageia, alt, cirros,
clearlinux, sl), deduplicated by `amd64` content digest to **5,606 unique
images**, each scanned by **14 open-source scanners**
(Syft, cdxgen, Trivy, Grype, OSV-Scanner, Clair, Dockle, Checkov, TruffleHog,
Gitleaks, detect-secrets, Whispers, ClamAV, YARA-Hunter).

## Layout

```
config/os.yaml          run config (queue, scanners, output, bind mounts)
config/scanners.yaml    scanner registry (Clair fixed with --image-ref)
data/hub_tags.jsonl     corpus definition: all tags of the 20 repos (Docker Hub API)
data/hub_repos.jsonl    repo metadata (pull counts, last_updated)
data/jobs_unique.jsonl  scan queue: 5,606 unique amd64 images, round-robin ordered
scripts/build_queue.py  builds jobs_unique.jsonl from the API pull
scripts/deploy_worker.sh deploys a distributed worker to a host (reverse-tunnel coordinator)
scripts/analyze.py      aggregates report.json into per_image.csv + RQ summaries
scripts/make_figs.py    generates the paper figure (run with: uv run --with matplotlib)
scripts/dashboard.py    live progress dashboard (stdlib http server)
scripts/compress_outputs.py  incremental gzip of completed scan outputs
paper/                  LaTeX source (SBC template) + figures
```

## Reproducing

One command each:

```bash
./reproduce.sh         # FROM THE DATA ONLY: regenerate every figure from the
                       # pre-computed data in data/ (no scan; ~1 min)
./reproduce.sh all     # THE WHOLE STUDY from scratch: crawl Docker Hub API ->
                       # queue -> scan (14 scanners) -> analysis -> same figures
```

(`./reproduce.sh analysis` is the intermediate step: raw `report.json` ->
`per_image.csv` -> figures.)

Pipeline stages (what `full` runs), all also callable standalone:

```bash
python3 scripts/crawl_hub.py      # Docker Hub API -> data/hub_repos.jsonl + hub_tags.jsonl
python3 scripts/build_queue.py    # dedup by amd64 digest -> data/jobs_unique.jsonl
python3 scripts/render_config.py  # auto-detect paths -> config/os.yaml
cd multiscan && uv run scanners seed --config ../config/os.yaml \
             && uv run scanners run  --config ../config/os.yaml && cd ..
python3 scripts/analyze.py        # report.json -> data/analysis/per_image.csv
uv run --with matplotlib,numpy python paper/make_figs.py
```

The scan engine is vendored in `multiscan/` and paths are auto-detected (no
manual editing). The `full` mode needs Docker and a Docker Hub access token (in
`config/accounts.json`, gitignored) to avoid pull rate limits. The pre-computed
data committed in `data/` lets `figures` mode reproduce every plot offline; the
full per-image multi-scanner dataset is released separately.
