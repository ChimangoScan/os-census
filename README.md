# Multi-Scanner Census of Linux OS Base Images on Docker Hub

Reproduction artifact for the short paper *"How Secure Is Your Base? A Recent
Multi-Scanner Census of Linux Operating-System Images on Docker Hub"*.

This repository holds the pipeline configuration, the corpus definition, and
the analysis/figure scripts. The full consolidated dataset (the per-image
reports of all 13 scanners over the census) is released separately **on
acceptance**.

## What it measures

A census of the **Linux operating-system base images** Docker Hub lists under
its *Operating systems* category: 21 repositories (alpine, ubuntu, debian,
centos, busybox, amazonlinux, fedora, oraclelinux, rockylinux, almalinux,
photon, opensuse, archlinux, kali, ...), deduplicated by `amd64` content digest
to **5,606 unique images**, each scanned by **13 open-source scanners**
(Syft, cdxgen, Trivy, Grype, OSV-Scanner, Clair, Dockle, Checkov, TruffleHog,
Gitleaks, detect-secrets, Whispers, ClamAV, YARA-Hunter).

## Layout

```
config/os.yaml          run config (queue, scanners, output, bind mounts)
config/scanners.yaml    scanner registry (Clair fixed with --image-ref)
data/hub_tags.jsonl     corpus definition: all tags of the 21 repos (Docker Hub API)
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

The scan engine is [`multiscan`](https://github.com/ChimangoScan/multiscan); this
repo provides the OS-specific config, corpus and analysis on top of it.

```bash
# 1. build the scan queue from the corpus definition
python3 scripts/build_queue.py

# 2. run the census (single host or distributed; see config/os.yaml)
cd /path/to/multiscan
uv run scanners seed --config /path/to/config/os.yaml
uv run scanners run  --config /path/to/config/os.yaml

# 3. analyse + plot
python3 scripts/analyze.py
uv run --with matplotlib python paper/make_figs.py
```

A Docker Hub access token (in `config/accounts.json`, gitignored) is needed to
avoid pull rate limits. The full per-image dataset will be released on
acceptance.
