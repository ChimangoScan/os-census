# Repository layout and data provenance

```
reproduce.sh            entry point: data|analysis|verify|all (see README)
config/scanners.yaml    scanner registry, versions pinned (Clair fixed with --image-ref)
config/os.yaml          run config, generated per-clone by render_config.py (gitignored)
data/hub_tags.jsonl     corpus definition: all tags of the 21 repositories (Docker Hub API)
data/hub_repos.jsonl    repository metadata (pull counts, last_updated)
data/jobs_unique.jsonl  scan queue: 5,606 unique amd64 images, round-robin ordered
data/analysis/per_image.csv        per-image aggregates (written by analyze.py)
data/analysis/rq3_sca_sets.json.gz per-engine (image, CVE) sets (written by analyze.py)
data/analysis/job_status.csv.gz    scan-queue outcome per image (export_job_status.py; RQ4)
data/secret_validation/            seeded sample (1,100), verdicts, population stats
data/malware_validation/           seeded sample (1,100), verdicts, all findings
data/rq3_validation/               200-item cross-engine adjudication
scripts/crawl_hub.py    Docker Hub API -> hub_repos.jsonl + hub_tags.jsonl
scripts/build_queue.py  dedup by amd64 digest -> jobs_unique.jsonl
scripts/render_config.py auto-detects paths -> config/os.yaml
scripts/deploy_worker.sh distributed worker deploy (reverse-tunnel coordinator)
scripts/analyze.py      report.json -> per_image.csv + rq3_sca_sets.json.gz
scripts/export_job_status.py  work/os.db -> job_status.csv.gz
scripts/make_figs.py    all figures (falls back to committed extracts when raw data absent)
scripts/verify_values.py  60 exact checks of the paper's numbers (expected/paper_values.json)
scripts/compress_outputs.py  incremental gzip of completed scan outputs
expected/paper_values.json  every number the paper asserts, with its source locator
docs/REPRODUCIBILITY_REPORT.md  known limitations + auto-generated verification table
multiscan/              vendored scan engine (queue, adapters, pipeline; own README)
figures/                generated plots (make_figs.py)
```

## Provenance of derived headline numbers

| Paper number | Derivation |
|---|---|
| 5,606 images / 20 distributions / 21 repositories | rows and distinct repos of `job_status.csv.gz` (= `jobs_unique.jsonl`) |
| 8% / "one in twelve" un-pullable | `status == skipped` rows of `job_status.csv.gz` (463/5,606) |
| RQ1 means/SDs, RQ2 age buckets, ρ=0.27, RQ5 betas, 83%/85% raw rates, 97%/98.0% | computed from `per_image.csv` (see resolvers in `verify_values.py`) |
| RQ3 Jaccards, 636k/323k/16k/50k, 1,025,210 → 710,739 dedup | `rq3_sca_sets.json.gz` after CVE-id normalization |
| 1,100 samples, 0 true positives, ≤0.35% Wilson, seed 42 | `data/{secret,malware}_validation/` verdicts + population stats |

The scan-queue database (`work/os.db`) and the raw scanner outputs are not in
git; the queue outcome is committed as `job_status.csv.gz` and the raw outputs
are in the release (see README *Dataset*).
