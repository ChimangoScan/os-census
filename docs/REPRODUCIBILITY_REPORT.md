# Reproducibility report

Every number asserted in the camera-ready is re-derived from the versioned
artifacts in `data/` and checked exactly by `scripts/verify_values.py` against
`expected/paper_values.json` (the auto-generated table below). This file also
records the known limitations found while building the reproduction pipeline.

## Known limitations and notes

- **Analyzed vs. corpus size.** The corpus has 5,606 unique images; 463 are
  un-pullable (legacy manifest schema, RQ4), leaving 5,143 completed scan jobs
  and 5,142 per-image reports (one completed job produced no `report.json`).
  All per-image statistics are over the 5,142 reports in `per_image.csv`.
- **RQ4 source.** The un-pullable analysis reads the scan-queue state. The
  original queue database (`work/os.db`) is not distributed; its relevant
  content is exported verbatim to `data/analysis/job_status.csv.gz` by
  `scripts/export_job_status.py`, and `make_figs.py` falls back to that
  extract when the database is absent.
- **RQ3 sets.** `data/analysis/rq3_sca_sets.json.gz` is now written by
  `scripts/analyze.py` on every aggregation run (it was previously produced by
  an ad-hoc dump). Regenerating from the raw reports yields identical sets.
- **Manual-validation populations.** The secret/malware samples (1,100 each,
  `seed=42`) were drawn at a validation snapshot taken while the census was
  still running: 26,892 secret detections and 13,348 YARA-Hunter matches then
  available, vs. 44,339 and 20,157 in the final census. The paper states this
  explicitly (appendix). The verdicts apply to the sampled populations.
- **The seeded draws themselves.** The malware draw is fully reproducible:
  `verify_values.py` replays the appendix protocol (seed=42, stratified by
  rule) over the committed `all_findings.jsonl` and the 1,100 drawn ids match
  the committed `sample.jsonl` exactly, in order (`malware_draw_reproduces`).
  The secrets draw is NOT re-executable because its snapshot population was
  never committed (only `population_stats.json` survives); what is checked
  instead (`secrets_draw_strata`) is that the committed sample matches the
  protocol's proportional allocation exactly (615 TruffleHog / 485 Gitleaks
  of 26,892) with 1,100 unique ids.
- **Numbers corrected in the camera-ready.** The submitted version carried
  values from a partial snapshot (~3.3k images) that do not hold on the final
  census: raw secret rate 72% → **83%** (TruffleHog∪Gitleaks), raw YARA rate
  76% → **85%**, Dr. Docker reproduction 98.7% → **98.0%**, and the
  within-distribution β "rising to 0.48" → replaced by the reproducible
  per-distribution values (Ubuntu 0.53, AlmaLinux 0.65). The submitted
  "20 repositories" is stated precisely as 20 distributions across 21
  repositories (`rockylinux` is published under two namespaces).
- **RQ5 regression models.** β_age≈0.44 and β_packages≈0.15 come from the
  two-predictor standardized regression (age, packages) in `make_figs.py`;
  β_size≈−0.23 adds size as a third predictor; β_pulls≈−0.07 is the pulls
  coefficient in the (age, packages, size, pulls) model; the within-distribution
  betas are (age, packages) restricted to one distribution.
  `verify_values.py` reproduces each.
- **Not recomputable from the released artifacts** (hardware/runtime facts):
  scan wall-clock time and worker-machine details. No such numbers are
  asserted in the paper.

## Verification results (auto-generated)

<!-- verify:auto:begin -->
| check | fonte no paper | esperado | obtido | resultado |
|---|---|---|---|---|
| corpus_images | abstract; sec 3 | 5606 | 5606 | PASS |
| corpus_distros | abstract; sec 3 '20 distributions' | 20 | 20 | PASS |
| corpus_repos | sec 3 '21 repositories' | 21 | 21 | PASS |
| scanners | abstract; sec 3 | 14 | 14 | PASS |
| rq1_debian_mean_ch | sec 4.1 | 329 | 329.2056 | PASS |
| rq1_debian_n | sec 4.1 | 2641 | 2641 | PASS |
| rq1_debian_sd | sec 4.1 | 375 | 374.8211 | PASS |
| rq1_centos_mean_ch | sec 4.1 | 206 | 206.5 | PASS |
| rq1_centos_n | sec 4.1 | 10 | 10 | PASS |
| rq1_oraclelinux_mean_ch | sec 4.1 | 190 | 190.0 | PASS |
| rq1_amazonlinux_mean_ch | sec 4.1 | 160 | 160.003 | PASS |
| rq1_rockylinux_mean_ch | sec 4.1 | 128 | 128.12 | PASS |
| rq1_alpine_mean_ch | sec 4.1 | 84 | 84.1989 | PASS |
| rq1_mageia_mean_packages | sec 4.5 'around 250 packages' | {'range': [240, 260]} | 250.0 | PASS |
| rq1_mageia_mean_total | sec 4.5 'about a dozen' | {'range': [10, 15]} | 12.0 | PASS |
| rq1_debian_fewer_pkgs_than_mageia | sec 4.5 | True | True | PASS |
| rq2_mean_0_6m | sec 4.2 | 289 | 288.868 | PASS |
| rq2_mean_1_2y | sec 4.2 | 381 | 380.5482 | PASS |
| rq2_mean_2_4y | sec 4.2 | 548 | 548.0459 | PASS |
| rq2_mean_4y_plus | sec 4.2 | 1118 | 1117.8233 | PASS |
| rq2_spearman_age_total | sec 4.2 | 0.27 | 0.2717 | PASS |
| rq2_p_below_001 | sec 4.2 | True | True | PASS |
| rq3_jaccard_trivy_grype | sec 4.3 | 0.36 | 0.3623 | PASS |
| rq3_jaccard_trivy_clair | sec 4.3 | 0.13 | 0.1276 | PASS |
| rq3_osv_clair_intersection | sec 4.3 | 0 | 0 | PASS |
| rq3_grype_pairs_k | sec 4.3 | 636 | 636 | PASS |
| rq3_trivy_pairs_k | sec 4.3 | 323 | 323 | PASS |
| rq3_osv_pairs_k | sec 4.3 | 16 | 16 | PASS |
| rq3_clair_pairs_k | sec 4.3 | 50 | 50 | PASS |
| counting_pairs_summed | sec 3 Counting | 1025210 | 1025210 | PASS |
| counting_pairs_unique | sec 3 Counting | 710739 | 710739 | PASS |
| counting_inflation | sec 3 Counting | 1.44 | 1.4425 | PASS |
| counting_dedup_spearman | sec 3 Counting | 0.86 | 0.8594 | PASS |
| rq4_unpullable_pct | sec 4.4 '8%' | 8 | 8.259 | PASS |
| rq4_one_in_n | abstract; sec 4.4 'one in twelve' | 12 | 12.108 | PASS |
| rq4_centos_rate | sec 4.4 'over half' | {'gt': 50} | 54.5455 | PASS |
| rq4_busybox_rate | sec 4.4 'over half' | {'gt': 50} | 53.5354 | PASS |
| rq4_ubuntu_rate | sec 4.4 'about a third' | {'range': [28, 39]} | 30.9783 | PASS |
| rq4_debian_rate | sec 4.4 'under 3%' | {'lt': 3} | 2.1489 | PASS |
| rq4_archlinux_rate | sec 4.4 'under 3%' | {'lt': 3} | 0.0 | PASS |
| rq4_rockylinux_rate | sec 4.4 'under 3%' | {'lt': 3} | 0.0 | PASS |
| rq4_centos_pulls_over_1b | sec 4.4 | True | True | PASS |
| rq5_beta_age | sec 4.5 | 0.44 | 0.4415 | PASS |
| rq5_beta_packages | sec 4.5 | 0.15 | 0.1511 | PASS |
| rq5_beta_size | sec 4.5 | -0.23 | -0.2256 | PASS |
| rq5_beta_pulls | sec 4.5 | -0.07 | -0.0656 | PASS |
| rq5_beta_pkgs_ubuntu | sec 4.5 '0.53 for Ubuntu' | 0.53 | 0.5272 | PASS |
| rq5_beta_pkgs_almalinux | sec 4.5 '0.65 for AlmaLinux' | 0.65 | 0.6457 | PASS |
| other_secrets_raw_pct | sec 4.6 '83%' | 83 | 83.3528 | PASS |
| other_yara_raw_pct | sec 4.6 '85%' | 85 | 84.6752 | PASS |
| secrets_population | appendix '26,892' | 26892 | 26892 | PASS |
| malware_population | appendix '13,348' | 13348 | 13348 | PASS |
| secrets_sample_n | sec 4.6; appendix | 1100 | 1100 | PASS |
| malware_sample_n | sec 4.6; appendix | 1100 | 1100 | PASS |
| secrets_true_positives | sec 4.6 'zero real secrets' | 0 | 0 | PASS |
| malware_true_positives | sec 4.6 'zero real malware' | 0 | 0 | PASS |
| validation_seed | appendix 'seed=42' | 42 | 42 | PASS |
| malware_draw_reproduces | appendix 'seed-fixed (seed=42) stratified random sample' (malware): replay exato do sorteio | True | True | PASS |
| secrets_draw_strata | appendix seed-fixed stratified sample (secrets): alocacao 615/485 proporcional + ids unicos | True | True | PASS |
| wilson_upper_pct | sec 4.6; appendix '<=0.35%' | 0.35 | 0.348 | PASS |
| repro_shu_high_pct | table 2 '97%' | 97 | 96.8689 | PASS |
| repro_drdocker_known_vuln_pct | table 2 '98.0%' | 98.0 | 98.0358 | PASS |

**62 PASS / 0 FAIL / 0 SKIP**
<!-- verify:auto:end -->
