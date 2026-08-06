# Partial ground truth for the disagreement between CVE scanners (RQ3)

Census of Linux operating-system base images, scanned by Trivy, Grype, OSV-Scanner and Clair. Validation by human reading of (image, CVE) pairs.

> **Scope.** This validation is supplementary material of the artifact. The paper does not report these precision figures; its Limitations state that package findings lack manual adjudication. Every number below is reproducible from the committed `verdicts.jsonl`.

## 1. Executive summary

Findings reported by a single scanner are not mostly false positives. Of a stratified sample of 200 (image, CVE, scanner) triples drawn with `seed=42` from the consolidated findings of the four engines, 169 are genuinely affected. Each triple was classified by reading two things: the package and installed version the scanner points at, taken from the engine output and from the image's Syft software bill of materials (SBOM), and the CVE advisory in the authoritative tracker (NVD, OSV, Debian, Ubuntu, Red Hat Security Data, Alpine, Photon), several of them consulted live.

| Class | n | % |
|---|---|---|
| True positive | 169 | 84.5% |
| False positive | 22 | 11.0% |
| Ambiguous | 9 | 4.5% |

- Overall precision, defined as TP/(TP+FP) and excluding the ambiguous pairs: **0.885**, 95% Wilson interval [0.832, 0.923].
- False-positive rate among the decided pairs: 11.5%.

Precision per scanner, over the pairs where that engine is the reporter:

| Scanner | n | TP | FP | AMB | Precision | 95% Wilson interval |
|---|---|---|---|---|---|---|
| Trivy | 27 | 26 | 1 | 0 | 0.963 | [0.817, 0.993] |
| Grype | 122 | 110 | 8 | 4 | 0.932 | [0.872, 0.965] |
| OSV-Scanner | 19 | 16 | 3 | 0 | 0.842 | [0.624, 0.945] |
| Clair | 32 | 17 | 10 | 5 | 0.630 | [0.442, 0.785] |

Restricted to the pairs reported by exactly one engine, which is the pure divergent signal:

| Scanner | n | TP | FP | AMB | Precision | 95% Wilson interval |
|---|---|---|---|---|---|---|
| Trivy | 27 | 26 | 1 | 0 | 0.963 | [0.817, 0.993] |
| Grype | 66 | 56 | 6 | 4 | 0.903 | [0.805, 0.955] |
| OSV-Scanner | 13 | 11 | 2 | 0 | 0.846 | [0.578, 0.957] |
| Clair | 14 | 8 | 2 | 4 | 0.800 | [0.490, 0.943] |

The central conclusion is that most of the disagreement between the engines comes from differences in coverage and feed, since each engine consults different databases and maps packages differently, rather than from matching error. The real false positives concentrate in two places: Clair reporting at source-package granularity, and OSV-Scanner applying a version range to system-installed pip and setuptools. A few informative or disputed CVEs mapped through broad Common Platform Enumeration (CPE) identifiers make up the rest.

## 2. Methodology

### 2.1 Source and format of the data

All scanner outputs are read only.

- Per-scanner findings live in `scan-out/out_so/<dir>/{trivy,grype,osv,clair}/*.json.gz`.
  - Trivy: `Results[].Vulnerabilities[]`, from which `PkgName`, `InstalledVersion`, `FixedVersion`, `Status` and `DataSource` are used.
  - Grype: `matches[]`, from which `artifact.name`, `artifact.version`, `artifact.purl`, `vulnerability.id`, `fix.versions`, `fix.state` and the feed `namespace` are used.
  - OSV-Scanner: `results[].packages[].vulnerabilities[]`, from which `package.name`, `package.version`, `package.ecosystem`, the identifier and its aliases are used.
  - Clair: `vulnerabilities{}`, `package_vulnerabilities{}` and `packages{}`, from which the vulnerability name (which embeds the CVE), the package, `fixed_in_version` and the `updater` are used.
- Installed versions come from the Syft SBOM in `out_so/<dir>/syft/*.syft.json.gz`.
- The consolidated set used for sampling is `data/analysis/rq3_sca_sets.json.gz`, which maps each engine to its list of `[image@sha256, CVE]` pairs.

### 2.2 Mapping an image to its output directory

The consolidated set identifies images by `repo@sha256:<digest>`, while the output directories end with the first eight hexadecimal characters of that digest, so `debian@sha256:6ea10209...` corresponds to `debian_10.0_6ea10209`. The mapping was validated: the 2,525 distinct digests map uniquely and without collision onto directories, and Clair's internal `manifest_hash` agrees with the full digest of the consolidated set. The distribution is inferred from the directory name, with `rhel-family` covering almalinux, rockylinux, oraclelinux, fedora, centos, sl and mageia.

### 2.3 Extraction and sampling

`extract_and_sample.py` decides no verdict. It maps digests to directories, computes per-pair agreement (how many of the four engines report each (image, CVE) pair), draws the stratified sample with `random.Random(42)`, and extracts the package and installed version from the reporting engine's output. The stable identifier is `rq3_` followed by `sha1(scanner|image|cve)[:14]`.

The sample is stratified into two strata:

- **Single**, 120 pairs reported by exactly one engine, where a false positive is most likely. They are allocated proportionally across the four engines with a coverage floor. The stratum universe is 215,062 pairs: Grype 142,798, Trivy 63,037, Clair 5,939 and OSV-Scanner 3,288.
- **Multi**, 80 pairs on which at least two engines agree, from a universe of 133,454. The rare combinations involving OSV-Scanner or Clair (clair+grype, clair+trivy, clair+grype+trivy, grype+osv, grype+osv+trivy, osv+trivy) are force-included, and the remainder is filled with the dominant grype+trivy combination.

`enrich_sbom.py` then attaches to each record the matching installed versions from the Syft SBOM, by exact name match plus related candidates. This is what resolves the cases where Clair reports a source-package name with no binary version.

The resulting sample covers all four engines and nine distribution groups: rhel-family (59), debian (46), amazonlinux (34), ubuntu (23), photon (16), archlinux (14), alpine (6), busybox (1) and cirros (1).

### 2.4 Classification

A single reviewer decided every verdict by reading the pair. For each one, the installed package and version were cross-checked against the advisory:

- **Distribution trackers** (Debian security tracker, Ubuntu CVE tracker, the Red Hat Security Data API, Photon, Alpine secdb) state whether the source package is affected and in which version it is fixed. When the status is fixed and the installed version precedes the fixing version, or when the status is affected, deferred, will-not-fix or needed with no fix available, the package is genuinely affected and unpatched.
- **NVD, OSV and upstream** supply the affected version range and whether the installed binary actually contains the vulnerable code.

Advisories were consulted live where the verdict depended on it. Examples include CVE-2024-5535 and CVE-2025-69420 (Red Hat: OpenSSL marked affected with a deferred fix), CVE-2021-43618 (Ubuntu: ignored as end-of-life in 21.04, not affected in 22.04), CVE-2007-5686 (Debian: unimportant, with the note that `LOG_UNKFAIL_ENAB=no` neutralizes the impact), CVE-2005-2541 (Debian: intended behaviour), CVE-2023-31439 (Debian: disputed by upstream), CVE-2025-60876 (NVD: BusyBox up to 1.37.0), CVE-2023-27534 (NVD: curl 7.18.0 to 7.88.1), and the OSV ranges for pip and setuptools.

The criterion is:

- **True positive**: the installed version falls inside the affected range with no fix present and no backport.
- **False positive**: not affected, because the version is outside the range, the fix is already applied or backported, the match landed on the wrong package or subpackage (one that does not carry the vulnerable code), the CVE belongs to another ecosystem, or the distribution rejects it as a vulnerability.
- **Ambiguous**: a genuine doubt, such as a disputed CVE that the distribution keeps open, a source-versus-binary granularity that cannot be decided, a development release with no consolidated status, or a recent CVE without reliable NVD data.

When a pair is a false positive or ambiguous, a cause is recorded from a fixed vocabulary: `feed_db`, `source_vs_binary`, `version_range`, `distro_backport`, `kernel_irrelevante`, `disputed`, `outro`. `write_verdicts.py` only records the decisions.

### 2.5 Reproducibility

Running `extract_and_sample.py` with `seed=42` reproduces exactly the same 200 identifiers; `enrich_sbom.py` reattaches the SBOM versions; `write_verdicts.py` rewrites the verdicts. The precision figures and Wilson intervals are recomputable by aggregating `verdicts.jsonl`.

## 3. Results

Both strata show high and statistically similar precision, so the disagreement between engines is not dominated by false positives.

- Read: 200 of 200. True positives 169, false positives 22, ambiguous 9.
- Overall precision: 0.885, 95% interval [0.832, 0.923].
- Single (divergent) stratum: 0.902, [0.833, 0.944]. Multi (agreement) stratum: 0.861, [0.768, 0.920].

### 3.1 Causes of the 22 false positives

| Cause | n |
|---|---|
| source_vs_binary | 12 |
| feed_db (informative CVE or broad CPE) | 5 |
| version_range | 5 |

The nine ambiguous pairs break down as source_vs_binary 4, version_range 3 and disputed 2.

### 3.2 Precision per distribution

| Distribution | n | TP | FP | AMB | Precision |
|---|---|---|---|---|---|
| rhel-family | 59 | 54 | 4 | 1 | 0.931 |
| debian | 46 | 31 | 13 | 2 | 0.705 |
| amazonlinux | 34 | 31 | 3 | 0 | 0.912 |
| ubuntu | 23 | 16 | 2 | 5 | 0.889 |
| photon | 16 | 16 | 0 | 0 | 1.000 |
| archlinux | 14 | 14 | 0 | 0 | 1.000 |
| alpine | 6 | 5 | 0 | 1 | 1.000 |
| busybox and cirros | 2 | 2 | 0 | 0 | 1.000 |

Debian has the lowest precision because it is where the Clair pairs carrying a source-package name (perl, zlib, systemd, shadow) land, together with the informative CVEs such as CVE-2007-5686 on login and shadow. Photon, Archlinux and Alpine reach precision 1.0 in this sample: Photon matches at distribution level with an explicit fixed version, and Archlinux findings are Go standard-library CVEs whose version range is directly verifiable. These are small samples, so the intervals are wide.

## 4. Why the scanners disagree

### 4.1 A consolidation artifact in Clair's own entries

Part of Clair's isolation, including its zero intersection with OSV-Scanner, is a measurement artifact rather than a scanner property. About half of Clair's entries in `rq3_sca_sets.json.gz` are stored as Clair's full vulnerability name, for example `CVE-2026-5435 on Ubuntu 22.04 LTS (jammy) - medium`, instead of the normalized CVE identifier: 5,866 of 11,736, with the other 5,870 clean. Trivy, Grype and OSV-Scanner have no such entries. A string carrying an `on Ubuntu ...` suffix can never match the clean CVE identifiers of the other engines, which inflates Clair's apparent divergence and drives intersections to zero, contributing to the low Jaccard coefficients and to the empty OSV-Clair intersection. The CVE was normalized at match time so the cases could be read, but the set-level metric should be recomputed after normalizing Clair's names. This is a cause of divergence in the measurement, distinct from a scanner false positive.

### 4.2 Source versus binary granularity, the dominant real cause (12 of 22)

Clair reports under the source-package name (perl, zlib, openssl, systemd, shadow). In slim and Debian images the binary actually present is a different package (perl-base, zlib1g, libsystemd0, passwd), and in several cases the subpackage present does not contain the vulnerable code. CVE-2013-4392, a time-of-check-to-time-of-use flaw in systemd, is reported where only libsystemd0 and libudev1 exist, without the systemd daemon; CVE-2026-8376 in perl is reported where only perl-base exists. The same pattern appears in Grype for data-only vim subpackages (vim-data, vim-common) that do not contain the vim executable, in CVE-2023-5344 and CVE-2026-32249. Trivy, Grype and OSV-Scanner anchor more closely on the installed binary, which is why they diverge from Clair on these pairs.

### 4.3 Version range, mostly OSV-Scanner on pip and setuptools (5 false positives, 3 ambiguous)

OSV-Scanner matches the system pip and setuptools through the PyPI ecosystem, but in several cases the installed version lies outside the affected range: setuptools 41.2.0, 53.0.0 and 59.6.0 are all below 59.8.0, and CVE-2024-6345 and CVE-2025-47273 only affect 59.8.0 and later. Two of these false positives are agreement pairs, one reported by both Grype and OSV-Scanner and one by both OSV-Scanner and Trivy, because both engines inherited the same misapplied OSV range. Agreement between scanners therefore does not guarantee a true positive. A comparable case is CVE-2017-13729, fixed in ncurses 6.1 with 6.1 installed.

### 4.4 Feed and broad CPE mapping (5 false positives)

CVE-2007-5686 concerns `/var/log/btmp` permissions in the initscripts package of a different distribution, and is matched through a broad CPE onto the login and shadow packages of Debian and Red Hat systems; Debian marks it unimportant and notes that `LOG_UNKFAIL_ENAB=no` neutralizes the impact. CVE-2005-2541, on `tar -p`, is intended behaviour according to Debian rather than a vulnerability. These reach the engines that consume NVD and CPE data without applying the distribution's veto.

### 4.5 Disputed advisories (2 ambiguous)

CVE-2023-31439 in systemd is disputed by upstream yet kept as vulnerable by Debian, and CVE-2017-20230 in perl has contested relevance. Both are marked ambiguous rather than false positives.

### 4.6 What is not error

The large majority of single-reporter divergences are true positives: the engine reporting alone was right, and the others simply did not cover that pair because they consult a different feed or ecosystem. OSV-Scanner finds pip, setuptools and Go findings through PyPI and Go metadata that Trivy and Grype either treat as operating-system packages or ignore; Grype and Trivy report Red Hat OpenSSL pairs marked affected with a deferred fix, which Red Hat acknowledges and has not fixed, so they are genuinely affected. This is a difference in coverage, not in correctness.

## 5. Limitations

1. **A single reviewer**, with no second annotation and therefore no inter-rater agreement statistic. The criteria are fixed in Section 2.4.
2. **No execution or proof of concept.** Verdicts rest on the version range, the presence of the vulnerable binary and the distribution's own assessment. For CVEs whose exploitability is architecture-specific, such as CVE-2025-22866 in the Go P-256 implementation, which is exploitable only on ppc64le while the images are amd64, the pair was marked a true positive because the toolchain version falls in the affected range, with the caveat recorded.
3. **n=200 gives wide intervals for the engines with few pairs.** OSV-Scanner has 19 pairs and Clair 32; Clair's precision of 0.630 carries an interval of [0.442, 0.785] and is pulled down by the forced sampling of Clair combinations and by one repeated source-versus-binary pattern (six pairs of CVE-2026-8376 on perl across distinct slim images).
4. **Per-scanner precision in the multi stratum** is attributed to the engine from which the package and version were extracted, which is one of the reporters rather than all of them. This is why the single-reporter-only figures are reported alongside; they are the cleaner measurement.
5. **Correlated false positives.** The same CVE and package recur across tags, which reduces effective diversity even though many images are covered.
6. **The Clair normalization artifact of Section 4.1 affects the set-level RQ3 metrics** (Jaccard coefficients and intersections), not the true-positive and false-positive verdicts here, which use the normalized CVE.

## 6. Artifacts

- `extract_and_sample.py`: digest mapping, seeded sampling and extraction; it does not classify.
- `enrich_sbom.py`: attaches the installed versions from the Syft SBOM.
- `sample.jsonl`: the 200 pairs, with identifier, image, directory, distribution, scanner, reporters, CVE, normalized CVE, package, installed version, fixed version, status, feed and SBOM data.
- `verdicts.jsonl`: the 200 verdicts, with identifier, index, CVE, scanner, reporters, distribution, stratum, verdict, cause and the recorded justification.
- `write_verdicts.py`: records the reviewer's decisions.
- `population_stats.json`: the universe and sample sizes.
