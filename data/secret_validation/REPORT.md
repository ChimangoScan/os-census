# Manual validation of the secret detections: true positives versus false positives

Census of Docker Hub operating-system base images, scanned by TruffleHog and Gitleaks, validated by human reading.

## 1. Executive summary

None of the secret detections in the sample is a usable credential. From a random sample of **1,100 detections**, stratified by scanner and drawn with `seed=42` from a population of **26,892** distinct detections over **2,747** images, every one was classified by reading the finding itself.

| Class | n | % |
|---|---|---|
| True positive | 0 | 0.00% |
| False positive | 1,100 | 100.00% |
| Ambiguous | 0 | 0.00% |

- Validated false-positive rate: 100.0% (95% Wilson confidence interval: 99.65% to 100.00%).
- Validated true-positive rate: 0.0% (95% Wilson interval: 0.00% to 0.348%; the rule-of-three upper bound for 0 successes in 1,100 trials is 0.273%).

All 1,100 detections are documentation placeholders, test keys shipped inside system libraries, package checksums, source-code identifiers, public-key material, or short-lived tokens already expired in log files.

## 2. Methodology

### 2.1 Source and format of the data

The scanner outputs are read only, from `scan-out/out_so/<image>/{trufflehog,gitleaks}/`.

- TruffleHog writes JSON Lines, one finding per line. The fields used are `DetectorName`, `Raw`/`RawV2`, `Verified` and `SourceMetadata.Data.Docker.file`. Every finding in the corpus carries `Verified=false`, meaning the scanner itself never confirmed a credential against its provider.
- Gitleaks writes a JSON array. The fields used are `RuleID`, `Secret`, `Match`, `File`, `StartLine` and `Entropy`.
- Compressed outputs are decompressed for reading. An empty result is `[]` for Gitleaks and a zero-byte file for TruffleHog.

### 2.2 Extraction and sampling

`extract_and_sample.py` performs only four steps: it extracts every finding, derives a stable identifier, draws the sample with a fixed seed, and writes the result. It classifies nothing.

- The stable identifier is `sha1(scanner|image|file|rule|locator|value)[:16]`, prefixed with `tr_` or `gi_` for the originating scanner. The locator is the line number for TruffleHog and `StartLine` for Gitleaks.
- After deduplication by identifier the population is 26,892 findings, 15,039 from TruffleHog and 11,853 from Gitleaks. The gap to the 27,285 raw records comes from identical findings collapsing together and from a small number of unparseable lines.
- Sampling is stratified by scanner and proportional, using `random.Random(42)`: 615 TruffleHog and 485 Gitleaks findings, 1,100 in total, spanning 677 distinct images.
- The sample is written to `sample.jsonl`, one finding per line, with its identifier, scanner, image, file, rule and matched value.

### 2.3 Classification

A single reviewer decided every verdict by reading the finding: the matched value, the file it came from, the rule that fired, and the surrounding context. No filter, regular expression or heuristic decided a verdict; the script only recorded the decision.

The criterion is:

- **True positive**: a real, usable credential, such as a production private key, an API token valid in both format and context, or a real password in a configuration file.
- **False positive**: a placeholder, a documentation example, a package hash or checksum, a public key, a known test secret, a path or binary matched by accident, or an expired short-lived token.
- **Ambiguous**: a genuine doubt, counted separately. There were none.

Verdicts are written incrementally to `verdicts.jsonl`, each an identifier, a verdict and a one-sentence reason.

### 2.4 Representativeness and precision

For N=26,892 and n=1,100, a proportion near 0.5 would give a 95% interval of about ±2.95%. Because the observed false-positive proportion is close to 1.0, the effective interval is far narrower, with a Wilson lower bound of 99.65%. Running `extract_and_sample.py` with `seed=42` reproduces exactly the same 1,100 identifiers.

## 3. Results

- Read: 1,100 of 1,100. True positives 0, false positives 1,100, ambiguous 0.
- False-positive rate: 100.0%, 95% Wilson interval [99.65%, 100.00%].
- True-positive rate: 0.0%, 95% Wilson interval [0.00%, 0.348%]; the rule of three over 0/1,100 gives an upper bound of 0.273%.

### 3.1 Estimated rate of validated secrets per image

The headline census figure collapses once a real credential is required. About 72% of the images carry at least one raw detection. To estimate the fraction that carries at least one real secret, we treat the detections of an image as independent, which is conservative here: in practice the false positives are strongly correlated, because they come from the same system files replicated across images.

- Point estimate of the fraction of images with at least one real secret: approximately 0%.
- Coarse upper bound: combining the 0.348% ceiling on the true-positive rate with the 72% ceiling on images with a raw detection puts the fraction below about 0.25%, that is, at most roughly 7 of the 2,747 images, and most likely none.

In practical terms, the finding that "72% of the images contain secrets" falls to about 0% once a validated, usable credential is required.

## 4. Why every detection is a false positive

Ten patterns account for the whole sample.

**(a) Test keys compiled into system libraries.** Test keys built into GnuTLS (`libgnutls.so*`, `gnutls-cli`), both RSA and elliptic-curve. These are public test fixtures, not credentials, and they are the most frequent pattern behind the `PrivateKey` detector.

**(b) Example and test keys in package documentation.** Keys under `m2crypto-*/demo/` (`server.pem`, `rsa.priv.pem`) and the pygpgme test keys (`tests/keys/key1.sec`, `key2.sec`, `signonly.sec`). They are real keys in format, but published test material.

**(c) Package hashes and checksums matched as tokens.** The TruffleHog Box, Agora, Alchemy, Pastebin, Flickr and BingSubscriptionKey detectors matching MD5 digests in `libc6:amd64.md5sums`, slices of the apt `Packages` and `Translation-en` files, and 32-character hexadecimal GUIDs inside binaries such as `systemd-resolved`.

**(d) C identifiers in headers.** The Gitleaks `generic-api-key` rule matching macro and type names: `TPM2B_ENCRYPTED_SECRET`, `krb5_const_principal`, `gnutls_x509_crt_fmt_t`, `NL80211_KEY_MAX`, `__NFTA_TUNNEL_KEY_IP6_MAX`, `COPHH_KEY_UTF8`, the SQLite symbols `soft_heap_limit64` and `column_bytes16`, the x86 intrinsic `_mm512_srli_epi64`, and the bison template token `b4_api_PREFIX`.

**(e) Example URLs in documentation.** Credential-bearing example URLs such as `http://joe:password@proxy.example.com`, `ftp://user:passwd@my.site.com` and `username:fakepwd`, taken from urllib2, urlgrabber, `HTTP/Tiny.pm` and the yum and curl manual pages.

**(f) Public-key material.** Base64 slices of `pacman/keyrings/archlinux.gpg`, which are PGP public-key packets, matched by the Box, UnifyID and `generic-api-key` rules.

**(g) File-type signatures inside a binary.** The Gitleaks `private-key` rule matching the literal strings `BEGIN PRIVATE KEY` and `BEGIN OPENSSH PRIVATE KEY` inside `magic.mgc`, the compiled libmagic database. The reported entropy, around 1.3 to 2.0, is far below that of key material.

**(h) A specification policy hash and a documentation identifier.** The `authPolicy` field of `tpm2-tss/fapi-profiles/*.json` is the default policy hash from the TSS specification, and the `tpmkey:uuid=...` string in the GnuTLS `NEWS` file is a changelog example.

**(i) Session hashes in installer logs.** The `key: <sha1>` entries under `var/log/anaconda/` are installer transaction identifiers, not credentials.

**(j) Expired temporary AWS STS tokens in logs.** `var/log/dnf.librepo.log` contains access-key identifiers prefixed `ASIA` and `X-Amz-Security-Token` values captured from pre-signed URLs of RPM mirrors on S3. These are short-lived session credentials, already expired and merely logged, so they are not usable. This is the most borderline pattern in the sample, and it is a false positive under the criterion of a real and usable secret.

No true positive was available to illustrate: the sample contains no production private key, no valid API token and no real configuration password.

## 5. Comparison with prior measurements

Our result sits further towards "almost everything is a false positive" than either published figure, and the corpus explains why.

| Study | Method | Valid or real hits |
|---|---|---|
| This work | Human reading of 1,100 of 26,892 detections, official OS base images | 0.0% (95% CI [0%, 0.35%]) |
| Dahlmanns et al. | Validation of secrets in Docker images | about 8.5% validated |
| Dr. Docker | Filtering of scanner hits | about 99.3% invalid, so about 0.7% valid |

Against Dr. Docker's roughly 0.7% valid hits, our point estimate is 0% and our interval ceiling of 0.35% falls below their figure: consistent in order of magnitude, and lower. Against the roughly 8.5% reported by Dahlmanns et al., our result is far lower. The corpus accounts for the gap. Our census covers official operating-system base images (almalinux, debian, ubuntu, archlinux, amazonlinux and the rest), which carry system libraries, headers and documentation but no third-party application code with accidentally committed credentials. Studies that sample application images find real secrets there. The reading is that operating-system base images have an effectively null true-positive rate, and that the secret-exposure risk lives in the application layers rather than in the base.

## 6. Limitations

1. **No active verification.** Tokens were not authenticated against their providers, which would be intrusive. Verdicts rest on judgement over format, content, file and context. For the AWS STS tokens, expiry was inferred from the credential type (a session credential with the `ASIA` prefix, found in a download log) rather than tested.
2. **The corpus is restricted to operating-system base images.** The 0% true-positive rate applies to that population and should not be generalized to application images.
3. **The false positives are correlated.** They come from the same system files replicated across hundreds of images and tags, which reduces the effective diversity of the sample even though it spans 677 distinct images. The binomial interval assumes independence and is therefore optimistic. Because the true-positive rate is 0 in every category, the qualitative conclusion of approximately 0% real secrets is robust to this.
4. **Deduplication.** The work is over 26,892 deduplicated findings rather than the 27,285 raw records, a difference of about 1.4% that does not affect the conclusion.
5. **Two scanners only.** TruffleHog and Gitleaks; other tools could have different false-positive profiles.

## 7. Artifacts

- `extract_and_sample.py`: extraction and seeded sampling; it does not classify.
- `sample.jsonl`: the 1,100 sampled findings, with the stable identifier and metadata.
- `verdicts.jsonl`: the 1,100 verdicts, each an identifier, a class and a reason.
- `population_stats.json`: the population and sample counts.

To reproduce the sample, run `python3 extract_and_sample.py`, which fixes `seed=42`. To reproduce the statistics, aggregate `verdicts.jsonl` by verdict and apply the Wilson interval.
