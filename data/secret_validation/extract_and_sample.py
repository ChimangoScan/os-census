#!/usr/bin/env python3
"""
Extract ALL secret findings from TruffleHog + Gitleaks outputs under
scan-out/out_so, assign a stable ID to each, and draw a
reproducible random sample of 1100 (seed=42), stratified proportionally by
scanner.

This script ONLY does (a) extraction, (b) seeded sampling, (c) writing the
sample. It performs NO TP/FP classification. The TP/FP decision is made by a
human reading sample.jsonl.
"""
import os
import sys
import gzip
import json
import glob
import hashlib
import random

ROOT = "scan-out/out_so"
OUTDIR = "data/secret_validation"
SAMPLE_N = 1100
SEED = 42


def open_maybe_gz(path):
    """Open `path` for text reading, transparently gzip-decompressing if it ends in .gz."""
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def stable_id(scanner, image, file_, rule, locator, value):
    """Deterministic id for a secret finding, prefixed by scanner ("tr_"/"gi_").

    SHA-1 of (scanner, image, file_, rule, locator, value) joined by "|",
    truncated to 16 hex chars, prefixed with the scanner's first 2 letters.
    Same inputs always yield the same id, so re-running extract() reproduces
    the ids already committed in sample.jsonl/population_stats.json.
    """
    h = hashlib.sha1()
    h.update("|".join([scanner, image, file_, rule, str(locator), value]).encode("utf-8", "replace"))
    return scanner[:2] + "_" + h.hexdigest()[:16]


def trunc(s, n=600):
    """Stringify `s` and truncate to `n` chars, appending a "[TRUNCATED k chars]" marker if cut.

    Used on secret values/context/descriptions so the committed sample.jsonl
    stays reviewable-sized even for pathological (very long) matches.
    """
    if s is None:
        return ""
    s = str(s)
    return s if len(s) <= n else s[:n] + "...[TRUNCATED %d chars]" % (len(s) - n)


def extract():
    """Scan every image dir under ROOT and return every raw TruffleHog + Gitleaks finding.

    For each image: parses *.trufflehog.jsonl* (one JSON object per line,
    pulling the Docker source file path, detector name, raw secret value,
    verified flag) and *.gitleaks.json* (a JSON array, pulling rule, secret,
    match context, file, start line, entropy). A malformed/unreadable file is
    skipped with a warning to stderr rather than aborting the whole extraction.
    This is the population from which a seeded validation sample is drawn
    (main()) for the manual TP/FP review behind the secrets true-positive
    rate reported in the paper's Appendix validation section.
    """
    findings = []
    images = sorted(os.listdir(ROOT))
    for image in images:
        idir = os.path.join(ROOT, image)
        if not os.path.isdir(idir):
            continue
        # --- TruffleHog (jsonl, one finding per line) ---
        for tf in glob.glob(os.path.join(idir, "trufflehog", "*.trufflehog.jsonl*")):
            try:
                with open_maybe_gz(tf) as fh:
                    for ln, line in enumerate(fh):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                        except Exception:
                            continue
                        sm = obj.get("SourceMetadata", {}) or {}
                        doc = (sm.get("Data", {}) or {}).get("Docker", {}) or {}
                        file_ = doc.get("file", "")
                        rule = obj.get("DetectorName", "")
                        raw = obj.get("Raw", "") or ""
                        rawv2 = obj.get("RawV2", "") or ""
                        verified = obj.get("Verified", False)
                        value = raw if raw else rawv2
                        locator = "line%d" % ln
                        fid = stable_id("trufflehog", image, file_, rule, locator, value)
                        findings.append({
                            "id": fid,
                            "scanner": "trufflehog",
                            "image": image,
                            "file": file_,
                            "rule": rule,
                            "locator": locator,
                            "verified": verified,
                            "value": trunc(value),
                            "context": trunc(rawv2 if rawv2 and rawv2 != raw else ""),
                            "detector_desc": trunc(obj.get("DetectorDescription", ""), 200),
                        })
            except Exception as e:
                sys.stderr.write("ERR trufflehog %s: %s\n" % (tf, e))
        # --- Gitleaks (json array) ---
        for gf in glob.glob(os.path.join(idir, "gitleaks", "*.gitleaks.json*")):
            try:
                with open_maybe_gz(gf) as fh:
                    data = fh.read().strip()
                if not data:
                    continue
                try:
                    arr = json.loads(data)
                except Exception:
                    continue
                if not isinstance(arr, list):
                    continue
                for obj in arr:
                    rule = obj.get("RuleID", "")
                    secret = obj.get("Secret", "") or ""
                    match = obj.get("Match", "") or ""
                    file_ = obj.get("File", "")
                    start = obj.get("StartLine", "")
                    locator = "L%s" % start
                    fid = stable_id("gitleaks", image, file_, rule, locator, secret)
                    findings.append({
                        "id": fid,
                        "scanner": "gitleaks",
                        "image": image,
                        "file": file_,
                        "rule": rule,
                        "locator": locator,
                        "verified": None,
                        "value": trunc(secret),
                        "context": trunc(match),
                        "entropy": obj.get("Entropy", None),
                        "detector_desc": trunc(obj.get("Description", ""), 200),
                    })
            except Exception as e:
                sys.stderr.write("ERR gitleaks %s: %s\n" % (gf, e))
    return findings


def main():
    """Deduplicate extract()'s findings, draw a seed=42 stratified sample of 1,100, and write it out.

    Deduplicates by id (last write wins per id — same finding extracted twice
    would otherwise double-count), sorts deterministically before sampling.
    Allocates the sample between TruffleHog and Gitleaks in proportion to each
    scanner's share of the deduplicated population (rounded; Gitleaks gets the
    remainder so the two quotas always sum to SAMPLE_N), then draws each
    scanner's quota with random.Random(SEED).sample and shuffles the combined
    sample. Writes data/secret_validation/sample.jsonl and
    population_stats.json (population/sample sizes per scanner + the seed),
    consumed by scripts/verify_values.py's secrets_draw_strata check to verify
    the committed sample matches what this exact draw produces.
    """
    findings = extract()
    # De-duplicate by id (same finding could in theory collide)
    seen = {}
    for f in findings:
        seen[f["id"]] = f
    findings = list(seen.values())
    findings.sort(key=lambda x: x["id"])  # deterministic order before sampling

    by_scanner = {"trufflehog": [], "gitleaks": []}
    for f in findings:
        by_scanner[f["scanner"]].append(f)

    total = len(findings)
    n_tf = len(by_scanner["trufflehog"])
    n_gl = len(by_scanner["gitleaks"])

    # Stratified proportional allocation
    quota_tf = round(SAMPLE_N * n_tf / total)
    quota_gl = SAMPLE_N - quota_tf

    rng = random.Random(SEED)
    samp_tf = rng.sample(by_scanner["trufflehog"], min(quota_tf, n_tf))
    samp_gl = rng.sample(by_scanner["gitleaks"], min(quota_gl, n_gl))
    sample = samp_tf + samp_gl
    rng.shuffle(sample)

    with open(os.path.join(OUTDIR, "sample.jsonl"), "w", encoding="utf-8") as out:
        for f in sample:
            out.write(json.dumps(f, ensure_ascii=False) + "\n")

    stats = {
        "total_findings": total,
        "trufflehog_findings": n_tf,
        "gitleaks_findings": n_gl,
        "sample_n": len(sample),
        "sample_trufflehog": len(samp_tf),
        "sample_gitleaks": len(samp_gl),
        "seed": SEED,
    }
    with open(os.path.join(OUTDIR, "population_stats.json"), "w") as out:
        json.dump(stats, out, indent=2)
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
