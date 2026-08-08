#!/usr/bin/env python3
"""Enrich sample.jsonl records with installed versions from the Syft SBOM,
matching by package name and source name. Read-only on out_so; only adds an
'sbom' field with candidate installed versions. Does NOT classify."""
import os, json, gzip, glob

BASE = "scan-out/out_so"
OUT = "data/rq3_validation"

def load_sbom(dd):
    """Return (name, version, type, source, purl) for every artifact in image dir `dd`'s Syft SBOM.

    Reads the first *.syft.json.gz found under BASE/dd/syft/; `[]` if none
    exists. `source` is the package's declared source/source-RPM name when
    present, used by main() to match a CVE's reported package to what Syft
    actually found installed (cross-checking scanner package-naming choices
    for the RQ3 divergence validation sample).
    """
    files = glob.glob(os.path.join(BASE, dd, "syft", "*.syft.json.gz"))
    if not files:
        return []
    with gzip.open(files[0], "rt", errors="replace") as f:
        j = json.load(f)
    arts = []
    for a in j.get("artifacts", []) or []:
        src = None
        md = a.get("metadata") or {}
        if isinstance(md, dict):
            src = md.get("source") or md.get("sourceRpm")
        arts.append((a.get("name"), a.get("version"), a.get("type"), src, a.get("purl")))
    return arts

def main():
    """Add an "sbom" field (candidate installed-package matches) to every record in data/rq3_validation/sample.jsonl, in place.

    For each record's reported package name, looks up its image's Syft SBOM
    (cached per image dir) and records exact name matches plus up to 8
    substring-related matches (methodological choice: catches
    binary-vs-source-package name mismatches, e.g. a CVE reported against a
    source RPM name that Syft lists under a different binary package name).
    Read-only on scan-out/; overwrites sample.jsonl with the enriched
    records. Gives the human reviewer of the RQ3 divergence sample the actual
    installed version to check the CVE's affected range against.
    """
    recs = [json.loads(l) for l in open(os.path.join(OUT, "sample.jsonl"))]
    cache = {}
    for r in recs:
        dd = r["dir"]
        if dd not in cache:
            cache[dd] = load_sbom(dd)
        arts = cache[dd]
        pkg = r.get("pacote")
        # match by exact name, then by name contained in source rpm/src
        matches = []
        for name, ver, typ, src, purl in arts:
            if name == pkg:
                matches.append({"name": name, "ver": ver, "type": typ})
        # also collect by substring (for binary-vs-source mismatches)
        related = []
        if pkg:
            base = pkg.split(":")[0]
            for name, ver, typ, src, purl in arts:
                if name != pkg and (base in (name or "") or (name or "") in base or (src and pkg in str(src))):
                    related.append({"name": name, "ver": ver, "type": typ})
        r["sbom"] = {"exact": matches, "related": related[:8], "n_artifacts": len(arts)}
    with open(os.path.join(OUT, "sample.jsonl"), "w") as f:
        for r in recs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print("enriched", len(recs), "records")

if __name__ == "__main__":
    main()
