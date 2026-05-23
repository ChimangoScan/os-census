#!/usr/bin/env python3
"""Enrich sample.jsonl records with installed versions from the Syft SBOM,
matching by package name and source name. Read-only on out_so; only adds an
'sbom' field with candidate installed versions. Does NOT classify."""
import os, json, gzip, glob

BASE = "scan-out/out_so"
OUT = "data/rq3_validation"

def load_sbom(dd):
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
