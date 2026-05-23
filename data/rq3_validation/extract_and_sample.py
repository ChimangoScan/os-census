#!/usr/bin/env python3
"""
RQ3 ground-truth sampling for CVE scanner divergence.
Does ONLY: build digest->dir map, compute scanner agreement per (image,CVE),
stratified seeded sample, extract pkg+installed version from the reporting
scanner output. Does NOT classify TP/FP (that is done by the human reviewer).

Reproducible: seed=42 fixed.
"""
import os, re, json, gzip, glob, random, hashlib, sys

BASE = "/mnt/win_ssd/scanners-data/out_so"
SETS = "/mnt/win_ssd/so-dockerhub-paper/data/analysis/rq3_sca_sets.json.gz"
OUT = "/mnt/win_ssd/so-dockerhub-paper/data/rq3_validation"
SEED = 42
N_SINGLE = 120   # pairs reported by exactly ONE scanner (divergent)
N_MULTI = 80     # pairs reported by 2+ scanners (agreement)

SCANNERS = ["trivy", "grype", "osv", "clair"]

def distro_family(dirname):
    name = re.sub(r"_[0-9a-f]{8}$", "", dirname)
    fam = re.split(r"[_-]", name)[0]
    rhel = {"almalinux","rockylinux","oraclelinux","fedora","centos","sl","mageia","leap","tumbleweed","clearlinux","alt"}
    if fam in rhel:
        return "rhel-family"
    return fam

def build_dir_map():
    m = {}
    for dd in os.listdir(BASE):
        mo = re.search(r"_([0-9a-f]{8})$", dd)
        if mo:
            m[mo.group(1)] = dd
    return m

def gzread_json(path):
    with gzip.open(path, "rt", errors="replace") as f:
        return json.load(f)

# ---- per-scanner extraction of (cve -> {pkg, version, fixed, src, namespace}) for one image dir ----
def extract_trivy(d):
    out = {}
    files = glob.glob(os.path.join(d, "trivy", "*.trivy.json.gz"))
    if not files: return out
    try: j = gzread_json(files[0])
    except Exception: return out
    for r in j.get("Results", []) or []:
        for v in (r.get("Vulnerabilities") or []):
            cve = v.get("VulnerabilityID")
            if not cve: continue
            out.setdefault(cve, []).append({
                "pkg": v.get("PkgName"),
                "version": v.get("InstalledVersion"),
                "fixed": v.get("FixedVersion"),
                "status": v.get("Status"),
                "src": v.get("DataSource", {}).get("Name") if isinstance(v.get("DataSource"), dict) else None,
                "type": r.get("Type"),
                "pkgid": v.get("PkgID"),
            })
    return out

def extract_grype(d):
    out = {}
    files = glob.glob(os.path.join(d, "grype", "*.grype.json.gz"))
    if not files: return out
    try: j = gzread_json(files[0])
    except Exception: return out
    for m in j.get("matches", []) or []:
        vul = m.get("vulnerability", {})
        cve = vul.get("id")
        art = m.get("artifact", {})
        ids = [cve]
        # also map related CVE ids
        for rel in (m.get("relatedVulnerabilities") or []):
            if rel.get("id","").startswith("CVE-"):
                ids.append(rel.get("id"))
        fix = vul.get("fix", {}) or {}
        rec = {
            "pkg": art.get("name"),
            "version": art.get("version"),
            "fixed": ",".join(fix.get("versions", []) or []),
            "status": fix.get("state"),
            "src": vul.get("namespace"),
            "type": art.get("type"),
            "purl": art.get("purl"),
            "grype_id": cve,
        }
        for cid in ids:
            if cid and cid.startswith("CVE-"):
                out.setdefault(cid, []).append(rec)
    return out

def extract_osv(d):
    out = {}
    files = glob.glob(os.path.join(d, "osv", "*.osv.json.gz"))
    if not files: return out
    try: j = gzread_json(files[0])
    except Exception: return out
    for r in j.get("results", []) or []:
        path = r.get("source", {}).get("path")
        for p in r.get("packages", []) or []:
            pkg = p.get("package", {})
            for vv in (p.get("vulnerabilities") or []):
                ids = [vv.get("id")] + (vv.get("aliases") or [])
                for cid in ids:
                    if cid and cid.startswith("CVE-"):
                        out.setdefault(cid, []).append({
                            "pkg": pkg.get("name"),
                            "version": pkg.get("version"),
                            "fixed": None,
                            "status": None,
                            "src": "OSV/" + str(pkg.get("ecosystem")),
                            "type": pkg.get("ecosystem"),
                            "path": path,
                            "osv_id": vv.get("id"),
                        })
    return out

def extract_clair(d):
    out = {}
    files = glob.glob(os.path.join(d, "clair", "*.clair.json.gz"))
    if not files: return out
    try: j = gzread_json(files[0])
    except Exception: return out
    pkgs = j.get("packages", {}) or {}
    vulns = j.get("vulnerabilities", {}) or {}
    pv = j.get("package_vulnerabilities", {}) or {}
    # name -> installed version (from package inventory)
    name2ver = {}
    for pid, p in pkgs.items():
        name2ver.setdefault(p.get("name"), p.get("version"))
    # vid -> list of pkgids that carry it
    vid2pids = {}
    for pid, vids in pv.items():
        for vid in vids:
            vid2pids.setdefault(vid, []).append(pid)
    for vid, v in vulns.items():
        name = v.get("name", "")
        cves = set(re.findall(r"CVE-\d{4}-\d+", name + " " + str(v.get("links", ""))))
        if not cves:
            continue
        fixed = v.get("fixed_in_version") or None
        emb = v.get("package", {}) or {}
        # resolve installed version: prefer pkg inventory entry referenced by pv, else by name
        ver = None
        pkgname = emb.get("name")
        for pid in vid2pids.get(vid, []):
            p = pkgs.get(pid, {})
            if p.get("name") == pkgname and p.get("version"):
                ver = p.get("version"); break
        if ver is None:
            ver = emb.get("version") or name2ver.get(pkgname)
        for cve in cves:
            out.setdefault(cve, []).append({
                "pkg": pkgname,
                "version": ver,
                "fixed": fixed,
                "status": "fixed" if fixed else None,
                "src": v.get("updater"),
                "type": emb.get("kind"),
                "srcname": (emb.get("source", {}) or {}).get("name") if isinstance(emb.get("source"), dict) else None,
            })
    return out

EXTRACT = {"trivy": extract_trivy, "grype": extract_grype, "osv": extract_osv, "clair": extract_clair}

def main():
    dmap = build_dir_map()
    sets = gzread_json(SETS)

    # membership: (image, cve) -> set of scanners
    membership = {}
    for s in SCANNERS:
        for img, cve in sets[s]:
            membership.setdefault((img, cve), set()).add(s)

    # Build candidate lists with distro, restricted to images that have a dir
    # singletons: exactly one scanner; multi: >=2 scanners
    singles = []  # (img, cve, scanner)
    multis = []   # (img, cve, sorted scanners tuple)
    for (img, cve), scs in membership.items():
        h = img.split("@")[1].replace("sha256:", "")[:8]
        dd = dmap.get(h)
        if not dd:
            continue
        fam = distro_family(dd)
        if len(scs) == 1:
            singles.append((img, cve, next(iter(scs)), fam, dd))
        else:
            multis.append((img, cve, tuple(sorted(scs)), fam, dd))

    rnd = random.Random(SEED)

    # ---- stratified sampling of singletons: cover all 4 scanners, spread distros ----
    # group singletons by scanner
    by_sc = {s: [] for s in SCANNERS}
    for rec in singles:
        by_sc[rec[2]].append(rec)
    for s in SCANNERS:
        by_sc[s].sort(key=lambda r: r[0] + r[1])  # deterministic order
        rnd.shuffle(by_sc[s])

    # allocate N_SINGLE roughly proportional but guarantee min coverage per scanner that has singletons
    counts = {s: len(by_sc[s]) for s in SCANNERS}
    total_single = sum(counts.values())
    alloc = {}
    for s in SCANNERS:
        alloc[s] = round(N_SINGLE * counts[s] / total_single) if total_single else 0
    # ensure scanners with singletons get at least some (min 10 if available)
    for s in SCANNERS:
        if counts[s] > 0:
            alloc[s] = max(alloc[s], min(15, counts[s]))
    # trim/extend to N_SINGLE
    sampled_single = []
    for s in SCANNERS:
        take = min(alloc[s], counts[s])
        sampled_single.extend(by_sc[s][:take])
    # adjust to exactly N_SINGLE by trimming largest scanner pools
    rnd.shuffle(sampled_single)
    sampled_single = sampled_single[:N_SINGLE]

    # ---- stratified sampling of multis: spread across agreement combos & distros ----
    multis.sort(key=lambda r: r[0] + r[1])
    rnd.shuffle(multis)
    # bucket by combo to ensure diversity (esp. include trivy+grype which is the bulk,
    # but force-include any combos involving osv/clair if present)
    by_combo = {}
    for rec in multis:
        by_combo.setdefault(rec[2], []).append(rec)
    sampled_multi = []
    # first guarantee representation of combos that include osv or clair
    rare = [c for c in by_combo if ("osv" in c or "clair" in c)]
    for c in sorted(rare):
        for rec in by_combo[c][:6]:
            sampled_multi.append(rec)
    # fill the rest from all multis (mostly trivy+grype) until N_MULTI
    pool = [r for r in multis if r not in sampled_multi]
    for rec in pool:
        if len(sampled_multi) >= N_MULTI:
            break
        sampled_multi.append(rec)
    sampled_multi = sampled_multi[:N_MULTI]

    # ---- build sample records with extracted pkg+version per reporting scanner ----
    # cache per-dir extraction
    cache = {}
    def get_extract(dd, scanner):
        key = (dd, scanner)
        if key not in cache:
            cache[key] = EXTRACT[scanner](os.path.join(BASE, dd))
        return cache[key]

    def make_id(img, cve, scanner):
        return "rq3_" + hashlib.sha1(f"{scanner}|{img}|{cve}".encode()).hexdigest()[:14]

    def norm_cve(cve):
        m = re.match(r"(CVE-\d{4}-\d+)", cve)
        return m.group(1) if m else cve

    records = []
    # singletons: scanner is the single reporter
    for img, cve, scanner, fam, dd in sampled_single:
        ncve = norm_cve(cve)
        ext = get_extract(dd, scanner).get(ncve, []) or get_extract(dd, scanner).get(cve, [])
        recs = ext if ext else [{}]
        pkgs = list({(r.get("pkg"), r.get("version")) for r in recs})
        records.append({
            "id": make_id(img, cve, scanner),
            "stratum": "single",
            "imagem": img,
            "dir": dd,
            "distro": fam,
            "scanner": scanner,
            "reported_by": [scanner],
            "cve": cve,
            "cve_norm": ncve,
            "pacote": recs[0].get("pkg"),
            "versao_instalada": recs[0].get("version"),
            "fixed_version": recs[0].get("fixed"),
            "status": recs[0].get("status"),
            "feed_src": recs[0].get("src"),
            "pkg_type": recs[0].get("type"),
            "all_pkg_matches": [{"pkg": p, "ver": v} for (p, v) in pkgs],
            "extra": {k: recs[0].get(k) for k in ("purl","path","pkgid","srcname","osv_id","grype_id") if recs[0].get(k)},
        })
    # multis: pick a representative reporting scanner (prefer one with extractable pkg)
    for img, cve, combo, fam, dd in sampled_multi:
        chosen = None
        chosen_recs = None
        ncve = norm_cve(cve)
        for scanner in combo:
            ext = get_extract(dd, scanner).get(ncve, []) or get_extract(dd, scanner).get(cve, [])
            if ext:
                chosen, chosen_recs = scanner, ext
                break
        if chosen is None:
            chosen = combo[0]
            chosen_recs = [{}]
        pkgs = list({(r.get("pkg"), r.get("version")) for r in chosen_recs})
        records.append({
            "id": make_id(img, cve, "+".join(combo)),
            "stratum": "multi",
            "imagem": img,
            "dir": dd,
            "distro": fam,
            "scanner": chosen,
            "reported_by": list(combo),
            "cve": cve,
            "cve_norm": ncve,
            "pacote": chosen_recs[0].get("pkg"),
            "versao_instalada": chosen_recs[0].get("version"),
            "fixed_version": chosen_recs[0].get("fixed"),
            "status": chosen_recs[0].get("status"),
            "feed_src": chosen_recs[0].get("src"),
            "pkg_type": chosen_recs[0].get("type"),
            "all_pkg_matches": [{"pkg": p, "ver": v} for (p, v) in pkgs],
            "extra": {k: chosen_recs[0].get(k) for k in ("purl","path","pkgid","srcname","osv_id","grype_id") if chosen_recs[0].get(k)},
        })

    with open(os.path.join(OUT, "sample.jsonl"), "w") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # population stats
    pop = {
        "n_singletons_total": len(singles),
        "n_multis_total": len(multis),
        "singleton_by_scanner": {s: len(by_sc[s]) for s in SCANNERS},
        "multi_combos": {"+".join(c): len(v) for c, v in sorted(by_combo.items())},
        "sample_single": len(sampled_single),
        "sample_multi": len(sampled_multi),
        "sample_total": len(records),
        "seed": SEED,
    }
    with open(os.path.join(OUT, "population_stats.json"), "w") as f:
        json.dump(pop, f, indent=1)
    print(json.dumps(pop, indent=1))

if __name__ == "__main__":
    main()
