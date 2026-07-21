#!/usr/bin/env python3
"""Verifica cada numero publicado no paper (expected/paper_values.json) contra os
artefatos versionados em data/. Regras: artefato ausente -> SKIP (roda em dados
parciais); artefato presente sem o valor -> FAIL; sai com 0 somente sem FAIL.
Reescreve a secao automatica de docs/REPRODUCIBILITY_REPORT.md. stdlib only.
Rodar:  python3 scripts/verify_values.py
"""
import csv, gzip, json, math, re, sys, collections, statistics as st
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ANA = ROOT / "data/analysis"
CVE = re.compile(r"CVE-\d{4}-\d+")

def short(r): return (r or "?").split("/")[-1]

def spearman(xs, ys):
    def ranks(v):
        order = sorted(range(len(v)), key=lambda i: v[i])
        r = [0.0] * len(v); i = 0
        while i < len(order):
            j = i
            while j + 1 < len(order) and v[order[j + 1]] == v[order[i]]: j += 1
            for k in range(i, j + 1): r[order[k]] = (i + j) / 2
            i = j + 1
        return r
    ra, rb = ranks(xs), ranks(ys)
    ma, mb = st.mean(ra), st.mean(rb)
    num = sum((a - ma) * (b - mb) for a, b in zip(ra, rb))
    den = math.sqrt(sum((a - ma) ** 2 for a in ra) * sum((b - mb) ** 2 for b in rb))
    return num / den if den else 0.0

def ols_std(y, xs):
    """Regressao multipla padronizada (equacoes normais); retorna betas."""
    n = len(y)
    def z(v):
        m, s = st.mean(v), st.pstdev(v)
        return [(x - m) / s if s else 0.0 for x in v]
    Y = z(y); X = [z(v) for v in xs]; k = len(X)
    A = [[sum(X[i][t] * X[j][t] for t in range(n)) for j in range(k)] for i in range(k)]
    b = [sum(X[i][t] * Y[t] for t in range(n)) for i in range(k)]
    for c in range(k):                       # eliminacao gaussiana
        p = max(range(c, k), key=lambda r: abs(A[r][c]))
        A[c], A[p] = A[p], A[c]; b[c], b[p] = b[p], b[c]
        for r in range(c + 1, k):
            f = A[r][c] / A[c][c]
            for j in range(c, k): A[r][j] -= f * A[c][j]
            b[r] -= f * b[c]
    beta = [0.0] * k
    for r in range(k - 1, -1, -1):
        beta[r] = (b[r] - sum(A[r][j] * beta[j] for j in range(r + 1, k))) / A[r][r]
    return beta

def wilson_upper(x, n, z=1.96):
    c = x + z * z / 2
    d = n + z * z
    return (c / d + (z / d) * math.sqrt(x * (n - x) / n + z * z / 4)) * 100

# ---------------------------------------------------------------- artefatos
def load_all():
    v = {}
    f = ANA / "per_image.csv"
    if f.exists():
        rows = list(csv.DictReader(open(f)))
        for r in rows:
            for k in ("age_days", "pull_count", "size_mb", "packages", "vuln_critical",
                      "vuln_high", "vuln_total", "secrets", "misconfig", "malware"):
                try: r[k] = float(r[k])
                except (ValueError, KeyError): r[k] = None
        byd = collections.defaultdict(list)
        for r in rows: byd[short(r["repo"])].append(r)
        def mch(d): return st.mean([r["vuln_critical"] + r["vuln_high"] for r in byd[d]])
        v["rq1_debian_mean_ch"] = mch("debian"); v["rq1_debian_n"] = len(byd["debian"])
        v["rq1_debian_sd"] = st.pstdev([r["vuln_critical"] + r["vuln_high"] for r in byd["debian"]])
        v["rq1_centos_mean_ch"] = mch("centos"); v["rq1_centos_n"] = len(byd["centos"])
        v["rq1_oraclelinux_mean_ch"] = st.mean([r["vuln_critical"] + r["vuln_high"] for r in byd["oraclelinux"] if r["repo"] == "library/oraclelinux"])
        v["rq1_amazonlinux_mean_ch"] = st.mean([r["vuln_critical"] + r["vuln_high"] for r in byd["amazonlinux"] if r["repo"] == "library/amazonlinux"])
        v["rq1_rockylinux_mean_ch"] = st.mean([r["vuln_critical"] + r["vuln_high"] for r in byd["rockylinux"] if r["repo"] == "library/rockylinux"])
        v["rq1_alpine_mean_ch"] = mch("alpine")
        v["rq1_mageia_mean_packages"] = st.mean([r["packages"] for r in byd["mageia"]])
        v["rq1_mageia_mean_total"] = st.mean([r["vuln_total"] for r in byd["mageia"]])
        v["rq1_debian_fewer_pkgs_than_mageia"] = st.mean([r["packages"] for r in byd["debian"]]) < v["rq1_mageia_mean_packages"]
        bk = [(0, 180, "rq2_mean_0_6m"), (365, 730, "rq2_mean_1_2y"),
              (730, 1460, "rq2_mean_2_4y"), (1460, 1e9, "rq2_mean_4y_plus")]
        for lo, hi, key in bk:
            v[key] = st.mean([r["vuln_total"] for r in rows if r["age_days"] is not None and lo <= r["age_days"] < hi])
        pares = [(r["age_days"], r["vuln_total"]) for r in rows if r["age_days"] is not None]
        rho = spearman([a for a, _ in pares], [b for _, b in pares])
        v["rq2_spearman_age_total"] = rho
        t = abs(rho) * math.sqrt((len(pares) - 2) / (1 - rho * rho))
        v["rq2_p_below_001"] = t > 3.29
        trip = [r for r in rows if r["packages"] and r["age_days"] is not None and r["vuln_total"] is not None]
        y = [r["vuln_total"] for r in trip]
        b2 = ols_std(y, [[r["age_days"] for r in trip], [r["packages"] for r in trip]])
        v["rq5_beta_age"], v["rq5_beta_packages"] = b2
        b3 = ols_std(y, [[r["age_days"] for r in trip], [r["packages"] for r in trip], [r["size_mb"] for r in trip]])
        v["rq5_beta_size"] = b3[2]
        quad = [r for r in trip if r["pull_count"]]
        b4 = ols_std([r["vuln_total"] for r in quad],
                     [[r["age_days"] for r in quad], [r["packages"] for r in quad],
                      [r["size_mb"] for r in quad], [r["pull_count"] for r in quad]])
        v["rq5_beta_pulls"] = b4[3]
        for distro, key in (("ubuntu", "rq5_beta_pkgs_ubuntu"), ("almalinux", "rq5_beta_pkgs_almalinux")):
            g = [r for r in byd[distro] if r["packages"] and r["age_days"] is not None]
            v[key] = ols_std([r["vuln_total"] for r in g],
                             [[r["age_days"] for r in g], [r["packages"] for r in g]])[1]
        v["other_secrets_raw_pct"] = 100 * sum(1 for r in rows if r["secrets"]) / len(rows)
        v["other_yara_raw_pct"] = 100 * sum(1 for r in rows if r["malware"]) / len(rows)
        v["repro_shu_high_pct"] = 100 * sum(1 for r in rows if r["vuln_critical"] + r["vuln_high"] > 0) / len(rows)
        v["repro_drdocker_known_vuln_pct"] = 100 * sum(1 for r in rows if r["vuln_total"] > 0) / len(rows)

    f = ANA / "rq3_sca_sets.json.gz"
    if f.exists():
        raw = json.load(gzip.open(f, "rt"))
        sets = {}
        for s, pairs in raw.items():
            sets[s] = {(img, CVE.search(str(c)).group(0)) for img, c in pairs if CVE.search(str(c))}
        def jac(a, b): return len(sets[a] & sets[b]) / len(sets[a] | sets[b])
        v["rq3_jaccard_trivy_grype"] = jac("trivy", "grype")
        v["rq3_jaccard_trivy_clair"] = jac("trivy", "clair")
        v["rq3_osv_clair_intersection"] = len(sets["osv"] & sets["clair"])
        for s in ("grype", "trivy", "osv", "clair"):
            v[f"rq3_{s}_pairs_k"] = round(len(sets[s]) / 1000)
        v["counting_pairs_summed"] = sum(len(x) for x in sets.values())
        uni = collections.defaultdict(set); soma = collections.Counter()
        for s, prs in sets.items():
            for img, c in prs:
                uni[img].add(c); soma[img] += 1
        v["counting_pairs_unique"] = sum(len(x) for x in uni.values())
        v["counting_inflation"] = v["counting_pairs_summed"] / v["counting_pairs_unique"]
        imgs = list(uni)
        v["counting_dedup_spearman"] = spearman([soma[i] for i in imgs], [len(uni[i]) for i in imgs])

    f = ANA / "job_status.csv.gz"
    if f.exists():
        jobs = list(csv.DictReader(gzip.open(f, "rt")))
        v["corpus_images"] = len(jobs)
        v["corpus_repos"] = len({j["repo"] for j in jobs})
        v["corpus_distros"] = len({short(j["repo"]) for j in jobs})
        tot = collections.Counter(); skp = collections.Counter()
        for j in jobs:
            rp = short(j["repo"]); tot[rp] += 1
            if j["status"] == "skipped": skp[rp] += 1
        nsk = sum(skp.values())
        v["rq4_unpullable_pct"] = 100 * nsk / len(jobs)
        v["rq4_one_in_n"] = len(jobs) / nsk
        for rp in ("centos", "busybox", "ubuntu", "debian", "archlinux", "rockylinux"):
            v[f"rq4_{rp}_rate"] = 100 * skp[rp] / tot[rp]
        v["rq4_centos_pulls_over_1b"] = any(
            j["repo"] == "library/centos" and float(j["pull_count"] or 0) > 1e9 for j in jobs)

    f = ROOT / "config/scanners.yaml"
    if (ROOT / "scripts/render_config.py").exists():
        m = re.search(r"only: \[(.*?)\]", (ROOT / "scripts/render_config.py").read_text(), re.S)
        if m: v["scanners"] = len([x for x in re.split(r"[,\s]+", m.group(1)) if x])

    for eixo, key in (("secret", "secrets"), ("malware", "malware")):
        d = ROOT / f"data/{eixo}_validation"
        if d.exists():
            verd = [json.loads(l) for l in open(d / "verdicts.jsonl")]
            v[f"{key}_sample_n"] = len(verd)
            v[f"{key}_true_positives"] = sum(1 for x in verd if x.get("verdict") not in ("FP", "fp", "false_positive"))
            pop = d / "population_stats.json"
            if pop.exists():
                p = json.load(open(pop))
                v[f"{key}_population"] = p.get("total_findings")
                v.setdefault("validation_seed", p.get("seed"))
    if "secrets_sample_n" in v:
        v["malware_population"] = v.get("malware_population") or sum(1 for _ in open(ROOT / "data/malware_validation/all_findings.jsonl"))
        v["wilson_upper_pct"] = wilson_upper(max(v.get("secrets_true_positives", 0), v.get("malware_true_positives", 0)),
                                             v["secrets_sample_n"])
        v["malware_draw_reproduces"] = _replay_malware_draw()
        pop = json.load(open(ROOT / "data/secret_validation/population_stats.json"))
        samp = [json.loads(l) for l in open(ROOT / "data/secret_validation/sample.jsonl")]
        cnt = collections.Counter(s["id"][:2] for s in samp)
        th = round(1100 * pop["trufflehog_findings"] / pop["total_findings"])
        v["secrets_draw_strata"] = (cnt["tr"] == th == pop["sample_trufflehog"]
                                    and cnt["gi"] == 1100 - th == pop["sample_gitleaks"]
                                    and len({s["id"] for s in samp}) == 1100)
    return v

def _replay_malware_draw():
    """Re-executa o sorteio do apendice (seed=42, estratificado por regra) sobre
    o all_findings.jsonl committado e compara com o sample.jsonl committado."""
    import random
    d = ROOT / "data/malware_validation"
    seen = {}
    for l in open(d / "all_findings.jsonl"):
        fd = json.loads(l); seen.setdefault(fd["id"], fd)
    uniq = list(seen.values())
    rng = random.Random(42)
    by_rule = collections.defaultdict(list)
    for fd in uniq: by_rule[fd["rule"]].append(fd)
    for r in by_rule:
        by_rule[r].sort(key=lambda x: x["id"]); rng.shuffle(by_rule[r])
    N, total, rules = 1100, len(uniq), sorted(by_rule)
    alloc = {r: max(1, round(N * len(by_rule[r]) / total)) for r in rules}
    while sum(alloc.values()) > N:
        r = max((x for x in rules if alloc[x] > 1), key=lambda x: alloc[x]); alloc[r] -= 1
    while sum(alloc.values()) < N:
        r = max(rules, key=lambda x: len(by_rule[x]) - alloc[x])
        if alloc[r] < len(by_rule[r]): alloc[r] += 1
        else: break
    sample = []
    for r in rules: sample.extend(by_rule[r][:min(alloc[r], len(by_rule[r]))])
    if len(sample) < N:
        chosen = {s["id"] for s in sample}
        rest = [fd for fd in uniq if fd["id"] not in chosen]
        rng.shuffle(rest); sample.extend(rest[:N - len(sample)])
    sample = sample[:N]; rng.shuffle(sample)
    committed = [json.loads(l)["id"] for l in open(d / "sample.jsonl")]
    return [s["id"] for s in sample] == committed

# ---------------------------------------------------------------- comparacao
def check(exp, got):
    if got is None: return "SKIP"
    e = exp["expect"]
    if "round" in e: got = round(got, e["round"]) if e["round"] else round(got)
    if "equals" in e: ok = got == e["equals"]
    elif "range" in e: ok = e["range"][0] <= got <= e["range"][1]
    elif "gt" in e: ok = got > e["gt"]
    elif "lt" in e: ok = got < e["lt"]
    else: return "SKIP"
    return "PASS" if ok else "FAIL"

def main():
    spec = json.load(open(ROOT / "expected/paper_values.json"))["checks"]
    got = load_all()
    lines, tally = [], collections.Counter()
    for c in spec:
        g = got.get(c["id"])
        r = check(c, g)
        tally[r] += 1
        shown = round(g, 4) if isinstance(g, float) else g
        alvo = c["expect"].get("equals", c["expect"])
        lines.append(f"| {c['id']} | {c['source']} | {alvo} | {shown} | {r} |")
    md = ["| check | fonte no paper | esperado | obtido | resultado |",
          "|---|---|---|---|---|"] + lines + [
          "", f"**{tally['PASS']} PASS / {tally['FAIL']} FAIL / {tally['SKIP']} SKIP**"]
    rep = ROOT / "docs/REPRODUCIBILITY_REPORT.md"
    if rep.exists():
        txt = rep.read_text()
        a, b = "<!-- verify:auto:begin -->", "<!-- verify:auto:end -->"
        if a in txt and b in txt:
            pre, resto = txt.split(a, 1); _, pos = resto.split(b, 1)
            rep.write_text(pre + a + "\n" + "\n".join(md) + "\n" + b + pos)
    print("\n".join(md))
    sys.exit(1 if tally["FAIL"] else 0)

if __name__ == "__main__":
    main()
