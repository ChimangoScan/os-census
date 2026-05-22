#!/usr/bin/env python3
"""Crawl da categoria 'Operating systems' do Docker Hub -> data/hub_repos.jsonl
+ data/hub_tags.jsonl, no formato consumido por build_queue.py. Reproduz o
corpus do estudo a partir da API publica do Docker Hub. stdlib only (urllib).

A lista REPOS abaixo e a categoria 'Operating systems' do Docker Hub no momento
do estudo (inclui clefos, sem imagem amd64, e rockylinux nos dois namespaces).
Re-rodar regenera hub_repos.jsonl/hub_tags.jsonl com os tags/digests atuais; o
numero de imagens unicas pode variar levemente conforme novas tags sao
publicadas. Uso:  python3 scripts/crawl_hub.py
"""
import json, time, urllib.request, urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
API = "https://hub.docker.com/v2/repositories"
REPOS = [
    "kalilinux/kali-rolling", "library/almalinux", "library/alpine", "library/alt",
    "library/amazonlinux", "library/archlinux", "library/busybox", "library/centos",
    "library/cirros", "library/clearlinux", "library/clefos", "library/debian",
    "library/fedora", "library/mageia", "library/oraclelinux", "library/photon",
    "library/rockylinux", "library/sl", "library/ubuntu", "opensuse/leap",
    "opensuse/tumbleweed", "rockylinux/rockylinux",
]


def get(url, tries=4):
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "os-census-crawler"})
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            time.sleep(2 * (i + 1))
        except Exception:
            time.sleep(2 * (i + 1))
    return None


def main():
    (ROOT / "data").mkdir(exist_ok=True)
    nrepo = ntag = 0
    with (ROOT / "data/hub_repos.jsonl").open("w") as frepos, \
         (ROOT / "data/hub_tags.jsonl").open("w") as ftags:
        for full in REPOS:
            ns, name = full.split("/", 1)
            info = get(f"{API}/{ns}/{name}/")
            if info:
                frepos.write(json.dumps(info) + "\n"); nrepo += 1
            url = f"{API}/{ns}/{name}/tags/?page_size=100&page=1"
            n = 0
            while url:
                page = get(url)
                if not page:
                    break
                for t in page.get("results", []):
                    t["_ns"], t["_name"] = ns, name
                    ftags.write(json.dumps(t) + "\n"); ntag += 1; n += 1
                url = page.get("next")
                time.sleep(0.3)
            print(f"  {full}: {n} tags")
    print(f"crawl: {nrepo} repos, {ntag} tags -> data/hub_repos.jsonl + data/hub_tags.jsonl")


if __name__ == "__main__":
    main()
