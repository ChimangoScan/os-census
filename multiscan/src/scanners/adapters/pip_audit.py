from __future__ import annotations
from pathlib import Path

from ..models import Category, Finding, Severity, Target
from .base import cves_in, f, read_json


def parse(out: Path, t: Target) -> list[Finding]:
    data = read_json(out / "pip-audit.json")
    if not isinstance(data, list):
        return []
    res = []
    for pkg in data:
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        source = pkg.get("_source", "")
        for vuln in pkg.get("vulns") or []:
            vid = vuln.get("id", "")
            aliases = vuln.get("aliases") or []
            all_ids = [vid] + list(aliases)
            cves = [i for i in all_ids if i.upper().startswith("CVE-")] or cves_in(vid)
            fix = ", ".join(vuln.get("fix_versions") or [])
            res.append(f("pip-audit", t,
                         category=Category.PKG_VULN,
                         severity=Severity.UNKNOWN,
                         id=vid,
                         title=f"{name} {version} — {vid}",
                         description=(vuln.get("description") or "")[:1000],
                         package=name,
                         version=version,
                         fixed_version=fix,
                         ecosystem="pypi",
                         location=source,
                         cves=cves,
                         raw=vuln))
    return res
