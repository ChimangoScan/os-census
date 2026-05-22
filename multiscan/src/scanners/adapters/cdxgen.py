from __future__ import annotations
from pathlib import Path

from ..models import Category, Severity, Target
from .base import cves_in, f, read_json


def _purl_eco(purl: str) -> str:
    if not purl.startswith("pkg:"):
        return ""
    return purl[4:].split("/", 1)[0]


def parse(out: Path, t: Target) -> list[Finding]:
    doc = read_json(out / f"{t.name}.cdxgen.json")
    if not isinstance(doc, dict):
        return []
    res = []
    for c in doc.get("components") or []:
        purl = c.get("purl") or ""
        lics = ", ".join(
            (lic.get("expression") or (lic.get("license") or {}).get("id") or "")
            for lic in (c.get("licenses") or [])
            if isinstance(lic, dict)
        )
        res.append(f("cdxgen", t, category=Category.SBOM_COMPONENT, severity=Severity.INFO,
                     id=purl or f"{c.get('name', '')}@{c.get('version', '')}",
                     title=c.get("name", ""), version=c.get("version", ""),
                     package=c.get("name", ""), ecosystem=_purl_eco(purl),
                     description=lics,
                     location=(((c.get("evidence") or {}).get("occurrences") or [{}])[0] or {}).get("location", ""),
                     raw=c))
    for v in doc.get("vulnerabilities") or []:
        vid = v.get("id", "")
        ratings = v.get("ratings") or []
        score = next((r.get("score") for r in ratings if isinstance(r.get("score"), (int, float))), None)
        sev = next((r.get("severity") for r in ratings if r.get("severity")), None)
        affects = v.get("affects") or [{}]
        pkg_ref = (affects[0] or {}).get("ref", "")
        res.append(f("cdxgen", t, category=Category.PKG_VULN,
                     severity=Severity.parse(sev) if sev else Severity.from_cvss(score),
                     id=vid, title=vid, description=(v.get("description") or "")[:1000],
                     cvss=float(score) if score is not None else None,
                     package=pkg_ref, cves=cves_in(vid),
                     references=[a.get("url") for a in (v.get("advisories") or []) if a.get("url")][:10],
                     raw=v))
    return res
