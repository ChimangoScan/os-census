"""Adapter for OWASP Dependency-Check (dependency vulnerability scanner).

Reads ``dependency-check-report.json`` and emits one ``PKG_VULN`` finding per
(dependency, vulnerability) pair — a single scanned file can carry several
vulnerable identified libraries, each of which can have several CVEs, so the
finding count is not 1:1 with dependencies."""
from __future__ import annotations
from pathlib import Path

from ..models import Category, Severity, Target
from .base import cves_in, f, read_json


def _cvss(v: dict) -> float | None:
    """Pick the vulnerability's base CVSS score, preferring the newest schema version (v4 > v3 > v2) present."""
    for key in ("cvssv4", "cvssv3", "cvssv2"):
        node = v.get(key) or {}
        score = node.get("baseScore") if isinstance(node, dict) else None
        if score is None and key == "cvssv2":
            score = node.get("score")
        try:
            if score is not None:
                return float(score)
        except (TypeError, ValueError):
            pass
    return None


def _purl_eco(purl: str) -> str:
    """Extract the package-ecosystem segment (e.g. ``npm``, ``maven``) from a purl string."""
    if not purl.startswith("pkg:"):
        return ""
    return purl[4:].split("/", 1)[0]


def parse(out: Path, t: Target) -> list[Finding]:
    """Turn ``dependency-check-report.json`` under ``out`` into per-vulnerability findings for target ``t``.

    ``id``/``cves`` treat the vulnerability name as a CVE only if it actually
    looks like one (Dependency-Check also reports non-CVE advisories, e.g.
    GHSA, under the same field). Returns ``[]`` if the report is missing or
    malformed.
    """
    doc = read_json(out / "dependency-check-report.json")
    if not isinstance(doc, dict):
        return []
    res = []
    for dep in doc.get("dependencies") or []:
        fname = dep.get("fileName") or dep.get("filePath") or ""
        purl = next((p.get("id", "") for p in (dep.get("packages") or []) if str(p.get("id", "")).startswith("pkg:")), "")
        for v in dep.get("vulnerabilities") or []:
            cwes = v.get("cwes") or []
            res.append(f("dependency-check", t, category=Category.PKG_VULN,
                         severity=Severity.parse(v.get("severity")),
                         id=v.get("name", ""), title=v.get("name", "") or "vulnerability",
                         description=(v.get("description") or "").strip()[:1200], cvss=_cvss(v),
                         package=(purl[4:].split("@")[0] if purl else fname)[:120],
                         ecosystem=_purl_eco(purl), location=fname[:200],
                         cves=[v["name"]] if str(v.get("name", "")).upper().startswith("CVE") else cves_in(v.get("name")),
                         references=[r.get("url") for r in (v.get("references") or []) if r.get("url")][:10],
                         raw={**v, "cwes": cwes}))
    return res
