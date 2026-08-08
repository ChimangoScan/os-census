"""Adapter for gosec (Go static security linter).

Reads ``<target>.gosec.json`` and normalizes each ``Issues[]`` entry as an
uncategorized (``Category.OTHER``) finding, with a link to the CWE definition
page attached when gosec provides a CWE id."""
from __future__ import annotations
from pathlib import Path

from ..models import Category, Severity, Target
from .base import cves_in, f, read_json

_SEV = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


def _strip_rootfs(path: str) -> str:
    """Drop the ``/scan`` mount prefix so locations read as in-image paths."""
    return path[6:] if path.startswith("/scan/") else (path or "")


def parse(out: Path, t: Target) -> list[Finding]:
    """Turn ``<target>.gosec.json`` under ``out`` into findings for target ``t``. Returns ``[]`` if the report is missing or malformed."""
    doc = read_json(out / f"{t.name}.gosec.json")
    if not isinstance(doc, dict):
        return []
    res = []
    for r in doc.get("Issues") or []:
        sev_str = str(r.get("severity", "")).upper()
        rule_id = r.get("rule_id", "")
        line = r.get("line", "")
        loc = _strip_rootfs(r.get("file", ""))
        if line:
            loc = f"{loc}:{line}"
        cwe_id = (r.get("cwe") or {}).get("id", "")
        details = r.get("details", "")
        res.append(f("gosec", t, category=Category.OTHER,
                     severity=_SEV.get(sev_str, Severity.UNKNOWN),
                     id=rule_id, title=details[:200] or rule_id,
                     description=details[:1000],
                     location=loc,
                     cves=cves_in(details),
                     references=["https://cwe.mitre.org/data/definitions/" + cwe_id + ".html"] if cwe_id else [],
                     raw=r))
    return res
