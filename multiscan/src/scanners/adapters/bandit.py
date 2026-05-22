from __future__ import annotations
from pathlib import Path

from ..models import Category, Severity, Target
from .base import cves_in, f, read_json

_SEV = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


def _strip_rootfs(path: str) -> str:
    return path[6:] if path.startswith("/scan/") else (path or "")


def parse(out: Path, t: Target) -> list[Finding]:
    doc = read_json(out / f"{t.name}.bandit.json")
    if not isinstance(doc, dict):
        return []
    res = []
    for r in doc.get("results") or []:
        sev_str = str(r.get("issue_severity", "")).upper()
        test_id = r.get("test_id", "")
        test_name = r.get("test_name", "")
        line = r.get("line_number", "")
        loc = _strip_rootfs(r.get("filename", ""))
        if line:
            loc = f"{loc}:{line}"
        res.append(f("bandit", t, category=Category.OTHER,
                     severity=_SEV.get(sev_str, Severity.UNKNOWN),
                     id=test_id, title=test_name or test_id,
                     description=(r.get("issue_text") or "")[:1000],
                     location=loc,
                     cves=cves_in(r.get("issue_text")),
                     references=[r["more_info"]] if r.get("more_info") else [],
                     raw=r))
    return res
