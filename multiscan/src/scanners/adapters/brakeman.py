from __future__ import annotations
from pathlib import Path

from ..models import Category, Severity, Target
from .base import cves_in, f, read_json

_SEV = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Weak": Severity.LOW,
}


def _strip_rootfs(path: str) -> str:
    return path[6:] if path.startswith("/scan/") else (path or "")


def parse(out: Path, t: Target) -> list[Finding]:
    doc = read_json(out / f"{t.name}.brakeman.json")
    if not isinstance(doc, dict):
        return []
    res = []
    for r in doc.get("warnings") or []:
        confidence = r.get("confidence", "")
        warn_type = r.get("warning_type", "")
        warn_code = r.get("warning_code", "")
        message = r.get("message", "")
        loc_file = _strip_rootfs(r.get("file", ""))
        line = r.get("line", "")
        loc = f"{loc_file}:{line}" if line else loc_file
        link = r.get("link", "")
        res.append(f("brakeman", t, category=Category.OTHER,
                     severity=_SEV.get(confidence, Severity.UNKNOWN),
                     id=f"BRAKEMAN-{warn_code}" if warn_code else warn_type,
                     title=warn_type or message[:200],
                     description=message[:1000],
                     location=loc,
                     cves=cves_in(message),
                     references=[link] if link else [],
                     raw=r))
    return res
