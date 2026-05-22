from __future__ import annotations
from pathlib import Path

from ..models import Category, Severity, Target
from .base import cves_in, f, read_json

_SEV = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW, "INFO": Severity.INFO}


def _strip_rootfs(path: str) -> str:
    return path[6:] if path.startswith("/scan/") else (path or "")


def _parse_checks(checks: list, scanner: str, t) -> list:
    res = []
    for c in checks or []:
        if not isinstance(c, dict):
            continue
        check_id = c.get("check_id") or ""
        sev_raw = str(c.get("severity") or "").upper()
        res.append(f(scanner, t, category=Category.IMAGE_CONFIG,
                     severity=_SEV.get(sev_raw, Severity.UNKNOWN),
                     id=check_id, title=c.get("check") or check_id,
                     description=(c.get("check") or "")[:800],
                     location=_strip_rootfs(c.get("repo_file_path") or c.get("file_path") or ""),
                     cves=cves_in(check_id),
                     references=[c["guideline"]] if c.get("guideline") else [],
                     raw=c))
    return res


def parse(out: Path, t: Target) -> list[Finding]:
    doc = read_json(out / "results_json.json")
    if doc is None:
        return []
    # checkov -o json may emit a list (one element per framework) or a dict
    docs = doc if isinstance(doc, list) else [doc]
    res = []
    for d in docs:
        if not isinstance(d, dict):
            continue
        results = d.get("results") or {}
        res.extend(_parse_checks(results.get("failed_checks") or [], "checkov", t))
    return res
