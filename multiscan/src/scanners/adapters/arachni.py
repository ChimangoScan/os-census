"""Adapter for Arachni (dynamic web vulnerability scanner).

Reads ``arachni.json`` (Arachni's native JSON report) from the scanner's
output directory and normalizes each ``issues[]`` entry into a
``Category.WEB_VULN`` finding. The finding's location is Arachni's ``vector``
URL (falling back to the target's IP) so results can be tied back to the
specific request that triggered the issue."""
from __future__ import annotations
from pathlib import Path

from ..models import Category, Finding, Severity, Target
from .base import cves_in, endpoint_of, f, read_json

# Arachni severity strings map to our levels
_SEV = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "info": Severity.INFO,
}


def parse(out: Path, t: Target) -> list[Finding]:
    """Turn ``arachni.json`` under ``out`` into web-vulnerability findings for target ``t``.

    Returns ``[]`` if the report is missing or not a JSON object (scanner
    crashed or produced no output). CVEs are pulled from the issue description
    and its collected reference URLs.
    """
    doc = read_json(out / "arachni.json")
    if not isinstance(doc, dict):
        return []
    issues = doc.get("issues") or []
    res = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        name = issue.get("name", "")
        sev_str = str(issue.get("severity", "")).lower()
        severity = _SEV.get(sev_str, Severity.parse(sev_str))
        desc = (issue.get("description") or "")[:1000]
        # URL of the finding comes from the top-level or from the vector
        vector = issue.get("vector") or {}
        url = vector.get("action") or issue.get("url") or ""
        cwe_url = issue.get("cwe_url") or ""
        refs = [r for r in [cwe_url] + list(issue.get("references") or {}).values() if r][:10]
        cves = cves_in(desc) or cves_in(str(refs))
        endpoint = endpoint_of(url) or endpoint_of(t.ip or "")
        res.append(f("arachni", t,
                     category=Category.WEB_VULN,
                     severity=severity,
                     id=issue.get("check", {}).get("shortname", "") or name,
                     title=name,
                     description=desc,
                     location=url,
                     endpoint=endpoint,
                     cves=cves,
                     references=refs,
                     raw=issue))
    return res
