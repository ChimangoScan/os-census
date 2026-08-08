"""Adapter for YaraHunter (Aqua's malware/IOC scanner, YARA rules over container layers).

Reads ``<target>.yarahunter.json`` and normalizes each entry in its
``IOC`` (indicator-of-compromise) list as a ``MALWARE`` finding. Severity
defaults to ``MEDIUM`` when YaraHunter doesn't report one of its own for a
match."""
from __future__ import annotations
from pathlib import Path

from ..models import Category, Finding, Severity, Target
from .base import f, read_json


def parse(out: Path, t: Target) -> list[Finding]:
    """Turn ``<target>.yarahunter.json`` under ``out`` into malware findings for target ``t``. Returns ``[]`` if the report is missing or malformed."""
    doc = read_json(out / f"{t.name}.yarahunter.json")
    if not isinstance(doc, dict):
        return []
    res = []
    for ioc in doc.get("IOC") or []:
        if not isinstance(ioc, dict):
            continue
        rule = ioc.get("Matched Rule Name", "")
        path = ioc.get("File Name", "")
        loc = path[6:] if path.startswith("/scan/") else path
        sev = Severity.parse(ioc.get("Severity", "")) if ioc.get("Severity") else Severity.MEDIUM
        res.append(f("yarahunter", t, category=Category.MALWARE, severity=sev,
                     id=rule, title=f"YARA rule {rule}",
                     description=(ioc.get("String Found") or "")[:600],
                     location=loc, raw=ioc))
    return res
