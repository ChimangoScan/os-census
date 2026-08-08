"""Adapter for Gitleaks (regex-based secret scanner, run against the exported rootfs).

Reads ``<target>.gitleaks.json`` (a JSON array, not an object — Gitleaks emits
no top-level wrapper) and normalizes each hit as a ``SECRET`` finding at fixed
``Severity.HIGH``."""
from __future__ import annotations
from pathlib import Path

from ..models import Category, Finding, Severity, Target
from .base import f, read_json


def parse(out: Path, t: Target) -> list[Finding]:
    """Turn ``<target>.gitleaks.json`` under ``out`` into secret findings for target ``t``. Returns ``[]`` if the report is missing or not a JSON list."""
    doc = read_json(out / f"{t.name}.gitleaks.json")
    if not isinstance(doc, list):
        return []
    res = []
    for d in doc:
        if not isinstance(d, dict):
            continue
        rule = d.get("RuleID", "")
        line = d.get("StartLine", "")
        res.append(f("gitleaks", t, category=Category.SECRET, severity=Severity.HIGH,
                     id=rule, title=d.get("Description") or rule,
                     description=str(d.get("Match", ""))[:500],
                     location=f"{d.get('File', '')}:{line}" if line != "" else d.get("File", ""),
                     raw=d))
    return res
