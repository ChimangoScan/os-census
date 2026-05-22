from __future__ import annotations
from pathlib import Path

from ..models import Category, Finding, Severity, Target
from .base import f, read_json


def parse(out: Path, t: Target) -> list[Finding]:
    doc = read_json(out / f"{t.name}.detect-secrets.json")
    if not isinstance(doc, dict):
        return []
    results = doc.get("results") or {}
    res = []
    for filename, hits in results.items():
        if not isinstance(hits, list):
            continue
        loc = filename[6:] if filename.startswith("/scan/") else filename
        for h in hits:
            if not isinstance(h, dict):
                continue
            rule = h.get("type", "")
            line = h.get("line_number", "")
            res.append(f("detect-secrets", t, category=Category.SECRET, severity=Severity.HIGH,
                         id=rule, title=rule or "secret",
                         description=f"hashed_secret={h.get('hashed_secret', '')}",
                         location=f"{loc}:{line}" if line != "" else loc,
                         raw=h))
    return res
