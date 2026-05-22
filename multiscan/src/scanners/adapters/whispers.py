from __future__ import annotations
from pathlib import Path

from ..models import Category, Finding, Severity, Target
from .base import f, read_json

# whispers' "comment" and "file-known" rules fire on every code comment and
# every recognised filename: they flag the artefact, not a secret in it, and
# account for ~99% of whispers' raw output. They are excluded as noise.
NOISE_RULES = {"comment", "file-known"}


def parse(out: Path, t: Target) -> list[Finding]:
    doc = read_json(out / "whispers.json")
    if not isinstance(doc, list):
        return []
    res = []
    for d in doc:
        if not isinstance(d, dict):
            continue
        key = d.get("key") or ""
        rule_id = d.get("rule_id") or key
        if rule_id in NOISE_RULES:
            continue
        filepath = d.get("file") or ""
        line = d.get("line", "")
        loc = f"{filepath}:{line}" if line != "" else filepath
        res.append(f("whispers", t, category=Category.SECRET,
                     severity=Severity.parse(d.get("severity")),
                     id=rule_id, title=key or rule_id,
                     description=f"Hardcoded secret: {key}",
                     location=loc,
                     raw={"rule_id": rule_id, "key": key,
                          "file": filepath, "line": line,
                          "value": str(d.get("value") or "")[:200]}))
    return res
