"""Adapter for kube-linter (Kubernetes manifest static analyzer, run against the exported rootfs).

Reads ``<target>.kube-linter.json`` and normalizes each ``Reports[]`` entry as
an ``IMAGE_CONFIG`` finding at fixed ``Severity.MEDIUM`` — kube-linter's own
checks don't carry a graded severity, only a check name and remediation
text."""
from __future__ import annotations
from pathlib import Path

from ..models import Category, Finding, Severity, Target
from .base import f, read_json


def parse(out: Path, t: Target) -> list[Finding]:
    """Turn ``<target>.kube-linter.json`` under ``out`` into config findings for target ``t``. Returns ``[]`` if the report is missing or malformed."""
    doc = read_json(out / f"{t.name}.kube-linter.json")
    if not isinstance(doc, dict):
        return []
    res = []
    for r in doc.get("Reports") or []:
        if not isinstance(r, dict):
            continue
        check = r.get("Check", "")
        msg = (r.get("Diagnostic") or {}).get("Message", "")
        obj = r.get("Object") or {}
        meta = obj.get("Metadata") or {}
        k8s = obj.get("K8sObject") or {}
        loc = meta.get("FilePath", "")
        if loc.startswith("/scan/"):
            loc = loc[6:]
        name = k8s.get("Name", "")
        kind = k8s.get("GroupVersionKind", {}).get("Kind", "") or k8s.get("Kind", "")
        title = f"{kind}/{name}: {check}" if (kind or name) else check
        res.append(f("kube-linter", t, category=Category.IMAGE_CONFIG, severity=Severity.MEDIUM,
                     id=check, title=title,
                     description=(msg + "\n" + r.get("Remediation", ""))[:800],
                     location=loc, raw=r))
    return res
