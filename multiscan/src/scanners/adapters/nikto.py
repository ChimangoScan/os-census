"""Adapter for Nikto (web server misconfiguration/vulnerability scanner).

Reads ``<target>.nikto.json`` and normalizes each per-host vulnerability entry
as a ``WEB_VULN`` finding at fixed ``Severity.LOW`` — Nikto's own output
carries no severity grading, only an OSVDB/plugin id."""
from __future__ import annotations
from pathlib import Path

from ..models import Category, Severity, Target
from .base import cves_in, f, read_json


def parse(out: Path, t: Target) -> list[Finding]:
    """Turn ``<target>.nikto.json`` under ``out`` into web findings for target ``t``.

    Nikto's report may be a single host object or a list of host objects
    (depending on scan mode); both shapes are normalized to a list before
    iterating.
    """
    doc = read_json(out / f"{t.name}.nikto.json")
    # nikto may emit a list (one host) or a dict
    hosts = doc if isinstance(doc, list) else ([doc] if isinstance(doc, dict) else [])
    res = []
    for h in hosts:
        ip = h.get("ip") or h.get("host", "")
        port = str(h.get("port", ""))
        ep = f"{ip}:{port}".strip(":")
        for v in h.get("vulnerabilities") or []:
            msg = v.get("msg") or v.get("title") or ""
            res.append(f("nikto", t, category=Category.WEB_VULN, severity=Severity.LOW,
                         id=str(v.get("id") or v.get("OSVDB") or ""), title=msg[:200],
                         description=msg[:800], location=v.get("url", ""), endpoint=ep,
                         cves=cves_in(msg), references=[r for r in [v.get("references")] if r], raw=v))
    return res
