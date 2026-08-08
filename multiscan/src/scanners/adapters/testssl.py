"""Adapter for testssl.sh (TLS/SSL configuration scanner).

Reads ``<target>.testssl.json`` (a flat list of finding objects, or a dict
wrapping one under ``scanResult`` depending on testssl version) and normalizes
each entry as a ``NETWORK_VULN`` finding. Pure connection/service-info lines
(``id`` starting with ``service`` at ``INFO`` severity) are dropped as noise —
they describe the probe itself, not a security-relevant observation."""
from __future__ import annotations
from pathlib import Path

from ..models import Category, Severity, Target
from .base import cves_in, f, read_json

_SEV = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "warn": Severity.MEDIUM,
    "info": Severity.INFO,
    "ok": Severity.INFO,
    "not ok": Severity.MEDIUM,
}


def parse(out: Path, t: Target) -> list[Finding]:
    """Turn ``<target>.testssl.json`` under ``out`` into TLS/network findings for target ``t``, skipping pure service-info noise."""
    doc = read_json(out / f"{t.name}.testssl.json")
    # testssl flat JSON is a list of finding objects
    items = doc if isinstance(doc, list) else (doc.get("scanResult") or [] if isinstance(doc, dict) else [])
    res = []
    for item in items:
        if not isinstance(item, dict):
            continue
        sev_raw = str(item.get("severity") or "").lower()
        sev = _SEV.get(sev_raw, Severity.UNKNOWN)
        if sev in (Severity.INFO,) and item.get("id", "").startswith("service"):
            continue  # skip pure service-info lines; they add noise
        finding = item.get("finding") or ""
        host = item.get("ip") or item.get("hostname") or t.ip or t.name
        port = str(item.get("port") or "")
        ep = f"{host}:{port}".strip(":")
        res.append(f("testssl", t, category=Category.NETWORK_VULN,
                     severity=sev,
                     id=item.get("id") or "",
                     title=f"{item.get('id', '')} ({sev_raw})",
                     description=str(finding)[:1000],
                     location=f"{host}:{port}",
                     endpoint=ep,
                     cves=cves_in(finding),
                     raw=item))
    return res
