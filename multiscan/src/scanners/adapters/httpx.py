"""Adapter for httpx (ProjectDiscovery's HTTP probe / tech fingerprinter).

Reads ``<target>.httpx.jsonl`` (one probe result per line) and turns each
live endpoint into ``WEB_VULN``-category ``INFO`` findings: one per detected
technology, or — if httpx detected no technology at all — a single
"HTTP endpoint alive" finding, so a bare live endpoint is never silently
dropped from the report just because fingerprinting found nothing."""
from __future__ import annotations
from pathlib import Path

from ..models import Category, Severity, Target
from .base import endpoint_of, f, read_jsonl


def parse(out: Path, t: Target) -> list[Finding]:
    """Turn ``<target>.httpx.jsonl`` under ``out`` into endpoint/technology findings for target ``t``."""
    res = []
    for rec in read_jsonl(out / f"{t.name}.httpx.jsonl"):
        if not isinstance(rec, dict):
            continue
        url = rec.get("url") or rec.get("input") or ""
        sc = rec.get("status_code") or 0
        title = rec.get("title") or ""
        techs = rec.get("tech") or rec.get("technologies") or []
        if isinstance(techs, dict):
            techs = list(techs.keys())
        webserver = rec.get("webserver") or ""
        # Emit one finding per detected technology (fingerprint / info)
        if techs:
            for tech in techs:
                res.append(f("httpx", t, category=Category.WEB_VULN,
                             severity=Severity.INFO,
                             id=f"tech:{tech.lower().replace(' ', '-')}",
                             title=f"Technology detected: {tech}",
                             description=f"URL: {url}  status={sc}  server={webserver}",
                             location=url, endpoint=endpoint_of(url), raw=rec))
        else:
            # Always emit at least one finding per live endpoint so the host is
            # surfaced in the merged report even without tech hits.
            res.append(f("httpx", t, category=Category.WEB_VULN,
                         severity=Severity.INFO,
                         id=f"http-alive:{sc}",
                         title=f"HTTP endpoint alive ({sc}): {title}",
                         description=f"URL: {url}  status={sc}  server={webserver}",
                         location=url, endpoint=endpoint_of(url), raw=rec))
    return res
