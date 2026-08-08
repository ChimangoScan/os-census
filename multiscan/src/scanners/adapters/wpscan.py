"""Adapter for WPScan (WordPress-specific vulnerability scanner).

Reads ``<target>.wpscan.json`` and emits ``WEB_VULN`` findings from three
separate sections of one report — WordPress core, each installed plugin, each
installed theme — since WPScan enumerates the whole WordPress stack in one
run rather than one component at a time."""
from __future__ import annotations
from pathlib import Path

from ..models import Category, Severity, Target
from .base import cves_in, endpoint_of, f, read_json


def parse(out: Path, t: Target) -> list[Finding]:
    """Turn ``<target>.wpscan.json`` under ``out`` into WordPress-vulnerability findings for target ``t``. Returns ``[]`` if the report is missing or malformed."""
    doc = read_json(out / f"{t.name}.wpscan.json")
    if not isinstance(doc, dict):
        return []
    res = []
    target_url = doc.get("target_url") or ""
    ep = endpoint_of(target_url)

    def _emit(vuln: dict, context: str) -> None:
        """Normalize and append one WPScan vulnerability entry, tagging it with where it was found (core/plugin/theme)."""
        title = vuln.get("title") or ""
        cvss_val = None
        cvss_block = vuln.get("cvss")
        if isinstance(cvss_block, dict):
            try:
                cvss_val = float(cvss_block.get("score") or 0) or None
            except (TypeError, ValueError):
                pass
        sev = Severity.from_cvss(cvss_val) if cvss_val else Severity.MEDIUM
        refs = vuln.get("references") or {}
        ref_urls = []
        for v in refs.values():
            if isinstance(v, list):
                ref_urls.extend(str(u) for u in v)
            elif isinstance(v, str):
                ref_urls.append(v)
        fixed_in = vuln.get("fixed_in") or ""
        res.append(f("wpscan", t, category=Category.WEB_VULN,
                     severity=sev,
                     id=str(vuln.get("id") or title),
                     title=title,
                     description=f"{context}: {vuln.get('vuln_type', '')}".strip(": "),
                     cvss=cvss_val,
                     fixed_version=str(fixed_in),
                     location=target_url,
                     endpoint=ep,
                     cves=cves_in(str(ref_urls) + str(vuln.get("references", ""))),
                     references=ref_urls[:10],
                     raw=vuln))

    # WordPress core vulnerabilities
    for vuln in (doc.get("wordpress") or {}).get("vulnerabilities") or []:
        _emit(vuln, "WordPress core")

    # Plugin vulnerabilities
    for plugin_name, plugin in (doc.get("plugins") or {}).items():
        for vuln in plugin.get("vulnerabilities") or []:
            _emit(vuln, f"plugin:{plugin_name}")

    # Theme vulnerabilities
    for theme_name, theme in (doc.get("themes") or {}).items():
        for vuln in theme.get("vulnerabilities") or []:
            _emit(vuln, f"theme:{theme_name}")

    return res
