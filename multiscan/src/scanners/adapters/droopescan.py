from __future__ import annotations
from pathlib import Path

from ..models import Category, Severity, Target
from .base import endpoint_of, f, read_json


def parse(out: Path, t: Target) -> list[Finding]:
    doc = read_json(out / f"{t.name}.droopescan.json")
    if not isinstance(doc, dict):
        return []
    res = []
    target_url = doc.get("host") or ""
    ep = endpoint_of(target_url)

    versions = [v for v in (doc.get("version") or {}).get("finds") or [] if v]
    version_str = ", ".join(str(v) for v in versions)

    plugins = (doc.get("plugins") or {}).get("finds") or []
    for plugin in plugins:
        if not isinstance(plugin, dict):
            continue
        name = plugin.get("name") or plugin.get("url") or ""
        url = plugin.get("url") or target_url
        res.append(f("droopescan", t, category=Category.WEB_VULN,
                     severity=Severity.INFO,
                     id=f"plugin:{name}",
                     title=f"CMS plugin detected: {name}",
                     description=f"Plugin found at {url}" + (f" (CMS version: {version_str})" if version_str else ""),
                     location=url, endpoint=ep,
                     raw=plugin))

    themes = (doc.get("themes") or {}).get("finds") or []
    for theme in themes:
        if not isinstance(theme, dict):
            continue
        name = theme.get("name") or theme.get("url") or ""
        url = theme.get("url") or target_url
        res.append(f("droopescan", t, category=Category.WEB_VULN,
                     severity=Severity.INFO,
                     id=f"theme:{name}",
                     title=f"CMS theme detected: {name}",
                     description=f"Theme found at {url}",
                     location=url, endpoint=ep,
                     raw=theme))

    for entry in (doc.get("interesting urls") or {}).get("finds") or []:
        if not isinstance(entry, dict):
            continue
        url = entry.get("url") or target_url
        desc = entry.get("description") or ""
        res.append(f("droopescan", t, category=Category.WEB_VULN,
                     severity=Severity.LOW,
                     id=f"interesting-url:{url}",
                     title=f"Interesting URL: {desc or url}",
                     description=desc,
                     location=url, endpoint=ep,
                     raw=entry))

    if version_str:
        res.append(f("droopescan", t, category=Category.WEB_VULN,
                     severity=Severity.INFO,
                     id=f"cms-version:{version_str}",
                     title=f"CMS version fingerprinted: {version_str}",
                     description=f"Host: {target_url}",
                     location=target_url, endpoint=ep,
                     version=versions[0] if versions else "",
                     raw=doc.get("version") or {}))

    return res
