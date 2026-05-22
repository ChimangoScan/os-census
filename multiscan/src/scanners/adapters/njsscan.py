from __future__ import annotations
from pathlib import Path

from ..models import Category, Severity, Target
from .base import cves_in, f, read_json

_SEV = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


def _strip_rootfs(path: str) -> str:
    return path[6:] if path.startswith("/scan/") else (path or "")


def _findings_from_section(section: dict) -> list[tuple[str, dict, list[dict]]]:
    out = []
    for rule_id, body in (section or {}).items():
        if not isinstance(body, dict):
            continue
        out.append((rule_id, body.get("metadata") or {}, body.get("files") or []))
    return out


def parse(out: Path, t: Target) -> list[Finding]:
    doc = read_json(out / f"{t.name}.njsscan.json")
    if not isinstance(doc, dict):
        return []
    res = []
    for section_key in ("nodejs", "templates"):
        for rule_id, meta, files in _findings_from_section(doc.get(section_key)):
            sev_str = str(meta.get("severity", "")).upper()
            description = (meta.get("description") or "")[:1000]
            owasp = meta.get("owasp") or ""
            cwe = meta.get("cwe") or ""
            refs = [r for r in [owasp, cwe] if r]
            for hit in files:
                file_path = _strip_rootfs(hit.get("file_path", ""))
                match_lines = hit.get("match_lines") or []
                line = match_lines[0] if match_lines else ""
                loc = (file_path + ":" + str(line)) if line else file_path
                res.append(f("njsscan", t, category=Category.OTHER,
                             severity=_SEV.get(sev_str, Severity.parse(meta.get("severity"))),
                             id=rule_id, title=meta.get("description", rule_id)[:200],
                             description=description,
                             location=loc,
                             cves=cves_in(description),
                             references=refs[:10],
                             raw={"rule_id": rule_id, "metadata": meta, "file": hit}))
    return res
