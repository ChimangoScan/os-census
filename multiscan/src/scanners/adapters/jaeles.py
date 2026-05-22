from __future__ import annotations
from pathlib import Path

from ..models import Category, Severity, Target
from .base import cves_in, endpoint_of, f, read_jsonl


def parse(out: Path, t: Target) -> list[Finding]:
    res = []
    for rec in read_jsonl(out / f"{t.name}.jaeles.jsonl"):
        if not isinstance(rec, dict):
            continue
        req = rec.get("Request") or rec.get("request") or {}
        resp = rec.get("Response") or rec.get("response") or {}
        sign = rec.get("Sign") or rec.get("sign") or {}
        url = req.get("Target") or req.get("URL") or rec.get("Target") or ""
        title = sign.get("Name") or sign.get("name") or rec.get("CheckName") or ""
        desc = sign.get("Desc") or rec.get("Desc") or resp.get("Reason") or ""
        sev_raw = sign.get("Risk") or sign.get("Severity") or rec.get("Risk") or ""
        res.append(f("jaeles", t, category=Category.WEB_VULN,
                     severity=Severity.parse(sev_raw),
                     id=sign.get("ID") or sign.get("id") or rec.get("CheckName") or "",
                     title=title,
                     description=str(desc)[:1000],
                     location=url,
                     endpoint=endpoint_of(url),
                     cves=cves_in(str(sign) + str(desc)),
                     raw=rec))
    return res
