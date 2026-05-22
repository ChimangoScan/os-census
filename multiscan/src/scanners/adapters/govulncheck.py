from __future__ import annotations
import json
import re
from pathlib import Path

from ..models import Category, Finding, Severity, Target
from .base import cves_in, f

# govulncheck's JSON stream contains trailing commas before a closing bracket
# (e.g. "aliases": ["CVE-2020-16845",]), which strict json rejects.
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def _iter_json_stream(path: Path):
    """Yield each JSON object from a stream of concatenated objects.

    ``govulncheck -format json`` emits a sequence of Message objects that are
    pretty-printed (each object spans many lines), so a line-by-line JSONL
    reader sees only fragments. We decode the whole text object by object,
    after stripping the trailing commas that strict json cannot parse."""
    try:
        text = path.read_text()
    except OSError:
        return
    text = _TRAILING_COMMA.sub(r"\1", text)
    dec = json.JSONDecoder()
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            break
        try:
            obj, i = dec.raw_decode(text, i)
            yield obj
        except json.JSONDecodeError:
            # a malformed/truncated object (e.g. govulncheck killed mid-write
            # by the scan timeout): resync to the next top-level object
            nxt = text.find("\n{\n", i + 1)
            if nxt < 0:
                break
            i = nxt + 1


def parse(out: Path, t: Target) -> list[Finding]:
    # govulncheck -format json emits a stream of Message objects. Each Message
    # has exactly one field populated: config, progress, osv, finding.
    # We collect osv metadata first (keyed by vuln ID), then emit one Finding
    # per unique (osv_id, binary) pair from finding messages.
    osv_meta: dict[str, dict] = {}
    findings_raw: list[dict] = []

    for msg in _iter_json_stream(out / "govulncheck.jsonl"):
        if not isinstance(msg, dict):
            continue
        if isinstance(msg.get("osv"), dict):
            osv = msg["osv"]
            vid = osv.get("id", "")
            if vid:
                osv_meta[vid] = osv
        elif isinstance(msg.get("finding"), dict):
            findings_raw.append(msg)

    res = []
    seen: set[tuple] = set()
    for msg in findings_raw:
        fnd = msg.get("finding") or {}
        vid = fnd.get("osv", "")
        if not vid:
            continue

        # module/version from the first trace frame
        trace = fnd.get("trace") or [{}]
        mod_raw = trace[0].get("module") or ""
        module = mod_raw.split("@")[0]
        version = mod_raw.split("@", 1)[1] if "@" in mod_raw else ""
        # the scanned binary, if the harness recorded it, else the module
        binary = msg.get("_binary", "") or module

        key = (vid, binary)
        if key in seen:
            continue
        seen.add(key)

        osv = osv_meta.get(vid, {})
        aliases = osv.get("aliases") or []
        cves = [a for a in aliases if a.upper().startswith("CVE-")] or cves_in(vid)
        summary = osv.get("summary") or osv.get("details") or ""
        refs = [r.get("url", "") for r in (osv.get("references") or []) if r.get("url")][:10]

        res.append(f("govulncheck", t,
                     category=Category.PKG_VULN,
                     severity=Severity.UNKNOWN,
                     id=vid,
                     title=f"{module} — {vid}" if module else vid,
                     description=summary[:1000],
                     package=module,
                     version=version,
                     fixed_version=fnd.get("fixed_version", ""),
                     ecosystem="go",
                     location=binary,
                     cves=cves,
                     references=refs,
                     raw={"finding": fnd, "osv": osv, "_binary": binary}))
    return res
