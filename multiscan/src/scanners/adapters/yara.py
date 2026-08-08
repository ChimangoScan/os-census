"""Adapter for plain YARA (rule-based malware/IOC scanner, run against the exported rootfs).

Like ClamAV, YARA here has no JSON output mode in use; the adapter parses the
plain-text stdout of ``yara -r -s rules dir``, reassembling each match's
matched-string lines (indented "offset:identifier:value" entries following a
"<rule> <path>" match line) into one ``MALWARE`` finding per match."""
from __future__ import annotations
import re
from pathlib import Path

from ..models import Category, Severity, Target
from .base import f

# `yara -r -s rules dir` prints "<rule> <path>" per match; with -s, indented
# lines below list the matched strings (offset:identifier:value). We keep those.
_MATCH = re.compile(r"^(\S+)\s+(/scan/\S.*)$")
_STR = re.compile(r"^0x[0-9a-f]+:\$")


def parse(out: Path, t: Target) -> list[Finding]:
    """Turn the captured ``yara`` text output under ``out`` into malware findings for target ``t``. Returns ``[]`` if no ``*.yara.txt`` capture exists."""
    txt = next(out.glob("*.yara.txt"), None)
    if not txt or not txt.is_file():
        return []
    res, cur, strings = [], None, []
    for line in txt.read_text(errors="replace").splitlines():
        m = _MATCH.match(line)
        if m:
            if cur:
                res.append(_finding(t, cur[0], cur[1], strings))
            cur, strings = (m.group(1), m.group(2)), []
        elif cur and (line.startswith("0x") or _STR.match(line)):
            strings.append(line.strip())
    if cur:
        res.append(_finding(t, cur[0], cur[1], strings))
    return res


def _finding(t: Target, rule: str, path: str, strings: list[str]) -> Finding:
    """Build one YARA-match Finding from a rule name, matched file path, and up to 30 matched-string lines."""
    loc = path[6:] if path.startswith("/scan/") else path
    return f("yara", t, category=Category.MALWARE, severity=Severity.MEDIUM,
             id=rule, title=f"YARA rule {rule}",
             description=("; ".join(strings[:8]))[:600] if strings else "",
             location=loc, raw={"rule": rule, "path": loc, "matched_strings": strings[:30]})
