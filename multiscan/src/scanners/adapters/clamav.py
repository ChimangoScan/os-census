"""Adapter for ClamAV (signature-based malware scanner, run against the exported rootfs).

ClamAV has no JSON output mode used here; the adapter parses the plain-text
stdout capture of ``clamscan -r -i`` line by line instead of reading a
structured report. Every infected-file hit becomes a ``MALWARE`` finding at
fixed ``Severity.HIGH`` — ClamAV signature hits don't carry a graded
severity of their own."""
from __future__ import annotations
import re
from pathlib import Path

from ..models import Category, Severity, Target
from .base import f

# `clamscan -r -i` prints "<path>: <signature> FOUND" per infected file.
_HIT = re.compile(r"^(.*?): (.+?) FOUND\s*$")


def parse(out: Path, t: Target) -> list[Finding]:
    """Turn the captured ``clamscan`` text output under ``out`` into malware findings for target ``t``.

    Returns ``[]`` if no ``*.clamav.txt`` capture exists. Only lines matching
    the "``<path>: <signature> FOUND``" pattern are treated as hits; clamscan's
    other status/summary lines are ignored.
    """
    txt = next(out.glob("*.clamav.txt"), None)
    if not txt or not txt.is_file():
        return []
    res = []
    for line in txt.read_text(errors="replace").splitlines():
        m = _HIT.match(line)
        if not m:
            continue
        path, sig = m.group(1), m.group(2)
        loc = path[6:] if path.startswith("/scan/") else path
        res.append(f("clamav", t, category=Category.MALWARE, severity=Severity.HIGH,
                     id=sig, title=sig, description=f"ClamAV signature {sig}",
                     location=loc, raw={"signature": sig, "path": loc}))
    return res
