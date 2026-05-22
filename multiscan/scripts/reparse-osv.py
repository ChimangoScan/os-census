#!/usr/bin/env python3
"""Re-parse osv-scanner raw output with the fixed adapter and patch report.json.

The osv adapter used to key on package.name (the Debian/RPM *source* package),
so every binary package of one source collapsed into identical-looking
findings. The fixed adapter prefers os_package_name. This re-parses the
preserved raw output in place (no re-scan).

Usage: python scripts/reparse-osv.py [out-dir]   (default: out-staticrr)
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from scanners.adapters.osv import parse                  # noqa: E402
from scanners.models import Target                       # noqa: E402


def main() -> int:
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "out-staticrr"
    patched = total = 0
    for rep_path in sorted(out_dir.glob("*/report.json")):
        cont = rep_path.parent.name
        osv_dir = rep_path.parent / "osv"
        if not (osv_dir / f"{cont}.osv.json").exists():
            continue
        rep = json.loads(rep_path.read_text())
        tj = rep.get("target") or {}
        t = Target(image=tj.get("image", ""),
                   name=tj.get("name", cont), ip=tj.get("ip"))
        fnd = [x.to_json() for x in parse(osv_dir, t)]
        rep["findings"] = [x for x in rep.get("findings", [])
                           if x.get("scanner") != "osv"] + fnd
        for inv in rep.get("invocations", []):
            if inv.get("scanner") == "osv":
                inv["findings"] = len(fnd)
        rep_path.write_text(json.dumps(rep))
        patched += 1
        total += len(fnd)
    print(f"patched {patched} reports, {total} osv findings total")
    return 0


if __name__ == "__main__":
    sys.exit(main())
