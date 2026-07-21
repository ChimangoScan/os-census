#!/usr/bin/env bash
# Scan a container rootfs for Python dependency vulnerabilities.
# Usage: /entrypoint.sh [rootfs] [output.json]
#   rootfs  – path to the flattened image filesystem (default /scan)
#   output  – path for the merged JSON result       (default /out/pip-audit.json)
set -euo pipefail

ROOTFS="${1:-/scan}"
OUT="${2:-/out/pip-audit.json}"
TMPDIR=$(mktemp -d /tmp/pip-audit-XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT

idx=0

# --- 1. requirements*.txt files ---
while IFS= read -r -d '' req; do
    part="$TMPDIR/part-${idx}.json"
    pip-audit -r "$req" -f json --no-deps --skip-editable \
        --output "$part" 2>/dev/null || true
    if [ -s "$part" ]; then
        # annotate each package entry with the source path
        rel="${req#${ROOTFS}}"
        python3 - "$part" "$rel" <<'PYEOF'
import json, sys
path, src = sys.argv[1], sys.argv[2]
data = json.loads(open(path).read())
for pkg in (data if isinstance(data, list) else []):
    pkg['_source'] = src
open(path, 'w').write(json.dumps(data))
PYEOF
        idx=$((idx + 1))
    fi
done < <(find "$ROOTFS" -maxdepth 8 -name 'requirements*.txt' -print0 2>/dev/null)

# --- 2. site-packages dirs: enumerate via importlib.metadata ---
while IFS= read -r -d '' sp; do
    reqs="$TMPDIR/sp-reqs-${idx}.txt"
    python3 - "$sp" "$reqs" <<'PYEOF'
import sys
try:
    import importlib.metadata as m
    pkgs = []
    for dist in m.distributions(path=[sys.argv[1]]):
        n = dist.metadata.get('Name', '')
        v = dist.metadata.get('Version', '')
        if n and v:
            pkgs.append(f'{n}=={v}')
    open(sys.argv[2], 'w').write('\n'.join(pkgs))
except Exception:
    pass
PYEOF
    if [ -s "$reqs" ]; then
        part="$TMPDIR/part-${idx}.json"
        pip-audit -r "$reqs" -f json --no-deps --skip-editable \
            --output "$part" 2>/dev/null || true
        if [ -s "$part" ]; then
            rel="${sp#${ROOTFS}}"
            python3 - "$part" "$rel" <<'PYEOF'
import json, sys
path, src = sys.argv[1], sys.argv[2]
data = json.loads(open(path).read())
for pkg in (data if isinstance(data, list) else []):
    pkg['_source'] = src
open(path, 'w').write(json.dumps(data))
PYEOF
            idx=$((idx + 1))
        fi
    fi
done < <(find "$ROOTFS" -maxdepth 10 -type d -name 'site-packages' -print0 2>/dev/null)

# --- 3. merge all partial arrays ---
python3 - "$TMPDIR" "$OUT" <<'PYEOF'
import json, os, sys
tmpdir, out = sys.argv[1], sys.argv[2]
merged, seen = [], set()
for fname in sorted(os.listdir(tmpdir)):
    if not fname.startswith('part-'):
        continue
    try:
        data = json.loads(open(os.path.join(tmpdir, fname)).read())
    except Exception:
        continue
    for pkg in (data if isinstance(data, list) else []):
        vuln_ids = tuple(sorted(v.get('id', '') for v in pkg.get('vulns', [])))
        key = (pkg.get('name', '').lower(), pkg.get('version', ''), vuln_ids)
        if key not in seen:
            seen.add(key)
            merged.append(pkg)
open(out, 'w').write(json.dumps(merged, indent=2))
PYEOF
