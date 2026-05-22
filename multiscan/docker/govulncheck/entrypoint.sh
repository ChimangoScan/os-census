#!/usr/bin/env bash
# Scan Go binaries in a container rootfs for known Go vulnerabilities.
# Usage: /entrypoint.sh [rootfs] [output.jsonl]
#   rootfs  – path to the flattened image filesystem (default /scan)
#   output  – path for the newline-delimited JSON result (default /out/govulncheck.jsonl)
set -euo pipefail

ROOTFS="${1:-/scan}"
OUT="${2:-/out/govulncheck.jsonl}"

> "$OUT"

# Identify Go ELF binaries: executables that contain the "Go build ID" string.
# `file` reports "ELF ... Go BuildID" for statically compiled Go binaries.
while IFS= read -r -d '' bin; do
    if file "$bin" 2>/dev/null | grep -q 'Go BuildID'; then
        # govulncheck -format json streams one JSON object per line (Message objects).
        # Append each line together with the binary path for the adapter to consume.
        govulncheck -mode binary -format json "$bin" 2>/dev/null \
        | while IFS= read -r line; do
            [ -z "$line" ] && continue
            # inject the binary path into every message line
            rel="${bin#${ROOTFS}}"
            printf '%s\n' "$line" \
            | python3 -c "
import json, sys
line = sys.stdin.read().strip()
if not line:
    sys.exit(0)
try:
    obj = json.loads(line)
except Exception:
    print(line)
    sys.exit(0)
obj['_binary'] = sys.argv[1]
print(json.dumps(obj))
" "$rel"
        done >> "$OUT" || true
    fi
done < <(find "$ROOTFS" -maxdepth 20 -type f -executable -print0 2>/dev/null)
