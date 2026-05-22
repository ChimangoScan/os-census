#!/usr/bin/env bash
# Run Arachni against a URL and emit a JSON report.
# Usage: /entrypoint.sh <url> <output.json>
# Arachni refuses to run as root, so the scan and the reporter are run as the
# unprivileged 'scanner' user (created in the image).
set -euo pipefail

URL="${1:?URL required}"
OUT="${2:-/out/arachni.json}"
AFR="${OUT%.json}.afr"

# the bind-mounted output dir must be writable by the unprivileged user
chmod -R 0777 "$(dirname "$OUT")" 2>/dev/null || true

# Run the scan; save native AFR report to a temp path
runuser -u scanner -- arachni \
    --output-only-positives \
    --report-save-path="$AFR" \
    --timeout 00:20:00 \
    --scope-page-limit 100 \
    "$URL" 2>&1 || true   # exit code 1 is normal (findings present)

if [ ! -f "$AFR" ]; then
    echo '{"issues":[]}' > "$OUT"
    exit 0
fi

# Convert the AFR to JSON via arachni_reporter
runuser -u scanner -- arachni_reporter "$AFR" --reporter "json:outfile=${OUT}" 2>&1 || true

# Clean up the AFR to save space
rm -f "$AFR"

# Ensure output exists
[ -f "$OUT" ] || echo '{"issues":[]}' > "$OUT"
