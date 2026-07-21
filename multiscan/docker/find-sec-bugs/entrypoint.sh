#!/usr/bin/env bash
# Scan .jar/.war/.ear files in a container rootfs with Find Security Bugs.
# Usage: /entrypoint.sh [rootfs] [output.xml]
#   rootfs  – path to the flattened image filesystem (default /scan)
#   output  – path for the merged SpotBugs XML result (default /out/find-sec-bugs.xml)
set -euo pipefail

ROOTFS="${1:-/scan}"
OUT="${2:-/out/find-sec-bugs.xml}"
TMPDIR=$(mktemp -d /tmp/fsb-XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT

idx=0
xml_parts=()

while IFS= read -r -d '' archive; do
    part="$TMPDIR/part-${idx}.xml"
    # -xml:withMessages includes human-readable text in the output
    findsecbugs.sh -xml:withMessages -output "$part" "$archive" 2>/dev/null || true
    if [ -s "$part" ]; then
        xml_parts+=("$part")
        idx=$((idx + 1))
    fi
done < <(find "$ROOTFS" -maxdepth 15 \( -name '*.jar' -o -name '*.war' -o -name '*.ear' \) -print0 2>/dev/null)

if [ ${#xml_parts[@]} -eq 0 ]; then
    # Write a minimal empty SpotBugs XML so the adapter can detect "no targets found"
    cat > "$OUT" <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<BugCollection version="4.8.6" threshold="low" effort="max">
</BugCollection>
XML
    exit 0
fi

# Merge all partial XML files: keep the header from the first, collect all
# BugInstance elements, write a single BugCollection.
python3 - "${xml_parts[@]}" "$OUT" <<'PYEOF'
import sys, xml.etree.ElementTree as ET

parts = sys.argv[1:-1]
out   = sys.argv[-1]

all_bugs = []
version = "4.8.6"

for p in parts:
    try:
        tree = ET.parse(p)
        root = tree.getroot()
        version = root.get('version', version)
        for bug in root.findall('BugInstance'):
            all_bugs.append(bug)
    except ET.ParseError:
        continue

root_out = ET.Element('BugCollection', version=version, threshold='low', effort='max')
for bug in all_bugs:
    root_out.append(bug)

ET.indent(root_out, space='  ')
ET.ElementTree(root_out).write(out, encoding='unicode', xml_declaration=True)
PYEOF
