#!/usr/bin/env bash
# Removes everything a run of this artifact created, inside the clone and outside it.
# It never touches anything tracked by git, and never removes the clone itself.
#
#   ./cleanup.sh --dry-run   list what would be removed, delete nothing
#   ./cleanup.sh             remove it
#   ./cleanup.sh --images    also remove the scanner images the optional re-scan pulled
set -euo pipefail
cd "$(dirname "$0")"

DRY=0; IMAGES=0
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    --images)  IMAGES=1 ;;
    *) echo "usage: $0 [--dry-run] [--images]" >&2; exit 2 ;;
  esac
done

total=0
gone() {   # gone <path> <what it is>
  local p="$1" what="$2" sz
  [ -e "$p" ] || return 0
  sz=$(du -sm "$p" 2>/dev/null | cut -f1); sz=${sz:-0}
  total=$((total + sz))
  printf '  %-40s %6s MB  %s\n' "$p" "$sz" "$what"
  [ "$DRY" = "1" ] || rm -rf "$p"
}

echo "Removing what a run of this artifact leaves behind:"
gone .venv          "the Python environment uv created"
gone .pytest_cache  "test cache"
gone .ruff_cache    "lint cache"
gone work           "scratch state of the scan pipeline"

# scan-out holds the 8.6 GB dataset that `reproduce.sh analysis` extracts, and the
# scan-smoke output. Containers write part of it as root, so a plain rm fails on those
# files; one throwaway container removes them with the ownership that created them.
if [ -e scan-out ]; then
  sz=$(du -sm scan-out 2>/dev/null | cut -f1); sz=${sz:-0}
  total=$((total + sz))
  printf '  %-40s %6s MB  %s\n' "scan-out" "$sz" "extracted dataset and scan output"
  if [ "$DRY" != "1" ]; then
    rm -rf scan-out 2>/dev/null || {
      command -v docker >/dev/null && docker run --rm -v "$PWD:/p" alpine rm -rf /p/scan-out
    }
  fi
fi

# The scanner images are third-party and may be in use for something else, so they go only
# when asked for. Only the ones this artifact names in its own config are considered.
if [ "$IMAGES" = "1" ] && command -v docker >/dev/null; then
  while read -r ref; do
    [ -n "$ref" ] || continue
    docker image inspect "$ref" >/dev/null 2>&1 || continue
    sz=$(docker image inspect "$ref" --format '{{.Size}}')
    total=$((total + sz / 1024 / 1024))
    printf '  %-40s %6s MB  %s\n' "$ref" "$((sz / 1024 / 1024))" "scanner image"
    [ "$DRY" = "1" ] || docker rmi -f "$ref" >/dev/null
  done < <(sed -n 's/^ *image: *//p' config/scanners.yaml | sed 's/#.*//; s/[[:space:]]*$//' | sort -u)
elif [ "$IMAGES" != "1" ]; then
  echo "  (the scanner images are kept; pass --images to remove those too)"
fi

echo
if [ "$DRY" = "1" ]; then
  echo "Dry run: nothing was removed. ${total} MB would be freed."
else
  echo "Done. ${total} MB freed. Nothing tracked by git was touched."
fi
