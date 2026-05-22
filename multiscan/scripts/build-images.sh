#!/usr/bin/env bash
# Build the custom scanner images under docker/<name>/, tagged multiscan/<name>:1.
# These scanners have no maintained upstream image; their Dockerfiles are pinned
# and version-controlled here. Run once on every host that will run workers.
set -eu
cd "$(dirname "$0")/.."
n=0
for d in docker/*/; do
  name=$(basename "$d")
  printf 'building multiscan/%s:1 ... ' "$name"
  if docker build -q -t "multiscan/$name:1" "$d" >/dev/null; then
    echo ok
    n=$((n + 1))
  else
    echo FAILED
  fi
done
echo "built $n image(s)"
