#!/usr/bin/env bash
set -euo pipefail

dir="${1:-}"

if [[ -z "$dir" || ! -d "$dir" ]]; then
  echo "Usage: $0 <directory>"
  exit 1
fi

shopt -s nullglob
for f in "$dir"/*.suit; do
  base="$(basename "$f")"
  python tools/manifest_extractor.py "$f" "inner/inner_${base}"
done
