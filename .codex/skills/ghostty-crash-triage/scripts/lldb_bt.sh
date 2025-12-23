#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
  echo "Usage: $0 <minidump.dmp> <binary> <dsym_dir> [out_file]" >&2
  exit 2
fi

MINIDUMP="$1"
BINARY="$2"
DSYM_DIR="$3"
OUT_FILE="${4:-}"

CMD=(lldb --batch -c "$MINIDUMP" "$BINARY" \
  -o "settings set target.debug-file-search-paths $DSYM_DIR" \
  -o "bt")

if [ -n "$OUT_FILE" ]; then
  "${CMD[@]}" 2>/dev/null | rg -n "stop reason|frame #" > "$OUT_FILE"
  echo "wrote $OUT_FILE"
else
  "${CMD[@]}" 2>/dev/null | rg -n "stop reason|frame #"
fi
