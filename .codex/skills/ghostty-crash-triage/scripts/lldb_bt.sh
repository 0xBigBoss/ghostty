#!/usr/bin/env bash
set -euo pipefail

# Usage: lldb_bt.sh <minidump.dmp> <binary> [dsym_dir] [out_file]
# Run lldb on a minidump and extract the backtrace.
# dsym_dir is optional - if empty or missing, no debug-file-search-paths is set.

if [ "$#" -lt 2 ] || [ "$#" -gt 4 ]; then
  echo "Usage: $0 <minidump.dmp> <binary> [dsym_dir] [out_file]" >&2
  exit 2
fi

MINIDUMP="$1"
BINARY="$2"
DSYM_DIR="${3:-}"
OUT_FILE="${4:-}"

if [ ! -f "$MINIDUMP" ]; then
  echo "error: minidump not found: $MINIDUMP" >&2
  exit 1
fi

if [ ! -f "$BINARY" ]; then
  echo "error: binary not found: $BINARY" >&2
  exit 1
fi

# Build lldb command
CMD=(lldb --batch -c "$MINIDUMP" "$BINARY")

# Only set debug-file-search-paths if dsym_dir is provided and exists
if [ -n "$DSYM_DIR" ] && [ -d "$DSYM_DIR" ]; then
  CMD+=(-o "settings set target.debug-file-search-paths $DSYM_DIR")
fi

CMD+=(-o "bt")

# Run lldb and filter to relevant frames
# Capture exit status of lldb (first command in pipeline)
set +e
if [ -n "$OUT_FILE" ]; then
  OUTPUT=$("${CMD[@]}" 2>&1)
  LLDB_EXIT=$?
  if [ $LLDB_EXIT -ne 0 ]; then
    echo "error: lldb failed with exit code $LLDB_EXIT" >&2
    echo "$OUTPUT" >&2
    exit 1
  fi
  echo "$OUTPUT" | rg -n "stop reason|frame #" > "$OUT_FILE"
  echo "wrote $OUT_FILE"
else
  OUTPUT=$("${CMD[@]}" 2>&1)
  LLDB_EXIT=$?
  if [ $LLDB_EXIT -ne 0 ]; then
    echo "error: lldb failed with exit code $LLDB_EXIT" >&2
    echo "$OUTPUT" >&2
    exit 1
  fi
  echo "$OUTPUT" | rg -n "stop reason|frame #"
fi
