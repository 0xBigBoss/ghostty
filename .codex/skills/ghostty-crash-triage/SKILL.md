---
name: ghostty-crash-triage
description: Triage Ghostty macOS crashes by extracting .ghosttycrash envelopes, matching minidumps to dSYM debug IDs, symbolicating with lldb/atos, and writing a dated bug+crash report archive entry. Use when debugging Ghostty renderer crashes, OSC8 hover issues, or any panic/index-out-of-bounds reports captured in ~/.local/state/ghostty/crash.
---

# Ghostty Crash Triage

## Overview
Extract a Sentry envelope from `~/.local/state/ghostty/crash`, match its debug ID to a dSYM, symbolicate the minidump, and write a minimal bug report with evidence in the repo archive.

## Workflow

### 1) Collect the crash envelope and extract the minidump
- Pick the newest `.ghosttycrash` in `~/.local/state/ghostty/crash`.
- Copy the envelope into the repo archive directory for today.
- Run the extractor script to write `event_summary.json` and the `.dmp`:

```bash
python .codex/skills/ghostty-crash-triage/scripts/extract_sentry_envelope.py \
  ~/.local/state/ghostty/crash/<id>.ghosttycrash \
  bug-crash-reports/<YYYY-MM-DD>
```

### 2) Match debug_id to a dSYM
- Read `ghostty_image.debug_id` from `event_summary.json`.
- Compare against available dSYMs:

```bash
dwarfdump --uuid macos/build/ReleaseLocal/Ghostty.app.dSYM
# or
if [ -d /Applications/Ghostty.app ]; then
  dwarfdump --uuid /Applications/Ghostty.app/Contents/MacOS/ghostty
fi
```

Use the dSYM whose UUID matches the event’s `debug_id`.

### 3) Symbolicate the minidump stack
Use lldb with the matching dSYM path and filter to frames:

```bash
.codex/skills/ghostty-crash-triage/scripts/lldb_bt.sh \
  bug-crash-reports/<YYYY-MM-DD>/<minidump>.dmp \
  /Applications/Ghostty.app/Contents/MacOS/ghostty \
  macos/build/ReleaseLocal \
  bug-crash-reports/<YYYY-MM-DD>/lldb_bt.txt
```

### 4) Inspect the likely source
- Open the top Ghostty frames in the backtrace and jump to files/lines.
- Common renderer crash pattern: `RenderState.linkCells` indexing `row_pins[viewport_point.y]` without bounds checks while render state lags resize.

### 5) Write a mini bug report
Create `bug-crash-reports/<YYYY-MM-DD>/REPORT.md` with:
- Summary, release/build tags, OS context (from `event_summary.json`).
- Symbolicated stack (from `lldb_bt.txt`).
- Hypothesis + candidate fix area.
- List of archived files.

## Scripts
- `scripts/extract_sentry_envelope.py`: Parse `.ghosttycrash`, extract minidump and write `event_summary.json`.
- `scripts/lldb_bt.sh`: Run lldb on a minidump and write a concise backtrace.
