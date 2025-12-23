---
name: ghostty-crash-triage
description: Triage Ghostty macOS crashes by extracting .ghosttycrash envelopes, matching minidumps to dSYM debug IDs, symbolicating with lldb/atos, and writing a dated bug+crash report archive entry. Use when debugging Ghostty renderer crashes, OSC8 hover issues, or any panic/index-out-of-bounds reports captured in ~/.local/state/ghostty/crash.
---

# Ghostty Crash Triage

## Overview

Extract a Sentry envelope from `~/.local/state/ghostty/crash`, match its debug ID to a dSYM, symbolicate the minidump, and write a minimal bug report with evidence in the repo archive.

## Quick Start

Run the one-command triage:

```bash
python .claude/skills/ghostty-crash-triage/scripts/triage.py
```

This will:
1. Select the newest crash file
2. Extract the minidump and event metadata
3. Search for a matching dSYM
4. Symbolicate with lldb (or fall back to atos if dSYM is unavailable)
5. Generate a REPORT.md skeleton

### Options

```bash
# Triage a specific crash file
python scripts/triage.py ~/.local/state/ghostty/crash/<id>.ghosttycrash

# Specify output directory
python scripts/triage.py --out-dir bug-crash-reports/my-issue

# Add extra dSYM search paths
python scripts/triage.py --dsym-search ~/my-dsyms
```

## Output Files

After running triage, the output directory contains:

| File | Description |
|------|-------------|
| `<id>.ghosttycrash` | Original crash envelope (copied) |
| `<uuid>.dmp` | Extracted minidump |
| `event_summary.json` | Parsed event metadata (release, OS, debug_id, etc.) |
| `dsym_uuids.txt` | All discovered dSYM UUIDs for reference |
| `lldb_bt.txt` | Symbolicated (or raw) backtrace from lldb |
| `atos_bt.txt` | Fallback symbolication via atos (if dSYM unavailable) |
| `REPORT.md` | Bug report skeleton to fill in |

## dSYM Archive Strategy

### The Problem

dSYM files are required for symbolication but are lost when the app is rebuilt. If you rebuild Ghostty after a crash, the new dSYM won't match the crash's `debug_id`.

### Recommended Solution

Archive dSYMs by debug_id in `~/.ghostty-dsyms/`:

```
~/.ghostty-dsyms/
├── 02F9811F-0F22-3C7B-BC89-79A31322DB2B/
│   └── Ghostty.app.dSYM/
├── BD9D9D6C-F0AB-318A-90A2-3192BFC87875/
│   └── Ghostty.app.dSYM/
└── ...
```

After building a release, archive the dSYM:

```bash
# Get the debug_id from the dSYM
UUID=$(dwarfdump --uuid macos/build/ReleaseLocal/Ghostty.app.dSYM | grep arm64 | awk '{print $2}')

# Archive it
mkdir -p ~/.ghostty-dsyms/$UUID
cp -r macos/build/ReleaseLocal/Ghostty.app.dSYM ~/.ghostty-dsyms/$UUID/
```

The triage script automatically searches `~/.ghostty-dsyms/` for matching dSYMs.

### Search Order

The triage script searches these locations (in order):

1. Extra paths via `--dsym-search`
2. `~/.ghostty-dsyms/` (archived dSYMs)
3. `macos/build/ReleaseLocal/` (local build)
4. `/Applications/Ghostty.app/` (installed app)

Modify `scripts/config.json` to customize the search paths.

## Manual Workflow

For advanced use, the individual scripts can be run manually:

### 1) Extract the envelope

```bash
python scripts/extract_sentry_envelope.py \
  ~/.local/state/ghostty/crash/<id>.ghosttycrash \
  bug-crash-reports/<YYYY-MM-DD>
```

### 2) Match debug_id to a dSYM

Read `ghostty_image.debug_id` from `event_summary.json` and compare:

```bash
dwarfdump --uuid macos/build/ReleaseLocal/Ghostty.app.dSYM
```

### 3) Symbolicate with lldb

```bash
scripts/lldb_bt.sh \
  bug-crash-reports/<YYYY-MM-DD>/<minidump>.dmp \
  /Applications/Ghostty.app/Contents/MacOS/ghostty \
  macos/build/ReleaseLocal \
  bug-crash-reports/<YYYY-MM-DD>/lldb_bt.txt
```

### 4) Fallback with atos (if no matching dSYM)

```bash
# Get load address from event_summary.json (image_addr field)
atos -o /path/to/ghostty -arch arm64 -l 0x100eec000 \
  0x00000001015b5d38 0x00000001015b59f8 ...
```

## Scripts

| Script | Description |
|--------|-------------|
| `triage.py` | One-command orchestrator (recommended) |
| `extract_sentry_envelope.py` | Parse `.ghosttycrash`, extract minidump |
| `lldb_bt.sh` | Run lldb on a minidump, filter to frames |
| `config.json` | Configuration for search paths and thresholds |

## Configuration

Edit `scripts/config.json`:

```json
{
  "dsym_search_paths": [
    "~/.ghostty-dsyms",
    "macos/build/ReleaseLocal",
    "/Applications/Ghostty.app/Contents/MacOS"
  ],
  "crash_dir": "~/.local/state/ghostty/crash",
  "output_root": "bug-crash-reports",
  "unsymbolicated_threshold": 0.5
}
```

- `dsym_search_paths`: Directories to search for dSYMs and binaries
- `crash_dir`: Where Ghostty writes crash files
- `output_root`: Base directory for triage output
- `unsymbolicated_threshold`: Ratio of unsymbolicated frames to trigger atos fallback

## Creating GitHub Discussions

Ghostty uses GitHub Discussions as the first line of reporting for bugs and crashes. After triaging a crash, create a `DISCUSSION.md` file in the output directory following the Issue Triage template.

### Discussion Template

The discussion should include:

| Section | Description |
|---------|-------------|
| Issue Description | Detailed description with root cause, trigger, Sentry UUID, and symbolicated stack trace |
| Expected Behavior | What should happen (e.g., "empty slice should be a no-op") |
| Actual Behavior | What actually happens (the crash) |
| Reproduction Steps | Steps to trigger the crash |
| Ghostty Logs | The panic message and relevant stack frames |
| Ghostty Version | Output from `event_summary.json` or `ghostty +version` |
| OS Version | From `event_summary.json` contexts.os |
| Minimal Config | Configuration needed to reproduce (or "default") |
| Fix (if available) | Commit hash and summary of the fix |

See `bug-crash-reports/2025-12-25/DISCUSSION.md` for an example.

### Creating via GitHub CLI

After writing `DISCUSSION.md`, create the discussion using the GraphQL API:

```bash
# Read the discussion content
BODY=$(cat bug-crash-reports/<date>/DISCUSSION.md)
TITLE="Search thread crash: integer underflow in CircBuf.getPtrSlice"

# Create the discussion
gh api graphql -f query='
mutation($repositoryId: ID!, $categoryId: ID!, $title: String!, $body: String!) {
  createDiscussion(input: {
    repositoryId: $repositoryId
    categoryId: $categoryId
    title: $title
    body: $body
  }) {
    discussion {
      url
    }
  }
}' \
  -f repositoryId="R_kgDOHFhdAg" \
  -f categoryId="DIC_kwDOHFhdAs4Cmv-L" \
  -f title="$TITLE" \
  -f body="$BODY"
```

### Reference IDs

| ID | Description |
|----|-------------|
| `R_kgDOHFhdAg` | ghostty-org/ghostty repository ID |
| `DIC_kwDOHFhdAs4Cmv-L` | Issue Triage category ID |

### Listing Categories

To discover category IDs:

```bash
gh api graphql -f query='{
  repository(owner: "ghostty-org", name: "ghostty") {
    discussionCategories(first: 10) {
      nodes { id name }
    }
  }
}'
```
