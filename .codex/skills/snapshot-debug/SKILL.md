---
name: snapshot-debug
description: >-
  Investigate and debug Ghostty scrollback snapshot persistence issues.
  Use when scrollback restore fails after app restart, upgrade, or rebase+rebuild.
  Use when investigating missing manifests, FileNotFound errors, UUID mismatches,
  or cleanup race conditions. Also use to take pre/post restart inventory of
  snapshots for QA validation.
---

# Snapshot Debug

Diagnostic toolkit for Ghostty's binary scrollback persistence feature.
Covers the full save/load/cleanup lifecycle and known failure modes.

## Quick Commands

### Snapshot inventory

Decode all GSNP manifest headers and display session metadata:

```bash
uv run .claude/skills/snapshot-debug/scripts/snapshot_inventory.py
```

Save inventory for pre/post restart comparison:

```bash
uv run .claude/skills/snapshot-debug/scripts/snapshot_inventory.py --save /tmp/snap-before.json
```

JSON output for programmatic use:

```bash
uv run .claude/skills/snapshot-debug/scripts/snapshot_inventory.py --json
```

### Restore logs

Check macOS unified logs for scrollback restore activity. Write the
predicate via a temp script to avoid shell quoting issues with the Bash
tool:

```bash
cat > /tmp/gl.sh << 'SCRIPT'
#!/bin/bash
log show --last "${1:-5m}" --info \
  --predicate 'subsystem == "com.mitchellh.ghostty"' \
  --style compact
SCRIPT
chmod +x /tmp/gl.sh

# Then filter for restore-related messages:
/tmp/gl.sh 10m 2>&1 | grep -i 'scrollback\|persist\|restore\|cleanup\|manifest'
```

The `log show` predicate requires specific quoting that the Bash tool
mangles. Always use the script wrapper above.

### Log levels in release builds

| Level | Visibility | Examples |
|-------|-----------|----------|
| info  | Release + Debug | `persisted scrollback restore loaded`, `restore disabled`, `restore unavailable` |
| warn  | Release + Debug | `persisted scrollback restore skipped path=... err=...`, hydration failures |
| debug | Debug only | `persisted scrollback save enabled/disabled`, PersistedState.init details |

## QA Workflow: Pre/Post Restart Comparison

### Before restart

```bash
uv run .claude/skills/snapshot-debug/scripts/snapshot_inventory.py --save /tmp/snap-before.json
```

Note the UUID count and key sessions (by pwd/title).

### After restart

```bash
# Check what's on disk now
uv run .claude/skills/snapshot-debug/scripts/snapshot_inventory.py

# Check restore logs
/tmp/gl.sh 10m 2>&1 | grep -i 'scrollback\|persist\|restore'

# Compare UUIDs
python3 -c "
import json
before = {e['uuid'][:8]: e for e in json.load(open('/tmp/snap-before.json'))}
after_raw = $(uv run .claude/skills/snapshot-debug/scripts/snapshot_inventory.py --json)
# Or just visually compare the two inventory outputs
"
```

What to look for:
- **All `restore loaded`**: everything worked
- **`restore skipped err=error.FileNotFound`**: manifest deleted before load — check UUID mismatch or cleanup race
- **`restore skipped err=error.InvalidSnapshot`**: binary format mismatch (version or corrupt data)
- **`restore disabled reason=...`**: config prevents restore (snapshot-limit=0)
- **`restore unavailable reason=no-session-id`**: no session ID provided by apprt
- **Missing UUIDs**: compare before/after — if UUIDs changed entirely, macOS state restoration gave back different surface IDs (app upgrade scenario)
- **`error flushing persisted scrollback`**: save side failing — manifest path or directory missing

## Architecture

### Binary format (GSNP v1)

```
Offset  Size   Field
0       4      Magic: "GSNP"
4       2      Version: 1 (u16 LE)
6       2      Flags (bit 0: has_alternate)
8       8      Reserved (zeros)
16      8      Timestamp (i64 LE, unix seconds)
24      2      Cols (u16 LE)
26      2      Rows (u16 LE)
28      4+N    Session ID (u32 length + UTF-8)
...     4+N    PWD (u32 length + UTF-8)
...     4+N    Title (u32 length + UTF-8)
...     ...    Primary screen block (styles + rows + graphemes)
...     ...    Alternate screen block (if flagged)
```

Cells are serialized as `@bitCast(u64)` of the packed `Cell` struct.
If `Cell` layout changes upstream, existing snapshots produce garbage.
Check `src/terminal/page.zig` for `Cell = packed struct(u64)`.

### Save flow

```
terminal content changes
  → markPersistedScrollbackDirtyLocked() sets dirty=true
  → persistedScrollbackCallback (timer) or stopCallback (shutdown)
    → capturePersistedScrollback()
      → snapshot.write() serializes primary + alternate screens
      → verifies non-empty via snapshot.read() roundtrip
    → persisted_scrollback.publish()
      → writes to manifest.tmp (mode 0o600)
      → atomic rename to manifest path
```

Key files:
- `src/termio/Termio.zig` — orchestration, dirty tracking, capture
- `src/termio/persisted_scrollback.zig` — file I/O, atomic publish
- `src/terminal/snapshot.zig` — binary serialization

### Load flow

```
Surface.init (macOS state restoration)
  → apprt passes surface UUID as surface_cfg.surfaceUUID
  → embedded.zig extracts surface_uuid directly (not via env map)
  → embedded.zig passes session_id to core Surface.init opts
  → Surface.zig forwards opts.session_id to termio.Options
  → Termio.init receives session_id directly
    → maybeLoadPersistedScrollback(alloc, config, session_id)
      → persisted_scrollback.manifestPath(alloc, session_id) derives path
      → persisted_scrollback.load() reads file
      → snapshot.read() deserializes binary data
    → hydrateRestoredTerminal() populates terminal screen
    → restoredSessionMarker() appends "[Restored ...]" label
```

Key files:
- `src/apprt/embedded.zig` — extracts surface_uuid, passes as session_id
- `src/Surface.zig` — forwards opts.session_id to termio Options
- `src/termio/Termio.zig` — maybeLoadPersistedScrollback, hydration
- `src/termio/persisted_scrollback.zig` — manifestPath, load

### Cleanup flow

```
ghostty_app_new (app startup)
  → persisted_scrollback.cleanupStaleSessions(alloc, 7 days)
    → scans $XDG_STATE_HOME/ghostty/session/*/
    → checks manifest mtime for each session directory
    → deletes directories whose manifest is older than retention period
    → active sessions stay fresh via the 300ms save timer
```

Key files:
- `src/apprt/embedded.zig` — calls cleanupStaleSessions during app init
- `src/termio/persisted_scrollback.zig` — cleanupStaleSessions, sessionBaseDir

### UUID lifecycle

```
Surface creation:
  SurfaceView.init() → self.id = uuid ?? UUID()  (new or restored)

Encoding (app quit / state save):
  encode(to:) → saves id.uuidString to NSCoder

Decoding (app restore):
  init(from decoder:) → reads uuidString → UUID(uuidString:)

Session ID plumbing (direct, no env map):
  Swift: surface_cfg.surfaceUUID = self.id.uuidString
  → C config: ghostty_surface_config_s.surface_uuid
  → embedded.zig: extracts uuid, passes as session_id to Surface.init opts
  → Surface.zig: forwards opts.session_id to termio.Options.session_id
  → Termio: persisted_scrollback.manifestPath(alloc, session_id)
    → $XDG_STATE_HOME/ghostty/session/{uuid}/manifest
```

## Known Bugs

### Bug 1: Env var lost via changeConditionalState (FIXED — eliminated)

**Status:** Root cause eliminated by refactor. The session ID now flows
as a direct parameter on `termio.Options`, bypassing the config env map
entirely. The manifest path env var no longer exists.

**Historical context:** `Surface.zig:init` calls `changeConditionalState`
which rebuilds config from replay steps. Programmatic env vars were lost
in the rebuild. This affected any theme-conditional config like
`theme = light:X,dark:Y`. The `TERM_SESSION_ID` env var is still preserved
via `c.env = config_original.env` in Surface.zig for child process use.

### Bug 2: UUID mismatch on app upgrade (MITIGATED)

**Status:** Mitigated by time-based cleanup (7-day retention). Orphaned
manifests are no longer deleted immediately — they survive until their
mtime exceeds the retention period.

**Remaining risk:** If macOS assigns new UUIDs after an app upgrade, the
old manifests exist on disk but the restored surfaces have different UUIDs.
The restore will fail with `error.FileNotFound` for those sessions. The
old manifests will be cleaned up after 7 days.

**Diagnosis:**
1. Run inventory before and after restart — UUIDs will be different
2. Logs show `restore skipped err=error.FileNotFound` for every surface
3. Old manifests still exist on disk (check inventory — they'll have old
   modification times and non-matching UUIDs)

**Potential further fixes:**
- Match manifests by content (pwd + session_id) rather than only by UUID
- Provide a manual recovery tool that remaps orphaned manifests to new UUIDs

### Bug 3: Cleanup race condition (FIXED — eliminated)

**Status:** Root cause eliminated by refactor. The complex Swift
registration/settlement/fallback state machine was replaced with a simple
time-based mtime scan in the Zig core. No coordination with restoration
timing is needed — active sessions keep their manifests fresh via the
300ms save timer, and stale sessions are cleaned up after 7 days.
