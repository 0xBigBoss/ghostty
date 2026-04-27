# Persisted Scrollback Termination And Scheduling

Ghostty persists terminal scrollback so sessions can be restored after relaunch, but the final visible terminal state is not guaranteed when the app quits quickly. The current macOS quit path saves window restoration metadata and then relies on surface destruction to eventually stop the IO thread. That is too weak for app termination because process exit can arrive before the final persisted scrollback flush runs.

The solution is to make persisted scrollback lifecycle ownership explicit:

- the app requests a bounded termination flush before quit completes
- the IO thread performs the final flush itself so the snapshot is taken from the authoritative terminal state
- background persistence favors burst coalescing and bounded staleness instead of constant high-frequency writes
- transient manifest write failures reschedule retries instead of waiting for future terminal mutations
- stale session directory cleanup runs throughout long-lived app processes, not only during startup

## Domain Model

- A `Surface` owns a `Termio`, renderer thread, and IO thread.
- `Termio` owns persisted scrollback state for one terminal session.
- Persisted scrollback stores a binary manifest snapshot derived from terminal state, not a replay log of terminal events.
- The macOS app owns the quit decision and must ask each active surface to prepare for termination before returning control to AppKit.
- The embedded app owns periodic stale session cleanup, while `Termio` close owns the session-close cleanup trigger.

## Requirements

- REQ-SNAPSHOT-001: App termination must request an explicit final persisted scrollback flush for every active macOS surface before quit completes.
- REQ-SNAPSHOT-002: Final termination flush must be bounded by a timeout. Quit must continue if the timeout expires.
- REQ-SNAPSHOT-003: Final termination flush must be performed from the IO side of the surface lifecycle so it observes the latest terminal state.
- REQ-SNAPSHOT-004: Termination may request graceful child shutdown before the final flush and may drain PTY output for a short bounded grace period.
- REQ-SNAPSHOT-005: Persisted scrollback background scheduling must coalesce bursty output with a short trailing debounce.
- REQ-SNAPSHOT-006: Persisted scrollback background scheduling must cap staleness during sustained output with a longer maximum interval.
- REQ-SNAPSHOT-007: Manifest publish failures must schedule bounded retries without requiring new terminal mutations.
- REQ-SNAPSHOT-008: Successful persisted scrollback flushes must reset retry state.
- REQ-SNAPSHOT-009: Persisted scrollback diagnostics must expose whether a flush was scheduled, rescheduled, retried, completed, failed, or timed out during termination.
- REQ-SNAPSHOT-010: Stale persisted session cleanup must run once during embedded app startup.
- REQ-SNAPSHOT-011: Stale persisted session cleanup must run hourly while the embedded app process remains alive.
- REQ-SNAPSHOT-012: Stale persisted session cleanup must run from session close, rate-limited so closing many tabs cannot trigger repeated full directory sweeps.
- REQ-SNAPSHOT-013: Stale persisted session cleanup must keep the hardcoded seven-day retention policy until a separate configuration phase changes it.
- REQ-SNAPSHOT-014: Surface close must flush dirty persisted scrollback before `Termio` releases persisted state.
- REQ-SNAPSHOT-015: Surface focus loss must schedule an already-dirty persisted scrollback state for the next immediate background flush without performing disk IO in the focus callback.
- REQ-SNAPSHOT-016: SIGTERM and SIGINT must request graceful app shutdown through an async-signal-safe flag that the app loop consumes.
- REQ-SNAPSHOT-017: The embedded C API must expose an app-wide persisted scrollback flush entry point for native lifecycle delegates to call before process teardown.

## Invariants

- Persisted scrollback remains snapshot-based. Ghostty does not buffer every terminal event for replay.
- Termination preparation must never block indefinitely.
- Background persistence policy must not require user-configurable knobs to preserve correctness.
- A failed persisted scrollback write must not silently leave the surface permanently stale.
- Stale session cleanup must not run on the renderer thread.
- Signal handlers must not call non-async-signal-safe persistence or app teardown code directly.

## Non-goals

- Changing the persisted scrollback file format.
- Changing window restoration semantics.
- Guaranteeing that every shell shutdown transcript is captured in full.
- Turning termination flushing into a best-effort free path that depends on ARC timing alone.
- Making stale session retention configurable.
- Wiring macOS Swift `applicationWillTerminate`.

## Acceptance Criteria

- [ ] Quitting immediately after terminal output restores the latest visible scrollback within the configured timeout budget.
- [ ] Quitting still returns promptly when a child process is slow to exit.
- [ ] Sustained output does not force a manifest rewrite every few hundred milliseconds forever.
- [ ] A transient manifest publish failure retries automatically and later success clears retry state.
- [ ] Diagnostic logs distinguish normal background flushes from termination flushes and retries.
- [ ] A Ghostty process running for more than an hour performs stale session cleanup without requiring restart.
- [ ] Closing a surface can delete a stale persisted session directory, but repeated closes within five minutes do not force repeated sweeps.
- [ ] Losing focus with dirty persisted scrollback schedules an immediate flush decision.
- [ ] SIGTERM or SIGINT exits through the normal app quit path instead of flushing from the signal handler.
- [ ] Native embedders can call `ghostty_app_persist_all` before application termination.

## Test Traceability

- REQ-SNAPSHOT-012: `src/termio/persisted_scrollback.zig` test `cleanupStaleSessionsOnClose deletes expired sessions and rate limits repeated closes`
- REQ-SNAPSHOT-015: `src/termio/Termio.zig` test `persisted scrollback lifecycle request flushes dirty state immediately`
- REQ-SNAPSHOT-016: `src/global.zig` test `graceful shutdown request flag is one-shot`
- REQ-SNAPSHOT-017: `src/apprt/embedded.zig` test `ghostty.h surface config has surface_uuid for session identity`
