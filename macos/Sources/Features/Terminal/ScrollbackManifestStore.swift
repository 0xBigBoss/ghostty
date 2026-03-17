import Foundation

/// Scrollback session directory management and cleanup are now handled by
/// the Zig core (`src/termio/persisted_scrollback.zig`). The core derives
/// manifest paths from the surface UUID and uses time-based mtime cleanup.
///
/// This file is intentionally empty — the enum is retained only as a
/// namespace anchor so existing import sites don't break during the
/// migration.
enum ScrollbackManifestStore {}
