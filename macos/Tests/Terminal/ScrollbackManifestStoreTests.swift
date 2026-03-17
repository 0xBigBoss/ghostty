import Testing

/// ScrollbackManifestStore tests were removed because session directory
/// management and cleanup moved to the Zig core
/// (`src/termio/persisted_scrollback.zig`). The Zig-side tests cover
/// manifest path derivation, roundtrip serialization, and stale session
/// cleanup.
struct ScrollbackManifestStoreTests {}
