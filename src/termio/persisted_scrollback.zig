const std = @import("std");
const Allocator = std.mem.Allocator;

const terminalpkg = @import("../terminal/main.zig");
const snapshot = terminalpkg.snapshot;

const posix = std.posix;

const log = std.log.scoped(.persisted_scrollback);

pub const Header = struct {
    timestamp: i64,
    cols: u16,
    rows: u16,
};

/// Pre-serialized snapshot data ready to be written to disk.
pub const Capture = struct {
    snapshot_data: []const u8,
};

/// Result of loading a persisted snapshot.
/// This is a re-export of snapshot.ReadResult.
pub const Loaded = snapshot.ReadResult;

pub const Error = error{
    InvalidSnapshot,
    UnsupportedVersion,
    InvalidDimensions,
};

/// Write pre-serialized snapshot data to the manifest file atomically.
pub fn publish(
    manifest_path: []const u8,
    capture: Capture,
) (std.fs.File.OpenError || std.fs.File.WriteError || std.fs.Dir.RenameError)!void {
    var manifest_dir = try openParentDir(manifest_path);
    defer manifest_dir.close();

    const manifest_name = std.fs.path.basename(manifest_path);
    try writeFileAtomic(&manifest_dir, manifest_name, capture.snapshot_data);
}

/// Load a binary snapshot from the manifest file.
pub fn load(
    alloc: Allocator,
    manifest_path: []const u8,
    max_file_size: usize,
) (Allocator.Error || std.fs.File.OpenError || std.fs.File.ReadError || snapshot.Error)!Loaded {
    const raw = try readFileAlloc(alloc, manifest_path, max_file_size);
    defer alloc.free(raw);

    return try snapshot.read(alloc, raw);
}

fn readFileAlloc(
    alloc: Allocator,
    path: []const u8,
    max_len: usize,
) ![]u8 {
    const file = if (std.fs.path.isAbsolute(path))
        try std.fs.openFileAbsolute(path, .{})
    else
        try std.fs.cwd().openFile(path, .{});
    defer file.close();

    return try file.readToEndAlloc(alloc, max_len);
}

fn writeFileAtomic(
    dir: *std.fs.Dir,
    path: []const u8,
    data: []const u8,
) (std.fs.File.OpenError || std.fs.File.WriteError || std.fs.Dir.RenameError)!void {
    var temp_name_buf: [std.fs.max_path_bytes]u8 = undefined;
    const temp_name = try std.fmt.bufPrint(&temp_name_buf, "{s}.tmp", .{path});

    const file = try dir.createFile(temp_name, .{
        .truncate = true,
        .mode = 0o600,
    });
    defer file.close();

    try file.writeAll(data);
    try dir.rename(temp_name, path);
}

fn openParentDir(path: []const u8) !std.fs.Dir {
    const dir_path = std.fs.path.dirname(path) orelse ".";
    return if (std.fs.path.isAbsolute(path))
        try std.fs.openDirAbsolute(dir_path, .{})
    else
        try std.fs.cwd().openDir(dir_path, .{});
}

pub fn dupeOptional(
    alloc: Allocator,
    value: ?[]const u8,
) Allocator.Error!?[]u8 {
    if (value) |bytes| return try alloc.dupe(u8, bytes);
    return null;
}

/// Derive the manifest path for a session ID using XDG state conventions.
/// Returns `$XDG_STATE_HOME/ghostty/session/{session_id}/manifest`,
/// falling back to `$HOME/.local/state/ghostty/session/{session_id}/manifest`.
pub fn manifestPath(alloc: Allocator, session_id: []const u8) ![]u8 {
    // XDG_STATE_HOME takes priority; fall back to $HOME/.local/state
    if (posix.getenv("XDG_STATE_HOME")) |xdg| {
        if (xdg.len > 0) return try std.fs.path.join(alloc, &.{
            xdg, "ghostty", "session", session_id, "manifest",
        });
    }
    const home = posix.getenv("HOME") orelse return error.HomeNotFound;
    if (home.len == 0) return error.HomeNotFound;
    return try std.fs.path.join(alloc, &.{
        home, ".local", "state", "ghostty", "session", session_id, "manifest",
    });
}

/// Create the session directory tree if it doesn't exist.
pub fn ensureSessionDir(manifest_path: []const u8) !void {
    const dir_path = std.fs.path.dirname(manifest_path) orelse return;
    // makePath creates all intermediate directories.
    std.fs.makeDirAbsolute(dir_path) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => {
            // makeDirAbsolute only creates a single level. For nested
            // paths we need to walk up and create parents. Use cwd-based
            // makePath via an opened root directory.
            var root = std.fs.openDirAbsolute("/", .{}) catch return err;
            defer root.close();
            root.makePath(dir_path[1..]) catch return err;
        },
    };
}

/// Return the base session directory (`{state}/ghostty/session`).
fn sessionBaseDir(alloc: Allocator) ![]u8 {
    if (posix.getenv("XDG_STATE_HOME")) |xdg| {
        if (xdg.len > 0) return try std.fs.path.join(alloc, &.{
            xdg, "ghostty", "session",
        });
    }
    const home = posix.getenv("HOME") orelse return error.HomeNotFound;
    if (home.len == 0) return error.HomeNotFound;
    return try std.fs.path.join(alloc, &.{
        home, ".local", "state", "ghostty", "session",
    });
}

/// Delete session directories whose manifest hasn't been modified within
/// `retention_seconds`. Active sessions stay fresh because the 300ms save
/// timer continuously updates the manifest mtime.
pub fn cleanupStaleSessions(alloc: Allocator, retention_seconds: i64) !void {
    const base = try sessionBaseDir(alloc);
    defer alloc.free(base);

    var dir = std.fs.openDirAbsolute(base, .{ .iterate = true }) catch |err| switch (err) {
        // Session directory doesn't exist yet — nothing to clean up.
        error.FileNotFound => return,
        else => return err,
    };
    defer dir.close();

    const now = std.time.timestamp();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .directory) continue;

        var sub = dir.openDir(entry.name, .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => {
                log.warn("stale session cleanup: cannot open dir={s} err={}", .{ entry.name, err });
                continue;
            },
        };
        defer sub.close();

        const stat = sub.statFile("manifest") catch |err| switch (err) {
            // No manifest file — stale empty directory, clean it up.
            error.FileNotFound => {
                dir.deleteTree(entry.name) catch |del_err| {
                    log.warn("stale session cleanup: delete empty dir={s} err={}", .{ entry.name, del_err });
                };
                continue;
            },
            else => {
                log.warn("stale session cleanup: cannot stat manifest dir={s} err={}", .{ entry.name, err });
                continue;
            },
        };

        const mtime_sec: i64 = @intCast(@divFloor(stat.mtime, std.time.ns_per_s));
        if (now - mtime_sec > retention_seconds) {
            dir.deleteTree(entry.name) catch |err| {
                log.warn("stale session cleanup: delete expired dir={s} err={}", .{ entry.name, err });
            };
        }
    }
}

test "cleanupStaleSessions deletes expired and keeps fresh" {
    const testing = std.testing;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create the ghostty/session structure that cleanupStaleSessions scans.
    try tmp.dir.makePath("ghostty/session/stale-uuid");
    try tmp.dir.writeFile(.{
        .sub_path = "ghostty/session/stale-uuid/manifest",
        .data = "old data",
    });
    try tmp.dir.makePath("ghostty/session/fresh-uuid");
    try tmp.dir.writeFile(.{
        .sub_path = "ghostty/session/fresh-uuid/manifest",
        .data = "new data",
    });

    // Backdate the stale session's manifest to 10 days ago.
    const ten_days_ago: i64 = std.time.timestamp() - 10 * 24 * 60 * 60;
    var times = [2]std.c.timespec{
        .{ .sec = ten_days_ago, .nsec = 0 },
        .{ .sec = ten_days_ago, .nsec = 0 },
    };
    var stale_dir = try tmp.dir.openDir("ghostty/session/stale-uuid", .{});
    defer stale_dir.close();
    _ = std.c.utimensat(stale_dir.fd, "manifest", &times, 0);

    // Point XDG_STATE_HOME at our temp dir so cleanupStaleSessions finds it.
    const base = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(base);

    const c_env = @cImport(@cInclude("stdlib.h"));
    const prev_xdg = posix.getenv("XDG_STATE_HOME");
    const base_z = try testing.allocator.dupeZ(u8, base);
    defer testing.allocator.free(base_z);
    _ = c_env.setenv("XDG_STATE_HOME", base_z.ptr, 1);
    defer {
        if (prev_xdg) |v| {
            _ = c_env.setenv("XDG_STATE_HOME", v.ptr, 1);
        } else {
            _ = c_env.unsetenv("XDG_STATE_HOME");
        }
    }

    // Call the actual function under test.
    const retention: i64 = 7 * 24 * 60 * 60;
    try cleanupStaleSessions(testing.allocator, retention);

    // Stale session should be deleted, fresh should remain.
    try testing.expectError(
        error.FileNotFound,
        tmp.dir.access("ghostty/session/stale-uuid/manifest", .{}),
    );
    try tmp.dir.access("ghostty/session/fresh-uuid/manifest", .{});
}

test "manifestPath uses XDG_STATE_HOME" {
    const testing = std.testing;
    // This test relies on HOME being set, which it always is in practice.
    const path = try manifestPath(testing.allocator, "test-uuid-1234");
    defer testing.allocator.free(path);
    // Should end with the expected suffix
    try testing.expect(std.mem.endsWith(u8, path, "ghostty/session/test-uuid-1234/manifest"));
}

test "persisted scrollback binary snapshot roundtrip" {
    const testing = std.testing;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("session");
    const session_path = try tmp.dir.realpathAlloc(testing.allocator, "session");
    defer testing.allocator.free(session_path);
    const manifest_path = try std.fs.path.join(testing.allocator, &.{ session_path, "manifest" });
    defer testing.allocator.free(manifest_path);

    // Create a terminal to generate snapshot data
    const Terminal = terminalpkg.Terminal;
    var term = try Terminal.init(testing.allocator, .{
        .cols = 80,
        .rows = 24,
    });
    defer term.deinit(testing.allocator);

    const screen = &term.screens.active.*;

    // Serialize snapshot
    var buf: std.Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();

    try snapshot.write(testing.allocator, &buf.writer, .{
        .primary = screen,
        .session_id = "test-session",
        .pwd = "/tmp/test",
        .title = "test title",
        .timestamp = 1735689600,
    });

    const snapshot_data = try buf.toOwnedSlice();
    defer testing.allocator.free(snapshot_data);

    // Publish to disk
    try publish(manifest_path, .{ .snapshot_data = snapshot_data });

    // Load from disk
    var loaded = try load(testing.allocator, manifest_path, 10 * 1024 * 1024);
    defer loaded.deinit(testing.allocator);

    try testing.expectEqual(@as(u16, 80), loaded.header.cols);
    try testing.expectEqual(@as(u16, 24), loaded.header.rows);
    try testing.expectEqual(@as(i64, 1735689600), loaded.header.timestamp);
    try testing.expectEqualStrings("test-session", loaded.session_id.?);
    try testing.expectEqualStrings("/tmp/test", loaded.pwd.?);
    try testing.expectEqualStrings("test title", loaded.title.?);
}

test "persisted scrollback load rejects old GSRM format" {
    const testing = std.testing;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("session");
    try tmp.dir.writeFile(.{
        .sub_path = "session/manifest",
        .data = "GSRM 1\n" ++
            "timestamp=1\n" ++
            "cols=80\n" ++
            "rows=24\n",
    });

    const manifest_path = try tmp.dir.realpathAlloc(testing.allocator, "session/manifest");
    defer testing.allocator.free(manifest_path);

    try testing.expectError(
        error.InvalidSnapshot,
        load(testing.allocator, manifest_path, 1024),
    );
}

test "persisted scrollback load rejects broken file" {
    const testing = std.testing;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("session");
    try tmp.dir.writeFile(.{
        .sub_path = "session/manifest",
        .data = "broken data",
    });

    const manifest_path = try tmp.dir.realpathAlloc(testing.allocator, "session/manifest");
    defer testing.allocator.free(manifest_path);

    try testing.expectError(
        error.InvalidSnapshot,
        load(testing.allocator, manifest_path, 1024),
    );
}

test "persisted scrollback publish overwrites old file" {
    const testing = std.testing;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("session");
    const session_path = try tmp.dir.realpathAlloc(testing.allocator, "session");
    defer testing.allocator.free(session_path);
    const manifest_path = try std.fs.path.join(testing.allocator, &.{ session_path, "manifest" });
    defer testing.allocator.free(manifest_path);

    // Write first snapshot
    const Terminal = terminalpkg.Terminal;
    var term = try Terminal.init(testing.allocator, .{
        .cols = 80,
        .rows = 24,
    });
    defer term.deinit(testing.allocator);

    {
        var buf: std.Io.Writer.Allocating = .init(testing.allocator);
        defer buf.deinit();
        try snapshot.write(testing.allocator, &buf.writer, .{
            .primary = &term.screens.active.*,
            .timestamp = 1,
        });
        const data = try buf.toOwnedSlice();
        defer testing.allocator.free(data);
        try publish(manifest_path, .{ .snapshot_data = data });
    }

    // Write second snapshot (overwrites first)
    {
        var buf: std.Io.Writer.Allocating = .init(testing.allocator);
        defer buf.deinit();
        try snapshot.write(testing.allocator, &buf.writer, .{
            .primary = &term.screens.active.*,
            .timestamp = 2,
        });
        const data = try buf.toOwnedSlice();
        defer testing.allocator.free(data);
        try publish(manifest_path, .{ .snapshot_data = data });
    }

    // Load and verify it's the second snapshot
    var loaded = try load(testing.allocator, manifest_path, 10 * 1024 * 1024);
    defer loaded.deinit(testing.allocator);

    try testing.expectEqual(@as(i64, 2), loaded.header.timestamp);
}
