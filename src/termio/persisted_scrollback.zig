const std = @import("std");
const Allocator = std.mem.Allocator;

const terminalpkg = @import("../terminal/main.zig");
const snapshot = terminalpkg.snapshot;

const posix = std.posix;

const log = std.log.scoped(.persisted_scrollback);

const magic_header = "GSPH";
const magic_metadata = "GSPM";
const magic_screen = "GSPS";
const current_version: u16 = 1;
const header_size: usize = 22;
const screen_prefix_size: usize = 14;
const scrollback_record_prefix_size: usize = 12;

/// Screen state is structurally bounded by terminal dimensions, not by the
/// user-facing scrollback log cap. Four MiB covers large visible screens while
/// still preventing unbounded reads from damaged or hostile session dirs.
pub const screen_file_max_size: usize = 4 * 1024 * 1024;

pub const Limits = struct {
    /// `scrollback-snapshot-limit` caps the on-disk scrollback log file only.
    /// Screen, header, and metadata files have internal hard caps appropriate
    /// to their structure, independent of user config.
    scrollback: usize,
    screen: usize = screen_file_max_size,
    header: usize = 4096,
    metadata: usize = 64 * 1024,
};

pub const Header = struct {
    timestamp: i64,
    cols: u16,
    rows: u16,
};

pub const Metadata = struct {
    session_id: ?[]const u8 = null,
    pwd: ?[]const u8 = null,
    title: ?[]const u8 = null,
};

pub const ScrollbackRecord = struct {
    bytes: []const u8,
};

/// Pre-serialized component data ready to be written to a session directory.
pub const Capture = struct {
    /// Written whenever the capture header differs from the durable header.
    header: ?Header = null,
    metadata: ?Metadata = null,
    scrollback_append: []const ScrollbackRecord = &.{},
    scrollback_first_seq: u64 = 0,
    rewrite_scrollback: bool = false,
    screen: ?[]const u8 = null,
    screen_seq: u64 = 0,
    screen_alt: ?[]const u8 = null,
    screen_alt_seq: ?u64 = null,
};

pub const PublishProgress = struct {
    header_written: bool = false,
    metadata_written: bool = false,
    scrollback_appended: bool = false,
    scrollback_tail_seq_after: u64 = 0,
    scrollback_size_after: u64 = 0,
    scrollback_record_count_after: usize = 0,
    screen_written: bool = false,
    screen_alt_written: bool = false,
};

/// Result of loading a persisted multi-file snapshot.
pub const Loaded = struct {
    header: snapshot.Header,
    session_id: ?[]u8 = null,
    pwd: ?[]u8 = null,
    title: ?[]u8 = null,
    primary: snapshot.ScreenData,
    alternate: ?snapshot.ScreenData = null,
    scrollback_rows: usize = 0,
    scrollback_tail_seq: u64 = 0,
    next_seq: u64 = 0,

    pub fn deinit(self: *Loaded, alloc: Allocator) void {
        if (self.session_id) |v| alloc.free(v);
        if (self.pwd) |v| alloc.free(v);
        if (self.title) |v| alloc.free(v);
        self.primary.deinit(alloc);
        if (self.alternate) |*v| v.deinit(alloc);
        self.* = undefined;
    }
};

pub const Error = error{
    InvalidSnapshot,
    UnsupportedVersion,
    InvalidDimensions,
};

/// Write component snapshot data to the session directory.
pub fn publish(
    session_dir: []const u8,
    capture: Capture,
) !PublishProgress {
    var progress: PublishProgress = .{};
    try publishWithProgress(session_dir, capture, &progress);
    return progress;
}

pub fn publishWithProgress(
    session_dir: []const u8,
    capture: Capture,
    progress: *PublishProgress,
) !void {
    try ensureSessionDir(session_dir);

    var dir = try openSessionDir(session_dir);
    defer dir.close();

    if (capture.header) |header| {
        try writeHeaderReplacing(&dir, header);
        progress.header_written = true;
    }

    if (capture.metadata) |metadata| {
        var buf: std.Io.Writer.Allocating = .init(std.heap.page_allocator);
        defer buf.deinit();
        try writeMetadata(&buf.writer, metadata);
        try writeFileAtomic(&dir, "metadata", buf.writer.buffer[0..buf.writer.end]);
        progress.metadata_written = true;
    }

    // Write screen files before advancing the append-only scrollback log. A
    // crash can then leave the screen newer than scrollback, which restore can
    // tolerate without dropping active rows; the inverse loses visible state.
    if (capture.screen) |screen| {
        var buf: std.Io.Writer.Allocating = .init(std.heap.page_allocator);
        defer buf.deinit();
        try writeScreenFile(&buf.writer, capture.screen_seq, screen);
        try writeFileAtomic(&dir, "screen", buf.writer.buffer[0..buf.writer.end]);
        progress.screen_written = true;
    }

    if (capture.screen_alt) |screen_alt| {
        var buf: std.Io.Writer.Allocating = .init(std.heap.page_allocator);
        defer buf.deinit();
        try writeScreenFile(&buf.writer, capture.screen_alt_seq orelse capture.screen_seq, screen_alt);
        try writeFileAtomic(&dir, "screen.alt", buf.writer.buffer[0..buf.writer.end]);
        progress.screen_alt_written = true;
    } else {
        dir.deleteFile("screen.alt") catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        progress.screen_alt_written = true;
    }

    if (capture.rewrite_scrollback) {
        // Rewrites are reserved for compaction-style captures where the
        // in-memory history head moved behind the persisted log. The normal
        // steady-state path below must only append new records.
        var buf: std.Io.Writer.Allocating = .init(std.heap.page_allocator);
        defer buf.deinit();
        try writeScrollbackRecords(&buf.writer, capture.scrollback_first_seq, capture.scrollback_append);
        try writeFileAtomic(&dir, "scrollback", buf.writer.buffer[0..buf.writer.end]);
        progress.scrollback_appended = true;
        progress.scrollback_size_after = @intCast(buf.writer.end);
        progress.scrollback_record_count_after = capture.scrollback_append.len;
        progress.scrollback_tail_seq_after = if (capture.scrollback_append.len > 0)
            capture.scrollback_first_seq +% @as(u64, @intCast(capture.scrollback_append.len)) -% 1
        else
            0;
    } else if (capture.scrollback_append.len > 0) {
        try appendScrollbackRecordsIdempotent(&dir, capture, progress);
    }
}

/// Load a multi-file snapshot from a session directory.
pub fn load(
    alloc: Allocator,
    session_dir: []const u8,
    limits: Limits,
) (Allocator.Error || std.fs.File.OpenError || std.fs.File.ReadError || snapshot.Error || Error)!Loaded {
    var dir = try openSessionDir(session_dir);
    defer dir.close();

    const header_raw = try readFileAllocDir(alloc, &dir, "header", limits.header);
    defer alloc.free(header_raw);
    const header = try readHeader(header_raw);

    const metadata = readMetadataFile(alloc, &dir, limits.metadata) catch |err| switch (err) {
        error.FileNotFound => MetadataOwned{},
        else => return err,
    };
    errdefer metadata.deinit(alloc);

    var builder: ScreenBuilder = try .init(alloc, header.cols);
    errdefer builder.deinit(alloc);

    // `scrollback-snapshot-limit` caps this append-only log only. Active screen
    // files are separate components with structural hard caps.
    const scrollback_info = try readScrollback(alloc, &dir, limits.scrollback, &builder);
    const scrollback_rows = builder.rowCount();

    const screen_raw = try readFileAllocDir(alloc, &dir, "screen", limits.screen);
    defer alloc.free(screen_raw);
    var screen_file = try readScreenFile(alloc, screen_raw);
    errdefer screen_file.deinit(alloc);

    // Reconciliation example:
    //   scrollback tail seq = 10
    //   screen file seq = 13, rows = [9,10,11,12,13]
    // Rows 9 and 10 are already durable in the append-only log, so load
    // drops that screen prefix and materializes [scrollback...,11,12,13].
    const screen_drop = duplicateScreenPrefixForScrollback(screen_file.seq, screen_file.data.rows.len, scrollback_info);
    try builder.appendOwnedScreen(alloc, &screen_file.data, screen_drop);
    var primary = try builder.toOwned(alloc);
    errdefer primary.deinit(alloc);

    var alternate: ?snapshot.ScreenData = null;
    var max_seq = @max(scrollback_info.tail_seq, screen_file.seq);
    if (readFileAllocDir(alloc, &dir, "screen.alt", limits.screen)) |alt_raw| {
        defer alloc.free(alt_raw);
        var alt_file = try readScreenFile(alloc, alt_raw);
        errdefer alt_file.deinit(alloc);
        max_seq = @max(max_seq, alt_file.seq);

        var alt_builder: ScreenBuilder = try .init(alloc, header.cols);
        errdefer alt_builder.deinit(alloc);
        const alt_drop = duplicateScreenPrefixForScrollback(alt_file.seq, alt_file.data.rows.len, scrollback_info);
        try alt_builder.appendOwnedScreen(alloc, &alt_file.data, alt_drop);
        alternate = try alt_builder.toOwned(alloc);
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    errdefer if (alternate) |*v| v.deinit(alloc);

    return .{
        .header = .{
            .timestamp = header.timestamp,
            .cols = header.cols,
            .rows = header.rows,
        },
        .session_id = metadata.session_id,
        .pwd = metadata.pwd,
        .title = metadata.title,
        .primary = primary,
        .alternate = alternate,
        .scrollback_rows = scrollback_rows,
        .scrollback_tail_seq = scrollback_info.tail_seq,
        .next_seq = max_seq +% 1,
    };
}

const MetadataOwned = struct {
    session_id: ?[]u8 = null,
    pwd: ?[]u8 = null,
    title: ?[]u8 = null,

    fn deinit(self: MetadataOwned, alloc: Allocator) void {
        if (self.session_id) |v| alloc.free(v);
        if (self.pwd) |v| alloc.free(v);
        if (self.title) |v| alloc.free(v);
    }
};

const ScreenFile = struct {
    seq: u64,
    data: snapshot.ScreenData,

    fn deinit(self: *ScreenFile, alloc: Allocator) void {
        self.data.deinit(alloc);
        self.* = undefined;
    }
};

const ScrollbackInfo = struct {
    tail_seq: u64 = 0,
    has_records: bool = false,
};

const ScrollbackDiskState = struct {
    size: u64 = 0,
    tail_seq: u64 = 0,
    record_count: usize = 0,
    has_records: bool = false,
};

const ScreenBuilder = struct {
    styles: std.ArrayListUnmanaged(terminalpkg.Style) = .empty,
    rows: std.ArrayListUnmanaged(snapshot.RowData) = .empty,
    graphemes: std.ArrayListUnmanaged(snapshot.GraphemeEntry) = .empty,
    cols: u16,

    fn init(alloc: Allocator, cols: u16) Allocator.Error!ScreenBuilder {
        _ = alloc;
        return .{ .cols = cols };
    }

    fn deinit(self: *ScreenBuilder, alloc: Allocator) void {
        for (self.graphemes.items) |g| alloc.free(g.codepoints);
        self.graphemes.deinit(alloc);
        for (self.rows.items) |r| alloc.free(r.cells);
        self.rows.deinit(alloc);
        self.styles.deinit(alloc);
        self.* = undefined;
    }

    fn rowCount(self: *const ScreenBuilder) usize {
        return self.rows.items.len;
    }

    fn appendOwnedScreen(
        self: *ScreenBuilder,
        alloc: Allocator,
        data: *snapshot.ScreenData,
        drop_rows: usize,
    ) Allocator.Error!void {
        const style_offset = self.styles.items.len;
        try self.styles.appendSlice(alloc, data.styles);

        for (data.rows[0..drop_rows]) |r| alloc.free(r.cells);

        const row_offset = self.rows.items.len;
        for (data.rows[drop_rows..]) |*row| {
            for (row.cells) |*raw| {
                var cell: terminalpkg.Cell = @bitCast(raw.*);
                if (cell.style_id != 0) cell.style_id = @intCast(@as(usize, cell.style_id) + style_offset);
                raw.* = @bitCast(cell);
            }
            try self.rows.append(alloc, row.*);
        }

        for (data.graphemes) |g| {
            if (g.row_index < drop_rows) {
                alloc.free(g.codepoints);
                continue;
            }
            var adjusted = g;
            adjusted.row_index = @intCast(@as(usize, g.row_index) - drop_rows + row_offset);
            try self.graphemes.append(alloc, adjusted);
        }

        alloc.free(data.styles);
        alloc.free(data.rows);
        alloc.free(data.graphemes);
        data.* = undefined;
    }

    fn toOwned(self: *ScreenBuilder, alloc: Allocator) Allocator.Error!snapshot.ScreenData {
        const styles = try self.styles.toOwnedSlice(alloc);
        errdefer alloc.free(styles);
        const rows = try self.rows.toOwnedSlice(alloc);
        errdefer {
            for (rows) |r| alloc.free(r.cells);
            alloc.free(rows);
        }
        const graphemes = try self.graphemes.toOwnedSlice(alloc);
        errdefer {
            for (graphemes) |g| alloc.free(g.codepoints);
            alloc.free(graphemes);
        }

        return .{
            .styles = styles,
            .rows = rows,
            .graphemes = graphemes,
            .cols = self.cols,
        };
    }
};

fn headerBytes(header: Header) [header_size]u8 {
    var data: [header_size]u8 = undefined;
    @memcpy(data[0..4], magic_header);
    std.mem.writeInt(u16, data[4..6], current_version, .little);
    std.mem.writeInt(u32, data[6..10], 0, .little);
    std.mem.writeInt(i64, data[10..18], header.timestamp, .little);
    std.mem.writeInt(u16, data[18..20], header.cols, .little);
    std.mem.writeInt(u16, data[20..22], header.rows, .little);
    return data;
}

fn writeHeaderReplacing(dir: *std.fs.Dir, header: Header) !void {
    const data = headerBytes(header);

    var file = dir.openFile("header", .{}) catch {
        return try writeFileAtomic(dir, "header", &data);
    };
    defer file.close();

    const stat = file.stat() catch {
        return try writeFileAtomic(dir, "header", &data);
    };
    if (stat.size != header_size) return try writeFileAtomic(dir, "header", &data);

    var existing: [header_size]u8 = undefined;
    const read_len = file.readAll(&existing) catch {
        return try writeFileAtomic(dir, "header", &data);
    };
    if (read_len == header_size and std.mem.eql(u8, &existing, &data)) return;

    try writeFileAtomic(dir, "header", &data);
}

fn readHeader(data: []const u8) Error!Header {
    if (data.len != header_size) return error.InvalidSnapshot;
    if (!std.mem.eql(u8, data[0..4], magic_header)) return error.InvalidSnapshot;
    const version = std.mem.readInt(u16, data[4..6], .little);
    if (version != current_version) return error.UnsupportedVersion;
    const cols = std.mem.readInt(u16, data[18..20], .little);
    const rows = std.mem.readInt(u16, data[20..22], .little);
    if (cols == 0 or rows == 0) return error.InvalidDimensions;
    return .{
        .timestamp = std.mem.readInt(i64, data[10..18], .little),
        .cols = cols,
        .rows = rows,
    };
}

fn writeMetadata(writer: *std.Io.Writer, metadata: Metadata) !void {
    try writer.writeAll(magic_metadata);
    try writer.writeInt(u16, current_version, .little);
    try writeLenPrefixed(writer, metadata.session_id);
    try writeLenPrefixed(writer, metadata.pwd);
    try writeLenPrefixed(writer, metadata.title);
}

fn readMetadataFile(alloc: Allocator, dir: *std.fs.Dir, max_len: usize) !MetadataOwned {
    const data = try readFileAllocDir(alloc, dir, "metadata", max_len);
    defer alloc.free(data);

    if (data.len < 6) return error.InvalidSnapshot;
    if (!std.mem.eql(u8, data[0..4], magic_metadata)) return error.InvalidSnapshot;
    if (std.mem.readInt(u16, data[4..6], .little) != current_version) return error.UnsupportedVersion;

    var pos: usize = 6;
    const session_id = try readLenPrefixed(alloc, data, &pos);
    errdefer if (session_id) |v| alloc.free(v);
    const pwd = try readLenPrefixed(alloc, data, &pos);
    errdefer if (pwd) |v| alloc.free(v);
    const title = try readLenPrefixed(alloc, data, &pos);
    errdefer if (title) |v| alloc.free(v);
    if (pos != data.len) return error.InvalidSnapshot;

    return .{ .session_id = session_id, .pwd = pwd, .title = title };
}

fn writeScreenFile(writer: *std.Io.Writer, seq: u64, screen: []const u8) !void {
    try writer.writeAll(magic_screen);
    try writer.writeInt(u16, current_version, .little);
    try writer.writeInt(u64, seq, .big);
    try writer.writeAll(screen);
}

fn readScreenFile(alloc: Allocator, data: []const u8) (Allocator.Error || Error || snapshot.Error)!ScreenFile {
    if (data.len < screen_prefix_size) return error.InvalidSnapshot;
    if (!std.mem.eql(u8, data[0..4], magic_screen)) return error.InvalidSnapshot;
    if (std.mem.readInt(u16, data[4..6], .little) != current_version) return error.UnsupportedVersion;
    const seq = std.mem.readInt(u64, data[6..14], .big);
    return .{
        .seq = seq,
        .data = try snapshot.readScreenData(alloc, data[14..]),
    };
}

fn writeScrollbackRecords(
    writer: *std.Io.Writer,
    first_seq: u64,
    records: []const ScrollbackRecord,
) !void {
    var seq = first_seq;
    for (records) |record| {
        try writer.writeInt(u64, seq, .big);
        try writer.writeInt(u32, @intCast(record.bytes.len), .big);
        try writer.writeAll(record.bytes);
        seq +%= 1;
    }
}

fn readScrollbackDiskState(file: *std.fs.File) !ScrollbackDiskState {
    const stat = try file.stat();
    try file.seekTo(0);

    var state: ScrollbackDiskState = .{ .size = stat.size };
    var pos: u64 = 0;
    while (pos < stat.size) {
        if (stat.size - pos < scrollback_record_prefix_size) return error.InvalidSnapshot;

        var prefix: [scrollback_record_prefix_size]u8 = undefined;
        const read_len = try file.readAll(&prefix);
        if (read_len != scrollback_record_prefix_size) return error.InvalidSnapshot;

        const seq = std.mem.readInt(u64, prefix[0..8], .big);
        const len = std.mem.readInt(u32, prefix[8..12], .big);
        if (state.has_records and seq <= state.tail_seq) return error.InvalidSnapshot;

        pos += scrollback_record_prefix_size;
        if (stat.size - pos < len) return error.InvalidSnapshot;

        pos += len;
        try file.seekTo(pos);

        state.tail_seq = seq;
        state.record_count += 1;
        state.has_records = true;
    }

    return state;
}

fn appendScrollbackRecordsIdempotent(
    dir: *std.fs.Dir,
    capture: Capture,
    progress: *PublishProgress,
) !void {
    var file = dir.openFile("scrollback", .{ .mode = .read_write }) catch |err| switch (err) {
        error.FileNotFound => try dir.createFile("scrollback", .{
            .read = true,
            .truncate = false,
            .mode = 0o600,
        }),
        else => return err,
    };
    defer file.close();

    const disk_state = try readScrollbackDiskState(&file);
    var first_seq = capture.scrollback_first_seq;
    var records = capture.scrollback_append;
    if (disk_state.has_records and disk_state.tail_seq >= first_seq) {
        const existing_count = disk_state.tail_seq - first_seq + 1;
        const skip_count: usize = @intCast(@min(
            existing_count,
            @as(u64, @intCast(records.len)),
        ));
        first_seq +%= skip_count;
        records = records[skip_count..];
    }

    progress.scrollback_appended = true;
    progress.scrollback_tail_seq_after = disk_state.tail_seq;
    progress.scrollback_size_after = disk_state.size;
    progress.scrollback_record_count_after = disk_state.record_count;

    if (records.len == 0) return;

    try file.seekFromEnd(0);

    // Serialize records into a heap buffer, then writeAll. The buffered
    // std.Io.Writer interface tracks its own pos starting at 0 and ignores
    // the file's kernel seek cursor (it uses pwrite under the hood), so write
    // directly via the legacy file API to honor seekFromEnd.
    var buf: std.Io.Writer.Allocating = .init(std.heap.page_allocator);
    defer buf.deinit();
    try writeScrollbackRecords(&buf.writer, first_seq, records);
    try file.writeAll(buf.writer.buffer[0..buf.writer.end]);

    const stat = try file.stat();
    progress.scrollback_tail_seq_after = first_seq +% @as(u64, @intCast(records.len)) -% 1;
    progress.scrollback_size_after = stat.size;
    progress.scrollback_record_count_after = disk_state.record_count + records.len;
}

fn readScrollback(
    alloc: Allocator,
    dir: *std.fs.Dir,
    max_len: usize,
    builder: *ScreenBuilder,
) (Allocator.Error || std.fs.File.OpenError || std.fs.File.ReadError || Error || snapshot.Error)!ScrollbackInfo {
    const data = readFileAllocDir(alloc, dir, "scrollback", max_len) catch |err| switch (err) {
        error.FileNotFound => return .{},
        else => return err,
    };
    defer alloc.free(data);

    var pos: usize = 0;
    var prev_seq: ?u64 = null;
    while (pos < data.len) {
        if (data.len - pos < scrollback_record_prefix_size) return error.InvalidSnapshot;
        const seq = std.mem.readInt(u64, data[pos..][0..8], .big);
        pos += 8;
        const len = std.mem.readInt(u32, data[pos..][0..4], .big);
        pos += 4;
        if (prev_seq) |prev| {
            if (seq <= prev) return error.InvalidSnapshot;
        }
        if (data.len - pos < len) return error.InvalidSnapshot;

        var record = try snapshot.readScreenData(alloc, data[pos .. pos + len]);
        errdefer record.deinit(alloc);
        try builder.appendOwnedScreen(alloc, &record, 0);

        prev_seq = seq;
        pos += len;
    }

    return .{
        .tail_seq = prev_seq orelse 0,
        .has_records = prev_seq != null,
    };
}

fn duplicateScreenPrefix(screen_seq: u64, row_count: usize, scrollback_tail_seq: u64) usize {
    if (row_count == 0) return 0;
    const first_seq = screen_seq -| (row_count - 1);
    if (scrollback_tail_seq < first_seq) return 0;
    return @min(row_count, scrollback_tail_seq - first_seq + 1);
}

fn duplicateScreenPrefixForScrollback(
    screen_seq: u64,
    row_count: usize,
    scrollback_info: ScrollbackInfo,
) usize {
    if (!scrollback_info.has_records) return 0;
    return duplicateScreenPrefix(screen_seq, row_count, scrollback_info.tail_seq);
}

fn writeLenPrefixed(writer: *std.Io.Writer, data: ?[]const u8) !void {
    if (data) |bytes| {
        try writer.writeInt(u32, @intCast(bytes.len), .little);
        try writer.writeAll(bytes);
    } else {
        try writer.writeInt(u32, 0, .little);
    }
}

fn readLenPrefixed(alloc: Allocator, data: []const u8, pos: *usize) !?[]u8 {
    if (data.len - pos.* < 4) return error.InvalidSnapshot;
    const len = std.mem.readInt(u32, data[pos.*..][0..4], .little);
    pos.* += 4;
    if (len == 0) return null;
    if (data.len - pos.* < len) return error.InvalidSnapshot;
    const result = try alloc.dupe(u8, data[pos.* .. pos.* + len]);
    pos.* += len;
    return result;
}

fn readFileAllocDir(
    alloc: Allocator,
    dir: *std.fs.Dir,
    path: []const u8,
    max_len: usize,
) ![]u8 {
    const file = try dir.openFile(path, .{});
    defer file.close();
    return try file.readToEndAlloc(alloc, max_len);
}

fn writeFileAtomic(
    dir: *std.fs.Dir,
    path: []const u8,
    data: []const u8,
) !void {
    var temp_name_buf: [std.fs.max_path_bytes]u8 = undefined;
    const temp_name = try std.fmt.bufPrint(&temp_name_buf, "{s}.tmp", .{path});

    var file = try dir.createFile(temp_name, .{
        .truncate = true,
        .mode = 0o600,
    });
    defer file.close();

    try file.writeAll(data);
    try dir.rename(temp_name, path);
}

fn openSessionDir(path: []const u8) !std.fs.Dir {
    return if (std.fs.path.isAbsolute(path))
        try std.fs.openDirAbsolute(path, .{})
    else
        try std.fs.cwd().openDir(path, .{});
}

pub fn dupeOptional(
    alloc: Allocator,
    value: ?[]const u8,
) Allocator.Error!?[]u8 {
    if (value) |bytes| return try alloc.dupe(u8, bytes);
    return null;
}

/// Derive the session directory for a session ID using XDG state conventions.
/// Returns `$XDG_STATE_HOME/ghostty/session/{session_id}`,
/// falling back to `$HOME/.local/state/ghostty/session/{session_id}`.
pub fn sessionDirPath(alloc: Allocator, session_id: []const u8) ![]u8 {
    if (posix.getenv("XDG_STATE_HOME")) |xdg| {
        if (xdg.len > 0) return try std.fs.path.join(alloc, &.{
            xdg, "ghostty", "session", session_id,
        });
    }
    const home = posix.getenv("HOME") orelse return error.HomeNotFound;
    if (home.len == 0) return error.HomeNotFound;
    return try std.fs.path.join(alloc, &.{
        home, ".local", "state", "ghostty", "session", session_id,
    });
}

/// Create the session directory tree if it doesn't exist.
pub fn ensureSessionDir(session_dir: []const u8) !void {
    if (std.fs.path.isAbsolute(session_dir)) {
        var root = try std.fs.openDirAbsolute("/", .{});
        defer root.close();
        return try root.makePath(session_dir[1..]);
    }

    return try std.fs.cwd().makePath(session_dir);
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

/// Delete session directories whose recognized state files are stale.
/// Legacy single-file `manifest` directories have no v1 state files and
/// are removed as one-time clean-break cleanup.
pub fn cleanupStaleSessions(alloc: Allocator, retention_seconds: i64) !void {
    const base = try sessionBaseDir(alloc);
    defer alloc.free(base);

    var dir = std.fs.openDirAbsolute(base, .{ .iterate = true }) catch |err| switch (err) {
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

        const stat = sub.statFile("screen") catch |screen_err| switch (screen_err) {
            error.FileNotFound => sub.statFile("header") catch |header_err| switch (header_err) {
                error.FileNotFound => {
                    dir.deleteTree(entry.name) catch |err| {
                        log.warn("stale session cleanup: delete legacy dir={s} err={}", .{ entry.name, err });
                    };
                    continue;
                },
                else => {
                    log.warn("stale session cleanup: cannot stat header dir={s} err={}", .{ entry.name, header_err });
                    continue;
                },
            },
            else => {
                log.warn("stale session cleanup: cannot stat screen dir={s} err={}", .{ entry.name, screen_err });
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

fn writeScreenBytes(
    alloc: Allocator,
    screen: *const terminalpkg.Screen,
    start_row: u32,
    row_count: ?u32,
) ![]u8 {
    var buf: std.Io.Writer.Allocating = .init(alloc);
    defer buf.deinit();
    try snapshot.writeScreenData(alloc, &buf.writer, .{
        .screen = screen,
        .start_row = start_row,
        .row_count = row_count,
    });
    return try buf.toOwnedSlice();
}

fn fileSize(dir: *std.fs.Dir, path: []const u8) !u64 {
    const stat = try dir.statFile(path);
    return stat.size;
}

test "cleanupStaleSessions deletes expired and keeps fresh" {
    const testing = std.testing;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("ghostty/session/stale-uuid");
    try tmp.dir.writeFile(.{ .sub_path = "ghostty/session/stale-uuid/screen", .data = "old data" });
    try tmp.dir.makePath("ghostty/session/fresh-uuid");
    try tmp.dir.writeFile(.{ .sub_path = "ghostty/session/fresh-uuid/screen", .data = "new data" });
    try tmp.dir.makePath("ghostty/session/legacy-uuid");
    try tmp.dir.writeFile(.{ .sub_path = "ghostty/session/legacy-uuid/manifest", .data = "legacy data" });

    const ten_days_ago: i64 = std.time.timestamp() - 10 * 24 * 60 * 60;
    var times = [2]std.c.timespec{
        .{ .sec = ten_days_ago, .nsec = 0 },
        .{ .sec = ten_days_ago, .nsec = 0 },
    };
    var stale_dir = try tmp.dir.openDir("ghostty/session/stale-uuid", .{});
    defer stale_dir.close();
    _ = std.c.utimensat(stale_dir.fd, "screen", &times, 0);

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

    try cleanupStaleSessions(testing.allocator, 7 * 24 * 60 * 60);

    try testing.expectError(error.FileNotFound, tmp.dir.access("ghostty/session/stale-uuid/screen", .{}));
    try tmp.dir.access("ghostty/session/fresh-uuid/screen", .{});
    try testing.expectError(error.FileNotFound, tmp.dir.access("ghostty/session/legacy-uuid/manifest", .{}));
}

test "sessionDirPath uses XDG_STATE_HOME" {
    const testing = std.testing;
    const path = try sessionDirPath(testing.allocator, "test-uuid-1234");
    defer testing.allocator.free(path);
    try testing.expect(std.mem.endsWith(u8, path, "ghostty/session/test-uuid-1234"));
}

test "persisted scrollback binary snapshot roundtrip" {
    const testing = std.testing;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("session");
    const session_path = try tmp.dir.realpathAlloc(testing.allocator, "session");
    defer testing.allocator.free(session_path);

    var term = try terminalpkg.Terminal.init(testing.allocator, .{ .cols = 80, .rows = 24 });
    defer term.deinit(testing.allocator);
    try term.printString("hello");

    const screen = try writeScreenBytes(testing.allocator, &term.screens.active.*, 0, null);
    defer testing.allocator.free(screen);

    _ = try publish(session_path, .{
        .header = .{ .timestamp = 1735689600, .cols = 80, .rows = 24 },
        .metadata = .{ .session_id = "test-session", .pwd = "/tmp/test", .title = "test title" },
        .screen = screen,
        .screen_seq = 23,
    });

    var loaded = try load(testing.allocator, session_path, .{ .scrollback = 10 * 1024 * 1024 });
    defer loaded.deinit(testing.allocator);

    try testing.expectEqual(@as(u16, 80), loaded.header.cols);
    try testing.expectEqual(@as(u16, 24), loaded.header.rows);
    try testing.expectEqual(@as(i64, 1735689600), loaded.header.timestamp);
    try testing.expectEqualStrings("test-session", loaded.session_id.?);
    try testing.expectEqualStrings("/tmp/test", loaded.pwd.?);
    try testing.expectEqualStrings("test title", loaded.title.?);
    try testing.expectEqual(@as(usize, 24), loaded.primary.rows.len);
}

test "load returns full screen when scrollback is empty" {
    const testing = std.testing;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("session");
    const session_path = try tmp.dir.realpathAlloc(testing.allocator, "session");
    defer testing.allocator.free(session_path);

    var term = try terminalpkg.Terminal.init(testing.allocator, .{ .cols = 80, .rows = 24 });
    defer term.deinit(testing.allocator);

    const screen = try writeScreenBytes(testing.allocator, &term.screens.active.*, 0, null);
    defer testing.allocator.free(screen);

    _ = try publish(session_path, .{
        .header = .{ .timestamp = 1, .cols = 80, .rows = 24 },
        .screen = screen,
        .screen_seq = 23,
    });
    try tmp.dir.writeFile(.{ .sub_path = "session/scrollback", .data = "" });

    var loaded = try load(testing.allocator, session_path, .{ .scrollback = 10 * 1024 * 1024 });
    defer loaded.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 0), loaded.scrollback_rows);
    try testing.expectEqual(@as(usize, 24), loaded.primary.rows.len);
}

test "persisted scrollback load rejects old GSRM format" {
    const testing = std.testing;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("session");
    try tmp.dir.writeFile(.{
        .sub_path = "session/header",
        .data = "GSRM 1\n" ++
            "timestamp=1\n" ++
            "cols=80\n" ++
            "rows=24\n",
    });

    const session_path = try tmp.dir.realpathAlloc(testing.allocator, "session");
    defer testing.allocator.free(session_path);

    try testing.expectError(error.InvalidSnapshot, load(testing.allocator, session_path, .{ .scrollback = 1024 }));
}

test "persisted scrollback load rejects broken file" {
    const testing = std.testing;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("session");
    try tmp.dir.writeFile(.{ .sub_path = "session/header", .data = "broken data" });

    const session_path = try tmp.dir.realpathAlloc(testing.allocator, "session");
    defer testing.allocator.free(session_path);

    try testing.expectError(error.InvalidSnapshot, load(testing.allocator, session_path, .{ .scrollback = 1024 }));
}

test "persisted scrollback publish overwrites old file" {
    const testing = std.testing;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("session");
    const session_path = try tmp.dir.realpathAlloc(testing.allocator, "session");
    defer testing.allocator.free(session_path);

    var term = try terminalpkg.Terminal.init(testing.allocator, .{ .cols = 80, .rows = 24 });
    defer term.deinit(testing.allocator);

    const screen = try writeScreenBytes(testing.allocator, &term.screens.active.*, 0, null);
    defer testing.allocator.free(screen);

    _ = try publish(session_path, .{
        .header = .{ .timestamp = 1, .cols = 80, .rows = 24 },
        .screen = screen,
        .screen_seq = 23,
    });
    _ = try publish(session_path, .{
        .header = .{ .timestamp = 2, .cols = 80, .rows = 24 },
        .metadata = .{ .title = "new title" },
        .screen = screen,
        .screen_seq = 24,
    });

    var loaded = try load(testing.allocator, session_path, .{ .scrollback = 10 * 1024 * 1024 });
    defer loaded.deinit(testing.allocator);

    try testing.expectEqual(@as(i64, 2), loaded.header.timestamp);
    try testing.expectEqualStrings("new title", loaded.title.?);
}

test "publish replaces header when dimensions change" {
    const testing = std.testing;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("session");
    const session_path = try tmp.dir.realpathAlloc(testing.allocator, "session");
    defer testing.allocator.free(session_path);

    var first_term = try terminalpkg.Terminal.init(testing.allocator, .{ .cols = 20, .rows = 3 });
    defer first_term.deinit(testing.allocator);
    const first_screen = try writeScreenBytes(testing.allocator, &first_term.screens.active.*, 0, null);
    defer testing.allocator.free(first_screen);

    _ = try publish(session_path, .{
        .header = .{ .timestamp = 1, .cols = 20, .rows = 3 },
        .screen = first_screen,
        .screen_seq = 2,
    });
    try tmp.dir.writeFile(.{ .sub_path = "session/header", .data = "bad header" });

    var second_term = try terminalpkg.Terminal.init(testing.allocator, .{ .cols = 40, .rows = 5 });
    defer second_term.deinit(testing.allocator);
    const second_screen = try writeScreenBytes(testing.allocator, &second_term.screens.active.*, 0, null);
    defer testing.allocator.free(second_screen);

    _ = try publish(session_path, .{
        .header = .{ .timestamp = 2, .cols = 40, .rows = 5 },
        .screen = second_screen,
        .screen_seq = 4,
    });

    var loaded = try load(testing.allocator, session_path, .{ .scrollback = 10 * 1024 * 1024 });
    defer loaded.deinit(testing.allocator);

    try testing.expectEqual(@as(u16, 40), loaded.header.cols);
    try testing.expectEqual(@as(u16, 5), loaded.header.rows);
}

test "append-on-eviction over multiple ticks appends only new bytes" {
    const testing = std.testing;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("session");
    const session_path = try tmp.dir.realpathAlloc(testing.allocator, "session");
    defer testing.allocator.free(session_path);

    var term = try terminalpkg.Terminal.init(testing.allocator, .{ .cols = 20, .rows = 3 });
    defer term.deinit(testing.allocator);
    try term.printString("one\ntwo\nthree\nfour");

    const screen = &term.screens.active.*;
    const first = try writeScreenBytes(testing.allocator, screen, 0, 1);
    defer testing.allocator.free(first);
    const active = try writeScreenBytes(testing.allocator, screen, 1, null);
    defer testing.allocator.free(active);

    _ = try publish(session_path, .{
        .header = .{ .timestamp = 1, .cols = 20, .rows = 3 },
        .scrollback_append = &.{.{ .bytes = first }},
        .scrollback_first_seq = 0,
        .screen = active,
        .screen_seq = 3,
    });

    var dir = try openSessionDir(session_path);
    defer dir.close();
    const size_after_first = try fileSize(&dir, "scrollback");

    const second = try writeScreenBytes(testing.allocator, screen, 1, 1);
    defer testing.allocator.free(second);
    _ = try publish(session_path, .{
        .scrollback_append = &.{.{ .bytes = second }},
        .scrollback_first_seq = 1,
        .screen = active,
        .screen_seq = 4,
    });

    const size_after_second = try fileSize(&dir, "scrollback");
    try testing.expectEqual(size_after_first + scrollback_record_prefix_size + second.len, size_after_second);
}

test "publish skips scrollback records already advanced on disk" {
    const testing = std.testing;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("session");
    const session_path = try tmp.dir.realpathAlloc(testing.allocator, "session");
    defer testing.allocator.free(session_path);

    var term = try terminalpkg.Terminal.init(testing.allocator, .{ .cols = 20, .rows = 3 });
    defer term.deinit(testing.allocator);
    try term.printString("one\ntwo\nthree\nfour");

    const scrollback = try writeScreenBytes(testing.allocator, &term.screens.active.*, 0, 1);
    defer testing.allocator.free(scrollback);
    const screen = try writeScreenBytes(testing.allocator, &term.screens.active.*, 1, null);
    defer testing.allocator.free(screen);

    // Simulate an earlier publish that appended scrollback and then failed
    // before the active screen was replaced. The retry must not append the
    // same seq again because readScrollback requires strictly increasing seqs.
    _ = try publish(session_path, .{
        .header = .{ .timestamp = 1, .cols = 20, .rows = 3 },
        .scrollback_append = &.{.{ .bytes = scrollback }},
        .scrollback_first_seq = 0,
    });

    var dir = try openSessionDir(session_path);
    defer dir.close();
    const size_after_partial = try fileSize(&dir, "scrollback");

    const progress = try publish(session_path, .{
        .header = .{ .timestamp = 1, .cols = 20, .rows = 3 },
        .scrollback_append = &.{.{ .bytes = scrollback }},
        .scrollback_first_seq = 0,
        .screen = screen,
        .screen_seq = 3,
    });

    try testing.expect(progress.scrollback_appended);
    try testing.expectEqual(size_after_partial, progress.scrollback_size_after);
    try testing.expectEqual(size_after_partial, try fileSize(&dir, "scrollback"));

    var loaded = try load(testing.allocator, session_path, .{ .scrollback = 10 * 1024 * 1024 });
    defer loaded.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), loaded.scrollback_rows);
    try testing.expectEqual(@as(usize, 4), loaded.primary.rows.len);
}

test "screen atomic-replace doesn't touch scrollback file" {
    const testing = std.testing;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("session");
    const session_path = try tmp.dir.realpathAlloc(testing.allocator, "session");
    defer testing.allocator.free(session_path);

    var term = try terminalpkg.Terminal.init(testing.allocator, .{ .cols = 20, .rows = 3 });
    defer term.deinit(testing.allocator);
    try term.printString("one\ntwo\nthree\nfour");

    const scrollback = try writeScreenBytes(testing.allocator, &term.screens.active.*, 0, 1);
    defer testing.allocator.free(scrollback);
    const screen = try writeScreenBytes(testing.allocator, &term.screens.active.*, 1, null);
    defer testing.allocator.free(screen);

    _ = try publish(session_path, .{
        .header = .{ .timestamp = 1, .cols = 20, .rows = 3 },
        .scrollback_append = &.{.{ .bytes = scrollback }},
        .scrollback_first_seq = 0,
        .screen = screen,
        .screen_seq = 3,
    });

    var dir = try openSessionDir(session_path);
    defer dir.close();
    const before = try dir.statFile("scrollback");

    _ = try publish(session_path, .{ .screen = screen, .screen_seq = 4 });
    _ = try publish(session_path, .{ .screen = screen, .screen_seq = 5 });

    const after = try dir.statFile("scrollback");
    try testing.expectEqual(before.size, after.size);
    try testing.expectEqual(before.mtime, after.mtime);
}

test "seq-number reconciliation drops duplicate screen rows during load" {
    const testing = std.testing;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("session");
    const session_path = try tmp.dir.realpathAlloc(testing.allocator, "session");
    defer testing.allocator.free(session_path);

    var term = try terminalpkg.Terminal.init(testing.allocator, .{ .cols = 20, .rows = 3 });
    defer term.deinit(testing.allocator);
    try term.printString("one\ntwo\nthree\nfour");

    const row0 = try writeScreenBytes(testing.allocator, &term.screens.active.*, 0, 1);
    defer testing.allocator.free(row0);
    const screen = try writeScreenBytes(testing.allocator, &term.screens.active.*, 0, null);
    defer testing.allocator.free(screen);

    _ = try publish(session_path, .{
        .header = .{ .timestamp = 1, .cols = 20, .rows = 3 },
        .scrollback_append = &.{.{ .bytes = row0 }},
        .scrollback_first_seq = 0,
        .screen = screen,
        .screen_seq = 3,
    });

    var loaded = try load(testing.allocator, session_path, .{ .scrollback = 10 * 1024 * 1024 });
    defer loaded.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 4), loaded.primary.rows.len);
}

test "load on missing scrollback file returns empty scrollback" {
    const testing = std.testing;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("session");
    const session_path = try tmp.dir.realpathAlloc(testing.allocator, "session");
    defer testing.allocator.free(session_path);

    var term = try terminalpkg.Terminal.init(testing.allocator, .{ .cols = 20, .rows = 3 });
    defer term.deinit(testing.allocator);

    const screen = try writeScreenBytes(testing.allocator, &term.screens.active.*, 0, null);
    defer testing.allocator.free(screen);
    _ = try publish(session_path, .{
        .header = .{ .timestamp = 1, .cols = 20, .rows = 3 },
        .screen = screen,
        .screen_seq = 2,
    });

    var loaded = try load(testing.allocator, session_path, .{ .scrollback = 10 * 1024 * 1024 });
    defer loaded.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 0), loaded.scrollback_rows);
}

test "load rejects mismatched seq monotonicity" {
    const testing = std.testing;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("session");
    const session_path = try tmp.dir.realpathAlloc(testing.allocator, "session");
    defer testing.allocator.free(session_path);

    var term = try terminalpkg.Terminal.init(testing.allocator, .{ .cols = 20, .rows = 3 });
    defer term.deinit(testing.allocator);

    const screen = try writeScreenBytes(testing.allocator, &term.screens.active.*, 0, null);
    defer testing.allocator.free(screen);
    _ = try publish(session_path, .{
        .header = .{ .timestamp = 1, .cols = 20, .rows = 3 },
        .screen = screen,
        .screen_seq = 2,
    });

    var data: std.Io.Writer.Allocating = .init(testing.allocator);
    defer data.deinit();
    try writeScrollbackRecords(&data.writer, 2, &.{ .{ .bytes = screen }, .{ .bytes = screen } });
    std.mem.writeInt(u64, data.writer.buffer[scrollback_record_prefix_size + screen.len ..][0..8], 1, .big);
    try tmp.dir.writeFile(.{ .sub_path = "session/scrollback", .data = data.writer.buffer[0..data.writer.end] });

    try testing.expectError(error.InvalidSnapshot, load(testing.allocator, session_path, .{ .scrollback = 10 * 1024 * 1024 }));
}

test "publish creates session dir tree if missing" {
    const testing = std.testing;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const base = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(base);
    const session_path = try std.fs.path.join(testing.allocator, &.{ base, "ghostty", "session", "new" });
    defer testing.allocator.free(session_path);

    var term = try terminalpkg.Terminal.init(testing.allocator, .{ .cols = 20, .rows = 3 });
    defer term.deinit(testing.allocator);
    const screen = try writeScreenBytes(testing.allocator, &term.screens.active.*, 0, null);
    defer testing.allocator.free(screen);

    _ = try publish(session_path, .{
        .header = .{ .timestamp = 1, .cols = 20, .rows = 3 },
        .screen = screen,
        .screen_seq = 2,
    });

    try tmp.dir.access("ghostty/session/new/header", .{});
    try tmp.dir.access("ghostty/session/new/screen", .{});
}
