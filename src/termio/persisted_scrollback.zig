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
const legacy_header_size: usize = 22;
const header_size: usize = 23;
const screen_prefix_size: usize = 14;
const scrollback_record_prefix_size: usize = 12;

pub const stale_session_retention_seconds: i64 = 7 * 24 * 60 * 60;
pub const stale_session_cleanup_interval_ms: u64 = 60 * 60 * 1000;
const stale_session_close_cleanup_min_interval_seconds: i64 = 5 * 60;

var stale_session_cleanup_running: std.atomic.Value(bool) = .init(false);
var stale_session_close_cleanup_last_timestamp: std.atomic.Value(i64) = .init(0);

/// Screen state is structurally bounded by terminal dimensions, not by the
/// user-facing scrollback log cap. The cap is a defense against damaged or
/// hostile session dirs, so it must comfortably exceed any plausible visible
/// grid that capture can write while still rejecting absurd files.
pub const screen_file_max_size: usize = 64 * 1024 * 1024;

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
    compression: ScrollbackCompression = scrollback_compression_default,
};

pub const ScrollbackCompression = enum(u8) {
    none = 0,
    gzip = 1,
    zstd = 2,
};

const scrollback_compression_default: ScrollbackCompression = .gzip;

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

fn screenFileSerializedSize(screen: []const u8) usize {
    return std.math.add(usize, screen_prefix_size, screen.len) catch std.math.maxInt(usize);
}

fn shouldSkipOversizedScreenFile(session_dir: []const u8, screen: []const u8) bool {
    const size = screenFileSerializedSize(screen);
    if (size <= screen_file_max_size) return false;

    log.warn(
        "persisted scrollback: skipping oversized screen file size={} cap={} session_id={s}",
        .{ size, screen_file_max_size, std.fs.path.basename(session_dir) },
    );
    return true;
}

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
    UnsupportedCompression,
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

    const publish_header = headerForPublish(&dir, capture);
    var scrollback_capture = capture;
    scrollback_capture.header = publish_header;

    if (publish_header) |header| {
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
        if (!shouldSkipOversizedScreenFile(session_dir, screen)) {
            var buf: std.Io.Writer.Allocating = .init(std.heap.page_allocator);
            defer buf.deinit();
            try writeScreenFile(&buf.writer, capture.screen_seq, screen);
            try writeFileAtomic(&dir, "screen", buf.writer.buffer[0..buf.writer.end]);
            progress.screen_written = true;
        }
    }

    if (capture.screen_alt) |screen_alt| {
        if (!shouldSkipOversizedScreenFile(session_dir, screen_alt)) {
            var buf: std.Io.Writer.Allocating = .init(std.heap.page_allocator);
            defer buf.deinit();
            try writeScreenFile(&buf.writer, capture.screen_alt_seq orelse capture.screen_seq, screen_alt);
            try writeFileAtomic(&dir, "screen.alt", buf.writer.buffer[0..buf.writer.end]);
            progress.screen_alt_written = true;
        }
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

        const compressed = try compressScrollbackAlloc(
            std.heap.page_allocator,
            scrollback_capture.header orelse try readHeaderFromDir(&dir),
            buf.writer.buffer[0..buf.writer.end],
        );
        defer std.heap.page_allocator.free(compressed);
        try writeFileAtomic(&dir, "scrollback", compressed);
        progress.scrollback_appended = true;
        progress.scrollback_size_after = @intCast(compressed.len);
        progress.scrollback_record_count_after = capture.scrollback_append.len;
        progress.scrollback_tail_seq_after = if (capture.scrollback_append.len > 0)
            capture.scrollback_first_seq +% @as(u64, @intCast(capture.scrollback_append.len)) -% 1
        else
            0;
    } else if (capture.scrollback_append.len > 0) {
        try appendScrollbackRecordsIdempotent(&dir, scrollback_capture, progress);
    }
}

fn headerForPublish(dir: *std.fs.Dir, capture: Capture) ?Header {
    const header = capture.header orelse return null;
    if (capture.rewrite_scrollback or capture.scrollback_append.len == 0) return header;

    const existing = readHeaderFromDir(dir) catch return header;
    if (existing.compression == header.compression) return header;
    dir.access("scrollback", .{}) catch |err| switch (err) {
        error.FileNotFound => return header,
        else => return header,
    };

    // Append-only publishes cannot reinterpret an existing uncompressed log as
    // gzip. Keep the durable algorithm until a rewrite has all records in hand.
    return .{
        .timestamp = header.timestamp,
        .cols = header.cols,
        .rows = header.rows,
        .compression = existing.compression,
    };
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
    const scrollback_info = try readScrollback(alloc, &dir, limits.scrollback, header.compression, &builder);
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
    data[22] = @intFromEnum(header.compression);
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
    if (data.len != legacy_header_size and data.len != header_size) return error.InvalidSnapshot;
    if (!std.mem.eql(u8, data[0..4], magic_header)) return error.InvalidSnapshot;
    const version = std.mem.readInt(u16, data[4..6], .little);
    if (version != current_version) return error.UnsupportedVersion;
    const cols = std.mem.readInt(u16, data[18..20], .little);
    const rows = std.mem.readInt(u16, data[20..22], .little);
    if (cols == 0 or rows == 0) return error.InvalidDimensions;
    const compression: ScrollbackCompression = if (data.len == legacy_header_size)
        .none
    else switch (data[22]) {
        @intFromEnum(ScrollbackCompression.none) => .none,
        @intFromEnum(ScrollbackCompression.gzip) => .gzip,
        @intFromEnum(ScrollbackCompression.zstd) => .zstd,
        else => return error.UnsupportedCompression,
    };
    return .{
        .timestamp = std.mem.readInt(i64, data[10..18], .little),
        .cols = cols,
        .rows = rows,
        .compression = compression,
    };
}

fn readHeaderFromDir(dir: *std.fs.Dir) !Header {
    const raw = try readFileAllocDir(std.heap.page_allocator, dir, "header", 4096);
    defer std.heap.page_allocator.free(raw);
    return try readHeader(raw);
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

fn readScrollbackDiskStateBytes(data: []const u8, disk_size: u64) !ScrollbackDiskState {
    var state: ScrollbackDiskState = .{ .size = disk_size };
    var pos: usize = 0;
    while (pos < data.len) {
        if (data.len - pos < scrollback_record_prefix_size) return error.InvalidSnapshot;

        const prefix = data[pos..][0..scrollback_record_prefix_size];
        const seq = std.mem.readInt(u64, prefix[0..8], .big);
        const len = std.mem.readInt(u32, prefix[8..12], .big);
        if (state.has_records and seq <= state.tail_seq) return error.InvalidSnapshot;

        pos += scrollback_record_prefix_size;
        if (data.len - pos < len) return error.InvalidSnapshot;

        pos += len;

        state.tail_seq = seq;
        state.record_count += 1;
        state.has_records = true;
    }

    return state;
}

fn decompressScrollbackAlloc(
    alloc: Allocator,
    compression: ScrollbackCompression,
    data: []const u8,
) (Allocator.Error || Error)![]u8 {
    return switch (compression) {
        .none => try alloc.dupe(u8, data),
        .gzip => try decompressGzipMembersAlloc(alloc, data),
        .zstd => error.UnsupportedCompression,
    };
}

fn compressScrollbackAlloc(
    alloc: Allocator,
    header: Header,
    data: []const u8,
) (Allocator.Error || Error || std.Io.Writer.Error)![]u8 {
    return switch (header.compression) {
        .none => try alloc.dupe(u8, data),
        .gzip => try compressGzipFixedAlloc(alloc, data),
        .zstd => error.UnsupportedCompression,
    };
}

fn appendCompressedScrollback(
    alloc: Allocator,
    file: *std.fs.File,
    header: Header,
    data: []const u8,
) !void {
    const compressed = try compressScrollbackAlloc(alloc, header, data);
    defer alloc.free(compressed);

    try file.seekFromEnd(0);
    try file.writeAll(compressed);
}

fn decompressGzipMembersAlloc(alloc: Allocator, data: []const u8) (Allocator.Error || Error)![]u8 {
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();

    var in: std.Io.Reader = .fixed(data);
    while (in.seek < in.end) {
        var gzip_stream: std.compress.flate.Decompress = .init(&in, .gzip, &.{});
        _ = gzip_stream.reader.streamRemaining(&out.writer) catch return error.InvalidSnapshot;
        if (gzip_stream.err) |_| return error.InvalidSnapshot;
    }

    return out.toOwnedSlice();
}

const DeflateBitWriter = struct {
    writer: *std.Io.Writer,
    bits: u32 = 0,
    bit_count: u5 = 0,

    fn writeBits(self: *DeflateBitWriter, value: u16, bit_count: u5) !void {
        self.bits |= @as(u32, value) << self.bit_count;
        self.bit_count += bit_count;
        while (self.bit_count >= 8) {
            try self.writer.writeByte(@truncate(self.bits));
            self.bits >>= 8;
            self.bit_count -= 8;
        }
    }

    fn finish(self: *DeflateBitWriter) !void {
        if (self.bit_count == 0) return;
        try self.writer.writeByte(@truncate(self.bits));
        self.bits = 0;
        self.bit_count = 0;
    }
};

fn reverseBits(value: u16, bit_count: u5) u16 {
    var result: u16 = 0;
    var i: u5 = 0;
    while (i < bit_count) : (i += 1) {
        result = (result << 1) | ((value >> @as(u4, @intCast(i))) & 1);
    }
    return result;
}

fn writeFixedCode(bits: *DeflateBitWriter, symbol: u16) !void {
    const code: u16, const bit_count: u5 = switch (symbol) {
        0...143 => .{ 0b0011_0000 + symbol, 8 },
        144...255 => .{ 0b1_1001_0000 + (symbol - 144), 9 },
        256...279 => .{ symbol - 256, 7 },
        280...287 => .{ 0b1100_0000 + (symbol - 280), 8 },
        else => return error.InvalidSnapshot,
    };
    try bits.writeBits(reverseBits(code, bit_count), bit_count);
}

const LengthCode = struct {
    code: u16,
    extra: u16,
    extra_bits: u5,
};

fn lengthCode(length: u16) Error!LengthCode {
    const bases = [_]u16{
        3,   4,   5,   6,   7,   8,  9,  10,
        11,  13,  15,  17,  19,  23, 27, 31,
        35,  43,  51,  59,  67,  83, 99, 115,
        131, 163, 195, 227, 258,
    };
    const extra_bits = [_]u5{
        0, 0, 0, 0, 0, 0, 0, 0,
        1, 1, 1, 1, 2, 2, 2, 2,
        3, 3, 3, 3, 4, 4, 4, 4,
        5, 5, 5, 5, 0,
    };

    if (length < 3 or length > 258) return error.InvalidSnapshot;
    for (bases, extra_bits, 0..) |base, bits, index| {
        const span: u16 = if (bits == 0) 1 else @as(u16, 1) << @as(u4, @intCast(bits));
        if (length >= base and length < base + span) {
            return .{
                .code = @intCast(257 + index),
                .extra = length - base,
                .extra_bits = bits,
            };
        }
    }

    return error.InvalidSnapshot;
}

fn writeLengthDistance(bits: *DeflateBitWriter, length: u16) !void {
    const len_code = try lengthCode(length);
    try writeFixedCode(bits, len_code.code);
    if (len_code.extra_bits > 0) try bits.writeBits(len_code.extra, len_code.extra_bits);
    // The simple encoder only emits distance=1 matches for repeated bytes.
    try bits.writeBits(0, 5);
}

/// Emit a small gzip member using a single fixed-Huffman deflate block.
/// Zig 0.15.2 ships gzip decompression, but its flate compressor is not a
/// usable public API in this fork's toolchain. Scrollback snapshots contain
/// long runs of zeroed cell/style data, so distance=1 RLE matches recover the
/// important space win without adding a fork-local dependency.
fn compressGzipFixedAlloc(alloc: Allocator, data: []const u8) (Allocator.Error || std.Io.Writer.Error || Error)![]u8 {
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();

    try out.writer.writeAll(&[_]u8{ 0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 });

    var bits: DeflateBitWriter = .{ .writer = &out.writer };
    try bits.writeBits(1, 1);
    try bits.writeBits(0b01, 2);

    var pos: usize = 0;
    while (pos < data.len) {
        if (pos > 0) {
            var run_len: usize = 0;
            while (pos + run_len < data.len and
                data[pos + run_len] == data[pos - 1] and
                run_len < 258) : (run_len += 1)
            {}

            if (run_len >= 3) {
                try writeLengthDistance(&bits, @intCast(run_len));
                pos += run_len;
                continue;
            }
        }

        try writeFixedCode(&bits, data[pos]);
        pos += 1;
    }

    try writeFixedCode(&bits, 256);
    try bits.finish();

    var crc = std.hash.Crc32.init();
    crc.update(data);
    try out.writer.writeInt(u32, crc.final(), .little);
    try out.writer.writeInt(u32, @truncate(data.len), .little);

    return out.toOwnedSlice();
}

fn appendScrollbackRecordsIdempotent(
    dir: *std.fs.Dir,
    capture: Capture,
    progress: *PublishProgress,
) !void {
    const header = capture.header orelse try readHeaderFromDir(dir);

    var file = dir.openFile("scrollback", .{ .mode = .read_write }) catch |err| switch (err) {
        error.FileNotFound => try dir.createFile("scrollback", .{
            .read = true,
            .truncate = false,
            .mode = 0o600,
        }),
        else => return err,
    };
    defer file.close();

    const disk_stat = try file.stat();
    try file.seekTo(0);
    const disk_raw = try file.readToEndAlloc(std.heap.page_allocator, std.math.maxInt(usize));
    defer std.heap.page_allocator.free(disk_raw);
    const disk_data = try decompressScrollbackAlloc(std.heap.page_allocator, header.compression, disk_raw);
    defer std.heap.page_allocator.free(disk_data);
    const disk_state = try readScrollbackDiskStateBytes(disk_data, disk_stat.size);
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

    // Serialize records into a heap buffer, then writeAll. The buffered
    // std.Io.Writer interface tracks its own pos starting at 0 and ignores
    // the file's kernel seek cursor (it uses pwrite under the hood), so write
    // directly via the legacy file API to honor seekFromEnd.
    var buf: std.Io.Writer.Allocating = .init(std.heap.page_allocator);
    defer buf.deinit();
    try writeScrollbackRecords(&buf.writer, first_seq, records);
    try appendCompressedScrollback(
        std.heap.page_allocator,
        &file,
        header,
        buf.writer.buffer[0..buf.writer.end],
    );

    const stat = try file.stat();
    progress.scrollback_tail_seq_after = first_seq +% @as(u64, @intCast(records.len)) -% 1;
    progress.scrollback_size_after = stat.size;
    progress.scrollback_record_count_after = disk_state.record_count + records.len;
}

fn readScrollback(
    alloc: Allocator,
    dir: *std.fs.Dir,
    max_len: usize,
    compression: ScrollbackCompression,
    builder: *ScreenBuilder,
) (Allocator.Error || std.fs.File.OpenError || std.fs.File.ReadError || Error || snapshot.Error)!ScrollbackInfo {
    const raw = readFileAllocDir(alloc, dir, "scrollback", max_len) catch |err| switch (err) {
        error.FileNotFound => return .{},
        else => return err,
    };
    defer alloc.free(raw);

    const data = try decompressScrollbackAlloc(alloc, compression, raw);
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

/// Run stale session cleanup if another cleanup pass is not already active.
/// Concurrent cleanup is idempotent but wasteful because each pass scans the
/// full persisted session directory tree.
pub fn cleanupStaleSessionsGuarded(alloc: Allocator) !bool {
    if (stale_session_cleanup_running.swap(true, .acq_rel)) return false;
    defer stale_session_cleanup_running.store(false, .release);

    try cleanupStaleSessions(alloc, stale_session_retention_seconds);
    return true;
}

/// Run stale session cleanup from the session-close hook, rate-limited so
/// closing many tabs cannot force repeated full directory sweeps.
pub fn cleanupStaleSessionsOnClose(alloc: Allocator) !bool {
    const now = std.time.timestamp();
    while (true) {
        const last = stale_session_close_cleanup_last_timestamp.load(.monotonic);
        if (last != 0 and now - last < stale_session_close_cleanup_min_interval_seconds) return false;
        if (stale_session_close_cleanup_last_timestamp.cmpxchgWeak(
            last,
            now,
            .monotonic,
            .monotonic,
        )) |_| continue;
        break;
    }

    return try cleanupStaleSessionsGuarded(alloc);
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

fn expectScrollbackPrefixEqual(alloc: Allocator, loaded: *const Loaded, expected_bytes: []const u8) !void {
    const testing = std.testing;

    var expected = try snapshot.readScreenData(alloc, expected_bytes);
    defer expected.deinit(alloc);

    try testing.expectEqual(expected.rows.len, loaded.scrollback_rows);
    try testing.expect(loaded.primary.rows.len >= expected.rows.len);
    for (expected.rows, loaded.primary.rows[0..expected.rows.len]) |expected_row, actual_row| {
        try testing.expectEqual(expected_row.wrap, actual_row.wrap);
        try testing.expectEqual(expected_row.wrap_continuation, actual_row.wrap_continuation);
        try testing.expectEqual(expected_row.semantic_prompt, actual_row.semantic_prompt);
        try testing.expectEqualSlices(u64, expected_row.cells, actual_row.cells);
    }
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

test "cleanupStaleSessionsOnClose deletes expired sessions and rate limits repeated closes" {
    const testing = std.testing;

    stale_session_cleanup_running.store(false, .monotonic);
    stale_session_close_cleanup_last_timestamp.store(0, .monotonic);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("ghostty/session/stale-uuid");
    try tmp.dir.writeFile(.{ .sub_path = "ghostty/session/stale-uuid/screen", .data = "old data" });

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

    try testing.expect(try cleanupStaleSessionsOnClose(testing.allocator));
    try testing.expectError(error.FileNotFound, tmp.dir.access("ghostty/session/stale-uuid/screen", .{}));

    try tmp.dir.makePath("ghostty/session/stale-uuid-two");
    try tmp.dir.writeFile(.{ .sub_path = "ghostty/session/stale-uuid-two/screen", .data = "old data" });
    var stale_dir_two = try tmp.dir.openDir("ghostty/session/stale-uuid-two", .{});
    defer stale_dir_two.close();
    _ = std.c.utimensat(stale_dir_two.fd, "screen", &times, 0);

    try testing.expect(!try cleanupStaleSessionsOnClose(testing.allocator));
    try tmp.dir.access("ghostty/session/stale-uuid-two/screen", .{});
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

test "persisted scrollback compresses scrollback log and roundtrips" {
    const testing = std.testing;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("session");
    const session_path = try tmp.dir.realpathAlloc(testing.allocator, "session");
    defer testing.allocator.free(session_path);

    var term = try terminalpkg.Terminal.init(testing.allocator, .{
        .cols = 32,
        .rows = 4,
        .max_scrollback = 16 * 1024,
    });
    defer term.deinit(testing.allocator);

    var input: std.Io.Writer.Allocating = .init(testing.allocator);
    defer input.deinit();
    for (0..80) |_| try input.writer.writeAll("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
    try term.printString(input.writer.buffer[0..input.writer.end]);

    const primary = term.screens.get(.primary) orelse term.screens.active;
    const scrollback = try writeScreenBytes(testing.allocator, primary, 0, 32);
    defer testing.allocator.free(scrollback);
    const screen = try writeScreenBytes(testing.allocator, primary, 32, 4);
    defer testing.allocator.free(screen);

    _ = try publish(session_path, .{
        .header = .{ .timestamp = 10, .cols = 32, .rows = 4 },
        .scrollback_append = &.{.{ .bytes = scrollback }},
        .screen = screen,
        .screen_seq = 100,
    });

    var dir = try std.fs.openDirAbsolute(session_path, .{});
    defer dir.close();
    const compressed_size = try fileSize(&dir, "scrollback");
    try testing.expect(compressed_size < scrollback_record_prefix_size + scrollback.len);

    var loaded = try load(testing.allocator, session_path, .{ .scrollback = 10 * 1024 * 1024 });
    defer loaded.deinit(testing.allocator);
    try expectScrollbackPrefixEqual(testing.allocator, &loaded, scrollback);
}

test "persisted scrollback load accepts uncompressed scrollback log" {
    const testing = std.testing;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("session");
    const session_path = try tmp.dir.realpathAlloc(testing.allocator, "session");
    defer testing.allocator.free(session_path);

    var term = try terminalpkg.Terminal.init(testing.allocator, .{
        .cols = 16,
        .rows = 3,
        .max_scrollback = 4096,
    });
    defer term.deinit(testing.allocator);
    try term.printString("legacy-one\nlegacy-two\nlegacy-three\nlegacy-four\nlegacy-five");

    const primary = term.screens.get(.primary) orelse term.screens.active;
    const scrollback = try writeScreenBytes(testing.allocator, primary, 0, 2);
    defer testing.allocator.free(scrollback);
    const screen = try writeScreenBytes(testing.allocator, primary, 2, 3);
    defer testing.allocator.free(screen);

    var dir = try std.fs.openDirAbsolute(session_path, .{});
    defer dir.close();
    try writeHeaderReplacing(&dir, .{
        .timestamp = 11,
        .cols = 16,
        .rows = 3,
        .compression = .none,
    });
    var scrollback_buf: std.Io.Writer.Allocating = .init(testing.allocator);
    defer scrollback_buf.deinit();
    try writeScrollbackRecords(&scrollback_buf.writer, 0, &.{.{ .bytes = scrollback }});
    try writeFileAtomic(&dir, "scrollback", scrollback_buf.writer.buffer[0..scrollback_buf.writer.end]);
    var screen_buf: std.Io.Writer.Allocating = .init(testing.allocator);
    defer screen_buf.deinit();
    try writeScreenFile(&screen_buf.writer, 100, screen);
    try writeFileAtomic(&dir, "screen", screen_buf.writer.buffer[0..screen_buf.writer.end]);

    var loaded = try load(testing.allocator, session_path, .{ .scrollback = 10 * 1024 * 1024 });
    defer loaded.deinit(testing.allocator);
    try expectScrollbackPrefixEqual(testing.allocator, &loaded, scrollback);
}

test "persisted scrollback gzip members append and load as one log" {
    const testing = std.testing;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("session");
    const session_path = try tmp.dir.realpathAlloc(testing.allocator, "session");
    defer testing.allocator.free(session_path);

    var term = try terminalpkg.Terminal.init(testing.allocator, .{
        .cols = 24,
        .rows = 4,
        .max_scrollback = 8192,
    });
    defer term.deinit(testing.allocator);
    try term.printString(
        "first append keeps this row\n" ++
            "first append keeps this row\n" ++
            "second append keeps this row\n" ++
            "second append keeps this row\n",
    );

    const primary = term.screens.get(.primary) orelse term.screens.active;
    const first = try writeScreenBytes(testing.allocator, primary, 0, 1);
    defer testing.allocator.free(first);
    const second = try writeScreenBytes(testing.allocator, primary, 1, 1);
    defer testing.allocator.free(second);
    const screen = try writeScreenBytes(testing.allocator, primary, 2, 4);
    defer testing.allocator.free(screen);

    _ = try publish(session_path, .{
        .header = .{ .timestamp = 12, .cols = 24, .rows = 4 },
        .scrollback_append = &.{.{ .bytes = first }},
        .screen = screen,
        .screen_seq = 100,
    });
    _ = try publish(session_path, .{
        .scrollback_first_seq = 1,
        .scrollback_append = &.{.{ .bytes = second }},
        .screen = screen,
        .screen_seq = 101,
    });

    var loaded = try load(testing.allocator, session_path, .{ .scrollback = 10 * 1024 * 1024 });
    defer loaded.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 2), loaded.scrollback_rows);

    var expected_first = try snapshot.readScreenData(testing.allocator, first);
    defer expected_first.deinit(testing.allocator);
    var expected_second = try snapshot.readScreenData(testing.allocator, second);
    defer expected_second.deinit(testing.allocator);

    try testing.expectEqualSlices(u64, expected_first.rows[0].cells, loaded.primary.rows[0].cells);
    try testing.expectEqualSlices(u64, expected_second.rows[0].cells, loaded.primary.rows[1].cells);
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

test "publish skips oversized screen files and keeps existing files" {
    const testing = std.testing;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("session");
    const session_path = try tmp.dir.realpathAlloc(testing.allocator, "session");
    defer testing.allocator.free(session_path);

    _ = try publish(session_path, .{
        .screen = "previous-screen",
        .screen_seq = 1,
        .screen_alt = "previous-alt-screen",
        .screen_alt_seq = 2,
    });

    const before_screen = try tmp.dir.readFileAlloc(testing.allocator, "session/screen", screen_file_max_size);
    defer testing.allocator.free(before_screen);
    const before_alt = try tmp.dir.readFileAlloc(testing.allocator, "session/screen.alt", screen_file_max_size);
    defer testing.allocator.free(before_alt);

    const oversized = try testing.allocator.alloc(u8, screen_file_max_size + 1);
    defer testing.allocator.free(oversized);
    @memset(oversized, 'x');

    const progress = try publish(session_path, .{
        .scrollback_append = &.{.{ .bytes = "scrollback-row" }},
        .scrollback_first_seq = 0,
        .screen = oversized,
        .screen_seq = 3,
        .screen_alt = oversized,
        .screen_alt_seq = 4,
    });

    try testing.expect(!progress.screen_written);
    try testing.expect(!progress.screen_alt_written);
    try testing.expect(progress.scrollback_appended);

    const after_screen = try tmp.dir.readFileAlloc(testing.allocator, "session/screen", screen_file_max_size);
    defer testing.allocator.free(after_screen);
    const after_alt = try tmp.dir.readFileAlloc(testing.allocator, "session/screen.alt", screen_file_max_size);
    defer testing.allocator.free(after_alt);

    try testing.expectEqualSlices(u8, before_screen, after_screen);
    try testing.expectEqualSlices(u8, before_alt, after_alt);
    try tmp.dir.access("session/scrollback", .{});
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
