const std = @import("std");
const Allocator = std.mem.Allocator;

const pagepkg = @import("page.zig");
const stylepkg = @import("style.zig");
const colorpkg = @import("color.zig");
const Screen = @import("Screen.zig");
const PageList = @import("PageList.zig");
const Cell = pagepkg.Cell;
const Row = pagepkg.Row;
const Page = pagepkg.Page;
const Style = stylepkg.Style;
const StyleId = stylepkg.Id;

const log = std.log.scoped(.snapshot);

/// File magic identifying a binary snapshot.
const magic = "GSNP";

/// Current binary format version.
const current_version: u16 = 1;

/// Header flag: alternate screen data follows primary.
const flag_has_alternate: u16 = 1;

/// Byte size of the fixed file header.
const file_header_size: usize = 16;

/// Byte size of a serialized style entry.
const style_entry_size: usize = 14;

pub const Error = error{
    InvalidSnapshot,
    UnsupportedVersion,
    InvalidDimensions,
    EndOfData,
};

/// Metadata matching persisted_scrollback.Header.
pub const Header = struct {
    timestamp: i64,
    cols: u16,
    rows: u16,
};

/// Input for the write path: references to live Screen objects.
pub const WriteCapture = struct {
    primary: *const Screen,
    alternate: ?*const Screen = null,
    session_id: ?[]const u8 = null,
    pwd: ?[]const u8 = null,
    title: ?[]const u8 = null,
    timestamp: i64 = 0,
    /// Maximum bytes for the serialized output. 0 means unlimited.
    /// When set, rows are dropped from the top (oldest scrollback first)
    /// until the output fits within this budget.
    max_bytes: usize = 0,
};

/// Input for writing a standalone screen block.
pub const ScreenBlockCapture = struct {
    screen: *const Screen,
    start_row: u32 = 0,
    row_count: ?u32 = null,
};

/// A single grapheme entry referencing a cell position.
pub const GraphemeEntry = struct {
    row_index: u32,
    col_index: u16,
    codepoints: []u21,

    fn deinit(self: GraphemeEntry, alloc: Allocator) void {
        alloc.free(self.codepoints);
    }
};

/// Deserialized row data.
pub const RowData = struct {
    cells: []u64,
    wrap: bool,
    wrap_continuation: bool,
    semantic_prompt: Row.SemanticPrompt,

    fn deinit(self: RowData, alloc: Allocator) void {
        alloc.free(self.cells);
    }
};

/// Deserialized screen data.
pub const ScreenData = struct {
    styles: []Style,
    rows: []RowData,
    graphemes: []GraphemeEntry,
    cols: u16,

    pub fn deinit(self: *ScreenData, alloc: Allocator) void {
        for (self.graphemes) |g| g.deinit(alloc);
        alloc.free(self.graphemes);
        for (self.rows) |r| r.deinit(alloc);
        alloc.free(self.rows);
        alloc.free(self.styles);
        self.* = undefined;
    }
};

/// Result of reading a binary snapshot.
pub const ReadResult = struct {
    header: Header,
    session_id: ?[]u8 = null,
    pwd: ?[]u8 = null,
    title: ?[]u8 = null,
    primary: ScreenData,
    alternate: ?ScreenData = null,

    pub fn deinit(self: *ReadResult, alloc: Allocator) void {
        if (self.session_id) |v| alloc.free(v);
        if (self.pwd) |v| alloc.free(v);
        if (self.title) |v| alloc.free(v);
        self.primary.deinit(alloc);
        if (self.alternate) |*v| v.deinit(alloc);
        self.* = undefined;
    }
};

// ── Style table helper ──────────────────────────────────────────────

/// Maps page-local styles to a global dedup table.
const StyleTable = struct {
    list: std.ArrayListUnmanaged(Style),

    fn init() StyleTable {
        return .{ .list = .empty };
    }

    fn deinit(self: *StyleTable, alloc: Allocator) void {
        self.list.deinit(alloc);
    }

    /// Returns 1-based global index (0 is reserved for default style).
    fn getOrPut(self: *StyleTable, alloc: Allocator, style: Style) Allocator.Error!u16 {
        for (self.list.items, 0..) |s, i| {
            if (s.eql(style)) return @intCast(i + 1);
        }
        try self.list.append(alloc, style);
        return @intCast(self.list.items.len);
    }
};

// ── Write path ──────────────────────────────────────────────────────

/// Serialize terminal screens to the binary snapshot format.
///
/// `max_bytes` is a per-surface byte cap matching the config contract.
/// Each screen block is independently capped to `max_bytes`.
///
/// Produces either a complete, parseable snapshot or zero bytes.
/// Zero bytes are written when `max_bytes` is positive but too small
/// for even an empty screen block (12 bytes minimum).
pub fn write(
    alloc: Allocator,
    writer: *std.Io.Writer,
    capture: WriteCapture,
) !void {
    const cols: u16 = @intCast(capture.primary.pages.cols);
    const rows: u16 = @intCast(capture.primary.pages.rows);

    if (cols == 0 or rows == 0) return error.InvalidDimensions;

    // If the per-surface cap is too small for even an empty screen block,
    // produce zero bytes so callers get a clean "nothing written" signal.
    if (capture.max_bytes > 0 and capture.max_bytes < min_screen_block_size) {
        return;
    }

    const flags: u16 = if (capture.alternate != null) flag_has_alternate else 0;

    // File header (16 bytes)
    try writer.writeAll(magic);
    try writer.writeInt(u16, current_version, .little);
    try writer.writeInt(u16, flags, .little);
    try writer.writeAll(&[_]u8{0} ** 8); // reserved

    // Metadata
    try writer.writeInt(i64, capture.timestamp, .little);
    try writer.writeInt(u16, cols, .little);
    try writer.writeInt(u16, rows, .little);
    try writeLenPrefixed(writer, capture.session_id);
    try writeLenPrefixed(writer, capture.pwd);
    try writeLenPrefixed(writer, capture.title);

    // Each screen block gets the full per-surface budget independently.
    try writeCappedScreenBlock(alloc, writer, capture.primary, capture.max_bytes);

    if (capture.alternate) |alt| {
        try writeCappedScreenBlock(alloc, writer, alt, capture.max_bytes);
    }
}

/// Serialize a screen block, enforcing a hard per-surface byte cap.
/// When `max_bytes` is 0, no cap is applied. If the cap is too small
/// for even an empty screen block, an empty block (zero rows) is written.
/// Minimum size of an empty screen block (style_count:2 + row_count:4 + cols:2 + grapheme_count:4).
const min_screen_block_size: usize = 12;

fn writeCappedScreenBlock(
    alloc: Allocator,
    writer: *std.Io.Writer,
    screen: *const Screen,
    max_bytes: usize,
) !void {
    if (max_bytes == 0) {
        return writeScreenBlock(alloc, writer, screen, std.math.maxInt(u32));
    }

    const screen_cols: usize = @intCast(screen.pages.cols);

    // First attempt: estimate how many rows fit.
    var row_limit = estimateMaxRows(screen, max_bytes);

    // Serialize to a temp buffer, then retry with fewer rows if needed.
    var buf: std.Io.Writer.Allocating = .init(alloc);
    defer buf.deinit();

    try writeScreenBlock(alloc, &buf.writer, screen, row_limit);

    var attempts: u32 = 0;
    while (buf.writer.end > max_bytes and attempts < 16) : (attempts += 1) {
        const overage = buf.writer.end - max_bytes;
        const bytes_per_row = screen_cols * 8 + 1;
        const drop = if (bytes_per_row > 0) @max(overage / bytes_per_row, 1) else 1;
        row_limit -|= @intCast(@min(drop, row_limit));

        buf.deinit();
        buf = .init(alloc);
        try writeScreenBlock(alloc, &buf.writer, screen, row_limit);

        if (row_limit == 0) break;
    }

    // If still over budget after dropping all rows (style overhead alone
    // exceeds cap), write an empty block — the 12-byte minimum framing
    // is irreducible but acceptable since the cap is below it.
    if (buf.writer.end > max_bytes) {
        buf.deinit();
        buf = .init(alloc);
        try writeScreenBlock(alloc, &buf.writer, screen, 0);
    }

    try writer.writeAll(buf.writer.buffer[0..buf.writer.end]);
}

/// Return the number of rows currently represented by a screen.
pub fn screenRowCount(screen: *const Screen) u32 {
    var total_rows: u32 = 0;
    var node_opt = screen.pages.pages.first;
    while (node_opt) |node| : (node_opt = node.next) {
        total_rows += node.data.size.rows;
    }
    return total_rows;
}

/// Serialize one standalone screen block using the existing ScreenData wire
/// format. The caller may select a contiguous row range, but the row bytes
/// themselves stay identical to the normal snapshot screen-block encoding.
pub fn writeScreenData(
    alloc: Allocator,
    writer: *std.Io.Writer,
    capture: ScreenBlockCapture,
) !void {
    const total_rows = screenRowCount(capture.screen);
    if (capture.start_row > total_rows) return error.InvalidDimensions;

    const available = total_rows - capture.start_row;
    const row_count = if (capture.row_count) |count| @min(count, available) else available;
    try writeScreenBlockRange(alloc, writer, capture.screen, capture.start_row, row_count);
}

/// Estimate the maximum number of rows that fit in a byte budget.
fn estimateMaxRows(screen: *const Screen, budget: usize) u32 {
    const screen_cols: usize = @intCast(screen.pages.cols);
    // Per-row: 1 byte flags + cols * 8 bytes cells
    const bytes_per_row = screen_cols * 8 + 1;
    // Screen block overhead: style_count(2) + row_count(4) + cols(2) + grapheme_count(4) = 12
    const overhead: usize = 12;
    const available = if (budget > overhead) budget - overhead else 0;
    if (bytes_per_row == 0) return std.math.maxInt(u32);
    return @intCast(@min(available / bytes_per_row, std.math.maxInt(u32)));
}

fn writeScreenBlock(
    alloc: Allocator,
    writer: *std.Io.Writer,
    screen: *const Screen,
    max_rows: u32,
) !void {
    const total_rows = screenRowCount(screen);

    // Limit rows: drop oldest (topmost) rows when max_rows is smaller.
    const rows_to_skip: u32 = if (max_rows < total_rows) total_rows - max_rows else 0;
    const rows_to_write = total_rows - rows_to_skip;

    return writeScreenBlockRange(alloc, writer, screen, rows_to_skip, rows_to_write);
}

fn writeScreenBlockRange(
    alloc: Allocator,
    writer: *std.Io.Writer,
    screen: *const Screen,
    start_row: u32,
    rows_to_write: u32,
) !void {
    const cols: u16 = @intCast(screen.pages.cols);
    const end_row = start_row + rows_to_write;

    // Build style table only from rows that will actually be written.
    var style_table: StyleTable = .init();
    defer style_table.deinit(alloc);

    {
        var scan_row: u32 = 0;
        var node_opt = screen.pages.pages.first;
        while (node_opt) |node| : (node_opt = node.next) {
            const page = &node.data;
            var y: usize = 0;
            while (y < page.size.rows) : (y += 1) {
                if (scan_row >= start_row and scan_row < end_row) {
                    const row = page.getRow(y);
                    const cells = page.getCells(row);
                    for (cells) |cell| {
                        if (cell.style_id != 0) {
                            const style = page.styles.get(page.memory, cell.style_id);
                            _ = try style_table.getOrPut(alloc, style.*);
                        }
                    }
                }
                scan_row += 1;
            }
        }
    }

    // Write style table
    const style_count: u16 = @intCast(style_table.list.items.len);
    try writer.writeInt(u16, style_count, .little);
    for (style_table.list.items) |s| {
        try writeStyle(writer, s);
    }

    // Write row count and cols
    try writer.writeInt(u32, rows_to_write, .little);
    try writer.writeInt(u16, cols, .little);

    // Pass 2: write rows + cells, collect graphemes
    var graphemes: std.ArrayListUnmanaged(GraphemeEntry) = .empty;
    defer {
        for (graphemes.items) |g| g.deinit(alloc);
        graphemes.deinit(alloc);
    }

    var global_row: u32 = 0;
    var written_row: u32 = 0;
    {
        var node_opt = screen.pages.pages.first;
        while (node_opt) |node| : (node_opt = node.next) {
            const page = &node.data;
            var y: usize = 0;
            while (y < page.size.rows) : (y += 1) {
                if (global_row < start_row) {
                    global_row += 1;
                    continue;
                }
                if (global_row >= end_row) break;

                const row = page.getRow(y);
                const cells = page.getCells(row);

                // Row flags byte
                const row_flags: u8 = (@as(u8, @intFromBool(row.wrap))) |
                    (@as(u8, @intFromBool(row.wrap_continuation)) << 1) |
                    (@as(u8, @intFromEnum(row.semantic_prompt)) << 2);
                try writer.writeByte(row_flags);

                // Cells — use index access so we can get pointers into page memory
                for (0..cells.len) |col| {
                    var c = cells[col];

                    // Remap style_id to global table index
                    if (c.style_id != 0) {
                        const s = page.styles.get(page.memory, c.style_id);
                        c.style_id = try style_table.getOrPut(alloc, s.*);
                    }

                    // Clear non-persisted fields
                    c.hyperlink = false;
                    c._padding = 0;

                    // Collect grapheme data — use pointer to actual cell in page memory.
                    // If the cell claims grapheme but the backing data is missing,
                    // sanitize the tag so the snapshot is internally consistent.
                    if (cells[col].content_tag == .codepoint_grapheme) {
                        if (page.lookupGrapheme(&cells[col])) |cps| {
                            const cps_copy = try alloc.alloc(u21, cps.len);
                            @memcpy(cps_copy, cps);
                            try graphemes.append(alloc, .{
                                .row_index = written_row,
                                .col_index = @intCast(col),
                                .codepoints = cps_copy,
                            });
                        } else {
                            log.warn("snapshot write orphaned grapheme tag row={} col={}, clearing", .{
                                written_row, col,
                            });
                            c.content_tag = .codepoint;
                        }
                    }

                    try writer.writeInt(u64, @bitCast(c), .little);
                }

                global_row += 1;
                written_row += 1;
            }
        }
    }

    // Write grapheme entries
    const grapheme_count: u32 = @intCast(graphemes.items.len);
    try writer.writeInt(u32, grapheme_count, .little);
    for (graphemes.items) |g| {
        try writer.writeInt(u32, g.row_index, .little);
        try writer.writeInt(u16, g.col_index, .little);
        const cp_count: u16 = @intCast(g.codepoints.len);
        try writer.writeInt(u16, cp_count, .little);
        for (g.codepoints) |cp| {
            try writer.writeInt(u32, @as(u32, cp), .little);
        }
    }
}

fn writeStyle(writer: *std.Io.Writer, style: Style) !void {
    try writeStyleColor(writer, style.fg_color);
    try writeStyleColor(writer, style.bg_color);
    try writeStyleColor(writer, style.underline_color);
    try writer.writeInt(u16, @bitCast(style.flags), .little);
}

fn writeStyleColor(writer: *std.Io.Writer, col: Style.Color) !void {
    switch (col) {
        .none => {
            try writer.writeByte(0);
            try writer.writeAll(&[_]u8{ 0, 0, 0 });
        },
        .palette => |idx| {
            try writer.writeByte(1);
            try writer.writeByte(idx);
            try writer.writeAll(&[_]u8{ 0, 0 });
        },
        .rgb => |rgb| {
            try writer.writeByte(2);
            try writer.writeByte(rgb.r);
            try writer.writeByte(rgb.g);
            try writer.writeByte(rgb.b);
        },
    }
}

fn writeLenPrefixed(writer: *std.Io.Writer, data: ?[]const u8) !void {
    if (data) |bytes| {
        try writer.writeInt(u32, @intCast(bytes.len), .little);
        try writer.writeAll(bytes);
    } else {
        try writer.writeInt(u32, 0, .little);
    }
}

// ── Read path ───────────────────────────────────────────────────────

/// Cursor for parsing binary data from a slice.
const ReadCursor = struct {
    data: []const u8,
    pos: usize = 0,

    fn remaining(self: *const ReadCursor) usize {
        return if (self.pos < self.data.len) self.data.len - self.pos else 0;
    }

    fn readByte(self: *ReadCursor) Error!u8 {
        if (self.pos >= self.data.len) return error.EndOfData;
        const val = self.data[self.pos];
        self.pos += 1;
        return val;
    }

    fn readU16(self: *ReadCursor) Error!u16 {
        if (self.pos + 2 > self.data.len) return error.EndOfData;
        const val = std.mem.readInt(u16, self.data[self.pos..][0..2], .little);
        self.pos += 2;
        return val;
    }

    fn readU32(self: *ReadCursor) Error!u32 {
        if (self.pos + 4 > self.data.len) return error.EndOfData;
        const val = std.mem.readInt(u32, self.data[self.pos..][0..4], .little);
        self.pos += 4;
        return val;
    }

    fn readU64(self: *ReadCursor) Error!u64 {
        if (self.pos + 8 > self.data.len) return error.EndOfData;
        const val = std.mem.readInt(u64, self.data[self.pos..][0..8], .little);
        self.pos += 8;
        return val;
    }

    fn readI64(self: *ReadCursor) Error!i64 {
        if (self.pos + 8 > self.data.len) return error.EndOfData;
        const val = std.mem.readInt(i64, self.data[self.pos..][0..8], .little);
        self.pos += 8;
        return val;
    }

    fn readBytes(self: *ReadCursor, alloc: Allocator) (Allocator.Error || Error)!?[]u8 {
        const len = try self.readU32();
        if (len == 0) return null;
        if (self.pos + len > self.data.len) return error.EndOfData;
        const result = try alloc.alloc(u8, len);
        @memcpy(result, self.data[self.pos .. self.pos + len]);
        self.pos += len;
        return result;
    }

    fn skip(self: *ReadCursor, n: usize) Error!void {
        if (self.pos + n > self.data.len) return error.EndOfData;
        self.pos += n;
    }
};

/// Deserialize a binary snapshot from a byte slice.
pub fn read(alloc: Allocator, data: []const u8) (Allocator.Error || Error)!ReadResult {
    var cursor: ReadCursor = .{ .data = data };

    // File header
    if (cursor.remaining() < file_header_size) return error.InvalidSnapshot;

    const m0 = try cursor.readByte();
    const m1 = try cursor.readByte();
    const m2 = try cursor.readByte();
    const m3 = try cursor.readByte();
    if (m0 != 'G' or m1 != 'S' or m2 != 'N' or m3 != 'P') return error.InvalidSnapshot;

    const version = try cursor.readU16();
    if (version != current_version) return error.UnsupportedVersion;

    const flags = try cursor.readU16();
    try cursor.skip(8); // reserved

    // Metadata
    const timestamp = try cursor.readI64();
    const cols = try cursor.readU16();
    const rows = try cursor.readU16();
    if (cols == 0 or rows == 0) return error.InvalidDimensions;

    const session_id = try cursor.readBytes(alloc);
    errdefer if (session_id) |v| alloc.free(v);

    const pwd = try cursor.readBytes(alloc);
    errdefer if (pwd) |v| alloc.free(v);

    const title = try cursor.readBytes(alloc);
    errdefer if (title) |v| alloc.free(v);

    // Primary screen block
    var primary = try readScreenBlock(alloc, &cursor);
    errdefer primary.deinit(alloc);

    // Alternate screen block (if flagged)
    var alternate: ?ScreenData = null;
    if (flags & flag_has_alternate != 0) {
        alternate = try readScreenBlock(alloc, &cursor);
    }
    errdefer if (alternate) |*v| v.deinit(alloc);

    return .{
        .header = .{
            .timestamp = timestamp,
            .cols = cols,
            .rows = rows,
        },
        .session_id = session_id,
        .pwd = pwd,
        .title = title,
        .primary = primary,
        .alternate = alternate,
    };
}

fn readScreenBlock(alloc: Allocator, cursor: *ReadCursor) (Allocator.Error || Error)!ScreenData {
    // Style table
    const style_count = try cursor.readU16();
    const styles = try alloc.alloc(Style, style_count);
    errdefer alloc.free(styles);

    for (styles) |*s| {
        s.* = try readStyle(cursor);
    }

    // Row data
    const total_rows = try cursor.readU32();
    const cols = try cursor.readU16();
    if (cols == 0) return error.InvalidDimensions;

    const rows_buf = try alloc.alloc(RowData, total_rows);
    var rows_populated: usize = 0;
    errdefer {
        for (rows_buf[0..rows_populated]) |r| r.deinit(alloc);
        alloc.free(rows_buf);
    }

    for (rows_buf) |*row| {
        const row_flags = try cursor.readByte();

        const cells = try alloc.alloc(u64, cols);
        errdefer alloc.free(cells);

        for (cells) |*cell| {
            cell.* = try cursor.readU64();
        }

        row.* = .{
            .cells = cells,
            .wrap = (row_flags & 1) != 0,
            .wrap_continuation = (row_flags & 2) != 0,
            .semantic_prompt = @enumFromInt(@as(u2, @truncate(row_flags >> 2))),
        };
        rows_populated += 1;
    }

    // Grapheme entries
    const grapheme_count = try cursor.readU32();
    const graphemes_buf = try alloc.alloc(GraphemeEntry, grapheme_count);
    var graphemes_populated: usize = 0;
    errdefer {
        for (graphemes_buf[0..graphemes_populated]) |g| g.deinit(alloc);
        alloc.free(graphemes_buf);
    }

    for (graphemes_buf) |*g| {
        const row_index = try cursor.readU32();
        const col_index = try cursor.readU16();
        const cp_count = try cursor.readU16();

        const cps = try alloc.alloc(u21, cp_count);
        errdefer alloc.free(cps);

        for (cps) |*cp| {
            const raw = try cursor.readU32();
            if (raw > std.math.maxInt(u21)) return error.InvalidSnapshot;
            cp.* = @intCast(raw);
        }

        g.* = .{
            .row_index = row_index,
            .col_index = col_index,
            .codepoints = cps,
        };
        graphemes_populated += 1;
    }

    return .{
        .styles = styles,
        .rows = rows_buf,
        .graphemes = graphemes_buf,
        .cols = cols,
    };
}

/// Deserialize one standalone screen block written by `writeScreenData`.
pub fn readScreenData(alloc: Allocator, data: []const u8) (Allocator.Error || Error)!ScreenData {
    var cursor: ReadCursor = .{ .data = data };
    var result = try readScreenBlock(alloc, &cursor);
    errdefer result.deinit(alloc);
    if (cursor.remaining() != 0) return error.InvalidSnapshot;
    return result;
}

fn readStyle(cursor: *ReadCursor) Error!Style {
    return .{
        .fg_color = try readStyleColor(cursor),
        .bg_color = try readStyleColor(cursor),
        .underline_color = try readStyleColor(cursor),
        .flags = @bitCast(try cursor.readU16()),
    };
}

fn readStyleColor(cursor: *ReadCursor) Error!Style.Color {
    const tag = try cursor.readByte();
    const b0 = try cursor.readByte();
    const b1 = try cursor.readByte();
    const b2 = try cursor.readByte();

    return switch (tag) {
        0 => .none,
        1 => .{ .palette = b0 },
        2 => .{ .rgb = .{ .r = b0, .g = b1, .b = b2 } },
        else => error.InvalidSnapshot,
    };
}

// ── Hydration ───────────────────────────────────────────────────────

/// Populate a Screen from deserialized ScreenData.
///
/// The screen must already be initialized at the correct dimensions.
/// Additional rows beyond the initial viewport are grown into the PageList.
/// After hydration, the cursor is positioned at the bottom of the viewport
/// so the most recent content is visible.
pub fn hydrateScreen(
    screen: *Screen,
    screen_data: ScreenData,
) !void {
    const total_rows = screen_data.rows.len;
    const viewport_rows: usize = screen.pages.rows;
    const cols: usize = screen_data.cols;

    // Grow the PageList to hold all saved rows beyond the initial viewport.
    if (total_rows > viewport_rows) {
        var rows_to_add = total_rows - viewport_rows;
        while (rows_to_add > 0) : (rows_to_add -= 1) {
            _ = try screen.pages.grow();
        }
    }

    // Write cell/style/row data into pages.
    var global_row: usize = 0;
    var last_node: ?*PageList.List.Node = null;
    var last_y: usize = 0;
    var node_opt = screen.pages.pages.first;
    while (node_opt) |node| : (node_opt = node.next) {
        const page = &node.data;
        const page_rows = page.size.rows;
        const page_cols = page.size.cols;

        var y: usize = 0;
        while (y < page_rows and global_row < total_rows) : ({
            y += 1;
            global_row += 1;
        }) {
            const saved_row = screen_data.rows[global_row];
            const row = page.getRow(y);

            // Set row flags
            row.wrap = saved_row.wrap;
            row.wrap_continuation = saved_row.wrap_continuation;
            row.semantic_prompt = saved_row.semantic_prompt;

            // Write cells
            const cells = page.getCells(row);
            const cell_count = @min(cols, page_cols);
            var has_styled = false;

            for (0..cell_count) |x| {
                if (x >= saved_row.cells.len) break;
                var cell: Cell = @bitCast(saved_row.cells[x]);

                // Clear grapheme tags from serialized cells — the grapheme
                // application loop below is the sole authority for restoring
                // them via setGraphemes. Writing raw .codepoint_grapheme tags
                // into the page would leave cells with no backing grapheme map
                // entry, which triggers MissingGraphemeData on integrity check.
                if (cell.content_tag == .codepoint_grapheme) {
                    cell.content_tag = .codepoint;
                }

                // Remap style_id from global table to page-local
                if (cell.style_id != 0) {
                    const global_idx = cell.style_id;
                    if (global_idx > 0 and global_idx <= screen_data.styles.len) {
                        const s = screen_data.styles[global_idx - 1];
                        cell.style_id = page.styles.add(page.memory, s) catch 0;
                    } else {
                        cell.style_id = 0;
                    }
                    if (cell.style_id != 0) has_styled = true;
                }

                cells[x] = cell;
            }

            if (has_styled) row.styled = true;

            // Track the last written position for cursor placement
            last_node = node;
            last_y = y;
        }
    }

    // Apply grapheme data
    var grapheme_page_start: usize = 0;
    node_opt = screen.pages.pages.first;
    while (node_opt) |node| : (node_opt = node.next) {
        const page = &node.data;
        const page_rows = page.size.rows;
        const page_end_row = grapheme_page_start + page_rows;

        for (screen_data.graphemes) |g| {
            if (g.row_index >= grapheme_page_start and g.row_index < page_end_row) {
                const local_y = g.row_index - @as(u32, @intCast(grapheme_page_start));
                const row = page.getRow(local_y);
                const cells = page.getCells(row);

                if (g.col_index < cells.len) {
                    const cell = &cells[g.col_index];

                    // setGraphemes requires content_tag == .codepoint
                    if (cell.content_tag == .codepoint_grapheme) {
                        cell.content_tag = .codepoint;
                    }

                    if (cell.codepoint() > 0 and cell.content_tag == .codepoint) {
                        page.setGraphemes(row, cell, g.codepoints) catch |err| {
                            log.warn("snapshot hydrate grapheme failed row={} col={} err={}", .{
                                g.row_index, g.col_index, err,
                            });
                            continue;
                        };
                        cell.content_tag = .codepoint_grapheme;
                        row.grapheme = true;
                    }
                }
            }
        }

        grapheme_page_start = page_end_row;
    }

    // Position cursor at the bottom of the viewport so the most recent
    // content is visible and the session marker appears after restored content.
    if (total_rows > 0) {
        if (last_node) |ln| {
            // Determine cursor.y: for content that fills or exceeds the viewport,
            // place cursor at the last viewport row. For shorter content, place
            // cursor at the last content row.
            const cursor_y: u16 = @intCast(@min(total_rows, viewport_rows) - 1);

            // Update the page pin to point to the last written row
            screen.cursor.page_pin.* = .{
                .node = ln,
                .y = @intCast(last_y),
                .x = 0,
            };
            screen.cursor.x = 0;
            screen.cursor.y = cursor_y;

            // Update derived pointers
            const rac = screen.cursor.page_pin.rowAndCell();
            screen.cursor.page_row = rac.row;
            screen.cursor.page_cell = rac.cell;
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────

test "snapshot header roundtrip" {
    const testing = std.testing;
    const alloc = testing.allocator;

    // Create a terminal with some content
    const Terminal = @import("Terminal.zig");
    var term = try Terminal.init(alloc, .{
        .cols = 80,
        .rows = 24,
    });
    defer term.deinit(alloc);

    const screen = &term.screens.active.*;

    var buf: std.Io.Writer.Allocating = .init(alloc);
    defer buf.deinit();

    try write(alloc, &buf.writer, .{
        .primary = screen,
        .timestamp = 1735689600,
    });

    const data = try buf.toOwnedSlice();
    defer alloc.free(data);

    var result = try read(alloc, data);
    defer result.deinit(alloc);

    try testing.expectEqual(@as(i64, 1735689600), result.header.timestamp);
    try testing.expectEqual(@as(u16, 80), result.header.cols);
    try testing.expectEqual(@as(u16, 24), result.header.rows);
    try testing.expect(result.alternate == null);
}

test "snapshot empty screen roundtrip" {
    const testing = std.testing;
    const alloc = testing.allocator;

    const Terminal = @import("Terminal.zig");
    var term = try Terminal.init(alloc, .{
        .cols = 40,
        .rows = 10,
    });
    defer term.deinit(alloc);

    const screen = &term.screens.active.*;

    var buf: std.Io.Writer.Allocating = .init(alloc);
    defer buf.deinit();

    try write(alloc, &buf.writer, .{ .primary = screen });

    const data = try buf.toOwnedSlice();
    defer alloc.free(data);

    var result = try read(alloc, data);
    defer result.deinit(alloc);

    try testing.expectEqual(@as(u16, 40), result.primary.cols);
    // All cells should be empty (codepoint 0)
    for (result.primary.rows) |row| {
        for (row.cells) |raw_cell| {
            const cell: Cell = @bitCast(raw_cell);
            try testing.expectEqual(@as(u21, 0), cell.codepoint());
        }
    }
}

test "snapshot plain text roundtrip" {
    const testing = std.testing;
    const alloc = testing.allocator;

    const Terminal = @import("Terminal.zig");
    var term = try Terminal.init(alloc, .{
        .cols = 80,
        .rows = 24,
    });
    defer term.deinit(alloc);

    // Write some text via the terminal
    const text = "Hello, World!";
    const stream_terminal = @import("stream_terminal.zig");
    const handler: stream_terminal.Handler = .init(&term);
    var stream: stream_terminal.Stream = .init(handler);
    stream.nextSlice(text);

    const screen = &term.screens.active.*;

    var buf: std.Io.Writer.Allocating = .init(alloc);
    defer buf.deinit();

    try write(alloc, &buf.writer, .{ .primary = screen });

    const data = try buf.toOwnedSlice();
    defer alloc.free(data);

    var result = try read(alloc, data);
    defer result.deinit(alloc);

    // Verify first row has our text
    const first_row = result.primary.rows[0];
    var decoded: [80]u8 = undefined;
    var len: usize = 0;
    for (first_row.cells) |raw_cell| {
        const cell: Cell = @bitCast(raw_cell);
        const cp = cell.codepoint();
        if (cp == 0) break;
        decoded[len] = @intCast(cp);
        len += 1;
    }
    try testing.expectEqualStrings(text, decoded[0..len]);
}

test "snapshot styled text roundtrip" {
    const testing = std.testing;
    const alloc = testing.allocator;

    const Terminal = @import("Terminal.zig");
    var term = try Terminal.init(alloc, .{
        .cols = 80,
        .rows = 24,
    });
    defer term.deinit(alloc);

    // Write bold red text via escape sequence
    const stream_terminal = @import("stream_terminal.zig");
    const handler: stream_terminal.Handler = .init(&term);
    var stream: stream_terminal.Stream = .init(handler);
    // ESC[1;31m = bold + red foreground (palette 1)
    stream.nextSlice("\x1b[1;31mRed Bold\x1b[0m Normal");

    const screen = &term.screens.active.*;

    var buf: std.Io.Writer.Allocating = .init(alloc);
    defer buf.deinit();

    try write(alloc, &buf.writer, .{ .primary = screen });

    const data = try buf.toOwnedSlice();
    defer alloc.free(data);

    var result = try read(alloc, data);
    defer result.deinit(alloc);

    // Verify styles exist (at least one non-default style for the bold red text)
    try testing.expect(result.primary.styles.len > 0);

    // Find a style with bold flag
    var found_bold = false;
    for (result.primary.styles) |style| {
        if (style.flags.bold) {
            found_bold = true;
            break;
        }
    }
    try testing.expect(found_bold);
}

test "snapshot palette and rgb color roundtrip" {
    const testing = std.testing;
    const alloc = testing.allocator;

    const Terminal = @import("Terminal.zig");
    var term = try Terminal.init(alloc, .{
        .cols = 80,
        .rows = 24,
    });
    defer term.deinit(alloc);

    // Write text with palette color (ESC[32m = green) and RGB color (ESC[38;2;255;128;0m)
    const stream_terminal = @import("stream_terminal.zig");
    const handler: stream_terminal.Handler = .init(&term);
    var stream: stream_terminal.Stream = .init(handler);
    stream.nextSlice("\x1b[32mGreen\x1b[38;2;255;128;0mOrange\x1b[0m");

    const screen = &term.screens.active.*;

    var buf: std.Io.Writer.Allocating = .init(alloc);
    defer buf.deinit();

    try write(alloc, &buf.writer, .{ .primary = screen });

    const data = try buf.toOwnedSlice();
    defer alloc.free(data);

    var result = try read(alloc, data);
    defer result.deinit(alloc);

    // Should have at least 2 styles (palette green, rgb orange)
    try testing.expect(result.primary.styles.len >= 2);

    var found_palette = false;
    var found_rgb = false;
    for (result.primary.styles) |style| {
        switch (style.fg_color) {
            .palette => {
                found_palette = true;
            },
            .rgb => |rgb| {
                if (rgb.r == 255 and rgb.g == 128 and rgb.b == 0) {
                    found_rgb = true;
                }
            },
            .none => {},
        }
    }
    try testing.expect(found_palette);
    try testing.expect(found_rgb);
}

test "snapshot wide character roundtrip" {
    const testing = std.testing;
    const alloc = testing.allocator;

    const Terminal = @import("Terminal.zig");
    var term = try Terminal.init(alloc, .{
        .cols = 80,
        .rows = 24,
    });
    defer term.deinit(alloc);

    // Write a wide character (CJK - U+4E16 "世")
    const stream_terminal = @import("stream_terminal.zig");
    const handler: stream_terminal.Handler = .init(&term);
    var stream: stream_terminal.Stream = .init(handler);
    stream.nextSlice("世界");

    const screen = &term.screens.active.*;

    var buf: std.Io.Writer.Allocating = .init(alloc);
    defer buf.deinit();

    try write(alloc, &buf.writer, .{ .primary = screen });

    const data = try buf.toOwnedSlice();
    defer alloc.free(data);

    var result = try read(alloc, data);
    defer result.deinit(alloc);

    // First cell should be wide, second should be spacer_tail
    const first_row = result.primary.rows[0];
    const cell0: Cell = @bitCast(first_row.cells[0]);
    const cell1: Cell = @bitCast(first_row.cells[1]);
    try testing.expectEqual(Cell.Wide.wide, cell0.wide);
    try testing.expectEqual(Cell.Wide.spacer_tail, cell1.wide);
    try testing.expectEqual(@as(u21, 0x4E16), cell0.codepoint());
}

test "snapshot invalid magic returns error" {
    const testing = std.testing;
    const alloc = testing.allocator;

    const bad_data = "XYZW\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    try testing.expectError(error.InvalidSnapshot, read(alloc, bad_data));
}

test "snapshot unsupported version returns error" {
    const testing = std.testing;
    const alloc = testing.allocator;

    // Valid magic but version 99
    const bad_data = "GSNP\x63\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    try testing.expectError(error.UnsupportedVersion, read(alloc, bad_data));
}

test "snapshot metadata roundtrip" {
    const testing = std.testing;
    const alloc = testing.allocator;

    const Terminal = @import("Terminal.zig");
    var term = try Terminal.init(alloc, .{
        .cols = 80,
        .rows = 24,
    });
    defer term.deinit(alloc);

    const screen = &term.screens.active.*;

    var buf: std.Io.Writer.Allocating = .init(alloc);
    defer buf.deinit();

    try write(alloc, &buf.writer, .{
        .primary = screen,
        .session_id = "test-session-123",
        .pwd = "/home/user",
        .title = "My Terminal",
        .timestamp = 1700000000,
    });

    const data = try buf.toOwnedSlice();
    defer alloc.free(data);

    var result = try read(alloc, data);
    defer result.deinit(alloc);

    try testing.expectEqualStrings("test-session-123", result.session_id.?);
    try testing.expectEqualStrings("/home/user", result.pwd.?);
    try testing.expectEqualStrings("My Terminal", result.title.?);
    try testing.expectEqual(@as(i64, 1700000000), result.header.timestamp);
}

test "snapshot hydrate populates screen" {
    const testing = std.testing;
    const alloc = testing.allocator;

    const Terminal = @import("Terminal.zig");

    // Create source terminal with content
    var src_term = try Terminal.init(alloc, .{
        .cols = 40,
        .rows = 10,
    });
    defer src_term.deinit(alloc);

    {
        const stream_terminal = @import("stream_terminal.zig");
        const handler: stream_terminal.Handler = .init(&src_term);
        var stream: stream_terminal.Stream = .init(handler);
        stream.nextSlice("Line one");
    }

    // Serialize
    var buf: std.Io.Writer.Allocating = .init(alloc);
    defer buf.deinit();
    try write(alloc, &buf.writer, .{ .primary = &src_term.screens.active.* });
    const data = try buf.toOwnedSlice();
    defer alloc.free(data);

    // Parse
    var result = try read(alloc, data);
    defer result.deinit(alloc);

    // Create destination terminal and hydrate
    var dst_term = try Terminal.init(alloc, .{
        .cols = 40,
        .rows = 10,
    });
    defer dst_term.deinit(alloc);

    try hydrateScreen(&dst_term.screens.active.*, result.primary);

    // Verify content was written to destination
    const dst_screen = &dst_term.screens.active.*;
    const page = &dst_screen.pages.pages.first.?.data;
    const row = page.getRow(0);
    const cells = page.getCells(row);

    var decoded: [40]u8 = undefined;
    var len: usize = 0;
    for (cells) |cell| {
        const cp = cell.codepoint();
        if (cp == 0) break;
        decoded[len] = @intCast(cp);
        len += 1;
    }
    try testing.expectEqualStrings("Line one", decoded[0..len]);
}

test "snapshot truncated data returns error" {
    const testing = std.testing;
    const alloc = testing.allocator;

    // Too short for header
    try testing.expectError(error.InvalidSnapshot, read(alloc, "GSNP"));
    // Just the header, no metadata
    try testing.expectError(error.EndOfData, read(alloc, "GSNP\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"));
}

test "snapshot grapheme cluster roundtrip" {
    const testing = std.testing;
    const alloc = testing.allocator;

    const Terminal = @import("Terminal.zig");
    var term = try Terminal.init(alloc, .{
        .cols = 80,
        .rows = 24,
    });
    defer term.deinit(alloc);

    // Write a skin-tone emoji (flag sequence: U+1F1FA U+1F1F8 = 🇺🇸)
    // and a combining character sequence (e + combining acute = é)
    const stream_terminal = @import("stream_terminal.zig");
    const handler: stream_terminal.Handler = .init(&term);
    var stream: stream_terminal.Stream = .init(handler);
    // e followed by combining acute accent (U+0301)
    stream.nextSlice("e\xCC\x81 test");

    const screen = &term.screens.active.*;

    var buf: std.Io.Writer.Allocating = .init(alloc);
    defer buf.deinit();

    try write(alloc, &buf.writer, .{ .primary = screen });

    const data = try buf.toOwnedSlice();
    defer alloc.free(data);

    var result = try read(alloc, data);
    defer result.deinit(alloc);

    // Check that grapheme data was captured
    try testing.expect(result.primary.graphemes.len > 0);

    // The first grapheme entry should be at row 0, col 0 (the é)
    const g = result.primary.graphemes[0];
    try testing.expectEqual(@as(u32, 0), g.row_index);
    try testing.expectEqual(@as(u16, 0), g.col_index);
    // Should contain the combining acute accent
    try testing.expectEqual(@as(u21, 0x0301), g.codepoints[0]);
}

test "snapshot large multi-page screen roundtrip" {
    const testing = std.testing;
    const alloc = testing.allocator;

    const Terminal = @import("Terminal.zig");
    var term = try Terminal.init(alloc, .{
        .cols = 80,
        .rows = 24,
        .max_scrollback = 500,
    });
    defer term.deinit(alloc);

    // Write 120+ lines to force multiple pages and scrollback
    const stream_terminal = @import("stream_terminal.zig");
    const handler: stream_terminal.Handler = .init(&term);
    var stream: stream_terminal.Stream = .init(handler);
    var line_buf: [90]u8 = undefined;
    for (0..130) |i| {
        const line = std.fmt.bufPrint(&line_buf, "Line {d:0>4}\r\n", .{i}) catch continue;
        stream.nextSlice(line);
    }

    const screen = &term.screens.active.*;

    var buf: std.Io.Writer.Allocating = .init(alloc);
    defer buf.deinit();

    try write(alloc, &buf.writer, .{ .primary = screen });

    const data = try buf.toOwnedSlice();
    defer alloc.free(data);

    var result = try read(alloc, data);
    defer result.deinit(alloc);

    // Should have captured all rows (scrollback + viewport)
    try testing.expect(result.primary.rows.len > 24);

    // Verify last line content
    const last_row = result.primary.rows[result.primary.rows.len - 2]; // -2 because last line is after \r\n
    const cell0: Cell = @bitCast(last_row.cells[0]);
    // Should start with 'L' from "Line NNNN"
    try testing.expectEqual(@as(u21, 'L'), cell0.codepoint());
}

test "snapshot hydrate cursor position at bottom" {
    const testing = std.testing;
    const alloc = testing.allocator;

    const Terminal = @import("Terminal.zig");

    // Create source terminal with several lines
    var src_term = try Terminal.init(alloc, .{
        .cols = 40,
        .rows = 10,
    });
    defer src_term.deinit(alloc);

    {
        const stream_terminal = @import("stream_terminal.zig");
        const handler: stream_terminal.Handler = .init(&src_term);
        var stream: stream_terminal.Stream = .init(handler);
        stream.nextSlice("Line 1\r\nLine 2\r\nLine 3\r\nLine 4\r\nLine 5");
    }

    // Serialize
    var buf: std.Io.Writer.Allocating = .init(alloc);
    defer buf.deinit();
    try write(alloc, &buf.writer, .{ .primary = &src_term.screens.active.* });
    const data = try buf.toOwnedSlice();
    defer alloc.free(data);

    // Parse
    var result = try read(alloc, data);
    defer result.deinit(alloc);

    // Hydrate into a new terminal
    var dst_term = try Terminal.init(alloc, .{
        .cols = 40,
        .rows = 10,
    });
    defer dst_term.deinit(alloc);

    try hydrateScreen(&dst_term.screens.active.*, result.primary);

    // Cursor should be near the bottom of content, not at (0,0)
    const cursor_y = dst_term.screens.active.cursor.y;
    try testing.expect(cursor_y >= 4);
}

test "snapshot max_bytes per-surface cap below minimum produces zero bytes" {
    const testing = std.testing;
    const alloc = testing.allocator;

    const Terminal = @import("Terminal.zig");
    var term = try Terminal.init(alloc, .{
        .cols = 80,
        .rows = 24,
    });
    defer term.deinit(alloc);

    const screen = &term.screens.active.*;

    // Per-surface cap below minimum block size (12 bytes): write()
    // produces zero bytes — no partial/invalid output.
    var buf: std.Io.Writer.Allocating = .init(alloc);
    defer buf.deinit();

    try write(alloc, &buf.writer, .{
        .primary = screen,
        .max_bytes = 10,
    });

    try testing.expectEqual(@as(usize, 0), buf.writer.end);
}

test "snapshot max_bytes enforces hard cap with content" {
    const testing = std.testing;
    const alloc = testing.allocator;

    const Terminal = @import("Terminal.zig");
    var term = try Terminal.init(alloc, .{
        .cols = 80,
        .rows = 24,
        .max_scrollback = 500,
    });
    defer term.deinit(alloc);

    // Write lots of content
    const stream_terminal = @import("stream_terminal.zig");
    const handler: stream_terminal.Handler = .init(&term);
    var stream: stream_terminal.Stream = .init(handler);
    var line_buf: [90]u8 = undefined;
    for (0..100) |i| {
        const line = std.fmt.bufPrint(&line_buf, "Line {d:0>4}\r\n", .{i}) catch continue;
        stream.nextSlice(line);
    }

    const screen = &term.screens.active.*;

    // Set a byte cap of 2048
    const cap: usize = 2048;
    var buf: std.Io.Writer.Allocating = .init(alloc);
    defer buf.deinit();

    try write(alloc, &buf.writer, .{
        .primary = screen,
        .max_bytes = cap,
    });

    // Output must not exceed the cap
    try testing.expect(buf.writer.end <= cap);
    // But should still be a valid snapshot (if any output was produced)
    if (buf.writer.end > 0) {
        const data = buf.writer.buffer[0..buf.writer.end];
        var result = try read(alloc, data);
        defer result.deinit(alloc);
        try testing.expectEqual(@as(u16, 80), result.header.cols);
    }
}

test "snapshot hydrate grapheme cells across scrollback does not crash" {
    // Regression test for grapheme integrity violation during hydration.
    //
    // The crash occurs because hydrateScreen writes raw cell bits (including
    // content_tag == .codepoint_grapheme) into pages before the grapheme map
    // entries are applied. When page.setGraphemes is called for the first
    // grapheme entry, its deferred assertIntegrity scans the whole page and
    // finds other cells still tagged .codepoint_grapheme with no backing
    // grapheme map entry — triggering MissingGraphemeData.
    //
    // Reproduces the y=295 x=17 crash seen with session 753BB357.
    const testing = std.testing;
    const alloc = testing.allocator;

    const Terminal = @import("Terminal.zig");
    const stream_terminal = @import("stream_terminal.zig");

    var term = try Terminal.init(alloc, .{
        .cols = 81,
        .rows = 36,
        .max_scrollback = 5000,
    });
    defer term.deinit(alloc);

    const handler: stream_terminal.Handler = .init(&term);
    var stream: stream_terminal.Stream = .init(handler);

    // Write enough lines to fill multiple pages of scrollback, with
    // grapheme clusters (✔️ = U+2714 U+FE0F) sprinkled across them.
    // The key is having multiple grapheme cells that land on the same
    // page after hydration — matching the real crash scenario.
    var line_buf: [120]u8 = undefined;
    for (0..1500) |i| {
        if (i % 100 == 5) {
            // Insert a line with a grapheme cluster at column 17
            const prefix = "                 "; // 17 spaces
            stream.nextSlice(prefix);
            // ✔ (U+2714) followed by variation selector (U+FE0F)
            stream.nextSlice("\xe2\x9c\x94\xef\xb8\x8f");
            stream.nextSlice(" done\r\n");
        } else {
            const line = std.fmt.bufPrint(&line_buf, "Line {d:0>4}\r\n", .{i}) catch continue;
            stream.nextSlice(line);
        }
    }

    const screen = &term.screens.active.*;

    // Snapshot
    var buf: std.Io.Writer.Allocating = .init(alloc);
    defer buf.deinit();
    try write(alloc, &buf.writer, .{ .primary = screen });
    const data = try buf.toOwnedSlice();
    defer alloc.free(data);

    // Parse
    var result = try read(alloc, data);
    defer result.deinit(alloc);

    // Verify we captured grapheme entries
    try testing.expect(result.primary.graphemes.len > 0);

    // Hydrate into a new terminal — this is where the crash occurs
    // because setGraphemes triggers assertIntegrity while other cells
    // on the same page still have orphaned .codepoint_grapheme tags.
    var dst_term = try Terminal.init(alloc, .{
        .cols = 81,
        .rows = 36,
    });
    defer dst_term.deinit(alloc);

    try hydrateScreen(&dst_term.screens.active.*, result.primary);
}
