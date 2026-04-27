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

/// Byte size of a serialized style entry.
const style_entry_size: usize = 14;

pub const Error = error{
    InvalidSnapshot,
    UnsupportedVersion,
    InvalidDimensions,
    EndOfData,
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
};

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
        const sp_raw: u2 = @truncate(row_flags >> 2);
        const semantic_prompt = std.meta.intToEnum(
            pagepkg.Row.SemanticPrompt,
            sp_raw,
        ) catch return error.InvalidSnapshot;

        const cells = try alloc.alloc(u64, cols);
        errdefer alloc.free(cells);

        for (cells) |*cell| {
            cell.* = try cursor.readU64();
        }

        row.* = .{
            .cells = cells,
            .wrap = (row_flags & 1) != 0,
            .wrap_continuation = (row_flags & 2) != 0,
            .semantic_prompt = semantic_prompt,
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

test "snapshot read rejects invalid semantic prompt row flag" {
    const testing = std.testing;

    var data: std.Io.Writer.Allocating = .init(testing.allocator);
    defer data.deinit();

    try data.writer.writeInt(u16, 0, .little);
    try data.writer.writeInt(u32, 1, .little);
    try data.writer.writeInt(u16, 1, .little);
    // Semantic prompt value 3 is outside Row.SemanticPrompt's 0..2 range.
    try data.writer.writeByte(0b1100);
    try data.writer.writeInt(u64, 0, .little);
    try data.writer.writeInt(u32, 0, .little);

    try testing.expectError(
        error.InvalidSnapshot,
        readScreenData(testing.allocator, data.writer.buffer[0..data.writer.end]),
    );
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
