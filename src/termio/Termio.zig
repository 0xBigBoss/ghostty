//! Primary terminal IO ("termio") state. This maintains the terminal state,
//! pty, subprocess, etc. This is flexible enough to be used in environments
//! that don't have a pty and simply provides the input/output using raw
//! bytes.
pub const Termio = @This();

const std = @import("std");
const assert = @import("../quirks.zig").inlineAssert;
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
const termio = @import("../termio.zig");
const StreamHandler = @import("stream_handler.zig").StreamHandler;
const terminalpkg = @import("../terminal/main.zig");
const xev = @import("../global.zig").xev;
const renderer = @import("../renderer.zig");
const apprt = @import("../apprt.zig");
const configpkg = @import("../config.zig");
const ProcessInfo = @import("../pty.zig").ProcessInfo;
const persisted_scrollback = @import("persisted_scrollback.zig");

const log = std.log.scoped(.io_exec);

/// Mutex state argument for queueMessage.
pub const MutexState = enum { locked, unlocked };

/// Allocator
alloc: Allocator,

/// This is the implementation responsible for io.
backend: termio.Backend,

/// The derived configuration for this termio implementation.
config: DerivedConfig,

/// The terminal emulator internal state. This is the abstract "terminal"
/// that manages input, grid updating, etc. and is renderer-agnostic. It
/// just stores internal state about a grid.
terminal: terminalpkg.Terminal,

/// The shared render state
renderer_state: *renderer.State,

/// A handle to wake up the renderer. This hints to the renderer that
/// a repaint should happen.
renderer_wakeup: xev.Async,

/// The mailbox for notifying the renderer of things.
renderer_mailbox: *renderer.Thread.Mailbox,

/// The mailbox for communicating with the surface.
surface_mailbox: apprt.surface.Mailbox,

/// The cached size info
size: renderer.Size,

/// The mailbox implementation to use.
mailbox: termio.Mailbox,

/// The stream parser. This parses the stream of escape codes and so on
/// from the child process and calls callbacks in the stream handler.
terminal_stream: StreamHandler.Stream,

/// Last time the cursor was reset. This is used to prevent message
/// flooding with cursor resets.
last_cursor_reset: ?std.time.Instant = null,

/// State we have for thread enter. This may be null if we don't need
/// to keep track of any state or if its already been freed.
thread_enter_state: ?*ThreadEnterState = null,

/// Persisted scrollback checkpoint state for session-directory restore.
persisted: ?PersistedState = null,

/// Coordination state for bounded termination flushing.
termination: TerminationState = .{},

/// The state we need to keep around only until we enter the IO
/// thread. Then we can throw it all away.
const ThreadEnterState = struct {
    arena: ArenaAllocator,

    /// Initial input to send to the subprocess after starting. This
    /// memory is freed once the subprocess start is attempted, even
    /// if it fails, because Exec only starts once.
    input: configpkg.io.RepeatableReadableIO,

    pub fn create(
        alloc: Allocator,
        config: *const configpkg.Config,
    ) !?*ThreadEnterState {
        // If we have no input then we have no thread enter state
        if (config.input.list.items.len == 0) return null;

        // Create our arena allocator
        var arena = ArenaAllocator.init(alloc);
        errdefer arena.deinit();
        const arena_alloc = arena.allocator();

        // Allocate our ThreadEnterState
        const ptr = try arena_alloc.create(ThreadEnterState);

        // Copy the input from the config
        const input = try config.input.cloneParsed(arena_alloc);

        // Return the initialized state
        ptr.* = .{
            .arena = arena,
            .input = input,
        };
        return ptr;
    }

    pub fn destroy(self: *ThreadEnterState) void {
        self.arena.deinit();
    }

    /// Prepare the inputs for use. Allocations happen on the arena.
    pub fn prepareInput(
        self: *ThreadEnterState,
    ) (Allocator.Error || error{InputNotFound})![]const Input {
        const alloc = self.arena.allocator();

        var input = try alloc.alloc(
            Input,
            self.input.list.items.len,
        );
        for (self.input.list.items, 0..) |item, i| {
            input[i] = switch (item) {
                .raw => |v| .{ .string = try alloc.dupe(u8, v) },
                .path => |path| file: {
                    const f = std.fs.cwd().openFile(
                        path,
                        .{},
                    ) catch |err| {
                        log.warn("failed to open input file={s} err={}", .{
                            path,
                            err,
                        });
                        return error.InputNotFound;
                    };

                    break :file .{ .file = f };
                },
            };
        }

        return input;
    }

    const Input = union(enum) {
        string: []const u8,
        file: std.fs.File,
    };
};

const PersistedState = struct {
    session_dir: []u8,
    session_id: ?[]u8,
    limit: usize,
    last_persisted_row_count: usize = 0,
    last_persisted_seq: u64 = 0,
    next_seq: u64 = 0,
    scrollback_size_bytes: usize = 0,
    scrollback_invalidated: bool = false,
    header_written: bool = false,
    last_header_dims: ?PersistedHeaderDims = null,
    last_metadata_hash: u64 = 0,
    dirty: bool = false,
    dirty_generation: u64 = 0,
    notify_pending: bool = false,
    dirty_started_at: ?std.time.Instant = null,
    last_dirty_at: ?std.time.Instant = null,
    retry_count: u8 = 0,

    fn init(
        alloc: Allocator,
        config: *const configpkg.Config,
        session_id: ?[]const u8,
        restored: ?*const persisted_scrollback.Loaded,
    ) !?PersistedState {
        const limit = config.@"scrollback-snapshot-limit";
        if (limit == 0) {
            log.debug("persisted scrollback save disabled reason=snapshot-limit-zero", .{});
            return null;
        }

        const sid = session_id orelse {
            log.debug("persisted scrollback save unavailable reason=no-session-id", .{});
            return null;
        };
        if (sid.len == 0) {
            log.debug("persisted scrollback save unavailable reason=empty-session-id", .{});
            return null;
        }

        const session_dir = try persisted_scrollback.sessionDirPath(alloc, sid);
        errdefer alloc.free(session_dir);

        // Ensure the session directory exists so publish can write to it.
        persisted_scrollback.ensureSessionDir(session_dir) catch |err| {
            log.warn("persisted scrollback save disabled reason=dir-create-failed err={}", .{err});
            alloc.free(session_dir);
            return null;
        };
        const scrollback_size_bytes = persistedScrollbackFileSize(session_dir) catch |err| size: {
            if (err != error.FileNotFound) {
                log.warn("persisted scrollback size unavailable dir={s} err={}", .{ session_dir, err });
            }
            break :size 0;
        };

        log.debug(
            "persisted scrollback save enabled dir={s} limit={} session_id={s}",
            .{ session_dir, limit, sid },
        );

        return .{
            .session_dir = session_dir,
            .session_id = try alloc.dupe(u8, sid),
            .limit = limit,
            .last_persisted_row_count = if (restored) |v| v.scrollback_rows else 0,
            .last_persisted_seq = if (restored) |v| v.scrollback_tail_seq else 0,
            .next_seq = if (restored) |v| v.next_seq else 0,
            .scrollback_size_bytes = scrollback_size_bytes,
            .header_written = restored != null,
            .last_header_dims = if (restored) |v| .{
                .cols = v.header.cols,
                .rows = v.header.rows,
            } else null,
        };
    }

    fn deinit(self: *PersistedState, alloc: Allocator) void {
        alloc.free(self.session_dir);
        if (self.session_id) |value| alloc.free(value);
        self.* = undefined;
    }
};

const PersistedHeaderDims = struct {
    cols: u16,
    rows: u16,
};

pub const persisted_scrollback_debounce_ms = 400;
const persisted_scrollback_max_staleness_ms = 2_000;
const persisted_scrollback_retry_base_ms = 250;
const persisted_scrollback_retry_cap_ms = 2_000;

pub const TerminationResult = enum(u8) {
    pending,
    flushed,
    flush_failed,
    timed_out,
};

const TerminationState = struct {
    mutex: std.Thread.Mutex = .{},
    reset: std.Thread.ResetEvent = .{},
    request_id: u64 = 0,
    completed_id: u64 = 0,
    result: TerminationResult = .pending,

    fn begin(self: *TerminationState) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.request_id +%= 1;
        self.completed_id = 0;
        self.result = .pending;
        self.reset = .{};
        return self.request_id;
    }

    fn complete(
        self: *TerminationState,
        request_id: u64,
        result: TerminationResult,
    ) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (request_id != self.request_id) return;
        self.completed_id = request_id;
        self.result = result;
        self.reset.set();
    }

    fn wait(
        self: *TerminationState,
        request_id: u64,
        timeout_ns: u64,
    ) TerminationResult {
        self.reset.timedWait(timeout_ns) catch return .timed_out;

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.completed_id != request_id) return .timed_out;
        return self.result;
    }
};

const PersistedScheduleState = struct {
    dirty: bool,
    dirty_age_ms: u64,
    idle_ms: u64,
};

const PersistedScheduleDecision = union(enum) {
    none,
    flush,
    reschedule: u64,
};

fn persistedScrollbackScheduleDecision(
    state: PersistedScheduleState,
) PersistedScheduleDecision {
    if (!state.dirty) return .none;
    if (state.dirty_age_ms >= persisted_scrollback_max_staleness_ms) return .flush;
    if (state.idle_ms >= persisted_scrollback_debounce_ms) return .flush;

    const quiet_remaining = persisted_scrollback_debounce_ms - state.idle_ms;
    const stale_remaining = persisted_scrollback_max_staleness_ms - state.dirty_age_ms;
    return .{ .reschedule = @max(@as(u64, 1), @min(quiet_remaining, stale_remaining)) };
}

fn persistedScrollbackRetryDelayMs(retry_count: u8) u64 {
    const shift = @min(retry_count, 3);
    const delay = @as(u64, persisted_scrollback_retry_base_ms) << @intCast(shift);
    return @min(delay, persisted_scrollback_retry_cap_ms);
}

/// The configuration for this IO that is derived from the main
/// configuration. This must be exported so that we don't need to
/// pass around Config pointers which makes memory management a pain.
pub const DerivedConfig = struct {
    arena: ArenaAllocator,

    palette: terminalpkg.color.Palette,
    image_storage_limit: usize,
    cursor_style: terminalpkg.CursorStyle,
    cursor_blink: ?bool,
    cursor_color: ?configpkg.Config.TerminalColor,
    foreground: configpkg.Config.Color,
    background: configpkg.Config.Color,
    osc_color_report_format: configpkg.Config.OSCColorReportFormat,
    clipboard_write: configpkg.ClipboardAccess,
    enquiry_response: []const u8,
    conditional_state: configpkg.ConditionalState,

    pub fn init(
        alloc_gpa: Allocator,
        config: *const configpkg.Config,
    ) !DerivedConfig {
        var arena = ArenaAllocator.init(alloc_gpa);
        errdefer arena.deinit();
        const alloc = arena.allocator();

        const palette: terminalpkg.color.Palette = palette: {
            if (config.@"palette-generate") generate: {
                if (config.palette.mask.findFirstSet() == null) {
                    // If the user didn't set any values manually, then
                    // we're using the default palette and we don't need
                    // to apply the generation code to it.
                    break :generate;
                }

                break :palette terminalpkg.color.generate256Color(config.palette.value, config.palette.mask, config.background.toTerminalRGB(), config.foreground.toTerminalRGB(), config.@"palette-harmonious");
            }

            break :palette config.palette.value;
        };

        return .{
            .palette = palette,
            .image_storage_limit = config.@"image-storage-limit",
            .cursor_style = config.@"cursor-style",
            .cursor_blink = config.@"cursor-style-blink",
            .cursor_color = config.@"cursor-color",
            .foreground = config.foreground,
            .background = config.background,
            .osc_color_report_format = config.@"osc-color-report-format",
            .clipboard_write = config.@"clipboard-write",
            .enquiry_response = try alloc.dupe(u8, config.@"enquiry-response"),
            .conditional_state = config._conditional_state,

            // This has to be last so that we copy AFTER the arena allocations
            // above happen (Zig assigns in order).
            .arena = arena,
        };
    }

    pub fn deinit(self: *DerivedConfig) void {
        self.arena.deinit();
    }
};

fn maybeLoadPersistedScrollback(
    alloc: Allocator,
    config: *const configpkg.Config,
    session_id: ?[]const u8,
) ?persisted_scrollback.Loaded {
    const limit = config.@"scrollback-snapshot-limit";
    if (limit == 0) {
        log.info("persisted scrollback restore disabled reason=snapshot-limit-zero", .{});
        return null;
    }

    const sid = session_id orelse {
        log.info("persisted scrollback restore unavailable reason=no-session-id", .{});
        return null;
    };
    if (sid.len == 0) {
        log.info("persisted scrollback restore unavailable reason=empty-session-id", .{});
        return null;
    }

    const path = persisted_scrollback.sessionDirPath(alloc, sid) catch |err| {
        log.warn("persisted scrollback restore skipped reason=path-error err={}", .{err});
        return null;
    };
    defer alloc.free(path);

    const loaded = persisted_scrollback.load(alloc, path, limit) catch |err| {
        log.warn("persisted scrollback restore skipped path={s} err={}", .{ path, err });
        return null;
    };

    log.info(
        "persisted scrollback restore loaded dir={s} rows={} cols={} primary_rows={} session_id_present={}",
        .{
            path,
            loaded.header.rows,
            loaded.header.cols,
            loaded.primary.rows.len,
            loaded.session_id != null,
        },
    );

    return loaded;
}

fn persistedScrollbackFileSize(session_dir: []const u8) !usize {
    var dir = if (std.fs.path.isAbsolute(session_dir))
        try std.fs.openDirAbsolute(session_dir, .{})
    else
        try std.fs.cwd().openDir(session_dir, .{});
    defer dir.close();

    const stat = try dir.statFile("scrollback");
    return @intCast(stat.size);
}

fn restoredSessionLabel(alloc: Allocator, timestamp: i64) Allocator.Error![]u8 {
    const secs: u64 = @intCast(@max(timestamp, 0));
    const epoch_seconds: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const epoch_day = epoch_seconds.getEpochDay();
    const day_seconds = epoch_seconds.getDaySeconds();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const month_names = [_][]const u8{
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "Jun",
        "Jul",
        "Aug",
        "Sep",
        "Oct",
        "Nov",
        "Dec",
    };
    const month_name = month_names[month_day.month.numeric() - 1];

    return std.fmt.allocPrint(
        alloc,
        "[Restored {s} {d}, {d} at {d:0>2}:{d:0>2}:{d:0>2} UTC]",
        .{
            month_name,
            month_day.day_index + 1,
            year_day.year,
            day_seconds.getHoursIntoDay(),
            day_seconds.getMinutesIntoHour(),
            day_seconds.getSecondsIntoMinute(),
        },
    );
}

fn restoredSessionMarker(
    alloc: Allocator,
    cols: usize,
    timestamp: i64,
) Allocator.Error![]u8 {
    _ = cols;

    const label = try restoredSessionLabel(alloc, timestamp);
    defer alloc.free(label);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);

    try out.appendSlice(alloc, "\r\n\x1b[0m\x1b[2m");
    try out.appendSlice(alloc, label);
    try out.appendSlice(alloc, "\x1b[0m\r\n");

    return try out.toOwnedSlice(alloc);
}

fn hydrateRestoredTerminal(
    alloc: Allocator,
    term: *terminalpkg.Terminal,
    restored: persisted_scrollback.Loaded,
) void {
    const snapshot = terminalpkg.snapshot;

    // Hydrate primary screen from binary snapshot data
    const screen = term.screens.get(.primary) orelse term.screens.active;
    snapshot.hydrateScreen(screen, restored.primary) catch |err| {
        log.warn("persisted scrollback primary hydrate failed err={}", .{err});
    };

    // Hydrate alternate screen if present — must init it first since
    // a fresh terminal only has the primary screen. Then switch to it
    // so the terminal resumes on the same screen it was saved from.
    if (restored.alternate) |alt_data| {
        const alt_screen = term.screens.getInit(alloc, .alternate, .{
            .cols = restored.header.cols,
            .rows = restored.header.rows,
        }) catch |err| {
            log.warn("persisted scrollback alternate screen init failed err={}", .{err});
            return;
        };
        snapshot.hydrateScreen(alt_screen, alt_data) catch |err| {
            log.warn("persisted scrollback alternate hydrate failed err={}", .{err});
        };
        term.screens.switchTo(.alternate);
    }

    if (restored.pwd) |pwd| {
        term.setPwd(pwd) catch |err| {
            log.warn("persisted scrollback pwd hydrate failed err={}", .{err});
        };
    }

    if (restored.title) |title| {
        term.setTitle(title) catch |err| {
            log.warn("persisted scrollback title hydrate failed err={}", .{err});
        };
    }

    // Append session marker via VT replay (small, constant-size)
    const marker = restoredSessionMarker(
        alloc,
        restored.header.cols,
        restored.header.timestamp,
    ) catch null;
    if (marker) |line| {
        defer alloc.free(line);
        var replay: terminalpkg.TerminalStream = .initAlloc(
            alloc,
            .init(term),
        );
        defer replay.deinit();
        replay.nextSlice(line);
    }
}

/// Initialize the termio state.
///
/// This will also start the child process if the termio is configured
/// to run a child process.
pub fn init(self: *Termio, alloc: Allocator, opts: termio.Options) !void {
    // The default terminal modes based on our config.
    const default_modes: terminalpkg.ModePacked = modes: {
        var modes: terminalpkg.ModePacked = .{};

        // Setup our initial grapheme cluster support if enabled. We use a
        // switch to ensure we get a compiler error if more cases are added.
        switch (opts.full_config.@"grapheme-width-method") {
            .unicode => modes.grapheme_cluster = true,
            .legacy => {},
        }

        // Set default cursor blink settings
        modes.cursor_blinking = opts.config.cursor_blink orelse true;

        break :modes modes;
    };

    var restored = maybeLoadPersistedScrollback(alloc, opts.full_config, opts.session_id);
    defer if (restored) |*v| v.deinit(alloc);

    // Create our terminal. If we restored persisted scrollback, initialize
    // the terminal to the saved dimensions and let Surface.resize reflow
    // to the current window size later in startup.
    var term = try terminalpkg.Terminal.init(alloc, opts: {
        const grid_size = opts.size.grid();
        break :opts .{
            .cols = if (restored) |v| v.header.cols else grid_size.columns,
            .rows = if (restored) |v| v.header.rows else grid_size.rows,
            .max_scrollback = opts.full_config.@"scrollback-limit",
            .default_modes = default_modes,
            .colors = .{
                .background = .init(opts.config.background.toTerminalRGB()),
                .foreground = .init(opts.config.foreground.toTerminalRGB()),
                .cursor = cursor: {
                    const color = opts.config.cursor_color orelse break :cursor .unset;
                    const rgb = color.toTerminalRGB() orelse break :cursor .unset;
                    break :cursor .init(rgb);
                },
                .palette = .init(opts.config.palette),
            },
            .kitty_image_storage_limit = opts.config.image_storage_limit,
            .kitty_image_loading_limits = .all,
        };
    });
    errdefer term.deinit(alloc);

    if (restored) |v| {
        hydrateRestoredTerminal(alloc, &term, v);
    }

    // Set our default cursor style
    term.screens.active.cursor.cursor_style = opts.config.cursor_style;

    // Setup our terminal size in pixels for certain requests.
    term.width_px = term.cols * opts.size.cell.width;
    term.height_px = term.rows * opts.size.cell.height;

    // Setup our backend.
    var backend = opts.backend;
    backend.initTerminal(&term);

    // Create our stream handler. This points to memory in self so it
    // isn't safe to use until self.* is set.
    const handler: StreamHandler = .{
        .alloc = alloc,
        .termio_mailbox = &self.mailbox,
        .surface_mailbox = opts.surface_mailbox,
        .renderer_state = opts.renderer_state,
        .renderer_wakeup = opts.renderer_wakeup,
        .renderer_mailbox = opts.renderer_mailbox,
        .size = &self.size,
        .terminal = &self.terminal,
        .osc_color_report_format = opts.config.osc_color_report_format,
        .clipboard_write = opts.config.clipboard_write,
        .enquiry_response = opts.config.enquiry_response,
        .default_cursor_style = opts.config.cursor_style,
        .default_cursor_blink = opts.config.cursor_blink,
    };

    const thread_enter_state = try ThreadEnterState.create(
        alloc,
        opts.full_config,
    );

    const persisted = try PersistedState.init(
        alloc,
        opts.full_config,
        opts.session_id,
        if (restored) |*v| v else null,
    );

    self.* = .{
        .alloc = alloc,
        .terminal = term,
        .config = opts.config,
        .renderer_state = opts.renderer_state,
        .renderer_wakeup = opts.renderer_wakeup,
        .renderer_mailbox = opts.renderer_mailbox,
        .surface_mailbox = opts.surface_mailbox,
        .size = opts.size,
        .backend = backend,
        .mailbox = opts.mailbox,
        .terminal_stream = .initAlloc(alloc, handler),
        .thread_enter_state = thread_enter_state,
        .persisted = persisted,
    };
}

pub fn deinit(self: *Termio) void {
    self.backend.deinit();
    self.terminal.deinit(self.alloc);
    self.config.deinit();
    self.mailbox.deinit(self.alloc);

    // Clear any StreamHandler state
    self.terminal_stream.deinit();

    // Clear any initial state if we have it
    if (self.thread_enter_state) |v| v.destroy();
    if (self.persisted) |*v| v.deinit(self.alloc);
}

pub fn threadEnter(
    self: *Termio,
    thread: *termio.Thread,
    data: *ThreadData,
) !void {
    // Always free our thread enter state when we're done.
    defer if (self.thread_enter_state) |v| {
        v.destroy();
        self.thread_enter_state = null;
    };

    // If we have thread enter state then we're going to validate
    // and set that all up now so that we can error before we actually
    // start the command and pty.
    const inputs: ?[]const ThreadEnterState.Input = if (self.thread_enter_state) |v|
        try v.prepareInput()
    else
        null;

    data.* = .{
        .alloc = self.alloc,
        .loop = &thread.loop,
        .renderer_state = self.renderer_state,
        .surface_mailbox = self.surface_mailbox,
        .mailbox = &self.mailbox,
        .backend = undefined, // Backend must replace this on threadEnter
    };

    // Setup our backend
    try self.backend.threadEnter(self.alloc, self, data);
    errdefer self.backend.threadExit(data);

    // If we have inputs, then queue them all up.
    for (inputs orelse &.{}) |input| switch (input) {
        .string => |v| self.queueWrite(data, v, false) catch |err| {
            log.warn("failed to queue input string err={}", .{err});
            return error.InputFailed;
        },
        .file => |f| self.queueWrite(
            data,
            f.readToEndAlloc(
                self.alloc,
                10 * 1024 * 1024, // 10 MiB max
            ) catch |err| {
                log.warn("failed to read input file err={}", .{err});
                return error.InputFailed;
            },
            false,
        ) catch |err| {
            log.warn("failed to queue input file err={}", .{err});
            return error.InputFailed;
        },
    };
}

pub fn threadExit(self: *Termio, data: *ThreadData) void {
    self.backend.threadExit(data);
}

pub fn prepareForQuit(
    self: *Termio,
    grace_ms: u32,
    timeout_ms: u32,
) bool {
    const request_id = self.termination.begin();
    self.queueMessage(.{ .prepare_termination = .{
        .request_id = request_id,
        .grace_ms = grace_ms,
    } }, .unlocked);

    const timeout_ns = @as(u64, timeout_ms) * std.time.ns_per_ms;
    const result = self.termination.wait(request_id, timeout_ns);
    if (result == .timed_out) {
        log.warn(
            "termination flush timed out request_id={} timeout_ms={}",
            .{ request_id, timeout_ms },
        );
    }

    return result == .flushed;
}

pub fn completeTermination(
    self: *Termio,
    request_id: u64,
    result: TerminationResult,
) void {
    self.termination.complete(request_id, result);
}

/// Send a message to the mailbox. Depending on the mailbox type in use
/// this may process now or it may just enqueue and process later.
///
/// This will also notify the mailbox thread to process the message. If
/// you're sending a lot of messages, it may be more efficient to use
/// the mailbox directly and then call notify separately.
pub fn queueMessage(
    self: *Termio,
    msg: termio.Message,
    mutex: MutexState,
) void {
    self.mailbox.send(msg, switch (mutex) {
        .locked => self.renderer_state.mutex,
        .unlocked => null,
    });
    self.mailbox.notify();
}

/// Queue a write directly to the pty.
///
/// If you're using termio.Thread, this must ONLY be called from the
/// mailbox thread. If you're not on the thread, use queueMessage with
/// mailbox messages instead.
///
/// If you're not using termio.Thread, this is not threadsafe.
pub inline fn queueWrite(
    self: *Termio,
    td: *ThreadData,
    data: []const u8,
    linefeed: bool,
) !void {
    try self.backend.queueWrite(self.alloc, td, data, linefeed);
}

/// Update the configuration.
pub fn changeConfig(self: *Termio, td: *ThreadData, config: *DerivedConfig) !void {
    // The remainder of this function is modifying terminal state or
    // the read thread data, all of which requires holding the renderer
    // state lock.
    self.renderer_state.mutex.lock();
    defer self.renderer_state.mutex.unlock();

    // Deinit our old config. We do this in the lock because the
    // stream handler may be referencing the old config (i.e. enquiry resp)
    self.config.deinit();
    self.config = config.*;

    // Update our stream handler. The stream handler uses the same
    // renderer mutex so this is safe to do despite being executed
    // from another thread.
    self.terminal_stream.handler.changeConfig(&self.config);
    td.backend.changeConfig(&self.config);

    // Update the configuration that we know about.
    //
    // Specific things we don't update:
    //   - command, working-directory: we never restart the underlying
    //   process so we don't care or need to know about these.

    // Update the default palette.
    self.terminal.colors.palette.changeDefault(config.palette);
    self.terminal.flags.dirty.palette = true;

    // Update all our other colors
    self.terminal.colors.background.default = config.background.toTerminalRGB();
    self.terminal.colors.foreground.default = config.foreground.toTerminalRGB();
    self.terminal.colors.cursor.default = cursor: {
        const color = config.cursor_color orelse break :cursor null;
        break :cursor color.toTerminalRGB() orelse break :cursor null;
    };

    // Set the image limits
    try self.terminal.setKittyGraphicsSizeLimit(self.alloc, config.image_storage_limit);
    self.terminal.setKittyGraphicsLoadingLimits(.all);
}

/// Resize the terminal.
pub fn resize(
    self: *Termio,
    td: *ThreadData,
    size: renderer.Size,
) !void {
    self.size = size;
    const grid_size = size.grid();

    // Update the size of our pty.
    try self.backend.resize(grid_size, size.terminal());

    // Enter the critical area that we want to keep small
    {
        self.renderer_state.mutex.lock();
        defer self.renderer_state.mutex.unlock();

        // A column change can reflow existing history rows in place. The
        // persisted append log has to be rebuilt so restore doesn't combine
        // stale pre-resize rows with the new layout.
        const old_cols = self.terminal.cols;
        try self.terminal.resize(
            self.alloc,
            grid_size.columns,
            grid_size.rows,
        );

        // Update our pixel sizes
        self.terminal.width_px = grid_size.columns * self.size.cell.width;
        self.terminal.height_px = grid_size.rows * self.size.cell.height;

        // Disable synchronized output mode so that we show changes
        // immediately for a resize. This is allowed by the spec.
        self.terminal.modes.set(.synchronized_output, false);

        // If we have size reporting enabled we need to send a report.
        if (self.terminal.modes.get(.in_band_size_reports)) {
            try self.sizeReportLocked(td, .mode_2048);
        }

        if (old_cols != grid_size.columns) self.markPersistedScrollbackInvalidatedLocked();
        self.markPersistedScrollbackDirtyLocked();
    }

    // Mail the renderer so that it can update the GPU and re-render
    _ = self.renderer_mailbox.push(.{ .resize = size }, .{ .forever = {} });
    self.renderer_wakeup.notify() catch {};
}

/// Make a size report.
pub fn sizeReport(self: *Termio, td: *ThreadData, style: termio.Message.SizeReport) !void {
    self.renderer_state.mutex.lock();
    defer self.renderer_state.mutex.unlock();
    try self.sizeReportLocked(td, style);
}

fn sizeReportLocked(self: *Termio, td: *ThreadData, style: termio.Message.SizeReport) !void {
    const grid_size = self.size.grid();
    const report_size: terminalpkg.size_report.Size = .{
        .rows = grid_size.rows,
        .columns = grid_size.columns,
        .cell_width = self.size.cell.width,
        .cell_height = self.size.cell.height,
    };

    // 1024 bytes should be enough for size report since report
    // in columns and pixels.
    var buf: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buf);
    try terminalpkg.size_report.encode(
        &writer,
        style,
        report_size,
    );

    try self.queueWrite(td, writer.buffered(), false);
}

/// Reset the synchronized output mode. This is usually called by timer
/// expiration from the termio thread.
pub fn resetSynchronizedOutput(self: *Termio) void {
    self.renderer_state.mutex.lock();
    defer self.renderer_state.mutex.unlock();
    self.terminal.modes.set(.synchronized_output, false);
    self.renderer_wakeup.notify() catch {};
}

/// Clear the screen.
pub fn clearScreen(self: *Termio, td: *ThreadData, history: bool) !void {
    {
        self.renderer_state.mutex.lock();
        defer self.renderer_state.mutex.unlock();

        // If we're on the alternate screen, we do not clear. Since this is an
        // emulator-level screen clear, this messes up the running programs
        // knowledge of where the cursor is and causes rendering issues. So,
        // for alt screen, we do nothing.
        if (self.terminal.screens.active_key == .alternate) return;

        // Clear our selection
        self.terminal.screens.active.clearSelection();

        // Clear our scrollback
        if (history) self.terminal.eraseDisplay(.scrollback, false);

        // If we're not at a prompt, we just delete above the cursor.
        if (!self.terminal.cursorIsAtPrompt()) {
            if (self.terminal.screens.active.cursor.y > 0) {
                self.terminal.screens.active.eraseActive(
                    self.terminal.screens.active.cursor.y - 1,
                );
            }

            // Clear all Kitty graphics state for this screen. This copies
            // Kitty's behavior when Cmd+K deletes all Kitty graphics. I
            // didn't spend time researching whether it only deletes Kitty
            // graphics that are placed above the cursor or if it deletes
            // all of them. We delete all of them for now but if this behavior
            // isn't fully correct we should fix this later.
            self.terminal.screens.active.kitty_images.delete(
                self.terminal.screens.active.alloc,
                &self.terminal,
                .{ .all = true },
            );

            self.markPersistedScrollbackDirtyLocked();
            return;
        }

        // At a prompt, we want to first fully clear the screen, and then after
        // send a FF (0x0C) to the shell so that it can repaint the screen.
        // Mark the current row as a not a prompt so we can properly
        // clear the full screen in the next eraseDisplay call.
        // TODO: fix this
        // self.terminal.markSemanticPrompt(.command);
        // assert(!self.terminal.cursorIsAtPrompt());
        self.terminal.eraseDisplay(.complete, false);
        self.markPersistedScrollbackDirtyLocked();
    }

    // If we reached here it means we're at a prompt, so we send a form-feed.
    try self.queueWrite(td, &[_]u8{0x0C}, false);
}

/// Scroll the viewport
pub fn scrollViewport(
    self: *Termio,
    scroll: terminalpkg.Terminal.ScrollViewport,
) void {
    self.renderer_state.mutex.lock();
    defer self.renderer_state.mutex.unlock();
    self.terminal.scrollViewport(scroll);
}

/// Jump the viewport to the prompt.
pub fn jumpToPrompt(self: *Termio, delta: isize) !void {
    {
        self.renderer_state.mutex.lock();
        defer self.renderer_state.mutex.unlock();
        self.terminal.screens.active.scroll(.{ .delta_prompt = delta });
    }

    try self.renderer_wakeup.notify();
}

/// Called when focus is gained or lost (when focus events are enabled)
pub fn focusGained(self: *Termio, td: *ThreadData, focused: bool) !void {
    self.renderer_state.mutex.lock();
    const focus_event = self.renderer_state.terminal.modes.get(.focus_event);
    self.renderer_state.mutex.unlock();

    // If we have focus events enabled, we send the focus event.
    if (focus_event) {
        var buf: [terminalpkg.focus.max_encode_size]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buf);
        terminalpkg.focus.encode(&writer, if (focused) .gained else .lost) catch |err| {
            log.err("error encoding focus event err={}", .{err});
            return;
        };
        try self.queueWrite(td, writer.buffered(), false);
    }

    // We always notify our backend of focus changes.
    try self.backend.focusGained(td, focused);
}

/// Process output from the pty. This is the manual API that users can
/// call with pty data but it is also called by the read thread when using
/// an exec subprocess.
pub fn processOutput(self: *Termio, buf: []const u8) void {
    // We are modifying terminal state from here on out and we need
    // the lock to grab our read data.
    self.renderer_state.mutex.lock();
    defer self.renderer_state.mutex.unlock();
    self.processOutputLocked(buf);
}

/// Process output from readdata but the lock is already held.
fn processOutputLocked(self: *Termio, buf: []const u8) void {
    // Schedule a render. We can call this first because we have the lock.
    self.terminal_stream.handler.queueRender() catch unreachable;

    // Whenever a character is typed, we ensure the cursor is in the
    // non-blink state so it is rendered if visible. If we're under
    // HEAVY read load, we don't want to send a ton of these so we
    // use a timer under the covers
    if (std.time.Instant.now()) |now| cursor_reset: {
        if (self.last_cursor_reset) |last| {
            if (now.since(last) <= (500 * std.time.ns_per_ms)) {
                break :cursor_reset;
            }
        }

        self.last_cursor_reset = now;
        _ = self.renderer_mailbox.push(.{
            .reset_cursor_blink = {},
        }, .{ .instant = {} });
    } else |err| {
        log.warn("failed to get current time err={}", .{err});
    }

    // If we have an inspector, we enter SLOW MODE because we need to
    // process a byte at a time alternating between the inspector handler
    // and the termio handler. This is very slow compared to our optimizations
    // below but at least users only pay for it if they're using the inspector.
    if (self.renderer_state.inspector) |insp| {
        for (buf, 0..) |byte, i| {
            insp.recordPtyRead(
                self.alloc,
                &self.terminal,
                buf[i .. i + 1],
            ) catch |err| {
                log.err("error recording pty read in inspector err={}", .{err});
            };

            self.terminal_stream.next(byte);
        }
    } else {
        self.terminal_stream.nextSlice(buf);
    }

    // If our stream handling caused messages to be sent to the mailbox
    // thread, then we need to wake it up so that it processes them.
    if (self.terminal_stream.handler.termio_messaged) {
        self.terminal_stream.handler.termio_messaged = false;
        self.mailbox.notify();
    }

    self.markPersistedScrollbackDirtyLocked();
}

fn markPersistedScrollbackDirtyLocked(self: *Termio) void {
    const persisted = if (self.persisted) |*value| value else return;
    const now = std.time.Instant.now() catch return;

    if (!persisted.dirty) persisted.dirty_started_at = now;
    persisted.dirty = true;
    persisted.last_dirty_at = now;
    persisted.dirty_generation +%= 1;
    if (persisted.notify_pending) return;

    persisted.notify_pending = true;
    self.queueMessage(.{ .persisted_scrollback_dirty = {} }, .locked);
}

fn markPersistedScrollbackInvalidatedLocked(self: *Termio) void {
    const persisted = if (self.persisted) |*value| value else return;
    persisted.scrollback_invalidated = true;
}

pub fn persistedScrollbackTimerDecision(self: *Termio) PersistedScheduleDecision {
    const now = std.time.Instant.now() catch return .flush;

    self.renderer_state.mutex.lock();
    defer self.renderer_state.mutex.unlock();

    const persisted = if (self.persisted) |*value| value else return .none;
    if (!persisted.dirty) {
        persisted.notify_pending = false;
        return .none;
    }

    const dirty_started_at = persisted.dirty_started_at orelse now;
    const last_dirty_at = persisted.last_dirty_at orelse dirty_started_at;
    return persistedScrollbackScheduleDecision(.{
        .dirty = persisted.dirty,
        .dirty_age_ms = @intCast(now.since(dirty_started_at) / std.time.ns_per_ms),
        .idle_ms = @intCast(now.since(last_dirty_at) / std.time.ns_per_ms),
    });
}

pub fn persistedScrollbackFlushStarted(self: *Termio) void {
    self.renderer_state.mutex.lock();
    defer self.renderer_state.mutex.unlock();

    if (self.persisted) |*value| value.notify_pending = false;
}

pub fn persistedScrollbackFlushFailed(self: *Termio) u64 {
    self.renderer_state.mutex.lock();
    defer self.renderer_state.mutex.unlock();

    const persisted = if (self.persisted) |*value| value else return persisted_scrollback_retry_cap_ms;
    persisted.retry_count +%= 1;
    persisted.notify_pending = true;
    const delay = persistedScrollbackRetryDelayMs(persisted.retry_count - 1);
    log.warn(
        "persisted scrollback flush retry scheduled retry={} delay_ms={}",
        .{ persisted.retry_count, delay },
    );
    return delay;
}

const PersistedCapture = struct {
    generation: u64,
    capture: persisted_scrollback.Capture,
    next_row_count: usize,
    next_tail_seq: u64,
    next_seq: u64,
    scrollback_size_bytes: usize,
    header_written: bool,
    header_dims: ?PersistedHeaderDims = null,
    metadata_hash: u64,
    scrollback_records: []persisted_scrollback.ScrollbackRecord,
    metadata_session_id: ?[]u8 = null,
    metadata_pwd: ?[]u8 = null,
    metadata_title: ?[]u8 = null,
    screen: ?[]u8 = null,
    screen_alt: ?[]u8 = null,

    fn deinit(self: *PersistedCapture, alloc: Allocator) void {
        for (self.scrollback_records) |record| alloc.free(record.bytes);
        alloc.free(self.scrollback_records);
        if (self.metadata_session_id) |v| alloc.free(v);
        if (self.metadata_pwd) |v| alloc.free(v);
        if (self.metadata_title) |v| alloc.free(v);
        if (self.screen) |v| alloc.free(v);
        if (self.screen_alt) |v| alloc.free(v);
        self.* = undefined;
    }
};

fn persistedMetadataHash(session_id: ?[]const u8, pwd: ?[]const u8, title: ?[]const u8) u64 {
    var hasher = std.hash.Wyhash.init(0);
    if (session_id) |v| hasher.update(v);
    hasher.update(&.{0});
    if (pwd) |v| hasher.update(v);
    hasher.update(&.{0});
    if (title) |v| hasher.update(v);
    return hasher.final();
}

fn captureScreenData(
    alloc: Allocator,
    screen: *const terminalpkg.Screen,
    start_row: u32,
    row_count: ?u32,
) ![]u8 {
    var buf: std.Io.Writer.Allocating = .init(alloc);
    defer buf.deinit();
    try terminalpkg.snapshot.writeScreenData(alloc, &buf.writer, .{
        .screen = screen,
        .start_row = start_row,
        .row_count = row_count,
    });
    return try buf.toOwnedSlice();
}

fn scrollbackRecordSize(record: persisted_scrollback.ScrollbackRecord) usize {
    return 12 + record.bytes.len;
}

fn appendScrollbackRecord(
    alloc: Allocator,
    records: *std.ArrayListUnmanaged(persisted_scrollback.ScrollbackRecord),
    primary: *const terminalpkg.Screen,
    row_index: u32,
    size_bytes: *usize,
) !void {
    const row_data = try captureScreenData(alloc, primary, row_index, 1);
    records.append(alloc, .{ .bytes = row_data }) catch |err| {
        alloc.free(row_data);
        return err;
    };
    size_bytes.* += 12 + row_data.len;
}

fn clearScrollbackRecords(
    alloc: Allocator,
    records: *std.ArrayListUnmanaged(persisted_scrollback.ScrollbackRecord),
) void {
    for (records.items) |record| alloc.free(record.bytes);
    records.clearRetainingCapacity();
}

fn trimScrollbackRecordsToLimit(
    alloc: Allocator,
    records: *std.ArrayListUnmanaged(persisted_scrollback.ScrollbackRecord),
    limit: usize,
    size_bytes: *usize,
) u32 {
    var drop_count: usize = 0;
    while (size_bytes.* > limit and drop_count < records.items.len) : (drop_count += 1) {
        const record = records.items[drop_count];
        size_bytes.* -= scrollbackRecordSize(record);
        alloc.free(record.bytes);
    }

    if (drop_count > 0) {
        std.mem.copyForwards(
            persisted_scrollback.ScrollbackRecord,
            records.items[0 .. records.items.len - drop_count],
            records.items[drop_count..],
        );
        records.shrinkRetainingCapacity(records.items.len - drop_count);
    }

    return @intCast(drop_count);
}

fn capturePersistedScrollback(self: *Termio) !?PersistedCapture {
    self.renderer_state.mutex.lock();
    defer self.renderer_state.mutex.unlock();

    const persisted = if (self.persisted) |*value| value else return null;
    if (!persisted.dirty) return null;

    const snapshot = terminalpkg.snapshot;
    const primary = self.terminal.screens.get(.primary) orelse self.terminal.screens.active;
    const alternate: ?*const terminalpkg.Screen = if (self.terminal.screens.active_key == .alternate)
        self.terminal.screens.active
    else
        null;

    const total_rows = snapshot.screenRowCount(primary);
    const active_rows: u32 = @intCast(@min(total_rows, primary.pages.rows));
    const history_rows: u32 = total_rows - active_rows;

    var rewrite_scrollback =
        persisted.scrollback_invalidated or
        history_rows < persisted.last_persisted_row_count or
        persisted.scrollback_size_bytes > persisted.limit;
    var append_start: u32 = if (rewrite_scrollback) 0 else @intCast(persisted.last_persisted_row_count);
    var scrollback_size_bytes: usize = if (rewrite_scrollback) 0 else persisted.scrollback_size_bytes;

    var records_list: std.ArrayListUnmanaged(persisted_scrollback.ScrollbackRecord) = .empty;
    errdefer {
        for (records_list.items) |record| self.alloc.free(record.bytes);
        records_list.deinit(self.alloc);
    }

    var row_index = append_start;
    while (row_index < history_rows) : (row_index += 1) {
        try appendScrollbackRecord(self.alloc, &records_list, primary, row_index, &scrollback_size_bytes);
    }

    if (!rewrite_scrollback and scrollback_size_bytes > persisted.limit) {
        clearScrollbackRecords(self.alloc, &records_list);
        rewrite_scrollback = true;
        append_start = 0;
        scrollback_size_bytes = 0;

        row_index = 0;
        while (row_index < history_rows) : (row_index += 1) {
            try appendScrollbackRecord(self.alloc, &records_list, primary, row_index, &scrollback_size_bytes);
        }
    }

    const dropped_rows = trimScrollbackRecordsToLimit(
        self.alloc,
        &records_list,
        persisted.limit,
        &scrollback_size_bytes,
    );
    if (dropped_rows > 0) rewrite_scrollback = true;

    var seq_cursor = persisted.next_seq;
    const history_seq_count: u32 = if (rewrite_scrollback)
        history_rows
    else
        @intCast(records_list.items.len);
    const scrollback_first_seq = if (rewrite_scrollback)
        seq_cursor +% dropped_rows
    else
        seq_cursor;
    const next_tail_seq = if (records_list.items.len > 0)
        scrollback_first_seq +% @as(u64, @intCast(records_list.items.len)) -% 1
    else if (rewrite_scrollback)
        0
    else
        persisted.last_persisted_seq;
    seq_cursor +%= history_seq_count;

    const screen_start = history_rows;
    const screen_data = try captureScreenData(self.alloc, primary, screen_start, active_rows);
    errdefer self.alloc.free(screen_data);
    const screen_seq = if (active_rows > 0) seq_cursor +% active_rows -% 1 else seq_cursor;
    seq_cursor = screen_seq +% 1;

    const screen_alt_data = if (alternate) |alt| alt: {
        const alt_total = snapshot.screenRowCount(alt);
        const alt_active_rows: u32 = @intCast(@min(alt_total, alt.pages.rows));
        const alt_start = alt_total - alt_active_rows;
        break :alt try captureScreenData(self.alloc, alt, alt_start, alt_active_rows);
    } else null;
    errdefer if (screen_alt_data) |data| self.alloc.free(data);

    const metadata_hash = persistedMetadataHash(
        persisted.session_id,
        self.terminal.getPwd(),
        self.terminal.getTitle(),
    );
    const metadata_changed = metadata_hash != persisted.last_metadata_hash;
    const header_dims: PersistedHeaderDims = .{
        .cols = @intCast(primary.pages.cols),
        .rows = @intCast(primary.pages.rows),
    };
    const header_changed = if (persisted.last_header_dims) |last|
        last.cols != header_dims.cols or last.rows != header_dims.rows
    else
        true;
    const include_header = !persisted.header_written or header_changed;

    const metadata_session_id = if (!persisted.header_written or metadata_changed)
        try persisted_scrollback.dupeOptional(self.alloc, persisted.session_id)
    else
        null;
    errdefer if (metadata_session_id) |v| self.alloc.free(v);
    const metadata_pwd = if (!persisted.header_written or metadata_changed)
        try persisted_scrollback.dupeOptional(self.alloc, self.terminal.getPwd())
    else
        null;
    errdefer if (metadata_pwd) |v| self.alloc.free(v);
    const metadata_title = if (!persisted.header_written or metadata_changed)
        try persisted_scrollback.dupeOptional(self.alloc, self.terminal.getTitle())
    else
        null;
    errdefer if (metadata_title) |v| self.alloc.free(v);

    const records = try records_list.toOwnedSlice(self.alloc);
    errdefer self.alloc.free(records);

    return .{
        .generation = persisted.dirty_generation,
        .capture = .{
            .header = if (include_header) .{
                .timestamp = std.time.timestamp(),
                .cols = header_dims.cols,
                .rows = header_dims.rows,
            } else null,
            .metadata = if (!persisted.header_written or metadata_changed) .{
                .session_id = metadata_session_id,
                .pwd = metadata_pwd,
                .title = metadata_title,
            } else null,
            .scrollback_append = records,
            .scrollback_first_seq = scrollback_first_seq,
            .rewrite_scrollback = rewrite_scrollback,
            .screen = screen_data,
            .screen_seq = screen_seq,
            .screen_alt = screen_alt_data,
            .screen_alt_seq = if (screen_alt_data != null) screen_seq else null,
        },
        .next_row_count = history_rows,
        .next_tail_seq = next_tail_seq,
        .next_seq = seq_cursor,
        .scrollback_size_bytes = scrollback_size_bytes,
        .header_written = true,
        .header_dims = if (include_header) header_dims else null,
        .metadata_hash = metadata_hash,
        .scrollback_records = records,
        .metadata_session_id = metadata_session_id,
        .metadata_pwd = metadata_pwd,
        .metadata_title = metadata_title,
        .screen = screen_data,
        .screen_alt = screen_alt_data,
    };
}

pub fn flushPersistedScrollback(self: *Termio) !void {
    self.renderer_state.mutex.lock();
    if (self.persisted) |*persisted| {
        if (!persisted.dirty) {
            self.renderer_state.mutex.unlock();
            return;
        }
    } else {
        self.renderer_state.mutex.unlock();
        return;
    }
    self.renderer_state.mutex.unlock();

    var capture = (try self.capturePersistedScrollback()) orelse return;
    defer capture.deinit(self.alloc);

    const persisted = self.persisted orelse return;
    try persisted_scrollback.publish(persisted.session_dir, capture.capture);

    self.renderer_state.mutex.lock();
    defer self.renderer_state.mutex.unlock();
    if (self.persisted) |*value| {
        value.retry_count = 0;
        value.last_persisted_row_count = capture.next_row_count;
        value.last_persisted_seq = capture.next_tail_seq;
        value.next_seq = capture.next_seq;
        value.scrollback_size_bytes = capture.scrollback_size_bytes;
        value.scrollback_invalidated = false;
        value.header_written = capture.header_written;
        if (capture.header_dims) |dims| value.last_header_dims = dims;
        value.last_metadata_hash = capture.metadata_hash;
        if (value.dirty_generation == capture.generation) {
            value.dirty = false;
            value.dirty_started_at = null;
            value.last_dirty_at = null;
        }
    }
}

/// Sends a DSR response for the current color scheme to the pty.
pub fn colorSchemeReport(self: *Termio, td: *ThreadData, force: bool) !void {
    self.renderer_state.mutex.lock();
    defer self.renderer_state.mutex.unlock();

    try self.colorSchemeReportLocked(td, force);
}

pub fn colorSchemeReportLocked(self: *Termio, td: *ThreadData, force: bool) !void {
    if (!force and !self.renderer_state.terminal.modes.get(.report_color_scheme)) {
        return;
    }
    const output = switch (self.config.conditional_state.theme) {
        .light => "\x1B[?997;2n",
        .dark => "\x1B[?997;1n",
    };
    try self.queueWrite(td, output, false);
}

/// ThreadData is the data created and stored in the termio thread
/// when the thread is started and destroyed when the thread is
/// stopped.
///
/// All of the fields in this struct should only be read/written by
/// the termio thread. As such, a lock is not necessary.
pub const ThreadData = struct {
    /// Allocator used for the event data
    alloc: Allocator,

    /// The event loop associated with this thread. This is owned by
    /// the Thread but we have a pointer so we can queue new work to it.
    loop: *xev.Loop,

    /// The shared render state
    renderer_state: *renderer.State,

    /// Mailboxes for different threads
    surface_mailbox: apprt.surface.Mailbox,

    /// Data associated with the backend implementation (i.e. pty/exec state)
    backend: termio.backend.ThreadData,
    mailbox: *termio.Mailbox,

    pub fn deinit(self: *ThreadData) void {
        self.backend.deinit(self.alloc);
        self.* = undefined;
    }
};

/// Get information about the process(es) attached to the backend. Returns
/// `null` if there was an error getting the information or the information is
/// not available on a particular platform.
pub fn getProcessInfo(self: *Termio, comptime info: ProcessInfo) ?ProcessInfo.Type(info) {
    return self.backend.getProcessInfo(info);
}

test "restored session marker uses dim text" {
    const testing = std.testing;

    const marker = try restoredSessionMarker(testing.allocator, 48, 0);
    defer testing.allocator.free(marker);

    const expected = "\r\n\x1b[0m\x1b[2m[Restored Jan 1, 1970 at 00:00:00 UTC]\x1b[0m\r\n";

    try testing.expectEqualStrings(expected, marker);
}

test "hydrateRestoredTerminal populates screen from snapshot" {
    const testing = std.testing;
    const snapshot = terminalpkg.snapshot;

    // Create source terminal with content
    var src_term = try terminalpkg.Terminal.init(testing.allocator, .{
        .cols = 48,
        .rows = 6,
    });
    defer src_term.deinit(testing.allocator);
    {
        const stream_terminal = @import("../terminal/stream_terminal.zig");
        const handler: stream_terminal.Handler = .init(&src_term);
        var stream: stream_terminal.Stream = .init(handler);
        stream.nextSlice("hello world");
    }

    // Serialize
    var buf: std.Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();
    try snapshot.write(testing.allocator, &buf.writer, .{
        .primary = &src_term.screens.active.*,
        .timestamp = 0,
    });
    const data = try buf.toOwnedSlice();
    defer testing.allocator.free(data);

    // Parse
    const restored_read = try snapshot.read(testing.allocator, data);
    var restored: persisted_scrollback.Loaded = .{
        .header = restored_read.header,
        .session_id = restored_read.session_id,
        .pwd = restored_read.pwd,
        .title = restored_read.title,
        .primary = restored_read.primary,
        .alternate = restored_read.alternate,
    };
    defer restored.deinit(testing.allocator);

    // Create destination terminal and hydrate
    var term = try terminalpkg.Terminal.init(testing.allocator, .{
        .cols = 48,
        .rows = 6,
    });
    defer term.deinit(testing.allocator);

    hydrateRestoredTerminal(testing.allocator, &term, restored);

    const primary = term.screens.get(.primary) orelse term.screens.active;
    const screen = try primary.dumpStringAlloc(testing.allocator, .{ .screen = .{} });
    defer testing.allocator.free(screen);

    try testing.expect(std.mem.indexOf(u8, screen, "hello world") != null);
    try testing.expect(std.mem.indexOf(u8, screen, "[Restored Jan 1, 1970 at 00:00:00 UTC]") != null);
}

test "maybeLoadPersistedScrollback leaves malformed session files in place" {
    const testing = std.testing;

    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // Create the session directory structure that sessionDirPath would produce.
    try tmp_dir.dir.makePath("ghostty/session/test-session-uuid");
    try tmp_dir.dir.writeFile(.{
        .sub_path = "ghostty/session/test-session-uuid/header",
        .data = "invalid header payload",
    });

    const victim_path = try tmp_dir.dir.realpathAlloc(
        testing.allocator,
        "ghostty/session/test-session-uuid",
    );
    defer testing.allocator.free(victim_path);

    var config = try configpkg.Config.default(testing.allocator);
    defer config.deinit();
    config.@"scrollback-snapshot-limit" = 1024;

    // Call load directly to verify the file is not deleted on parse failure.
    try testing.expectError(
        error.InvalidSnapshot,
        persisted_scrollback.load(testing.allocator, victim_path, 1024),
    );
    // Directory should still exist after the failed load.
    var dir = try std.fs.openDirAbsolute(victim_path, .{});
    dir.close();
}

fn persistedTestTermio(
    alloc: Allocator,
    session_dir: []u8,
    terminal: terminalpkg.Terminal,
    renderer_state: *renderer.State,
    limit: usize,
) Termio {
    return .{
        .alloc = alloc,
        .terminal = terminal,
        .renderer_state = renderer_state,
        .backend = undefined,
        .config = undefined,
        .renderer_wakeup = undefined,
        .renderer_mailbox = undefined,
        .surface_mailbox = undefined,
        .size = undefined,
        .mailbox = undefined,
        .terminal_stream = undefined,
        .persisted = .{
            .session_dir = session_dir,
            .session_id = null,
            .limit = limit,
            .dirty = true,
            .dirty_generation = 1,
            .notify_pending = true,
        },
    };
}

fn markPersistedDirtyForTest(io: *Termio) void {
    if (io.persisted) |*persisted| {
        persisted.dirty = true;
        persisted.dirty_generation +%= 1;
    }
}

fn capturePrimarySnapshotForTest(
    alloc: Allocator,
    terminal: *const terminalpkg.Terminal,
) !terminalpkg.snapshot.ScreenData {
    const primary = terminal.screens.get(.primary) orelse terminal.screens.active;
    const total_rows = terminalpkg.snapshot.screenRowCount(primary);
    const bytes = try captureScreenData(alloc, primary, 0, total_rows);
    defer alloc.free(bytes);
    return try terminalpkg.snapshot.readScreenData(alloc, bytes);
}

fn expectScreenDataEqual(
    expected: *const terminalpkg.snapshot.ScreenData,
    actual: *const terminalpkg.snapshot.ScreenData,
) !void {
    const testing = std.testing;

    try testing.expectEqual(expected.cols, actual.cols);
    try testing.expectEqual(expected.rows.len, actual.rows.len);
    for (expected.rows, actual.rows) |expected_row, actual_row| {
        try testing.expectEqual(expected_row.wrap, actual_row.wrap);
        try testing.expectEqual(expected_row.wrap_continuation, actual_row.wrap_continuation);
        try testing.expectEqual(expected_row.semantic_prompt, actual_row.semantic_prompt);
        try testing.expectEqualSlices(u64, expected_row.cells, actual_row.cells);
    }
}

fn screenDataContainsAscii(
    data: *const terminalpkg.snapshot.ScreenData,
    needle: []const u8,
) bool {
    if (needle.len == 0) return true;

    var matched: usize = 0;
    for (data.rows) |row| {
        for (row.cells) |raw| {
            const cell: terminalpkg.Cell = @bitCast(raw);
            if (cell.content_tag != .codepoint) {
                matched = 0;
                continue;
            }

            const cp = cell.content.codepoint;
            if (cp > std.math.maxInt(u8)) {
                matched = 0;
                continue;
            }

            if (@as(u8, @intCast(cp)) == needle[matched]) {
                matched += 1;
                if (matched == needle.len) return true;
            } else {
                matched = 0;
            }
        }
        matched = 0;
    }

    return false;
}

test "persisted scrollback capture enforces byte limit with recent tail rows" {
    const testing = std.testing;

    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try tmp_dir.dir.makePath("session");

    const session_path = try tmp_dir.dir.realpathAlloc(testing.allocator, "session");
    defer testing.allocator.free(session_path);
    const session_dir = try testing.allocator.dupe(u8, session_path);

    var terminal = try terminalpkg.Terminal.init(testing.allocator, .{
        .cols = 8,
        .rows = 3,
        .max_scrollback = 100,
    });

    var mutex = std.Thread.Mutex{};
    var state: renderer.State = .{
        .mutex = &mutex,
        .terminal = &terminal,
    };
    var io = persistedTestTermio(testing.allocator, session_dir, terminal, &state, 1024);
    state.terminal = &io.terminal;
    defer {
        if (io.persisted) |*persisted| persisted.deinit(testing.allocator);
        io.terminal.deinit(testing.allocator);
    }

    var input: std.Io.Writer.Allocating = .init(testing.allocator);
    defer input.deinit();
    for (0..40) |i| try input.writer.print("row-{d:0>2}\n", .{i});
    try io.terminal.printString(input.writer.buffer[0..input.writer.end]);

    const total_rows = terminalpkg.snapshot.screenRowCount(&io.terminal.screens.active.*);
    const history_rows = total_rows - @min(total_rows, io.terminal.screens.active.pages.rows);

    try io.flushPersistedScrollback();

    var dir = try std.fs.openDirAbsolute(session_path, .{});
    defer dir.close();
    const scrollback_stat = try dir.statFile("scrollback");
    try testing.expect(scrollback_stat.size <= 1024);

    var loaded = try persisted_scrollback.load(testing.allocator, session_path, 1024);
    defer loaded.deinit(testing.allocator);

    try testing.expect(loaded.scrollback_rows < history_rows);
    try testing.expect(screenDataContainsAscii(&loaded.primary, "row-39"));
    try testing.expect(!screenDataContainsAscii(&loaded.primary, "row-00"));
}

test "persisted scrollback capture rewrites after resize reflow" {
    const testing = std.testing;

    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try tmp_dir.dir.makePath("session");

    const session_path = try tmp_dir.dir.realpathAlloc(testing.allocator, "session");
    defer testing.allocator.free(session_path);
    const session_dir = try testing.allocator.dupe(u8, session_path);

    var terminal = try terminalpkg.Terminal.init(testing.allocator, .{
        .cols = 10,
        .rows = 3,
        .max_scrollback = 100,
    });

    var mutex = std.Thread.Mutex{};
    var state: renderer.State = .{
        .mutex = &mutex,
        .terminal = &terminal,
    };
    var io = persistedTestTermio(testing.allocator, session_dir, terminal, &state, 64 * 1024);
    state.terminal = &io.terminal;
    defer {
        if (io.persisted) |*persisted| persisted.deinit(testing.allocator);
        io.terminal.deinit(testing.allocator);
    }

    try io.terminal.printString("abcdefghijABCDEFGHIJ\nklmnopqrstKLMNOPQRST\nuvwxyzabcdUVWXYZABCD\n");
    try io.flushPersistedScrollback();

    try io.terminal.resize(testing.allocator, 5, 3);
    io.markPersistedScrollbackInvalidatedLocked();
    markPersistedDirtyForTest(&io);

    var expected = try capturePrimarySnapshotForTest(testing.allocator, &io.terminal);
    defer expected.deinit(testing.allocator);

    try io.flushPersistedScrollback();

    var loaded = try persisted_scrollback.load(testing.allocator, session_path, 64 * 1024);
    defer loaded.deinit(testing.allocator);

    try expectScreenDataEqual(&expected, &loaded.primary);
}

test "persisted scrollback schedule waits for trailing debounce" {
    const testing = std.testing;

    try testing.expectEqual(
        PersistedScheduleDecision{ .reschedule = 300 },
        persistedScrollbackScheduleDecision(.{
            .dirty = true,
            .dirty_age_ms = 100,
            .idle_ms = 100,
        }),
    );
}

test "persisted scrollback schedule flushes at max staleness" {
    const testing = std.testing;

    try testing.expectEqual(
        PersistedScheduleDecision.flush,
        persistedScrollbackScheduleDecision(.{
            .dirty = true,
            .dirty_age_ms = 2_000,
            .idle_ms = 50,
        }),
    );
}

test "persisted scrollback schedule flushes after quiet debounce" {
    const testing = std.testing;

    try testing.expectEqual(
        PersistedScheduleDecision.flush,
        persistedScrollbackScheduleDecision(.{
            .dirty = true,
            .dirty_age_ms = 500,
            .idle_ms = 400,
        }),
    );
}

test "persisted scrollback retry delay backs off and caps" {
    const testing = std.testing;

    try testing.expectEqual(@as(u64, 250), persistedScrollbackRetryDelayMs(0));
    try testing.expectEqual(@as(u64, 500), persistedScrollbackRetryDelayMs(1));
    try testing.expectEqual(@as(u64, 1_000), persistedScrollbackRetryDelayMs(2));
    try testing.expectEqual(@as(u64, 2_000), persistedScrollbackRetryDelayMs(3));
    try testing.expectEqual(@as(u64, 2_000), persistedScrollbackRetryDelayMs(8));
}
