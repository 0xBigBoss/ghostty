---
name: ghostty-code-patterns
description: Ghostty codebase coding patterns for Zig (core, C API, termio) and Swift (macOS app). Load when reading or writing Zig or Swift files in this repo. Covers naming, error handling, logging, config, memory, imports, tests, C interop, and state restoration conventions.
---

# Ghostty Codebase Patterns

Conventions extracted from the upstream Ghostty maintainers' code. Follow these when contributing Zig or Swift changes to this repo.

## Rule Strength

Use this priority when applying guidance:

- **Required**: must follow for consistency, correctness, or API safety.
- **Preferred**: default style; deviate only when the surrounding file/module has an established pattern.
- **Direction**: migration target for new code; existing code may still use older patterns.

## Zig Conventions

### Imports

**Preferred:** order imports consistently across all files:

1. `std` and stdlib extractions (`Allocator`, `posix`, `assert`)
2. Internal project imports (`termio`, `terminal`, `renderer`, `apprt`, `configpkg`)
3. Local/sibling imports (`snapshot`, `shell_integration`)
4. `const log = std.log.scoped(.scope_name);` — always last among imports

### File Structure

- **Preferred:** **File-is-struct idiom**: files that define a primary struct use `const X = @This();` at the top.
- **Preferred:** **Private helpers**: free functions (no `self`), no `pub`, placed near related code.
- **Preferred:** **Init pattern**: `pub fn init(self: *Self, alloc: Allocator, ...) !void` with `self.* = .{ ... }` assignment.
- **Preferred:** **Labeled blocks**: use `break :label value` for complex initialization inside `init`.

### Naming

- **Required:** `@""` syntax for hyphenated config keys: `config.@"window-save-state"`.
- **Required:** preserve established naming in the file/module; do not rename public APIs just to normalize style.
- **Preferred:** local/private Zig identifiers are generally `snake_case`.
- **Current practice:** some long-lived/public APIs use camelCase; match adjacent code.
- **Preferred:** common abbreviations: `alloc`, `cfg`, `td`, `io`, `gpa`, `env`.

### Error Handling

- **Required:** handle all errors explicitly.
- **Preferred:** use `errdefer` immediately after fallible allocations/resource acquisition.
- **Preferred:** CAPI export functions: complex ones use a two-function split (public export wrapper catches errors + logs, private `_` suffixed inner function returns `!T`). Simpler ones handle errors inline.
- **Preferred:** `catch |err| { log.warn/err(...); return ...; }` for inline error handling.
- **Preferred:** prefer `const` over `var`; use `var` when mutation is required.

### Logging

Format: `log.level("description key={fmt}", .{value})`.

```
log.err("error initializing app err={}", .{err});
log.warn("snapshot restore skipped path={s} err={}", .{ path, err });
log.info("deleting widget id={d}", .{id});
```

- **Preferred:** `log.err` for initialization failures and critical errors.
- **Preferred:** `log.warn` for recoverable issues, bad input, skipped operations.
- **Preferred:** `log.info` for state changes.
- **Preferred:** `log.debug` for internal diagnostics.
- **Preferred:** key-value pairs: `err={}`, `path={s}`, `id={d}`, `dir={s}` (no quotes, no space around `=`).

### Memory

- **Required:** ownership must be explicit and deinit/free paths must be obvious.
- **Preferred:** pass allocators explicitly.
- **Scope note:** runtime bridge/CAPI layers may intentionally use shared runtime allocators (for example `global.alloc`) where ownership is process-global and crosses FFI boundaries.
- **Preferred:** `defer` immediately after acquiring a resource.
- **Preferred:** arena allocators for batch/scoped allocations (`ArenaAllocator.init` / `defer arena.deinit()`).
- **Required (tests):** `std.testing.allocator` for leak detection.

### Config Options (`src/config/Config.zig`)

- **Required:** doc comments use `///` in Pandoc-flavored Markdown.
- **Preferred:** first paragraph is a concise summary.
- **Preferred:** valid values as bullet list with `* \`value\`` format.
- **Preferred:** cross-references use backtick-quoted option names.
- **Preferred:** platform notes at end (for example: "This is currently only supported on macOS. This has no effect on Linux.").
- **Required:** field names use `@"kebab-case-name"`.

### Tests

- **Preferred:** descriptive string names: `test "snapshot header roundtrip"`.
- **Preferred:** first line in test blocks: `const testing = std.testing;`.
- **Required:** use `std.testing.allocator` for leak detection.
- **Preferred:** assertions: `try testing.expectEqual(...)`, `try testing.expectEqualSlices(...)`, `try testing.expectError(...)`.
- **Preferred:** module test block uses `refAllDecls(@This())` plus explicit `_ = @import(...)` for otherwise-unreferenced modules.

### Writer/Reader API

**Current practice:** codebase contains both `std.Io` and `std.io` usage.

**Direction (new code):** prefer `std.Io.Writer`, `std.Io.Reader` (uppercase `I`) unless you're touching code that is still centered on older `std.io` stream APIs; in that case, stay consistent within the file/change.

```zig
var vt: std.Io.Writer.Allocating = .init(alloc);
var reader: std.Io.Reader = .fixed(data);
```

### CAPI Functions (`src/apprt/embedded.zig`)

- **Required:** live inside `pub const CAPI = struct { ... }`.
- **Required:** export name prefix `ghostty_` with snake_case (for example `ghostty_surface_export_snapshot`).
- **Required:** return `bool` or `?*T` for fallible operations (no Zig errors cross FFI boundary).
- **Preferred:** parameter naming: `c_path`, `c_input` for C-originated pointers; `surface`, `app` for Ghostty objects.
- **Required:** use `std.mem.sliceTo(c_ptr, 0)` to convert sentinel-terminated C strings to slices.

## Swift Conventions (macOS App)

### Naming

- **Required:** Swift `camelCase` for properties, methods, local variables.
- **Required:** C struct fields stay `snake_case` (e.g., `config.working_directory`).
- **Required:** config keys use `kebab-case` in C API strings, `camelCase` as Swift computed properties.
- **Preferred:** `CodingKeys` enum cases are `camelCase`; append new keys at end for stable ordering.

### File Organization

- **Preferred:** one major type per file.
- **Current practice:** cohesive files may contain multiple related types/protocols/extensions (especially restoration/state modules). Keep related pieces together when it improves cohesion.
- **Preferred:** `extension Ghostty { ... }` namespace for Ghostty-specific types.
- **Preferred:** `// MARK: -` section dividers for protocol conformances and logical sections.

### Access Control

- **Preferred:** `private(set)` for externally-readable/internally-writable.
- **Preferred:** `@Published private(set)` for observable state.
- **Preferred:** `private static` for internal helpers.
- **Preferred:** rely on default `internal` access unless explicit visibility is needed.

### Error Handling

- **Preferred:** `guard ... else { return }` for early returns.
- **Preferred:** `do/catch` with `logger.warning(...)` for non-fatal errors.
- **Preferred:** `throws` propagation for fatal errors.

### Logging

Apple `OSLog` framework via `Logger`:

```swift
static let logger = Logger(
    subsystem: Bundle.main.bundleIdentifier!,
    category: String(describing: MyType.self)
)
```

Called as `Self.logger.warning("description key=\(value)")` or `AppDelegate.logger.warning(...)`.

### Config Access

**Preferred:** access config through computed properties (`ghostty.config.propertyName` or `appDelegate.ghostty.config.propertyName`). Config values are `String`, `Bool`, etc., returned by `ghostty_config_get` calls inside the computed var.

### Async / Dispatch

**Current practice:** mixed model. The macOS app uses both GCD (`DispatchQueue`) and structured concurrency (`async/await`, `Task`).

**Preferred:** follow the surrounding module's established pattern and actor constraints:

- Use `DispatchQueue` for callback-based/legacy flows and AppKit scheduling.
- Use `async/await` + `Task` in async workflows (for example App Intents, Swift concurrency-native paths).
- Capture weak references when escaping closures can outlive object ownership and `self` retention would be problematic.

```swift
DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(3)) { [weak self] in
    guard let self else { return }
    // ...
}
```

### C Interop

- **Required:** preserve C string lifetime safety with `withCString`/`withCValue` wrappers.
- **Preferred:** `Optional<String>.withCString` passes `nil` for `.none`.
- **Preferred:** each optional C string field adds one nesting level in `withCValue`.

### Codable / State Restoration

- **Required:** state versioning via `class var version: Int` where restoration models require version checks.
- **Preferred:** `CodingKeys` enum with camelCase cases.
- **Preferred:** `decodeIfPresent` for newer/optional fields (backward compatibility).
- **Current practice:** Codable models may use `required convenience init(from decoder:)`; NSCoding restoration paths may use `init?(coder:)` wrappers around codable bridges.

### Stores / Managers

- **Preferred:** caseless `enum` with static methods (not `class`) for stateless namespaces.
- **Preferred:** `NSLock()` for thread safety on shared mutable state.
- **Preferred:** `FileManager` + `URL` APIs for filesystem operations.
- **Required:** XDG compliance: respect `XDG_STATE_HOME`, default to `~/.local/state/ghostty/`.
