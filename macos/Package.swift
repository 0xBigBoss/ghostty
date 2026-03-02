// swift-tools-version: 6.0
// [fork-only] GhosttySwift SPM library for embedding Ghostty's macOS runtime.
import PackageDescription

let moduleCachePath = "\(Context.packageDirectory)/.build/module-cache"

let package = Package(
  name: "GhosttyMacOS",
  platforms: [.macOS(.v14)],
  products: [
    .library(name: "GhosttySwift", targets: ["GhosttySwift"]),
  ],
  targets: [
    // C module map for libghostty's public header.
    // Prerequisite: run `zig build` from the repo root so that
    // zig-out/include/ghostty.h and zig-out/lib/libghostty.a exist.
    .target(
      name: "GhosttyKit",
      path: "GhosttyKit",
      publicHeadersPath: ".",
      cSettings: [
        .unsafeFlags(["-fmodules-cache-path=\(moduleCachePath)"]),
      ]
    ),
    .target(
      name: "GhosttySwift",
      dependencies: ["GhosttyKit"],
      path: "Sources",
      exclude: [
        // Ghostty's own app entry point (Sox provides its own).
        "App",

        // Feature dirs excluded — Ghostty branding, Sparkle updates,
        // XIB-heavy or AppDelegate-coupled features.
        "Features/About",
        "Features/App Intents",
        "Features/Custom App Icon",
        "Features/Global Keybinds",
        "Features/QuickTerminal",
        "Features/Services",
        "Features/Settings",
        "Features/Update",

        // Individual files within included features.
        "Features/ClipboardConfirmation/ClipboardConfirmation.xib",
        "Features/Command Palette/TerminalCommandPalette.swift",
        "Features/Terminal/Window Styles/Terminal.xib",
        "Features/Terminal/Window Styles/TerminalHiddenTitlebar.xib",
        "Features/Terminal/Window Styles/TerminalTabsTitlebarTahoe.xib",
        "Features/Terminal/Window Styles/TerminalTabsTitlebarVentura.xib",
        "Features/Terminal/Window Styles/TerminalTransparentTitlebar.xib",

        // ObjC files (separate target if needed).
        "Helpers/ObjCExceptionCatcher.h",
        "Helpers/ObjCExceptionCatcher.m",
        "Helpers/VibrantLayer.h",
        "Helpers/VibrantLayer.m",
      ],
      cSettings: [
        .unsafeFlags(["-fmodules-cache-path=\(moduleCachePath)"]),
      ],
      swiftSettings: [
        .define("GHOSTTY_SPM_LIBRARY"),
        .unsafeFlags(["-Xcc", "-fmodules-cache-path=\(moduleCachePath)"]),
      ],
      linkerSettings: [
        .unsafeFlags(["-L", "../zig-out/lib"]),
        .linkedLibrary("ghostty"),
        .linkedLibrary("c++"),
        .linkedFramework("AppKit"),
        .linkedFramework("Carbon"),
        .linkedFramework("CoreText"),
        .linkedFramework("CoreVideo"),
        .linkedFramework("Metal"),
        .linkedFramework("QuartzCore"),
      ]
    ),
  ]
)
