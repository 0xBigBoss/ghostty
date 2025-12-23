#!/usr/bin/env python3
"""
Ghostty crash triage orchestrator.

One-command workflow to:
1. Extract a .ghosttycrash envelope
2. Match debug symbols (dSYM)
3. Symbolicate with lldb
4. Fall back to atos if unsymbolicated
5. Generate a REPORT.md skeleton
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_DSYM_SEARCH_PATHS = [
    "~/.ghostty-dsyms",
    "macos/build/ReleaseLocal",
    "/Applications/Ghostty.app/Contents/MacOS",
]
DEFAULT_CRASH_DIR = "~/.local/state/ghostty/crash"
DEFAULT_OUTPUT_ROOT = "bug-crash-reports"
DEFAULT_UNSYM_THRESHOLD = 0.5


@dataclass
class Config:
    dsym_search_paths: list[str] = field(default_factory=lambda: list(DEFAULT_DSYM_SEARCH_PATHS))
    crash_dir: str = DEFAULT_CRASH_DIR
    output_root: str = DEFAULT_OUTPUT_ROOT
    unsymbolicated_threshold: float = DEFAULT_UNSYM_THRESHOLD

    @classmethod
    def load(cls, path: Path | None = None) -> "Config":
        """Load config from JSON file, falling back to defaults."""
        if path is None:
            path = Path(__file__).parent / "config.json"
        if path.exists():
            try:
                content = path.read_text()
                if not content.strip():
                    raise TriageError(f"config file is empty: {path}")
                data = json.loads(content)
            except FileNotFoundError:
                raise TriageError(f"config file not found: {path}") from None
            except PermissionError:
                raise TriageError(f"permission denied reading config: {path}") from None
            except json.JSONDecodeError as err:
                raise TriageError(f"invalid config JSON in {path}: {err}") from err
            return cls(
                dsym_search_paths=data.get("dsym_search_paths", DEFAULT_DSYM_SEARCH_PATHS),
                crash_dir=data.get("crash_dir", DEFAULT_CRASH_DIR),
                output_root=data.get("output_root", DEFAULT_OUTPUT_ROOT),
                unsymbolicated_threshold=data.get("unsymbolicated_threshold", DEFAULT_UNSYM_THRESHOLD),
            )
        return cls()


# ---------------------------------------------------------------------------
# Data Types
# ---------------------------------------------------------------------------

@dataclass
class GhosttyImage:
    code_file: str
    debug_id: str
    image_addr: str
    image_size: int
    arch: str = "arm64"  # default, detected from debug_id match


@dataclass
class EventSummary:
    event_id: str
    timestamp: str
    level: str
    release: str
    environment: str
    tags: dict[str, str]
    contexts: dict[str, Any]
    ghostty_image: GhosttyImage | None
    minidump_filename: str


@dataclass
class DsymMatch:
    path: Path
    uuid: str
    arch: str
    is_dsym_bundle: bool  # True if matched a .dSYM bundle, False if bare binary


class TriageError(Exception):
    """User-facing error during triage."""


# ---------------------------------------------------------------------------
# Crash File Selection
# ---------------------------------------------------------------------------

def find_newest_crash(crash_dir: Path) -> Path:
    """Find the newest .ghosttycrash file in the crash directory."""
    if not crash_dir.exists():
        raise TriageError(f"crash directory not found: {crash_dir}")

    crashes = list(crash_dir.glob("*.ghosttycrash"))
    if not crashes:
        raise TriageError(f"no .ghosttycrash files found in: {crash_dir}")

    return max(crashes, key=lambda p: p.stat().st_mtime)


# ---------------------------------------------------------------------------
# dSYM Matching
# ---------------------------------------------------------------------------

def run_dwarfdump(path: Path) -> list[tuple[str, str]]:
    """Run dwarfdump --uuid and return list of (arch, uuid) tuples."""
    try:
        result = subprocess.run(
            ["dwarfdump", "--uuid", str(path)],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        return []
    except subprocess.TimeoutExpired:
        return []

    if result.returncode != 0:
        return []

    # Parse output like: UUID: 02F9811F-0F22-3C7B-BC89-79A31322DB2B (arm64) /path/to/file
    matches: list[tuple[str, str]] = []
    for line in result.stdout.splitlines():
        m = re.match(r"UUID:\s+([A-Fa-f0-9-]+)\s+\((\w+)\)", line)
        if m:
            uuid = m.group(1).upper().replace("-", "")
            arch = m.group(2)
            matches.append((arch, uuid))
    return matches


def normalize_uuid(uuid: str) -> str:
    """Normalize a UUID to uppercase without dashes."""
    return uuid.upper().replace("-", "")


def find_matching_dsym(
    debug_id: str,
    search_paths: list[Path],
) -> DsymMatch | None:
    """Search for a dSYM matching the given debug_id.

    Prioritizes dSYM bundles over bare binaries for reliable symbolication.
    """
    target_uuid = normalize_uuid(debug_id)

    # (path, arch, uuid, is_dsym_bundle)
    dsym_candidates: list[tuple[Path, str, str, bool]] = []
    binary_candidates: list[tuple[Path, str, str, bool]] = []

    for search_path in search_paths:
        if not search_path.exists():
            continue

        # Look for dSYM bundles (preferred)
        for dsym in search_path.glob("**/*.dSYM"):
            dwarf_path = dsym / "Contents" / "Resources" / "DWARF" / "ghostty"
            if dwarf_path.exists():
                for arch, uuid in run_dwarfdump(dwarf_path):
                    dsym_candidates.append((dsym, arch, uuid, True))

        # Look for bare binaries (fallback)
        for binary in search_path.glob("**/ghostty"):
            if binary.is_file() and not str(binary).endswith(".dSYM"):
                for arch, uuid in run_dwarfdump(binary):
                    binary_candidates.append((binary.parent, arch, uuid, False))

    # Prefer dSYM bundles over bare binaries
    for path, arch, uuid, is_dsym in dsym_candidates:
        if uuid == target_uuid:
            return DsymMatch(path=path, uuid=uuid, arch=arch, is_dsym_bundle=True)

    for path, arch, uuid, is_dsym in binary_candidates:
        if uuid == target_uuid:
            return DsymMatch(path=path, uuid=uuid, arch=arch, is_dsym_bundle=False)

    return None


def write_dsym_uuids(candidates: list[tuple[Path, str]], out_path: Path) -> None:
    """Write discovered dSYM UUIDs to a file for reference."""
    lines = []
    for path, output in candidates:
        lines.append(f"# {path}")
        lines.append(output)
        lines.append("")
    out_path.write_text("\n".join(lines))


# ---------------------------------------------------------------------------
# lldb + Symbolication
# ---------------------------------------------------------------------------

def run_lldb_bt(
    minidump: Path,
    binary: Path,
    dsym_dir: Path | None,
    out_file: Path,
    script_dir: Path,
) -> bool:
    """Run lldb_bt.sh and return True if successful."""
    cmd = [
        str(script_dir / "lldb_bt.sh"),
        str(minidump),
        str(binary),
        str(dsym_dir) if dsym_dir else "",
        str(out_file),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return result.returncode == 0


# Pattern to detect ghostty frames
GHOSTTY_FRAME_PATTERN = re.compile(r"frame #\d+:.*ghostty")

# Pattern to detect SYMBOLICATED ghostty frames (has backtick + function name)
# Examples:
#   ghostty`terminal.render.RenderState.linkCells at render.zig:820
#   ghostty`posix.abort at posix.zig:732
SYMBOLICATED_PATTERN = re.compile(r"ghostty`[a-zA-Z_]")


def analyze_symbolication(bt_path: Path) -> tuple[int, int, list[str]]:
    """
    Analyze lldb backtrace for unsymbolicated frames.

    Returns: (total_ghostty_frames, unsymbolicated_count, unsym_addresses)
    """
    if not bt_path.exists():
        return 0, 0, []

    content = bt_path.read_text()
    lines = content.splitlines()

    total_ghostty = 0
    unsym_count = 0
    unsym_addresses: list[str] = []

    for line in lines:
        if GHOSTTY_FRAME_PATTERN.search(line):
            total_ghostty += 1
            # A frame is unsymbolicated if it doesn't have `ghostty`function_name
            # (i.e., just "ghostty" or "ghostty`0x...")
            if not SYMBOLICATED_PATTERN.search(line):
                unsym_count += 1
                # Extract the instruction address (first hex after frame #N:)
                addr_match = re.search(r"frame #\d+:\s+(0x[0-9a-fA-F]+)", line)
                if addr_match:
                    unsym_addresses.append(addr_match.group(1))

    return total_ghostty, unsym_count, unsym_addresses


# ---------------------------------------------------------------------------
# atos Fallback
# ---------------------------------------------------------------------------

def run_atos_fallback(
    binary: Path,
    arch: str,
    load_addr: str,
    addresses: list[str],
    out_file: Path,
) -> bool:
    """
    Run atos to symbolicate addresses when dSYM is unavailable.

    Uses the binary + load address to attempt symbolication.
    """
    if not addresses:
        return False

    cmd = [
        "atos",
        "-o", str(binary),
        "-arch", arch,
        "-l", load_addr,
    ] + addresses

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

    if result.returncode != 0:
        return False

    # Write output with address mapping
    lines = ["# atos symbolication fallback", f"# binary: {binary}", f"# arch: {arch}", f"# load_addr: {load_addr}", ""]
    symbols = result.stdout.strip().splitlines()
    for addr, sym in zip(addresses, symbols):
        lines.append(f"{addr}: {sym}")

    out_file.write_text("\n".join(lines))
    return True


# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------

def generate_report(
    out_dir: Path,
    event: EventSummary,
    dsym_match: DsymMatch | None,
    has_atos: bool,
    files: list[str],
) -> Path:
    """Generate REPORT.md skeleton from event data."""

    release = event.release or "unknown"
    os_ctx = event.contexts.get("os", {})
    os_version = os_ctx.get("version", "unknown")
    os_build = os_ctx.get("build", "")

    tags = event.tags or {}
    build_mode = tags.get("build-mode", "unknown")
    renderer = tags.get("renderer", "unknown")
    thread_type = tags.get("thread-type", "unknown")

    if dsym_match:
        dsym_status = "matched (dSYM bundle)" if dsym_match.is_dsym_bundle else "matched (binary only - symbols may be limited)"
    elif has_atos:
        dsym_status = "NOT FOUND - used atos fallback"
    else:
        dsym_status = "NOT FOUND"

    report = f"""# Ghostty crash report ({datetime.now().strftime('%Y-%m-%d')})

## Summary
[TODO: Describe the crash - what was happening when it occurred]

## Context
- **Release**: {release}
- **Build mode**: {build_mode}
- **Renderer**: {renderer}
- **Thread type**: {thread_type}
- **OS**: macOS {os_version} (build {os_build})
- **dSYM status**: {dsym_status}

## Evidence
- Backtrace: `lldb_bt.txt`
{"- atos fallback: `atos_bt.txt`" if has_atos else ""}
- Event summary: `event_summary.json`

## Symbolicated Stack (excerpt)
[TODO: Paste relevant frames from lldb_bt.txt or atos_bt.txt]

## Likely Cause
[TODO: Identify the likely root cause after inspecting the stack]

## Suggested Fixes
[TODO: Propose fixes or areas to investigate]

## Files
{chr(10).join(f'- `{f}`' for f in files)}
"""

    report_path = out_dir / "REPORT.md"
    report_path.write_text(report)
    return report_path


# ---------------------------------------------------------------------------
# Main Orchestrator
# ---------------------------------------------------------------------------

def parse_event_summary(path: Path) -> EventSummary:
    """Parse event_summary.json into typed EventSummary."""
    data = json.loads(path.read_text())
    event = data.get("event") or {}
    attachment = data.get("attachment") or {}

    ghostty_img_data = event.get("ghostty_image")
    ghostty_image = None
    if ghostty_img_data:
        ghostty_image = GhosttyImage(
            code_file=ghostty_img_data.get("code_file", ""),
            debug_id=ghostty_img_data.get("debug_id", ""),
            image_addr=ghostty_img_data.get("image_addr", ""),
            image_size=ghostty_img_data.get("image_size", 0),
        )

    return EventSummary(
        event_id=event.get("event_id", ""),
        timestamp=event.get("timestamp", ""),
        level=event.get("level", ""),
        release=event.get("release", ""),
        environment=event.get("environment", ""),
        tags=event.get("tags") or {},
        contexts=event.get("contexts") or {},
        ghostty_image=ghostty_image,
        minidump_filename=attachment.get("filename", "event.dmp"),
    )


def triage(
    crash_file: Path | None,
    out_dir: Path | None,
    extra_dsym_paths: list[Path],
    config: Config,
) -> int:
    """Run the full triage workflow."""
    script_dir = Path(__file__).parent

    # 1. Resolve crash file
    crash_dir = Path(config.crash_dir).expanduser()
    if crash_file is None:
        crash_file = find_newest_crash(crash_dir)
        print(f"selected newest crash: {crash_file.name}", flush=True)
    elif not crash_file.exists():
        raise TriageError(f"crash file not found: {crash_file}")

    # 2. Create output directory
    if out_dir is None:
        # Use YYYY-MM-DD/HH-MM-SS format for better segmentation of multiple crashes
        now = datetime.now()
        date_str = now.strftime("%Y-%m-%d")
        time_str = now.strftime("%H-%M-%S")
        out_dir = Path(config.output_root).expanduser() / date_str / time_str
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"output directory: {out_dir}")

    # 3. Copy crash file
    dest_crash = out_dir / crash_file.name
    if not dest_crash.exists():
        shutil.copy2(crash_file, dest_crash)

    # 4. Extract envelope
    extract_script = script_dir / "extract_sentry_envelope.py"
    result = subprocess.run(
        [sys.executable, str(extract_script), str(crash_file), str(out_dir)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        raise TriageError("failed to extract envelope")

    # 5. Parse event summary
    summary_path = out_dir / "event_summary.json"
    event = parse_event_summary(summary_path)

    if event.ghostty_image is None:
        raise TriageError("event_summary.json missing ghostty_image - cannot symbolicate")
    if not event.ghostty_image.debug_id:
        raise TriageError("event_summary.json missing ghostty_image.debug_id")

    print(f"debug_id: {event.ghostty_image.debug_id}")
    print(f"load_addr: {event.ghostty_image.image_addr}")

    # 6. Build search paths and match dSYM
    search_paths = [p.expanduser() for p in [Path(p) for p in extra_dsym_paths]]
    search_paths += [Path(p).expanduser() for p in config.dsym_search_paths]

    # Collect all candidates for dsym_uuids.txt
    all_uuids: list[tuple[Path, str]] = []
    for sp in search_paths:
        if not sp.exists():
            continue
        for dsym in sp.glob("**/*.dSYM"):
            dwarf = dsym / "Contents" / "Resources" / "DWARF" / "ghostty"
            if dwarf.exists():
                result = subprocess.run(
                    ["dwarfdump", "--uuid", str(dwarf)],
                    capture_output=True, text=True, timeout=30,
                )
                if result.returncode == 0:
                    all_uuids.append((dwarf, result.stdout.strip()))
        for binary in sp.glob("**/ghostty"):
            if binary.is_file():
                result = subprocess.run(
                    ["dwarfdump", "--uuid", str(binary)],
                    capture_output=True, text=True, timeout=30,
                )
                if result.returncode == 0:
                    all_uuids.append((binary, result.stdout.strip()))

    write_dsym_uuids(all_uuids, out_dir / "dsym_uuids.txt")

    dsym_match = find_matching_dsym(event.ghostty_image.debug_id, search_paths)

    if dsym_match:
        match_type = "dSYM bundle" if dsym_match.is_dsym_bundle else "binary only"
        print(f"dSYM match: {dsym_match.path} ({dsym_match.arch}, {match_type})", flush=True)
        event.ghostty_image.arch = dsym_match.arch
        if not dsym_match.is_dsym_bundle:
            print("warning: matched binary but no dSYM bundle - symbols may be limited", flush=True)
    else:
        print("warning: no matching dSYM found", flush=True)

    # 7. Find binary for lldb
    binary_path: Path | None = None
    for sp in search_paths:
        candidate = sp / "ghostty"
        if candidate.is_file():
            binary_path = candidate
            break
        # Check inside .app bundle
        candidate = sp / "Ghostty.app" / "Contents" / "MacOS" / "ghostty"
        if candidate.is_file():
            binary_path = candidate
            break

    if binary_path is None:
        # Fallback to installed app
        installed = Path("/Applications/Ghostty.app/Contents/MacOS/ghostty")
        if installed.exists():
            binary_path = installed

    if binary_path is None:
        raise TriageError("cannot find ghostty binary for symbolication")

    print(f"using binary: {binary_path}")

    # 8. Run lldb
    minidump_path = out_dir / event.minidump_filename
    lldb_bt_path = out_dir / "lldb_bt.txt"

    # lldb expects the directory containing .dSYM bundles for target.debug-file-search-paths
    dsym_dir: Path | None = None
    if dsym_match and dsym_match.is_dsym_bundle:
        # Use parent directory of the .dSYM bundle
        dsym_dir = dsym_match.path.parent
        print(f"running lldb with dSYM search path: {dsym_dir}", flush=True)
    elif dsym_match:
        print("running lldb without dSYM (binary-only match)", flush=True)
    else:
        print("running lldb without dSYM", flush=True)
    success = run_lldb_bt(minidump_path, binary_path, dsym_dir, lldb_bt_path, script_dir)
    if not success:
        print("warning: lldb failed to generate backtrace", file=sys.stderr)

    # 9. Analyze symbolication
    total_frames, unsym_count, unsym_addrs = analyze_symbolication(lldb_bt_path)

    has_atos = False
    if total_frames > 0:
        unsym_ratio = unsym_count / total_frames
        print(f"symbolication: {total_frames - unsym_count}/{total_frames} frames resolved ({unsym_ratio:.0%} unsymbolicated)")

        if unsym_ratio >= config.unsymbolicated_threshold and unsym_addrs:
            # Validate image_addr before attempting atos
            if not event.ghostty_image.image_addr:
                print("warning: skipping atos fallback - missing image_addr in event", flush=True)
            else:
                print("attempting atos fallback...")
                atos_out = out_dir / "atos_bt.txt"
                has_atos = run_atos_fallback(
                    binary_path,
                    event.ghostty_image.arch,
                    event.ghostty_image.image_addr,
                    unsym_addrs,
                    atos_out,
                )
                if has_atos:
                    print(f"wrote {atos_out}")
                else:
                    print("warning: atos fallback failed", file=sys.stderr)

    # 10. Generate report
    files = [f.name for f in out_dir.iterdir() if f.is_file()]
    report_path = generate_report(out_dir, event, dsym_match, has_atos, sorted(files))
    print(f"wrote {report_path}")

    # 11. Summary
    print()
    print("=" * 60)
    print("Triage complete!")
    print(f"  Output: {out_dir}")
    print(f"  Report: {report_path}")
    print()
    print("Next steps:")
    print("  1. Review lldb_bt.txt for the crash stack")
    if has_atos:
        print("  2. Check atos_bt.txt for additional symbol resolution")
    print("  3. Edit REPORT.md with your analysis")
    print("=" * 60)

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Triage a Ghostty crash file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Triage the newest crash
  python triage.py

  # Triage a specific crash file
  python triage.py ~/.local/state/ghostty/crash/abc123.ghosttycrash

  # Specify output directory
  python triage.py --out-dir bug-crash-reports/my-issue

  # Add extra dSYM search paths
  python triage.py --dsym-search ~/my-dsyms --dsym-search /path/to/other
""",
    )
    parser.add_argument(
        "crash_file",
        type=Path,
        nargs="?",
        help="Path to .ghosttycrash file (default: newest in crash dir)",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        help="Output directory (default: bug-crash-reports/YYYY-MM-DD)",
    )
    parser.add_argument(
        "--dsym-search",
        type=Path,
        action="append",
        default=[],
        dest="dsym_paths",
        help="Additional dSYM search paths (can be specified multiple times)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to config.json (default: scripts/config.json)",
    )

    args = parser.parse_args()

    try:
        config = Config.load(args.config)
        return triage(
            crash_file=args.crash_file,
            out_dir=args.out_dir,
            extra_dsym_paths=args.dsym_paths,
            config=config,
        )
    except TriageError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
