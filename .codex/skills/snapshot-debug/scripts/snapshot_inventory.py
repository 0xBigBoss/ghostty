#!/usr/bin/env python3
"""Decode GSNP binary manifest headers and display snapshot inventory.

Reads all manifest files from ~/.local/state/ghostty/session/*/manifest,
parses the GSNP v1 binary header, and displays a table of session metadata.

Usage:
    uv run scripts/snapshot_inventory.py [--save PATH] [--json]
"""
# /// script
# requires-python = ">=3.10"
# ///

import argparse
import datetime
import json
import os
import pathlib
import struct
import sys


def read_bytes_field(data: bytes, off: int) -> tuple[str | None, int]:
    """Read a u32 length-prefixed UTF-8 string from snapshot data."""
    if off + 4 > len(data):
        return None, off
    length = struct.unpack_from("<I", data, off)[0]
    off += 4
    if length == 0:
        return None, off
    if off + length > len(data):
        return None, off
    val = data[off : off + length].decode("utf-8", errors="replace")
    off += length
    return val, off


def parse_manifest(path: pathlib.Path) -> dict | None:
    """Parse a GSNP v1 manifest file and return metadata dict."""
    data = path.read_bytes()
    if len(data) < 28 or data[:4] != b"GSNP":
        return None

    version = struct.unpack_from("<H", data, 4)[0]
    if version != 1:
        return None

    _flags = struct.unpack_from("<H", data, 6)[0]
    # 8 bytes reserved at offset 8
    timestamp = struct.unpack_from("<q", data, 16)[0]
    cols = struct.unpack_from("<H", data, 24)[0]
    rows = struct.unpack_from("<H", data, 26)[0]

    off = 28
    session_id, off = read_bytes_field(data, off)
    pwd, off = read_bytes_field(data, off)
    title, off = read_bytes_field(data, off)

    stat = path.stat()
    return {
        "uuid": path.parent.name,
        "size": stat.st_size,
        "modified": stat.st_mtime,
        "timestamp": timestamp,
        "cols": cols,
        "rows": rows,
        "pwd": pwd,
        "title": title,
        "session_id": session_id,
    }


def shorten_path(p: str | None) -> str:
    """Replace home directory prefix with ~/."""
    if not p:
        return "(none)"
    home = os.path.expanduser("~")
    if p.startswith(home + "/"):
        return "~/" + p[len(home) + 1 :]
    return p


def main() -> None:
    parser = argparse.ArgumentParser(description="Ghostty snapshot inventory")
    parser.add_argument(
        "--save", metavar="PATH", help="save inventory to file for later comparison"
    )
    parser.add_argument("--json", action="store_true", help="output as JSON")
    parser.add_argument(
        "--session-dir",
        default=os.path.expanduser("~/.local/state/ghostty/session"),
        help="session directory (default: ~/.local/state/ghostty/session)",
    )
    args = parser.parse_args()

    session = pathlib.Path(args.session_dir)
    if not session.exists():
        print(f"session directory not found: {session}", file=sys.stderr)
        sys.exit(1)

    results = []
    for d in sorted(session.iterdir()):
        f = d / "manifest"
        if not f.is_file():
            continue
        entry = parse_manifest(f)
        if entry:
            results.append(entry)

    # Sort by modification time, newest first
    results.sort(key=lambda r: -r["modified"])

    if args.json or args.save:
        output = json.dumps(results, indent=2)
        if args.save:
            pathlib.Path(args.save).write_text(output)
            print(f"saved {len(results)} entries to {args.save}")
        if args.json:
            print(output)
            return

    # Table output
    print(
        f"{'ID':8}  {'Size':>8}  {'Dims':7}  {'Modified':11}  "
        f"{'PWD':<45}  Title"
    )
    print("-" * 130)
    for r in results:
        short_id = r["uuid"][:8]
        sz = f"{r['size']}B"
        dims = f"{r['cols']}x{r['rows']}"
        mod = datetime.datetime.fromtimestamp(r["modified"]).strftime("%m-%d %H:%M")
        pwd = shorten_path(r["pwd"])
        if len(pwd) > 45:
            pwd = "..." + pwd[-42:]
        title = r["title"] or "(none)"
        if len(title) > 50:
            title = title[:47] + "..."
        print(f"{short_id}  {sz:>8}  {dims:>7}  {mod:>11}  {pwd:<45}  {title}")

    print(f"\nTotal: {len(results)} manifests")


if __name__ == "__main__":
    main()
