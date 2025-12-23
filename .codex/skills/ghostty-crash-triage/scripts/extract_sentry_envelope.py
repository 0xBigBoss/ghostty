#!/usr/bin/env python3
"""Extract Sentry envelope event + minidump from a .ghosttycrash file."""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class EnvelopeItem:
    header: dict[str, Any]
    payload: bytes


@dataclass
class ParsedEnvelope:
    header: dict[str, Any]
    items: list[EnvelopeItem]


class EnvelopeError(Exception):
    """User-facing error for envelope parsing issues."""


def _read_line(buf: bytes, start: int) -> tuple[bytes | None, int]:
    end = buf.find(b"\n", start)
    if end == -1:
        return None, start
    return buf[start:end], end + 1


def parse_envelope(path: Path) -> ParsedEnvelope:
    """Parse a Sentry envelope file into header and items."""
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        raise EnvelopeError(f"crash file not found: {path}") from None
    except PermissionError:
        raise EnvelopeError(f"permission denied reading: {path}") from None

    if len(data) == 0:
        raise EnvelopeError(f"crash file is empty: {path}")

    header_line, i = _read_line(data, 0)
    if header_line is None:
        raise EnvelopeError("invalid envelope: missing header line")

    try:
        header = json.loads(header_line.decode("utf-8"))
    except json.JSONDecodeError as err:
        raise EnvelopeError(f"invalid envelope header (not valid JSON): {err}") from err

    items: list[EnvelopeItem] = []
    while i < len(data):
        item_header_line, i = _read_line(data, i)
        if item_header_line is None or item_header_line.strip() == b"":
            break
        try:
            item_header = json.loads(item_header_line.decode("utf-8"))
        except json.JSONDecodeError as err:
            raise EnvelopeError(f"invalid item header (not valid JSON): {err}") from err

        length = item_header.get("length")
        if length is None:
            raise EnvelopeError("invalid envelope: item header missing 'length' field")
        payload = data[i : i + length]
        i += length
        if i < len(data) and data[i : i + 1] == b"\n":
            i += 1
        items.append(EnvelopeItem(header=item_header, payload=payload))

    return ParsedEnvelope(header=header, items=items)


def extract_envelope(envelope_path: Path, out_dir: Path) -> Path:
    """Extract event summary and minidump from envelope. Returns path to event_summary.json."""
    envelope = parse_envelope(envelope_path)
    out_dir.mkdir(parents=True, exist_ok=True)

    summary: dict[str, Any] = {
        "envelope_header": envelope.header,
        "event": None,
        "attachment": None,
    }

    found_event = False
    found_minidump = False

    for item in envelope.items:
        if item.header.get("type") == "event":
            found_event = True
            try:
                event = json.loads(item.payload.decode("utf-8", errors="replace"))
            except json.JSONDecodeError as err:
                raise EnvelopeError(f"invalid event payload (not valid JSON): {err}") from err

            dbg = event.get("debug_meta") or {}
            images = dbg.get("images") or []
            ghostty_img = next(
                (
                    im
                    for im in images
                    if im.get("code_file", "").endswith("/Ghostty.app/Contents/MacOS/ghostty")
                ),
                None,
            )
            summary["event"] = {
                "event_id": event.get("event_id"),
                "timestamp": event.get("timestamp"),
                "level": event.get("level"),
                "release": event.get("release"),
                "environment": event.get("environment"),
                "tags": event.get("tags"),
                "contexts": event.get("contexts"),
                "ghostty_image": ghostty_img,
            }

        if item.header.get("type") == "attachment" and item.header.get("attachment_type") == "event.minidump":
            found_minidump = True
            summary["attachment"] = item.header
            fname = item.header.get("filename") or "event.dmp"
            out_path = out_dir / fname
            out_path.write_bytes(item.payload)

    if not found_event:
        raise EnvelopeError("envelope contains no event item")
    if not found_minidump:
        raise EnvelopeError("envelope contains no minidump attachment")

    summary_path = out_dir / "event_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True))

    return summary_path


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Extract Sentry envelope event + minidump from a .ghosttycrash file."
    )
    ap.add_argument("envelope", type=Path, help="Path to .ghosttycrash envelope")
    ap.add_argument("out_dir", type=Path, help="Output directory")
    args = ap.parse_args()

    try:
        summary_path = extract_envelope(args.envelope, args.out_dir)
        print(f"wrote {summary_path}")
        return 0
    except EnvelopeError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
