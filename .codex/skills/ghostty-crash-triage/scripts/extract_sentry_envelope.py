#!/usr/bin/env python3
"""Extract Sentry envelope event + minidump from a .ghosttycrash file."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Tuple, List, Dict, Any


def _read_line(buf: bytes, start: int) -> Tuple[bytes | None, int]:
    end = buf.find(b"\n", start)
    if end == -1:
        return None, start
    return buf[start:end], end + 1


def parse_envelope(path: Path) -> Tuple[Dict[str, Any], List[Tuple[Dict[str, Any], bytes]]]:
    data = path.read_bytes()
    header_line, i = _read_line(data, 0)
    if header_line is None:
        raise ValueError("missing envelope header")
    header = json.loads(header_line.decode("utf-8"))
    items: List[Tuple[Dict[str, Any], bytes]] = []
    while i < len(data):
        item_header_line, i = _read_line(data, i)
        if item_header_line is None or item_header_line.strip() == b"":
            break
        item_header = json.loads(item_header_line.decode("utf-8"))
        length = item_header.get("length")
        if length is None:
            raise ValueError("missing length in item header")
        payload = data[i : i + length]
        i += length
        if i < len(data) and data[i : i + 1] == b"\n":
            i += 1
        items.append((item_header, payload))
    return header, items


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("envelope", type=Path, help="Path to .ghosttycrash envelope")
    ap.add_argument("out_dir", type=Path, help="Output directory")
    args = ap.parse_args()

    header, items = parse_envelope(args.envelope)

    args.out_dir.mkdir(parents=True, exist_ok=True)

    summary: Dict[str, Any] = {
        "envelope_header": header,
        "event": None,
        "attachment": None,
    }

    for item_header, payload in items:
        if item_header.get("type") == "event":
            event = json.loads(payload.decode("utf-8", errors="replace"))
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
        if item_header.get("type") == "attachment" and item_header.get("attachment_type") == "event.minidump":
            summary["attachment"] = item_header
            fname = item_header.get("filename") or "event.dmp"
            out_path = args.out_dir / fname
            out_path.write_bytes(payload)

    summary_path = args.out_dir / "event_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True))

    print(f"wrote {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
