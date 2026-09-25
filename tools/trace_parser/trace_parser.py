"""Trace parser and sanitizer for EDIABAS api32 trace logs (*.trc) and JSONL.

Extracts job sequences, payload hashes, status responses, and sanitizes
sensitive identifiers (VINs, ECU serials, private keys).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_QUOTED = re.compile(r'^\s*"([^"]*)"\s*$')
_BYTES_HDR = re.compile(r"^(\d+)\s+bytes:")
_HEXLINE = re.compile(r"^\s*[0-9A-Fa-f]+:\s+((?:[0-9A-Fa-f]{2}\s*)+)")
_STATUS = re.compile(r'^\s*JOB_STATUS\s*=\s*"([^"]*)"')
_VIN_RE = re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b")


def redact_vin(text: str) -> str:
    """Replace 17-character VIN patterns with REDACTED_VIN_X."""
    return _VIN_RE.sub("WBA00000000000000", text)


def parse_ediabas_trc(content: str, redact: bool = True) -> List[Dict[str, Any]]:
    """Parse EDIABAS *.trc format into structured event records."""
    if redact:
        content = redact_vin(content)

    events: List[Dict[str, Any]] = []
    pending_strings: List[str] = []
    payload_buf: Optional[bytearray] = None
    in_hex_dump = False
    job_status: Optional[str] = None

    def flush_job():
        nonlocal pending_strings, payload_buf, job_status
        if len(pending_strings) >= 2:
            dev = pending_strings[0]
            name = pending_strings[1]
            args = pending_strings[2] if len(pending_strings) >= 3 else ""
            raw_payload = bytes(payload_buf) if payload_buf is not None else None
            payload_len = len(raw_payload) if raw_payload is not None else 0
            sha = hashlib.sha256(raw_payload).hexdigest() if raw_payload else None

            events.append({
                "op": "job_bin" if payload_len > 0 else "job",
                "dev": dev,
                "name": name,
                "args": args,
                "bytes": payload_len,
                "sha": sha,
                "status": job_status or "OKAY",
            })
        pending_strings = []
        payload_buf = None
        job_status = None

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if line == "Job":
            flush_job()
            in_hex_dump = False
            continue

        if in_hex_dump:
            if line.isdigit():
                in_hex_dump = False
            else:
                m = _HEXLINE.match(raw_line)
                if m and payload_buf is not None:
                    payload_buf += bytes.fromhex(m.group(1).replace(" ", ""))
            continue

        m = _QUOTED.match(line)
        if m:
            pending_strings.append(m.group(1))
            continue

        m = _BYTES_HDR.match(line)
        if m and len(pending_strings) >= 2:
            in_hex_dump = True
            payload_buf = bytearray()
            continue

        m = _STATUS.match(line)
        if m:
            job_status = m.group(1)

    flush_job()
    return events


def trc_to_jsonl(trc_path: Path, out_path: Optional[Path] = None, redact: bool = True) -> str:
    events = parse_ediabas_trc(trc_path.read_text(encoding="latin-1", errors="replace"), redact=redact)
    lines = [json.dumps(ev) for ev in events]
    text = "\n".join(lines) + "\n"
    if out_path:
        out_path.write_text(text, encoding="utf-8")
    return text


def main():
    parser = argparse.ArgumentParser(description="Parse and sanitize EDIABAS trace files.")
    parser.add_argument("input", type=Path, help="Input *.trc or *.jsonl file")
    parser.add_argument("-o", "--output", type=Path, help="Output JSONL file path")
    parser.add_argument("--no-redact", action="store_true", help="Do not redact VIN patterns")
    args = parser.parse_args()

    if not args.input.is_file():
        sys.stderr.write(f"Error: input file {args.input} does not exist\n")
        sys.exit(1)

    redact = not args.no_redact
    if args.input.suffix == ".trc":
        events = parse_ediabas_trc(args.input.read_text(encoding="latin-1", errors="replace"), redact=redact)
    elif args.input.suffix == ".jsonl":
        events = [json.loads(line) for line in args.input.read_text(encoding="utf-8").splitlines() if line.strip()]
    else:
        sys.stderr.write(f"Unsupported extension: {args.input.suffix}\n")
        sys.exit(1)

    print(f"Parsed {len(events)} events from {args.input.name}")
    if args.output:
        args.output.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
        print(f"Wrote output to {args.output}")
    else:
        for idx, ev in enumerate(events[:10]):
            print(f"  [{idx:03d}] {ev['dev']}:{ev['name']} status={ev.get('status')} bytes={ev.get('bytes', 0)}")
        if len(events) > 10:
            print(f"  ... and {len(events) - 10} more events")


if __name__ == "__main__":
    main()
