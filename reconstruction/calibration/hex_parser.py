"""BMW EDIABAS Intel Hex Parser (.0da / .0pa).

Supports standard Intel Hex records (00, 01, 02, 04) and custom BMW records (0x10).
Handles dual linear (Type 04) and segmented (Type 02) addressing modes.
Parses file header directives (e.g. ;$REFERENZ, ;$CHECKSUMME, ;$CARB_MODE_9_CVN).
Strictly offline and deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Union


@dataclass(frozen=True)
class MemorySegment:
    """A contiguous block of memory decoded from Intel Hex data."""

    start_address: int
    end_address: int  # Exclusive end address (start_address + size)
    data: bytes

    @property
    def size(self) -> int:
        """Return the size in bytes of the segment."""
        return len(self.data)

    def to_dict(self) -> Dict[str, Any]:
        """Return deterministic dictionary representation."""
        return {
            "start_address": f"0x{self.start_address:08X}",
            "end_address": f"0x{self.end_address:08X}",
            "start_int": self.start_address,
            "end_int": self.end_address,
            "size": self.size,
        }


@dataclass
class ParsedHexImage:
    """Decoded Intel Hex binary image with segments and metadata."""

    segments: List[MemorySegment] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    trailers: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def total_bytes(self) -> int:
        """Total payload bytes across all segments."""
        return sum(s.size for s in self.segments)

    def find_segment(self, address: int) -> Optional[MemorySegment]:
        """Find segment containing the specified address."""
        for seg in self.segments:
            if seg.start_address <= address < seg.end_address:
                return seg
        return None

    def read_bytes(self, address: int, length: int) -> Optional[bytes]:
        """Read `length` bytes starting at `address` across segments if present."""
        seg = self.find_segment(address)
        if seg is None:
            return None
        offset = address - seg.start_address
        if offset + length <= seg.size:
            return seg.data[offset : offset + length]
        return None

    def get_byte_at(self, address: int) -> Optional[int]:
        """Read a single byte at `address`."""
        b = self.read_bytes(address, 1)
        return b[0] if b else None

    def to_dict(self) -> Dict[str, Any]:
        """Deterministic dictionary representation."""
        return {
            "total_bytes": self.total_bytes,
            "segment_count": len(self.segments),
            "segments": [s.to_dict() for s in self.segments],
            "headers": self.headers,
            "trailer_count": len(self.trailers),
        }


class IntelHexParser:
    """Parser for Intel Hex format with BMW EDIABAS extensions."""

    @classmethod
    def parse_file(cls, filepath: Union[str, Path]) -> ParsedHexImage:
        """Parse Intel Hex file from disk."""
        path = Path(filepath)
        with path.open("r", encoding="latin-1", errors="replace") as f:
            return cls.parse(f)

    @classmethod
    def parse(cls, text_or_lines: Union[str, Iterable[str]]) -> ParsedHexImage:
        """Parse Intel Hex from string or iterable of lines."""
        if isinstance(text_or_lines, str):
            lines = text_or_lines.splitlines()
        else:
            lines = list(text_or_lines)

        headers: Dict[str, str] = {}
        trailers: List[Dict[str, Any]] = []

        # Current address bases
        linear_base: int = 0   # From type 04 (value << 16)
        segment_base: int = 0  # From type 02 (value << 4)

        # Raw memory map: address -> byte
        memory: Dict[int, int] = {}

        for line_no, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line:
                continue

            # Header directives and comments
            if line.startswith(";") or line.startswith("$"):
                if line.startswith(";$"):
                    content = line[2:].strip()
                    parts = content.split(None, 1)
                    if len(parts) == 2:
                        headers[parts[0]] = parts[1].strip()
                    elif len(parts) == 1:
                        headers[parts[0]] = ""
                elif line.startswith("$"):
                    content = line[1:].strip()
                    parts = content.split(None, 1)
                    if len(parts) == 2:
                        headers[parts[0]] = parts[1].strip()
                    elif len(parts) == 1:
                        headers[parts[0]] = ""
                elif line.startswith(";;"):
                    content = line[2:].strip()
                    if ":" in content:
                        k, v = content.split(":", 1)
                        k_clean = k.strip()
                        v_clean = v.strip()
                        if k_clean and v_clean:
                            headers[k_clean] = v_clean
                continue

            if not line.startswith(":"):
                continue

            # Intel Hex record format:
            # : LL AAAA TT [DD...] CC
            # LL = byte count (2 hex chars)
            # AAAA = address offset (4 hex chars)
            # TT = record type (2 hex chars)
            # DD... = data (2*LL hex chars)
            # CC = checksum (2 hex chars)
            if len(line) < 11:
                raise ValueError(f"Line {line_no}: record too short: '{line}'")

            try:
                byte_count = int(line[1:3], 16)
                offset = int(line[3:7], 16)
                record_type = int(line[7:9], 16)
                data_hex = line[9 : 9 + (byte_count * 2)]
                checksum_hex = line[9 + (byte_count * 2) : 11 + (byte_count * 2)]

                if len(checksum_hex) != 2:
                    raise ValueError(f"Line {line_no}: incomplete record")

                checksum = int(checksum_hex, 16)
            except ValueError as e:
                raise ValueError(f"Line {line_no}: hex decoding error: {e}") from e

            # Verify checksum: sum of all bytes modulo 256 == 0
            raw_bytes = bytes.fromhex(line[1 : 11 + (byte_count * 2)])
            if sum(raw_bytes) & 0xFF != 0:
                raise ValueError(f"Line {line_no}: checksum error in record '{line}'")

            data = bytes.fromhex(data_hex)

            if record_type == 0x00:
                # Data record
                effective_address = linear_base + segment_base + offset
                for i, byte_val in enumerate(data):
                    memory[effective_address + i] = byte_val

            elif record_type == 0x01:
                # End of File record
                break

            elif record_type == 0x02:
                # Extended Segment Address record: data is 16-bit segment << 4
                if len(data) != 2:
                    raise ValueError(f"Line {line_no}: invalid type 02 length {len(data)}")
                segment_base = (int.from_bytes(data, byteorder="big")) << 4

            elif record_type == 0x04:
                # Extended Linear Address record: data is upper 16 bits of address
                if len(data) != 2:
                    raise ValueError(f"Line {line_no}: invalid type 04 length {len(data)}")
                linear_base = (int.from_bytes(data, byteorder="big")) << 16

            elif record_type == 0x10:
                # Custom BMW EDIABAS block trailer / checksum record
                effective_address = linear_base + segment_base + offset
                trailers.append({
                    "line": line_no,
                    "type": 0x10,
                    "address": f"0x{effective_address:08X}",
                    "address_int": effective_address,
                    "data": data,
                    "data_hex": data.hex().upper(),
                })

            else:
                # Unsupported record type: keep record for audit
                effective_address = linear_base + segment_base + offset
                trailers.append({
                    "line": line_no,
                    "type": record_type,
                    "address": f"0x{effective_address:08X}",
                    "address_int": effective_address,
                    "data": data,
                    "data_hex": data.hex().upper(),
                })

        # Assemble sorted contiguous segments
        segments = cls._build_segments(memory)
        return ParsedHexImage(segments=segments, headers=headers, trailers=trailers)

    @staticmethod
    def _build_segments(memory: Dict[int, int]) -> List[MemorySegment]:
        """Merge individual address bytes into contiguous memory segments."""
        if not memory:
            return []

        sorted_addrs = sorted(memory.keys())
        segments: List[MemorySegment] = []

        seg_start = sorted_addrs[0]
        prev_addr = seg_start
        current_data = bytearray([memory[seg_start]])

        for addr in sorted_addrs[1:]:
            if addr == prev_addr + 1:
                current_data.append(memory[addr])
                prev_addr = addr
            else:
                # Gap detected: finalize previous segment
                segments.append(
                    MemorySegment(
                        start_address=seg_start,
                        end_address=prev_addr + 1,
                        data=bytes(current_data),
                    )
                )
                seg_start = addr
                prev_addr = addr
                current_data = bytearray([memory[addr]])

        # Finalize last segment
        segments.append(
            MemorySegment(
                start_address=seg_start,
                end_address=prev_addr + 1,
                data=bytes(current_data),
            )
        )

        return segments
