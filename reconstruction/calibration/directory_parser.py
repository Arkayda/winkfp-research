"""Calibration Object Directory Parser for BMW ZF GS19.11 Mechatronics (Milestone 5.20).

Parses the 9,176-entry 32-bit Big-Endian pointer directory table in Segment 4
(0x00076000 - 0x0007EF60) of A7592133.0da and maps exact object boundaries,
lengths, types, and geometries across Segments 1, 2, and 3.

Pure offline analysis. Zero hardware I/O.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from reconstruction.calibration.hex_parser import MemorySegment, ParsedHexImage


@dataclass
class ExtractedCalibrationObject:
    """A calibration entity defined by an entry in the master directory pointer table."""

    index: int
    directory_address: int  # Address in Segment 4 where pointer is stored
    target_address: int     # Address in Segments 1, 2, or 3 where data resides
    length: int             # Length in bytes
    data: bytes             # Raw byte payload
    object_type: str        # 'SCALAR', 'AXIS', 'TABLE_2D', 'CURVE_1D', 'DATA_BLOCK'
    width_bits: int         # 8, 16, 32
    endianness: str         # 'big', 'little', 'none'
    dimensions: List[int]   # [] for scalar, [N] for 1D, [Nx, Ny] for 2D
    is_monotonic: bool      # True if sequence is strictly increasing
    values: List[int] = field(default_factory=list)

    @property
    def element_count(self) -> int:
        if self.values:
            return len(self.values)
        if self.dimensions:
            count = 1
            for d in self.dimensions:
                count *= d
            return count
        return 1 if self.object_type == "SCALAR" else 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dimensions": self.dimensions,
            "directory_address": f"0x{self.directory_address:08X}",
            "element_count": self.element_count,
            "endianness": self.endianness,
            "id": f"CAL_OBJ_{self.index:04d}",
            "is_monotonic": self.is_monotonic,
            "length": self.length,
            "object_type": self.object_type,
            "raw_hex": self.data.hex(),
            "target_address": f"0x{self.target_address:08X}",
            "values": self.values[:32],  # truncate large tables in summary
            "width_bits": self.width_bits,
        }


class CalibrationDirectoryParser:
    """Parser for Segment 4 master pointer directory in A7592133.0da."""

    DIRECTORY_START = 0x00076000
    DIRECTORY_END = 0x0007EF60

    COMMON_2D_GRID_SIZES = [
        (10, 13),  # 130 elements (260 bytes @ 16-bit)
        (6, 6),    # 36 elements (72 bytes @ 16-bit)
        (8, 8),    # 64 elements (128 bytes @ 16-bit)
        (8, 12),   # 96 elements (192 bytes @ 16-bit)
        (12, 8),   # 96 elements
        (16, 16),  # 256 elements (512 bytes @ 16-bit)
        (14, 14),  # 196 elements (392 bytes @ 16-bit)
        (10, 10),  # 100 elements (200 bytes @ 16-bit)
        (6, 12),   # 72 elements (144 bytes @ 16-bit)
        (12, 6),   # 72 elements
        (4, 4),    # 16 elements (32 bytes @ 16-bit)
        (8, 6),    # 48 elements (96 bytes @ 16-bit)
        (6, 8),    # 48 elements
        (10, 8),   # 80 elements (160 bytes @ 16-bit)
        (8, 10),   # 80 elements
        (16, 8),   # 128 elements (256 bytes @ 16-bit)
        (8, 16),   # 128 elements
        (13, 10),  # 130 elements
        (10, 39),  # 390 elements (780 bytes @ 16-bit, e.g. 3x 10x13)
        (6, 65),   # 390 elements
    ]

    def __init__(self, image: ParsedHexImage) -> None:
        self.image = image
        self.segments_by_addr = {s.start_address: s for s in image.segments}
        self.raw_pointers: List[int] = []
        self._extract_directory_pointers()

    def _extract_directory_pointers(self) -> None:
        """Extract all 32-bit BE pointers from Segment 4."""
        seg4 = next((s for s in self.image.segments if s.start_address == self.DIRECTORY_START), None)
        if not seg4:
            raise ValueError(f"Directory segment at 0x{self.DIRECTORY_START:08X} not found.")

        data = seg4.data
        count = len(data) // 4
        self.raw_pointers = [struct.unpack(">I", data[i * 4 : (i + 1) * 4])[0] for i in range(count)]

    def _get_bytes_at(self, address: int, length: int) -> Optional[bytes]:
        """Retrieve raw bytes from whichever segment encompasses the address range."""
        for seg in self.image.segments:
            if seg.start_address <= address < seg.end_address:
                offset = address - seg.start_address
                if offset + length <= len(seg.data):
                    return seg.data[offset : offset + length]
                # If length spans beyond segment boundary, truncate to segment end
                available = len(seg.data) - offset
                return seg.data[offset : offset + available]
        return None

    def parse_objects(self) -> List[ExtractedCalibrationObject]:
        """Extract and structurally classify all objects indexed by the directory table."""
        objects: List[ExtractedCalibrationObject] = []
        n_ptrs = len(self.raw_pointers)

        for i in range(n_ptrs):
            ptr = self.raw_pointers[i]
            dir_addr = self.DIRECTORY_START + i * 4

            # Determine length from distance to next higher pointer
            # In pointer tables, consecutive entries point to consecutive objects.
            # If the next pointer is greater, length is next_ptr - ptr.
            length = 0
            if i < n_ptrs - 1:
                next_ptr = self.raw_pointers[i + 1]
                if next_ptr > ptr:
                    length = next_ptr - ptr

            if length == 0 or length > 8192:
                # Look forward for the next distinct valid pointer > ptr
                for j in range(i + 1, min(i + 16, n_ptrs)):
                    future_ptr = self.raw_pointers[j]
                    if future_ptr > ptr:
                        candidate_len = future_ptr - ptr
                        if candidate_len <= 8192:
                            length = candidate_len
                            break
                if length == 0:
                    length = 2  # default fallback minimum word size

            raw = self._get_bytes_at(ptr, length)
            if not raw or len(raw) == 0:
                continue

            # Classify object
            obj = self._classify_object(index=i, dir_addr=dir_addr, target_addr=ptr, data=raw)
            objects.append(obj)

        return objects

    def _classify_object(
        self, index: int, dir_addr: int, target_addr: int, data: bytes
    ) -> ExtractedCalibrationObject:
        """Classify object structure into SCALAR, AXIS, TABLE_2D, CURVE_1D, or DATA_BLOCK."""
        length = len(data)

        # 1. Scalars
        if length == 1:
            val = data[0]
            return ExtractedCalibrationObject(
                index=index,
                directory_address=dir_addr,
                target_address=target_addr,
                length=1,
                data=data,
                object_type="SCALAR",
                width_bits=8,
                endianness="none",
                dimensions=[],
                is_monotonic=False,
                values=[val],
            )
        elif length == 2:
            val_be = struct.unpack(">H", data)[0]
            return ExtractedCalibrationObject(
                index=index,
                directory_address=dir_addr,
                target_address=target_addr,
                length=2,
                data=data,
                object_type="SCALAR",
                width_bits=16,
                endianness="big",
                dimensions=[],
                is_monotonic=False,
                values=[val_be],
            )
        elif length == 4:
            val_be = struct.unpack(">I", data)[0]
            return ExtractedCalibrationObject(
                index=index,
                directory_address=dir_addr,
                target_address=target_addr,
                length=4,
                data=data,
                object_type="SCALAR",
                width_bits=32,
                endianness="big",
                dimensions=[],
                is_monotonic=False,
                values=[val_be],
            )

        # 2. Check for Monotonic Breakpoint Axis (8-bit or 16-bit BE/LE/signed)
        if 4 <= length <= 64:
            # Check 8-bit unsigned monotonic (strictly or weakly increasing with >= 3 distinct points)
            bytes_val = list(data)
            if all(bytes_val[k] <= bytes_val[k + 1] for k in range(length - 1)) and len(set(bytes_val)) >= 3:
                return ExtractedCalibrationObject(
                    index=index,
                    directory_address=dir_addr,
                    target_address=target_addr,
                    length=length,
                    data=data,
                    object_type="AXIS",
                    width_bits=8,
                    endianness="none",
                    dimensions=[length],
                    is_monotonic=True,
                    values=bytes_val,
                )

            # Check 16-bit Big-Endian monotonic
            if length % 2 == 0 and length >= 8:
                n_elems = length // 2
                words_be = [struct.unpack(">H", data[k * 2 : (k + 1) * 2])[0] for k in range(n_elems)]
                if all(words_be[k] <= words_be[k + 1] for k in range(n_elems - 1)) and len(set(words_be)) >= 3:
                    return ExtractedCalibrationObject(
                        index=index,
                        directory_address=dir_addr,
                        target_address=target_addr,
                        length=length,
                        data=data,
                        object_type="AXIS",
                        width_bits=16,
                        endianness="big",
                        dimensions=[n_elems],
                        is_monotonic=True,
                        values=words_be,
                    )

                # Check 16-bit signed Big-Endian monotonic (e.g. temperatures)
                swords_be = [struct.unpack(">h", data[k * 2 : (k + 1) * 2])[0] for k in range(n_elems)]
                if all(swords_be[k] <= swords_be[k + 1] for k in range(n_elems - 1)) and len(set(swords_be)) >= 3:
                    return ExtractedCalibrationObject(
                        index=index,
                        directory_address=dir_addr,
                        target_address=target_addr,
                        length=length,
                        data=data,
                        object_type="AXIS",
                        width_bits=16,
                        endianness="big",
                        dimensions=[n_elems],
                        is_monotonic=True,
                        values=swords_be,
                    )

        # 3. Check for 2D Calibration Table (matching common grid sizes)
        # Check 16-bit grid
        if length % 2 == 0:
            total_16 = length // 2
            for nx, ny in self.COMMON_2D_GRID_SIZES:
                if nx * ny == total_16:
                    words = [struct.unpack(">H", data[k * 2 : (k + 1) * 2])[0] for k in range(total_16)]
                    return ExtractedCalibrationObject(
                        index=index,
                        directory_address=dir_addr,
                        target_address=target_addr,
                        length=length,
                        data=data,
                        object_type="TABLE_2D",
                        width_bits=16,
                        endianness="big",
                        dimensions=[nx, ny],
                        is_monotonic=False,
                        values=words,
                    )

        # Check 8-bit grid
        for nx, ny in self.COMMON_2D_GRID_SIZES:
            if nx * ny == length:
                return ExtractedCalibrationObject(
                    index=index,
                    directory_address=dir_addr,
                    target_address=target_addr,
                    length=length,
                    data=data,
                    object_type="TABLE_2D",
                    width_bits=8,
                    endianness="none",
                    dimensions=[nx, ny],
                    is_monotonic=False,
                    values=list(data),
                )

        # 4. 1D Characteristic Curve
        if length % 2 == 0 and length <= 128:
            n_elems = length // 2
            words = [struct.unpack(">H", data[k * 2 : (k + 1) * 2])[0] for k in range(n_elems)]
            return ExtractedCalibrationObject(
                index=index,
                directory_address=dir_addr,
                target_address=target_addr,
                length=length,
                data=data,
                object_type="CURVE_1D",
                width_bits=16,
                endianness="big",
                dimensions=[n_elems],
                is_monotonic=False,
                values=words,
            )

        # 5. Default generic Data Block
        return ExtractedCalibrationObject(
            index=index,
            directory_address=dir_addr,
            target_address=target_addr,
            length=length,
            data=data,
            object_type="DATA_BLOCK",
            width_bits=8,
            endianness="none",
            dimensions=[length],
            is_monotonic=False,
            values=list(data[:32]),
        )
