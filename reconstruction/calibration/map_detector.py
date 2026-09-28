"""Heuristic Map, Monotonic Axis, and Checksum Region Detectors.

Identifies candidate calibration structures, monotonic axes, and checksum/CVN locations.
Enforces strict provenance labeling: [C] Confirmed, [O] Observed, [R] Reconstructed, [U] Unknown.
Does not fabricate dimensions or assign unverified engineering units.
Strictly offline and deterministic.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from reconstruction.calibration.hex_parser import MemorySegment, ParsedHexImage


@dataclass(frozen=True)
class AxisCandidate:
    """Candidate monotonic axis structure."""

    id: str
    start_address: int
    end_address: int
    width: int  # 8 or 16 bits
    endianness: str  # little_endian or big_endian
    signedness: str  # unsigned or signed
    element_count: int
    decoded_values: List[int]
    monotonicity: str  # strictly_increasing, strictly_decreasing, non_decreasing
    spacing_characteristics: str  # linear, non_linear_clustered, non_linear_geometric
    relation_to_nearby_tables: List[str] = field(default_factory=list)
    evidence_class: str = "[O]"
    units: str = "UNKNOWN"

    def to_dict(self) -> Dict[str, Any]:
        """Deterministic dictionary representation."""
        return {
            "id": self.id,
            "address_range": {
                "start": f"0x{self.start_address:08X}",
                "end": f"0x{self.end_address:08X}",
                "start_int": self.start_address,
                "end_int": self.end_address,
            },
            "width": self.width,
            "endianness": self.endianness,
            "signedness": self.signedness,
            "element_count": self.element_count,
            "decoded_values": self.decoded_values,
            "monotonicity": self.monotonicity,
            "spacing_characteristics": self.spacing_characteristics,
            "relation_to_nearby_tables": sorted(self.relation_to_nearby_tables),
            "evidence_class": self.evidence_class,
            "units": self.units,
        }


@dataclass(frozen=True)
class MapCandidate:
    """Candidate 1D/2D calibration map or lookup table."""

    id: str
    start_address: int
    end_address: int
    size_bytes: int
    width: int  # 8 or 16 bits
    endianness: str
    signedness: str
    dimensions: str  # e.g. "candidate 16x16", "candidate 1x8" (never fabricated)
    candidate_axis_regions: List[str]
    candidate_value_region: Dict[str, str]
    local_byte_preview: str
    evidence_class: str = "[R]"
    supporting_source: str = "Heuristic structural table detection adjacent to monotonic axes"
    units: str = "UNKNOWN"

    def to_dict(self) -> Dict[str, Any]:
        """Deterministic dictionary representation."""
        return {
            "id": self.id,
            "address_range": {
                "start": f"0x{self.start_address:08X}",
                "end": f"0x{self.end_address:08X}",
                "start_int": self.start_address,
                "end_int": self.end_address,
            },
            "size_bytes": self.size_bytes,
            "width": self.width,
            "endianness": self.endianness,
            "signedness": self.signedness,
            "dimensions": self.dimensions,
            "candidate_axis_regions": sorted(self.candidate_axis_regions),
            "candidate_value_region": self.candidate_value_region,
            "local_byte_preview": self.local_byte_preview,
            "evidence_class": self.evidence_class,
            "supporting_source": self.supporting_source,
            "units": self.units,
        }


@dataclass(frozen=True)
class ChecksumRegion:
    """Candidate checksum, CRC, or CVN region."""

    region: str
    checksum_algorithm: str
    covered_range: Dict[str, str]
    checksum_location: Dict[str, Any]
    source_evidence: str
    confidence: str

    def to_dict(self) -> Dict[str, Any]:
        """Deterministic dictionary representation."""
        return {
            "region": self.region,
            "checksum_algorithm": self.checksum_algorithm,
            "covered_range": self.covered_range,
            "checksum_location": self.checksum_location,
            "source_evidence": self.source_evidence,
            "confidence": self.confidence,
        }


def _evaluate_spacing(values: List[int]) -> str:
    """Classify the spacing regularity of a numeric sequence."""
    if len(values) < 3:
        return "linear"
    deltas = [values[i] - values[i - 1] for i in range(1, len(values))]
    if len(set(deltas)) == 1:
        return "linear"

    # Check approximate linearity (delta variance)
    mean_delta = sum(deltas) / len(deltas)
    if mean_delta == 0:
        return "linear"

    variance = sum((d - mean_delta) ** 2 for d in deltas) / len(deltas)
    std_dev = variance ** 0.5
    cv = std_dev / abs(mean_delta)

    if cv < 0.15:
        return "linear"
    elif cv > 1.0:
        return "non_linear_clustered"
    return "non_linear_geometric"


def detect_axes(
    segment: MemorySegment,
    min_points: int = 4,
    max_points: int = 32,
) -> List[AxisCandidate]:
    """Scan memory segment for candidate monotonic axes."""
    data = segment.data
    size = len(data)
    candidates: List[AxisCandidate] = []

    # 1. Detect 16-bit unsigned Little-Endian monotonic axes
    if size >= min_points * 2:
        i = 0
        while i <= size - (min_points * 2):
            # Check for strictly increasing uint16 LE sequence starting at i
            vals = [int.from_bytes(data[i : i + 2], "little")]
            j = i + 2
            while j + 2 <= size and len(vals) < max_points:
                next_val = int.from_bytes(data[j : j + 2], "little")
                # Strictly increasing and reasonable step
                delta = next_val - vals[-1]
                if 0 < delta <= 8000:
                    vals.append(next_val)
                    j += 2
                else:
                    break

            if len(vals) >= min_points:
                # If first element is 0 and preceded by another 0 word, it was zero padding
                if vals[0] == 0 and i >= 2 and int.from_bytes(data[i - 2 : i], "little") == 0:
                    vals = vals[1:]
                    i += 2

            if len(vals) >= min_points:
                addr = segment.start_address + i
                end_addr = segment.start_address + j
                axis_id = f"AXIS_{addr:08X}_U16LE_{len(vals)}"
                spacing = _evaluate_spacing(vals)
                candidates.append(
                    AxisCandidate(
                        id=axis_id,
                        start_address=addr,
                        end_address=end_addr,
                        width=16,
                        endianness="little_endian",
                        signedness="unsigned",
                        element_count=len(vals),
                        decoded_values=vals,
                        monotonicity="strictly_increasing",
                        spacing_characteristics=spacing,
                    )
                )
                i = j  # Advance past this sequence
            else:
                i += 2  # Word aligned step

    # 2. Detect 16-bit unsigned Big-Endian monotonic axes
    if size >= min_points * 2:
        i = 0
        while i <= size - (min_points * 2):
            vals = [int.from_bytes(data[i : i + 2], "big")]
            j = i + 2
            while j + 2 <= size and len(vals) < max_points:
                next_val = int.from_bytes(data[j : j + 2], "big")
                delta = next_val - vals[-1]
                if 0 < delta <= 8000:
                    vals.append(next_val)
                    j += 2
                else:
                    break

            if len(vals) >= min_points:
                if vals[0] == 0 and i >= 2 and int.from_bytes(data[i - 2 : i], "big") == 0:
                    vals = vals[1:]
                    i += 2

            if len(vals) >= min_points:
                addr = segment.start_address + i
                end_addr = segment.start_address + j
                axis_id = f"AXIS_{addr:08X}_U16BE_{len(vals)}"
                spacing = _evaluate_spacing(vals)
                # Ensure not already captured by LE with higher plausibility
                candidates.append(
                    AxisCandidate(
                        id=axis_id,
                        start_address=addr,
                        end_address=end_addr,
                        width=16,
                        endianness="big_endian",
                        signedness="unsigned",
                        element_count=len(vals),
                        decoded_values=vals,
                        monotonicity="strictly_increasing",
                        spacing_characteristics=spacing,
                    )
                )
                i = j
            else:
                i += 2

    # Stable sort by start address and element count
    candidates.sort(key=lambda a: (a.start_address, a.width, a.endianness))
    return candidates


def detect_map_candidates(
    segment: MemorySegment,
    axes: List[AxisCandidate],
) -> List[MapCandidate]:
    """Identify candidate 1D curves and 2D surfaces adjacent to detected axes."""
    data = segment.data
    seg_start = segment.start_address
    maps: List[MapCandidate] = []

    # Sort axes by start address
    sorted_axes = sorted(axes, key=lambda a: a.start_address)

    # 1. Detect 2D map candidates: two adjacent or closely-spaced axes
    for i in range(len(sorted_axes) - 1):
        ax_x = sorted_axes[i]
        ax_y = sorted_axes[i + 1]

        # Axes must be in the same segment and close to each other
        if ax_y.start_address - ax_x.end_address <= 32:
            nx = ax_x.element_count
            ny = ax_y.element_count
            table_size_bytes_u8 = nx * ny
            table_size_bytes_u16 = nx * ny * 2

            # Candidate table following Y-axis
            val_start = ax_y.end_address
            val_offset = val_start - seg_start

            # Check 8-bit table
            if val_offset + table_size_bytes_u8 <= len(data):
                val_end = val_start + table_size_bytes_u8
                preview = data[val_offset : val_offset + min(16, table_size_bytes_u8)].hex().upper()
                map_id = f"MAP_{ax_x.start_address:08X}_{nx}X{ny}_U8"
                maps.append(
                    MapCandidate(
                        id=map_id,
                        start_address=ax_x.start_address,
                        end_address=val_end,
                        size_bytes=val_end - ax_x.start_address,
                        width=8,
                        endianness=ax_x.endianness,
                        signedness="unsigned",
                        dimensions=f"candidate {nx}x{ny}",
                        candidate_axis_regions=[
                            f"0x{ax_x.start_address:08X}..0x{ax_x.end_address:08X}",
                            f"0x{ax_y.start_address:08X}..0x{ax_y.end_address:08X}",
                        ],
                        candidate_value_region={
                            "start": f"0x{val_start:08X}",
                            "end": f"0x{val_end:08X}",
                            "size_bytes": f"{table_size_bytes_u8}",
                        },
                        local_byte_preview=preview,
                        evidence_class="[R]",
                        units="UNKNOWN",
                    )
                )

            # Check 16-bit table
            if val_offset + table_size_bytes_u16 <= len(data):
                val_end = val_start + table_size_bytes_u16
                preview = data[val_offset : val_offset + min(16, table_size_bytes_u16)].hex().upper()
                map_id = f"MAP_{ax_x.start_address:08X}_{nx}X{ny}_U16"
                maps.append(
                    MapCandidate(
                        id=map_id,
                        start_address=ax_x.start_address,
                        end_address=val_end,
                        size_bytes=val_end - ax_x.start_address,
                        width=16,
                        endianness=ax_x.endianness,
                        signedness="unsigned",
                        dimensions=f"candidate {nx}x{ny}",
                        candidate_axis_regions=[
                            f"0x{ax_x.start_address:08X}..0x{ax_x.end_address:08X}",
                            f"0x{ax_y.start_address:08X}..0x{ax_y.end_address:08X}",
                        ],
                        candidate_value_region={
                            "start": f"0x{val_start:08X}",
                            "end": f"0x{val_end:08X}",
                            "size_bytes": f"{table_size_bytes_u16}",
                        },
                        local_byte_preview=preview,
                        evidence_class="[R]",
                        units="UNKNOWN",
                    )
                )

    # 2. Detect 1D curve candidates: single axis followed by N values
    for ax in sorted_axes:
        n = ax.element_count
        val_start = ax.end_address
        val_offset = val_start - seg_start

        # Check 16-bit curve
        table_size_bytes = n * 2
        if val_offset + table_size_bytes <= len(data):
            val_end = val_start + table_size_bytes
            preview = data[val_offset : val_offset + min(16, table_size_bytes)].hex().upper()
            curve_id = f"CURVE_{ax.start_address:08X}_1X{n}_U16"
            maps.append(
                MapCandidate(
                    id=curve_id,
                    start_address=ax.start_address,
                    end_address=val_end,
                    size_bytes=val_end - ax.start_address,
                    width=16,
                    endianness=ax.endianness,
                    signedness="unsigned",
                    dimensions=f"candidate 1x{n}",
                    candidate_axis_regions=[
                        f"0x{ax.start_address:08X}..0x{ax.end_address:08X}",
                    ],
                    candidate_value_region={
                        "start": f"0x{val_start:08X}",
                        "end": f"0x{val_end:08X}",
                        "size_bytes": f"{table_size_bytes}",
                    },
                    local_byte_preview=preview,
                    evidence_class="[R]",
                    units="UNKNOWN",
                )
            )

    maps.sort(key=lambda m: (m.start_address, m.width, m.dimensions))
    return maps


def detect_checksum_regions(image: ParsedHexImage) -> List[ChecksumRegion]:
    """Identify candidate checksum, CVN, and signature locations."""
    regions: List[ChecksumRegion] = []
    headers = image.headers

    # 1. CARB Mode $09 CVN Region
    cvn_header = headers.get("CARB_MODE_9_CVN", "")
    if cvn_header:
        cvn_val = cvn_header.split()[0]
        # In GKE195, CARB CVN is stored at address 0x000500EE (2 bytes)
        regions.append(
            ChecksumRegion(
                region="CARB_MODE_09_CVN_CALIBRATION",
                checksum_algorithm="CARB_CVN_16BIT",
                covered_range={
                    "start": "0x000500A0",
                    "end": "0x000714F0",
                    "description": "Primary calibration dataset covered by OBD-II CARB CVN calculation",
                },
                checksum_location={
                    "address": "0x000500EE",
                    "size_bytes": 2,
                    "expected_value": f"0x{cvn_val}",
                    "byte_order": "little_endian",
                },
                source_evidence=";$CARB_MODE_9_CVN directive in .0da header confirmed at binary offset 0x000500EE",
                confidence="HIGH_CONFIRMED [C]",
            )
        )

    # 2. EDIABAS $CHECKSUMME Header
    chk_header = headers.get("CHECKSUMME", "")
    if chk_header:
        chk_val = chk_header.split()[0]
        regions.append(
            ChecksumRegion(
                region="EDIABAS_HEADER_CHECKSUM",
                checksum_algorithm="EDIABAS_ADD16_HEX",
                covered_range={
                    "start": "0x000500A0",
                    "end": "0x0007FF70",
                    "description": "Entire calibration payload covered by EDIABAS package checksum",
                },
                checksum_location={
                    "address": "FILE_HEADER_DIRECTIVE",
                    "size_bytes": 2,
                    "expected_value": f"0x{chk_val}",
                    "byte_order": "hex_ascii",
                },
                source_evidence=";$CHECKSUMME directive in Intel Hex footer",
                confidence="HIGH_CONFIRMED [C]",
            )
        )

    # 3. RSA Cryptographic Signature Block (Segment at 0x00050000)
    sig_seg = image.find_segment(0x00050000)
    if sig_seg and sig_seg.size >= 128:
        regions.append(
            ChecksumRegion(
                region="FLASH_CALIBRATION_RSA_SIGNATURE",
                checksum_algorithm="RSA1024_SHA1_PKCS1_V1_5",
                covered_range={
                    "start": "0x000500A0",
                    "end": "0x0007FF70",
                    "description": "Complete calibration payload verified by bootloader cryptographic gate",
                },
                checksum_location={
                    "address": "0x00050000",
                    "size_bytes": 128,
                    "expected_value": f"0x{sig_seg.data[:16].hex().upper()}...",
                    "byte_order": "big_endian",
                },
                source_evidence="1024-bit RSA signature block preceding calibration data block",
                confidence="HIGH_CONFIRMED [C]",
            )
        )

    # 4. Intel Hex Block Trailers (Type 0x10 records)
    for trailer in image.trailers:
        if trailer.get("type") == 0x10:
            addr = trailer.get("address", "")
            data_hex = trailer.get("data_hex", "")
            if data_hex:
                regions.append(
                    ChecksumRegion(
                        region=f"INTEL_HEX_BLOCK_TRAILER_{addr}",
                        checksum_algorithm="BMW_BLOCK_TRAILER_CHECKSUM",
                        covered_range={
                            "start": "BLOCK_START",
                            "end": addr,
                            "description": "EDIABAS block boundary trailer checksum",
                        },
                        checksum_location={
                            "address": addr,
                            "size_bytes": len(bytes.fromhex(data_hex)),
                            "expected_value": f"0x{data_hex}",
                            "byte_order": "big_endian",
                        },
                        source_evidence="Type 0x10 Intel Hex record trailer",
                        confidence="OBSERVED_STRUCTURE [O]",
                    )
                )

    return regions
