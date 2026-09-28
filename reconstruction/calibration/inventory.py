"""Flash Inventory and Layout Scanner for BMW E60 / GKE195 binaries.

Constructs deterministic inventories and memory segment layouts from SP-Daten artifacts.
Provides provenance tracking and address range classification.
Strictly offline and deterministic.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from reconstruction.calibration.hex_parser import MemorySegment, ParsedHexImage


@dataclass(frozen=True)
class FlashArtifact:
    """Metadata describing an analyzed flash artifact."""

    filename: str
    sha256: str
    size_bytes: int
    ecu_family: str
    artifact_type: str  # calibration, program, assembly_table, synthetic
    format: str         # intel_hex_bmw, text_dat, raw_binary
    provenance: str     # [C], [O], [R], [U]
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Deterministic dictionary representation."""
        return {
            "filename": self.filename,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "ecu_family": self.ecu_family,
            "artifact_type": self.artifact_type,
            "format": self.format,
            "provenance": self.provenance,
            "references": sorted(self.references),
        }


@dataclass(frozen=True)
class MemorySegmentLayout:
    """Classified memory range in flash binary."""

    start_address: str
    end_address: str
    start_int: int
    end_int: int
    size_bytes: int
    classification: str  # code, constants, calibration_data, metadata_header, trailer, rsa_signature, padding
    evidence_class: str  # [C], [O], [R], [U]
    description: str
    endianness: str      # little_endian, big_endian, mixed, not_applicable

    def to_dict(self) -> Dict[str, Any]:
        """Deterministic dictionary representation."""
        return {
            "start_address": self.start_address,
            "end_address": self.end_address,
            "start_int": self.start_int,
            "end_int": self.end_int,
            "size_bytes": self.size_bytes,
            "classification": self.classification,
            "evidence_class": self.evidence_class,
            "description": self.description,
            "endianness": self.endianness,
        }


def compute_sha256(filepath: Union[str, Path]) -> str:
    """Compute hex SHA-256 hash of file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().lower()


def build_flash_inventory(source_files: Dict[str, Union[Path, str]]) -> Dict[str, Any]:
    """Build machine-readable inventory of analyzed flash artifacts."""
    artifacts: List[Dict[str, Any]] = []

    # Sort keys for determinism
    for role in sorted(source_files.keys()):
        raw_path = source_files[role]
        path = Path(raw_path)
        if not path.is_file():
            continue

        filename = path.name
        file_sha256 = compute_sha256(path)
        file_size = path.stat().st_size

        # Infer ECU family, format, and references
        ecu_family = "UNKNOWN"
        artifact_type = "unknown"
        format_type = "unknown"
        provenance = "[U]"
        references: List[str] = []

        if filename.endswith(".0da") or filename.endswith(".0DA"):
            format_type = "intel_hex_bmw"
            artifact_type = "calibration"
            provenance = "[C]"
            if "GKE195" in str(path) or "195" in filename:
                ecu_family = "GKE195"
            elif "GKE215" in str(path) or "215" in filename:
                ecu_family = "GKE215"
            else:
                ecu_family = "GKE195"

            if filename == "A7592133.0da":
                references.extend([
                    "0479S90T641Z1ZY02",
                    "ZB 7592132",
                    "HW 7591972",
                    "SW 7592133DA",
                    "E60 M57D30TU2",
                ])

        elif filename.endswith(".0pa") or filename.endswith(".0PA"):
            format_type = "intel_hex_bmw"
            artifact_type = "program"
            provenance = "[C]"
            if "GKE215" in str(path) or "7591971" in filename:
                ecu_family = "GKE215/GKE195"
            else:
                ecu_family = "GKE"

            if "7591971" in filename:
                references.extend([
                    "0479SA0T641Z",
                    "SW 7591971A",
                    "GS19.11 6HP19/TÜ",
                ])

        elif filename.endswith(".DAT") or filename.endswith(".dat"):
            format_type = "text_dat"
            artifact_type = "assembly_table"
            provenance = "[C]"
            if "GKE195" in filename:
                ecu_family = "GKE195"
                references.extend([
                    "ZB 7592132 -> HW 7591972 + SW 7592133DA",
                ])

        elif filename.endswith(".bin"):
            format_type = "raw_binary"
            artifact_type = "synthetic"
            provenance = "[R]"
            ecu_family = "SYNTHETIC"
            references.append("test_synthetic_fixture")

        artifact = FlashArtifact(
            filename=filename,
            sha256=file_sha256,
            size_bytes=file_size,
            ecu_family=ecu_family,
            artifact_type=artifact_type,
            format=format_type,
            provenance=provenance,
            references=references,
        )
        artifacts.append(artifact.to_dict())

    return {
        "title": "BMW E60 GKE195 Flash Image and Calibration Inventory",
        "provenance_policy": "Strict provenance: [C]=Directly Established, [O]=Observed Binary, [R]=Reconstructed, [U]=Unknown",
        "total_analyzed": len(artifacts),
        "artifacts": artifacts,
    }


def classify_calibration_segment(seg: MemorySegment) -> MemorySegmentLayout:
    """Classify a memory segment from a GKE195 calibration binary."""
    start = seg.start_address
    end = seg.end_address
    size = seg.size

    if start == 0x00050000 and size <= 132:
        return MemorySegmentLayout(
            start_address=f"0x{start:08X}",
            end_address=f"0x{end:08X}",
            start_int=start,
            end_int=end,
            size_bytes=size,
            classification="rsa_signature",
            evidence_class="[C]",
            description="RSA cryptographic signature / header block for calibration payload",
            endianness="big_endian",
        )
    elif start >= 0x000500A0 and end <= 0x00050200:
        return MemorySegmentLayout(
            start_address=f"0x{start:08X}",
            end_address=f"0x{end:08X}",
            start_int=start,
            end_int=end,
            size_bytes=size,
            classification="metadata_header",
            evidence_class="[C]",
            description="Calibration metadata header ($REFERENZ, block descriptors, CARB CVN)",
            endianness="mixed",
        )
    elif 0x00050000 <= start < 0x00076000:
        return MemorySegmentLayout(
            start_address=f"0x{start:08X}",
            end_address=f"0x{end:08X}",
            start_int=start,
            end_int=end,
            size_bytes=size,
            classification="calibration_data",
            evidence_class="[O]",
            description="Primary calibration dataset: lookup tables, monotonic axes, and characteristic maps",
            endianness="little_endian",
        )
    elif 0x00076000 <= start < 0x0007FF00:
        return MemorySegmentLayout(
            start_address=f"0x{start:08X}",
            end_address=f"0x{end:08X}",
            start_int=start,
            end_int=end,
            size_bytes=size,
            classification="calibration_data",
            evidence_class="[O]",
            description="Secondary calibration dataset: shift characteristics and application curves",
            endianness="little_endian",
        )
    elif start >= 0x0007FF00:
        return MemorySegmentLayout(
            start_address=f"0x{start:08X}",
            end_address=f"0x{end:08X}",
            start_int=start,
            end_int=end,
            size_bytes=size,
            classification="trailer",
            evidence_class="[O]",
            description="Calibration trailer block: segment end descriptors and block checksums",
            endianness="little_endian",
        )
    else:
        return MemorySegmentLayout(
            start_address=f"0x{start:08X}",
            end_address=f"0x{end:08X}",
            start_int=start,
            end_int=end,
            size_bytes=size,
            classification="calibration_data",
            evidence_class="[R]",
            description="Generic calibration data segment",
            endianness="unknown",
        )


def classify_program_segment(seg: MemorySegment) -> MemorySegmentLayout:
    """Classify a memory segment from a GKE195/GKE215 program binary."""
    start = seg.start_address
    end = seg.end_address
    size = seg.size

    if start == 0x00000000 and end <= 0x00010000:
        return MemorySegmentLayout(
            start_address=f"0x{start:08X}",
            end_address=f"0x{end:08X}",
            start_int=start,
            end_int=end,
            size_bytes=size,
            classification="code",
            evidence_class="[O]",
            description="Infineon TriCore / C167 interrupt vector table and bootstrap code",
            endianness="little_endian",
        )
    elif start < 0x00050000:
        return MemorySegmentLayout(
            start_address=f"0x{start:08X}",
            end_address=f"0x{end:08X}",
            start_int=start,
            end_int=end,
            size_bytes=size,
            classification="code",
            evidence_class="[O]",
            description="Firmware program routines, communication stacks, and operating system logic",
            endianness="little_endian",
        )
    else:
        return MemorySegmentLayout(
            start_address=f"0x{start:08X}",
            end_address=f"0x{end:08X}",
            start_int=start,
            end_int=end,
            size_bytes=size,
            classification="constants",
            evidence_class="[O]",
            description="Program flash constants and default calibration values",
            endianness="little_endian",
        )


def build_flash_layout(images: Dict[str, ParsedHexImage]) -> Dict[str, Any]:
    """Build structural layout mapping address ranges to classifications."""
    layout: Dict[str, Any] = {"images": {}}

    for name in sorted(images.keys()):
        image = images[name]
        is_program = name.endswith(".0pa") or name.endswith(".0PA")

        image_segments: List[Dict[str, Any]] = []
        for seg in image.segments:
            if is_program:
                classified = classify_program_segment(seg)
            else:
                classified = classify_calibration_segment(seg)
            image_segments.append(classified.to_dict())

        layout["images"][name] = {
            "total_segments": len(image_segments),
            "total_payload_bytes": image.total_bytes,
            "segments": image_segments,
        }

    return layout
