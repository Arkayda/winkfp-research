"""Calibration Reconnaissance Orchestrator.

Drives inventory generation, memory layout mapping, candidate map/axis extraction,
and checksum region detection for BMW E60 / GKE195 binaries.
Enforces strict determinism and zero hardware access.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from reconstruction.calibration.hex_parser import IntelHexParser, ParsedHexImage
from reconstruction.calibration.inventory import build_flash_inventory, build_flash_layout
from reconstruction.calibration.map_detector import (
    detect_axes,
    detect_checksum_regions,
    detect_map_candidates,
)

DEFAULT_SPDATEN_ROOT = Path("/Users/blogman/bmw_flash_re/spdaten_gke/E60/data")
DEFAULT_OUTPUT_DIR = Path("artifacts/calibration")


def run_reconnaissance(
    spdaten_root: Optional[Union[str, Path]] = None,
    output_dir: Optional[Union[str, Path]] = None,
) -> Dict[str, Path]:
    """Execute complete offline calibration reconnaissance and write deterministic JSON artifacts."""
    root = Path(spdaten_root) if spdaten_root else DEFAULT_SPDATEN_ROOT
    out = Path(output_dir) if output_dir else DEFAULT_OUTPUT_DIR
    out.mkdir(parents=True, exist_ok=True)

    # 1. Collect all flash artifacts
    gke195_dir = root / "GKE195"
    gke215_dir = root / "GKE215"
    synthetic_bin = Path("tests/fixtures/synthetic/synthetic_image.bin")

    source_files: Dict[str, Path] = {}

    # Primary calibration, base program, assembly table, and synthetic fixture
    primary_da = gke195_dir / "A7592133.0da"
    if primary_da.is_file():
        source_files["01_primary_calibration_A7592133"] = primary_da

    base_pa = gke215_dir / "7591971A.0pa"
    if base_pa.is_file():
        source_files["02_base_program_7591971A"] = base_pa

    dat_file = gke195_dir / "GKE195.DAT"
    if dat_file.is_file():
        source_files["03_assembly_table_GKE195_DAT"] = dat_file

    if synthetic_bin.is_file():
        source_files["04_synthetic_fixture"] = synthetic_bin

    # Sibling calibration files in GKE195
    if gke195_dir.is_dir():
        for sibling in sorted(gke195_dir.glob("*.0da")):
            if sibling.name != "A7592133.0da":
                source_files[f"sibling_{sibling.stem}"] = sibling

    # 2. Build Inventory
    inventory_data = build_flash_inventory(source_files)
    inventory_path = out / "flash_inventory.json"
    _write_deterministic_json(inventory_path, inventory_data)

    # 3. Parse Primary Images
    parsed_images: Dict[str, ParsedHexImage] = {}
    if primary_da.is_file():
        parsed_images["A7592133.0da"] = IntelHexParser.parse_file(primary_da)
    if base_pa.is_file():
        parsed_images["7591971A.0pa"] = IntelHexParser.parse_file(base_pa)

    # 4. Build Layout
    layout_data = build_flash_layout(parsed_images)
    layout_path = out / "flash_layout.json"
    _write_deterministic_json(layout_path, layout_data)

    # 5. Extract Axes, Maps, and Checksums from Primary Calibration
    axes_data: Dict[str, Any] = {"total_axes": 0, "axes": []}
    maps_data: Dict[str, Any] = {"total_map_candidates": 0, "map_candidates": []}
    checksums_data: Dict[str, Any] = {"total_regions": 0, "regions": []}

    if "A7592133.0da" in parsed_images:
        da_image = parsed_images["A7592133.0da"]

        all_axes = []
        all_maps = []
        for seg in da_image.segments:
            # We scan calibration data segments (ignoring the standalone 128B RSA signature at 0x50000)
            if seg.start_address >= 0x000500A0:
                seg_axes = detect_axes(seg)
                seg_maps = detect_map_candidates(seg, seg_axes)
                all_axes.extend(seg_axes)
                all_maps.extend(seg_maps)

        all_checksums = detect_checksum_regions(da_image)

        axes_data = {
            "title": "BMW E60 GKE195 Candidate Monotonic Calibration Axes",
            "provenance_policy": "Strict provenance: [O]=Observed Binary. Units strictly UNKNOWN without external evidence.",
            "total_axes": len(all_axes),
            "axes": [a.to_dict() for a in all_axes],
        }

        maps_data = {
            "title": "BMW E60 GKE195 Candidate Calibration Maps and Tables",
            "provenance_policy": "Strict provenance: [R]=Reconstructed candidate dimensions. Units strictly UNKNOWN.",
            "total_map_candidates": len(all_maps),
            "map_candidates": [m.to_dict() for m in all_maps],
        }

        checksums_data = {
            "title": "BMW E60 GKE195 Checksum, CVN, and Cryptographic Signature Regions",
            "provenance_policy": "Strict provenance: [C]=Directly Confirmed, [O]=Observed Structure.",
            "total_regions": len(all_checksums),
            "regions": [c.to_dict() for c in all_checksums],
        }

    axes_path = out / "axes.json"
    _write_deterministic_json(axes_path, axes_data)

    maps_path = out / "map_candidates.json"
    _write_deterministic_json(maps_path, maps_data)

    checksums_path = out / "checksum_regions.json"
    _write_deterministic_json(checksums_path, checksums_data)

    return {
        "flash_inventory": inventory_path,
        "flash_layout": layout_path,
        "axes": axes_path,
        "map_candidates": maps_path,
        "checksum_regions": checksums_path,
    }


def _write_deterministic_json(path: Path, data: Any) -> None:
    """Serialize data to JSON with sorted keys and trailing newline for deterministic hashing."""
    content = json.dumps(data, indent=2, sort_keys=True) + "\n"
    path.write_text(content, encoding="utf-8")
