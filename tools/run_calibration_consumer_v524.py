#!/usr/bin/env python3
"""Milestone 5.24 CLI Orchestrator: Descriptor Consumer Discovery & Executable Consumer Reconstruction.

Executes Variant 1: Multi-Tier Exhaustive Forensic Scanner & Boundary Tracer.
Scans for executable and data references to MAP_DESC_0001 and canonical targets,
enforces false-positive control, evaluates stop conditions, and emits 8 deterministic JSON artifacts.

Usage:
    python tools/run_calibration_consumer_v524.py [--artifacts-dir artifacts/calibration]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Add repo root to python path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from reconstruction.calibration.code_regions_v522 import (
    DEFAULT_DA_PATH,
    DEFAULT_PA_PATH,
)
from reconstruction.calibration.descriptor_consumer_v524 import (
    reconstruct_descriptor_consumers,
)
from reconstruction.calibration.hex_parser import IntelHexParser


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Milestone 5.24 Descriptor Consumer Discovery & Executable Consumer Reconstruction"
    )
    parser.add_argument(
        "--pa-path",
        type=Path,
        default=DEFAULT_PA_PATH,
        help="Path to 7591971A.0pa binary",
    )
    parser.add_argument(
        "--da-path",
        type=Path,
        default=DEFAULT_DA_PATH,
        help="Path to A7592133.0da binary",
    )
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        default=REPO_ROOT / "artifacts" / "calibration",
        help="Directory to write generated v524 artifacts",
    )
    args = parser.parse_args()

    print("========================================================================")
    print("  Milestone 5.24 — Descriptor Consumer Discovery & Code-Path Tracer")
    print("  Target: BMW E60 / M57D30TU2 / ZF 6HP28 (GKE195 / GS19.11)")
    print("  Mode: 100% Offline Forensic Reverse-Engineering | Zero Hardware I/O")
    print("========================================================================")

    pa_path = args.pa_path if args.pa_path.exists() else Path("spdaten_gke/E60/data/GKE215/7591971A.0pa")
    da_path = args.da_path if args.da_path.exists() else Path("spdaten_gke/E60/data/GKE195/A7592133.0da")

    if not pa_path.exists() or not da_path.exists():
        print(f"[!] Error: Binaries not found at {pa_path} or {da_path}")
        return 1

    print(f"[*] Parsing Base Program: {pa_path}")
    pa_image = IntelHexParser.parse_file(pa_path)
    print(f"    Loaded {pa_image.total_bytes:,} bytes across {len(pa_image.segments)} segments.")

    print(f"[*] Parsing Calibration Image: {da_path}")
    da_image = IntelHexParser.parse_file(da_path)
    print(f"    Loaded {da_image.total_bytes:,} bytes across {len(da_image.segments)} segments.")

    print("[*] Executing Multi-Tier Exhaustive Forensic Scanner...")
    catalog = reconstruct_descriptor_consumers(pa_image, da_image)

    cov = catalog.coverage
    print(f"    Scanned Executable Segments: {cov['scanned_executable_segments']}")
    print(f"    Scanned Data Segments:       {cov['scanned_data_segments']}")
    print(f"    Instruction Classes:         {len(cov['instruction_reference_classes'])} classes")
    print(f"    Data Reference Classes:      {len(cov['data_reference_classes'])} classes")

    print("\n[*] Canonical Target Resolution:")
    for tid, t in sorted(catalog.canonical_targets.items()):
        print(f"    {tid:22s} -> {t['start_address']}..{t['end_address']} ({t['span_bytes']}B, {t['element_count']} pts, {t['data_type']})")

    print("\n[*] Candidate References Found:")
    print(f"    Total Evaluated: {len(catalog.candidate_references) + len(catalog.rejected_candidates)}")
    print(f"    Data References: {len([c for c in catalog.candidate_references if c.reference_kind == 'DATA_REFERENCE'])}")
    print(f"    Executable References: {len([c for c in catalog.candidate_references if c.reference_kind == 'EXECUTABLE_REFERENCE'])}")
    print(f"    Rejected Candidates:   {len(catalog.rejected_candidates)}")

    for r in catalog.rejected_candidates:
        print(f"    [REJECTED] {r.candidate_address or r.source_address}: {r.rejection_class} ({r.evidence_reason[:60]}...)")

    print("\n[*] Secondary Structure Candidates:")
    for s in catalog.secondary_structure_candidates:
        print(f"    [SECONDARY] {s.candidate_address} ({s.source_file}): {s.structural_role} -> {s.mapped_target}")

    print("\n[*] Code Candidate 0x00086000 Status:")
    bb = catalog.code_candidate_0001
    print(f"    Classification:      {bb['classification']}")
    print(f"    Procedure Identity:  {bb['procedure_identity']}")
    print(f"    Function Entry:      {bb['function_entry']}")
    print(f"    Verified Callers:    {bb['verified_callers']}")

    print("\n[*] Stop Condition Resolution:")
    stop = catalog.stop_condition
    print(f"    Case Result:     {stop['case_result']}")
    print(f"    Forensic Status: {stop['forensic_status']}")
    print(f"    Confidence:      {stop['confidence']}")

    print(f"\n[*] Emitting 8 Deterministic Artifacts to {args.artifacts_dir}...")
    emitted = catalog.emit_artifacts(args.artifacts_dir)
    for p in emitted:
        print(f"    - {p.name}")

    print("\n[+] Milestone 5.24 Consumer Discovery Pipeline Completed Successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
