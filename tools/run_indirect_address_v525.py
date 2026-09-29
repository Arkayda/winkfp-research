#!/usr/bin/env python3
"""Milestone 5.25 CLI Orchestrator: Indirect Address / Pointer-Chain Forensic Reconstruction.

Executes Approach 2: Modular Forensic Pipeline (Tier A, Tier B, Tier C):
- Evaluates indirect address expressions, displacements, and pointer tables.
- Strictly enforces decoder-based boundary validation without address parity heuristics.
- Separates memory byte retrieval from explicit endian decoding without automatic LD.A => BE assumptions.
- Preserves concrete pointer values through known immediate arithmetic.
- Discriminated target reads (PROVEN consumer) from target writes (UNCONFIRMED consumer).
- Emits 10 deterministic JSON artifacts with non-circular manifest (self_hash_policy: EXCLUDED).

Usage:
    python tools/run_indirect_address_v525.py [--artifacts-dir artifacts/calibration]
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
from reconstruction.calibration.hex_parser import IntelHexParser
from reconstruction.calibration.indirect_address_v525 import (
    reconstruct_indirect_address,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Milestone 5.25 Indirect Address / Pointer-Chain Forensic Reconstruction"
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
        help="Directory to write generated v525 artifacts",
    )
    args = parser.parse_args()

    print("========================================================================")
    print("  Milestone 5.25 — Indirect Address & Pointer-Chain Reconstruction")
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

    print("[*] Executing Modular Forensic Pipeline (Tier A, Tier B, Tier C)...")
    catalog = reconstruct_indirect_address(pa_image, da_image)

    cov = catalog.coverage
    print(f"    Scanned Executable Segments: {cov['scanned_executable_segments']}")
    print(f"    Scanned Data Segments:       {cov['scanned_data_segments']}")
    print(f"    Instruction Classes:         {len(cov['instruction_reference_classes'])} classes")
    print(f"    Address Expression Classes:  {len(cov['address_expression_classes'])} classes")

    print("\n[*] Canonical Target Resolution (Range Semantics: [START, END)):")
    for tid, t in sorted(catalog.canonical_targets.items()):
        print(f"    {tid:22s} -> {t['start_address']}..{t['end_address']} ({t['span_bytes']}B, {t['element_count']} pts, {t['data_type']}) [Seg {t['target_segment']}]")

    print("\n[*] Tier A: Candidate References Evaluated:")
    print(f"    Total Evaluated:        {len(catalog.candidate_references)}")
    print(f"    Descriptor Fields:      {len([c for c in catalog.candidate_references if c.candidate_id.startswith('CAND_DESC_')])}")
    print(f"    Secondary Table Entries:{len([c for c in catalog.candidate_references if c.candidate_id.startswith('CAND_SEC_')])}")
    print(f"    Synthetic Rejections:   {len([c for c in catalog.candidate_references if c.candidate_id.startswith('CAND_SYNTH_')])}")
    print(f"    RAM Offset Collisions:  {len([c for c in catalog.candidate_references if c.candidate_id == 'CAND_RAM_C1A04'])}")

    print("\n[*] Tier B & Tier C: Dynamic Address Resolution:")
    print(f"    Pointer Producers:      {len(catalog.pointer_producers)}")
    print(f"    Pointer Chains:         {len(catalog.pointer_chains)}")
    print(f"    Target Accesses:        {len(catalog.target_accesses)}")
    reads = [a for a in catalog.target_accesses if a.access_direction in ("TARGET_READ", "TARGET_POINTER_READ")]
    writes = [a for a in catalog.target_accesses if a.access_direction == "TARGET_WRITE"]
    print(f"    - Target Reads (PROVEN):{len(reads)}")
    print(f"    - Target Writes (UNCONF):{len(writes)}")

    print("\n[*] Epistemic Status Ceilings:")
    bb = catalog.code_candidate_0001
    print(f"    0x00086000:          {bb['classification']} (procedure_identity: {bb['procedure_identity']}, function_entry: {bb['function_entry']})")
    print("    0x000455xx:          REJECTED_SYNTHETIC_ADDRESS")
    print("    0x000C1A04:          CONSTANT_COLLISION (ST.B into dynamic RAM via %a15)")
    print("    Scalars 750 / 500:   UNCONFIRMED (clamp semantics unproven)")
    print("    Integer 6800:        UNKNOWN / UNCONFIRMED")

    print("\n[*] Stop Condition Resolution:")
    stop = catalog.stop_condition
    print(f"    Case Result:         {stop['case_result']}")
    print(f"    Forensic Status:     {stop['forensic_status']}")
    print(f"    Confidence:          {stop['confidence']}")
    print(f"    Explanation:         {stop['explanation']}")

    print(f"\n[*] Emitting 10 Deterministic Artifacts to {args.artifacts_dir}...")
    emitted = catalog.emit_artifacts(args.artifacts_dir)
    for p in emitted:
        print(f"    - {p.name}")

    print("\n[+] Milestone 5.25 Indirect Address Reconstruction Completed Successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
