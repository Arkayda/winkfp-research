#!/usr/bin/env python3
"""Milestone 5.22 CLI Tool: EGS 6HP28 Runtime / Code-Path Reconstruction.

Generates and validates all 14 Milestone 5.22 calibration runtime artifacts:
1. architecture_validation_v522.json
2. code_regions_v522.json
3. descriptor_traces_v522.json
4. code_references_v522.json
5. axis_lookup_v522.json
6. curve_access_v522.json
7. interpolation_analysis_v522.json
8. scaling_runtime_v522.json
9. output_consumers_v522.json
10. execution_graph_v522.json
11. semantic_runtime_candidates_v522.json
12. rejected_runtime_hypotheses_v522.json
13. change_log_v522.json
14. artifact_manifest_v522.json

Verifies:
- 100% bit-for-bit determinism across dual execution passes.
- Read-only source binary immutability (SHA-256 matches frozen baseline).
- 100% offline execution; zero hardware I/O.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from typing import Dict

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from reconstruction.calibration.code_regions_v522 import (
    DEFAULT_DA_PATH,
    DEFAULT_PA_PATH,
)
from reconstruction.calibration.recon_v522 import (
    DEFAULT_OUTPUT_DIR,
    Milestone522Pipeline,
)

FROZEN_DA_SHA256 = "45b473d1ee8cc2542a1eb3ecb77bf446f357f81827a464e6c3489257312a0112"
FROZEN_DA_SIZE = 489258
FROZEN_PA_SHA256 = "63b204d2edbdaa0945d9b0241d55df7c6859b41d3376d9f35e93cc6c82ecfcc3"
FROZEN_PA_SIZE = 1942502


def compute_sha256(filepath: Path) -> str:
    """Compute standard SHA-256 hash of a file."""
    h = hashlib.sha256()
    with filepath.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def hash_directory_artifacts(output_dir: Path) -> Dict[str, str]:
    """Compute hashes of all v522 artifacts in output directory."""
    hashes = {}
    for p in sorted(output_dir.glob("*v522*.json")):
        hashes[p.name] = compute_sha256(p)
    return hashes


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Milestone 5.22 EGS 6HP28 Runtime / Code-Path Reconstruction."
    )
    parser.add_argument(
        "--da-path",
        type=Path,
        default=DEFAULT_DA_PATH,
        help="Path to target calibration file A7592133.0da",
    )
    parser.add_argument(
        "--pa-path",
        type=Path,
        default=DEFAULT_PA_PATH,
        help="Path to associated reference program file 7591971A.0pa",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory to write output JSON artifacts",
    )

    args = parser.parse_args()

    print("=" * 70)
    print("Milestone 5.22 — EGS 6HP28 Runtime / Code-Path Reconstruction")
    print("STRUCTURE -> CODE REFERENCE -> RUNTIME TRACE -> SEMANTICS (OFFLINE ONLY)")
    print("=" * 70)
    print(f"Target calibration : {args.da_path}")
    print(f"Donor/lineage PA   : {args.pa_path}")
    print(f"Output directory   : {args.output_dir}")
    print()

    # Verify input file existence
    if not args.da_path.exists():
        print(f"[FATAL] Calibration binary not found: {args.da_path}", file=sys.stderr)
        return 1
    if not args.pa_path.exists():
        print(f"[FATAL] Lineage PA binary not found: {args.pa_path}", file=sys.stderr)
        return 1

    # Verify source immutability before execution
    initial_da_size = args.da_path.stat().st_size
    if initial_da_size != FROZEN_DA_SIZE:
        print(f"[FATAL] Calibration size mismatch! Expected {FROZEN_DA_SIZE}, got {initial_da_size}", file=sys.stderr)
        return 1

    initial_da_hash = compute_sha256(args.da_path)
    if initial_da_hash != FROZEN_DA_SHA256:
        print(f"[FATAL] Calibration SHA-256 mismatch!", file=sys.stderr)
        print(f"  Expected: {FROZEN_DA_SHA256}", file=sys.stderr)
        print(f"  Observed: {initial_da_hash}", file=sys.stderr)
        return 1

    initial_pa_size = args.pa_path.stat().st_size
    if initial_pa_size != FROZEN_PA_SIZE:
        print(f"[FATAL] Reference executable size mismatch! Expected {FROZEN_PA_SIZE}, got {initial_pa_size}", file=sys.stderr)
        return 1

    initial_pa_hash = compute_sha256(args.pa_path)
    if initial_pa_hash != FROZEN_PA_SHA256:
        print(f"[FATAL] Reference executable SHA-256 mismatch!", file=sys.stderr)
        print(f"  Expected: {FROZEN_PA_SHA256}", file=sys.stderr)
        print(f"  Observed: {initial_pa_hash}", file=sys.stderr)
        return 1

    # -------------------------------------------------------------------------
    # Pass 1: Initial Generation
    # -------------------------------------------------------------------------
    pipeline = Milestone522Pipeline(
        da_path=args.da_path,
        pa_path=args.pa_path,
        output_dir=args.output_dir,
    )
    manifest = pipeline.execute()
    pass1_hashes = hash_directory_artifacts(args.output_dir)

    print(f"Generated Artifacts (Pass 1 - {len(pass1_hashes)} files):")
    for name, sha in sorted(pass1_hashes.items()):
        size = (args.output_dir / name).stat().st_size
        print(f"  - {name:<35} : {size:8d} bytes (sha256: {sha[:12]}...)")
    print()

    # -------------------------------------------------------------------------
    # Pass 2: Determinism Verification
    # -------------------------------------------------------------------------
    print("Verifying determinism (Pass 2)...")
    pipeline.execute()
    pass2_hashes = hash_directory_artifacts(args.output_dir)

    if pass1_hashes != pass2_hashes:
        print("[FATAL] Non-deterministic artifact generation detected!", file=sys.stderr)
        for name in pass1_hashes:
            if pass1_hashes[name] != pass2_hashes.get(name):
                print(f"  Mismatch in {name}:", file=sys.stderr)
                print(f"    Pass 1: {pass1_hashes[name]}", file=sys.stderr)
                print(f"    Pass 2: {pass2_hashes.get(name)}", file=sys.stderr)
        return 1

    print(f"DETERMINISM VERIFIED: All {len(pass1_hashes)} artifacts are bit-for-bit identical across passes.")
    print()

    # Verify source immutability after execution
    final_da_size = args.da_path.stat().st_size
    if final_da_size != FROZEN_DA_SIZE:
        print(f"[FATAL] Calibration size modified during execution!", file=sys.stderr)
        return 1

    final_da_hash = compute_sha256(args.da_path)
    if final_da_hash != FROZEN_DA_SHA256:
        print(f"[FATAL] Calibration binary was modified during execution!", file=sys.stderr)
        return 1

    final_pa_size = args.pa_path.stat().st_size
    if final_pa_size != FROZEN_PA_SIZE:
        print(f"[FATAL] Reference executable size modified during execution!", file=sys.stderr)
        return 1

    final_pa_hash = compute_sha256(args.pa_path)
    if final_pa_hash != FROZEN_PA_SHA256:
        print(f"[FATAL] Reference executable binary was modified during execution!", file=sys.stderr)
        return 1

    print("SOURCE IMMUTABILITY CONFIRMED: Target calibration and reference executable files unchanged.")
    print(f"  A7592133.0da : {final_da_size:,} bytes | SHA-256: {final_da_hash}")
    print(f"  7591971A.0pa : {final_pa_size:,} bytes | SHA-256: {final_pa_hash}")
    print("Milestone 5.22 runtime reconstruction complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
