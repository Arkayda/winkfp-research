#!/usr/bin/env python3
"""CLI Runner for Milestone 5.20 Calibration Map Reconstruction.

Executes complete offline reconstruction of A7592133.0da calibration artifacts:
- Generates all 8 deterministic JSON artifacts in artifacts/calibration/
- Verifies bit-for-bit determinism across repeated executions
- Enforces strict hardware interlocks (zero hardware I/O)
- Audits pre-flight and post-flight source immutability
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from reconstruction.calibration.recon_v520 import (
    DEFAULT_DA_PATH,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_PA_PATH,
    CalibrationReconstructionV520,
)

FROZEN_DA_SHA256 = "45b473d1ee8cc2542a1eb3ecb77bf446f357f81827a464e6c3489257312a0112"


def verify_source_integrity(da_path: Path) -> None:
    """Verify source calibration file is bit-for-bit identical to frozen baseline."""
    if not da_path.exists():
        raise FileNotFoundError(f"Target calibration artifact not found: {da_path}")
    digest = hashlib.sha256(da_path.read_bytes()).hexdigest()
    if digest != FROZEN_DA_SHA256:
        raise ValueError(
            f"SOURCE MUTATION DETECTED! Expected SHA-256 {FROZEN_DA_SHA256}, got {digest}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Milestone 5.20 Calibration Map Reconstruction Runner"
    )
    parser.add_argument(
        "--da-path",
        type=Path,
        default=DEFAULT_DA_PATH,
        help="Path to target A7592133.0da calibration file",
    )
    parser.add_argument(
        "--pa-path",
        type=Path,
        default=DEFAULT_PA_PATH,
        help="Path to donor/lineage 7591971A.0pa program file",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Output directory for generated JSON artifacts",
    )
    parser.add_argument(
        "--verify-determinism",
        action="store_true",
        default=True,
        help="Verify bit-for-bit determinism across repeated executions",
    )
    args = parser.parse_args()

    # Pre-flight check: Source immutability
    verify_source_integrity(args.da_path)

    print("=" * 70)
    print("Milestone 5.20 — EGS 6HP28 Calibration Map Reconstruction")
    print("STRUCTURE FIRST. SEMANTICS SECOND. (100% OFFLINE / ZERO HARDWARE)")
    print("=" * 70)
    print(f"Target calibration : {args.da_path}")
    print(f"Donor/lineage PA   : {args.pa_path}")
    print(f"Output directory   : {args.output_dir}")
    print()

    # Pass 1: Reconstruction
    orchestrator = CalibrationReconstructionV520(
        da_path=args.da_path,
        pa_path=args.pa_path,
        output_dir=args.output_dir,
    )
    artifacts = orchestrator.run_all()

    hashes_pass1 = {}
    print("Generated Artifacts (Pass 1):")
    for name, path in sorted(artifacts.items()):
        content = path.read_bytes()
        h = hashlib.sha256(content).hexdigest()
        hashes_pass1[name] = h
        print(f"  - {path.name:32s} : {len(content):7d} bytes (sha256: {h[:12]}...)")
    print()

    # Determinism verification (Pass 2)
    if args.verify_determinism:
        print("Verifying determinism (Pass 2)...")
        orchestrator_pass2 = CalibrationReconstructionV520(
            da_path=args.da_path,
            pa_path=args.pa_path,
            output_dir=args.output_dir,
        )
        artifacts_pass2 = orchestrator_pass2.run_all()
        for name, path in sorted(artifacts_pass2.items()):
            content = path.read_bytes()
            h2 = hashlib.sha256(content).hexdigest()
            h1 = hashes_pass1[name]
            if h1 != h2:
                print(f"ERROR: Non-deterministic output in {path.name}!")
                print(f"Pass 1: {h1}")
                print(f"Pass 2: {h2}")
                return 1
        print("DETERMINISM VERIFIED: All 8 artifacts are bit-for-bit identical across passes.")
        print()

    # Post-flight check: Source immutability
    verify_source_integrity(args.da_path)
    print("SOURCE IMMUTABILITY CONFIRMED: Target calibration file unchanged.")
    print("Milestone 5.20 reconstruction complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
