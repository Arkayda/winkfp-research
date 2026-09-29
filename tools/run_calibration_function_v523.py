#!/usr/bin/env python3
"""Milestone 5.23 CLI Runner — Calibration Function Reconstruction & Engineering Semantics.

Usage:
    .venv/bin/python3 tools/run_calibration_function_v523.py [--output-dir DIR]

Executes the dual-pass deterministic pipeline and generates all 17 artifacts
in artifacts/calibration/. Pure offline execution. Zero hardware I/O.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from reconstruction.calibration.code_regions_v522 import (
    DEFAULT_DA_PATH,
    DEFAULT_PA_PATH,
)
from reconstruction.calibration.recon_v523 import (
    DEFAULT_OUTPUT_DIR,
    Milestone523Pipeline,
)


def verify_source_integrity(da_path: Path, pa_path: Path) -> None:
    """Verify cryptographic hashes of SP-Daten binaries."""
    EXPECTED_DA_SHA = "45b473d1ee8cc2542a1eb3ecb77bf446f357f81827a464e6c3489257312a0112"
    EXPECTED_PA_SHA = "63b204d2edbdaa0945d9b0241d55df7c6859b41d3376d9f35e93cc6c82ecfcc3"
    EXPECTED_DA_SIZE = 489258
    EXPECTED_PA_SIZE = 1942502

    if not da_path.exists():
        sys.exit(f"[FATAL] Target calibration binary not found: {da_path}")
    if not pa_path.exists():
        sys.exit(f"[FATAL] Reference program binary not found: {pa_path}")

    da_bytes = da_path.read_bytes()
    pa_bytes = pa_path.read_bytes()

    da_sha = hashlib.sha256(da_bytes).hexdigest()
    pa_sha = hashlib.sha256(pa_bytes).hexdigest()

    if da_sha != EXPECTED_DA_SHA or len(da_bytes) != EXPECTED_DA_SIZE:
        sys.exit(f"[FATAL] Target calibration checksum mismatch: {da_sha} != {EXPECTED_DA_SHA}")
    if pa_sha != EXPECTED_PA_SHA or len(pa_bytes) != EXPECTED_PA_SIZE:
        sys.exit(f"[FATAL] Reference executable checksum mismatch: {pa_sha} != {EXPECTED_PA_SHA}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Milestone 5.23: EGS 6HP28 Calibration Function Reconstruction"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory to write generated artifacts (default: artifacts/calibration)",
    )
    parser.add_argument(
        "--da-path",
        type=Path,
        default=DEFAULT_DA_PATH,
        help="Path to A7592133.0da",
    )
    parser.add_argument(
        "--pa-path",
        type=Path,
        default=DEFAULT_PA_PATH,
        help="Path to 7591971A.0pa",
    )
    args = parser.parse_args()

    print("=" * 70)
    print("Milestone 5.23 — Calibration Function Reconstruction")
    print("BINARY STRUCTURE -> CODE PATH -> CALFUNC -> SEMANTICS (OFFLINE ONLY)")
    print("=" * 70)
    print(f"Target calibration : {args.da_path}")
    print(f"Donor/lineage PA   : {args.pa_path}")
    print(f"Output directory   : {args.output_dir}")

    # 1. Source integrity check
    verify_source_integrity(args.da_path, args.pa_path)

    # 2. Pass 1: Primary generation into destination
    pipeline1 = Milestone523Pipeline(
        da_path=args.da_path,
        pa_path=args.pa_path,
        output_dir=args.output_dir,
    )
    manifest1 = pipeline1.execute()

    print(f"\nGenerated Artifacts (Pass 1 - {len(manifest1['artifacts']) + 1} files):")
    for art in manifest1["artifacts"]:
        print(f"  - {art['filename']:36s}: {art['size_bytes']:8d} bytes (sha256: {art['sha256'][:12]}...)")

    manifest_file = args.output_dir / "artifact_manifest_v523.json"
    manifest_bytes = manifest_file.read_bytes()
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    print(f"  - {'artifact_manifest_v523.json':36s}: {len(manifest_bytes):8d} bytes (sha256: {manifest_sha[:12]}...)")

    # 3. Pass 2: Determinism verification
    print("\nVerifying determinism (Pass 2)...")
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_out = Path(tmpdir)
        pipeline2 = Milestone523Pipeline(
            da_path=args.da_path,
            pa_path=args.pa_path,
            output_dir=tmp_out,
        )
        pipeline2.execute()

        # Compare all files
        all_expected = [art["filename"] for art in manifest1["artifacts"]] + ["artifact_manifest_v523.json"]
        for fname in all_expected:
            f1 = (args.output_dir / fname).read_bytes()
            f2 = (tmp_out / fname).read_bytes()
            if f1 != f2:
                sys.exit(f"[FATAL] Non-deterministic artifact generation detected in: {fname}")

    print(f"DETERMINISM VERIFIED: All {len(all_expected)} artifacts are bit-for-bit identical across passes.")

    # 4. Source immutability re-check
    verify_source_integrity(args.da_path, args.pa_path)
    print("\nSOURCE IMMUTABILITY CONFIRMED: Target calibration and reference executable files unchanged.")
    print("Milestone 5.23 calibration function reconstruction complete.")


if __name__ == "__main__":
    main()
