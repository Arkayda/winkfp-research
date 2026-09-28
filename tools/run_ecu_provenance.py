#!/usr/bin/env python3
"""CLI runner for Milestone 5.19 Forensic Provenance Resolution.

Strictly offline, read-only, non-destructive provenance generator.
Prohibits hardware access and validates source and trace immutability.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from reconstruction.ecu.provenance import (
    CANONICAL_SOURCE_HASHES,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_SPDATEN_ROOT,
    compute_sha256,
    export_provenance_artifacts,
    verify_source_integrity,
    verify_trace_integrity,
)


def main() -> int:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(
        description="Run offline forensic provenance resolution of ZB 7592132 (Milestone 5.19)."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Destination directory for output JSON artifacts",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Verify existing artifacts without regenerating",
    )

    # Prohibited hardware arguments safety check
    for arg in sys.argv:
        if any(bad in arg.lower() for bad in ["port", "cu.usb", "tty.", "baud", "hw", "k+dcan"]):
            print(f"[FATAL SAFETY VIOLATION] Hardware flag detected: '{arg}'.", file=sys.stderr)
            print("Milestone 5.19 is 100% offline. Zero serial or hardware access is permitted.", file=sys.stderr)
            return 2

    args = parser.parse_args()

    print("=" * 75)
    print("  BMW E60 / M57D30TU2 / ZF 6HP28 FORENSIC PROVENANCE RESOLUTION")
    print("  Milestone 5.19 — Strict Read-Only / Zero Hardware Access")
    print("=" * 75)

    # 1. Pre-flight source hash validation
    print("[+] Validating source file integrity...")
    integrity_results = verify_source_integrity()
    for name, ok in sorted(integrity_results.items()):
        status = "[VERIFIED]" if ok else "[FAILED]"
        print(f"    {name:<15}: {status}")
        if not ok:
            print(f"[FATAL ERROR] Source file integrity failure on {name}!", file=sys.stderr)
            return 1

    # Pre-flight trace integrity
    print("\n[+] Validating frozen hardware trace integrity...")
    trace_results = verify_trace_integrity(PROJECT_ROOT)
    for name, ok in sorted(trace_results.items()):
        status = "[VERIFIED]" if ok else "[FAILED]"
        print(f"    {name:<50}: {status}")
        if not ok:
            print(f"[FATAL ERROR] Hardware trace mutation detected in {name}!", file=sys.stderr)
            return 1

    expected_artifacts = [
        "zb_7592132_provenance.json",
        "egs_6hp28_software_lineage.json",
        "egs_6hp19_6hp26_6hp28_family_matrix.json",
    ]

    if args.verify_only:
        print("\n[+] Verify-only requested. Checking existing artifacts...")
        for artifact in expected_artifacts:
            art_path = args.output_dir / artifact
            if not art_path.is_file():
                print(f"[!] Missing artifact: {art_path}", file=sys.stderr)
                return 1
            print(f"    Artifact present: {artifact} ({art_path.stat().st_size} bytes)")
        print("[+] All artifacts verified.")
        return 0

    # 2. Export artifacts
    print(f"\n[+] Exporting deterministic artifacts to {args.output_dir}...")
    artifacts = export_provenance_artifacts(args.output_dir)
    for filename, path in sorted(artifacts.items()):
        size = path.stat().st_size
        sha = compute_sha256(path)[:16]
        print(f"    {filename:<45}: {size:>6} bytes | SHA256: {sha}...")

    # 3. Post-flight source immutability check
    print("\n[+] Verifying post-flight source immutability...")
    post_integrity = verify_source_integrity()
    assert all(post_integrity.values()), "Post-run source file mutation detected!"
    post_traces = verify_trace_integrity(PROJECT_ROOT)
    assert all(post_traces.values()), "Post-run hardware trace mutation detected!"
    print("    Source files and traces remain 100% bit-for-bit unchanged.")

    print("\n" + "=" * 75)
    print("  PROVENANCE RESOLUTION SUCCESS: 3/3 ARTIFACTS DETERMINISTICALLY GENERATED")
    print("=" * 75)
    return 0


if __name__ == "__main__":
    sys.exit(main())
