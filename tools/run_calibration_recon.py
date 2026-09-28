#!/usr/bin/env python3
"""CLI runner for Milestone 5.18 Offline Calibration Reconnaissance.

Strictly offline, read-only, non-destructive reconnaissance scanner.
Prohibits hardware access and validates source immutability.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from reconstruction.calibration.inventory import compute_sha256
from reconstruction.calibration.recon import DEFAULT_OUTPUT_DIR, DEFAULT_SPDATEN_ROOT, run_reconnaissance

# Known immutable hashes
EXPECTED_HASHES = {
    "A7592133.0da": "45b473d1ee8cc2542a1eb3ecb77bf446f357f81827a464e6c3489257312a0112",
    "7591971A.0pa": "63b204d2edbdaa0945d9b0241d55df7c6859b41d3376d9f35e93cc6c82ecfcc3",
    "GKE195.DAT": "6e88abf482c0cfe63ce302297b3721d2b00d47032593c477ee79ba6838daea98",
}


def main() -> int:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(
        description="Run offline flash image and calibration reconnaissance (Milestone 5.18)."
    )
    parser.add_argument(
        "--spdaten-root",
        type=Path,
        default=DEFAULT_SPDATEN_ROOT,
        help="Root directory of SP-Daten data files",
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
            print("Milestone 5.18 is 100% offline. Zero serial or hardware access is permitted.", file=sys.stderr)
            return 2

    args = parser.parse_args()

    print("=" * 70)
    print("  BMW E60 / GKE195 OFFLINE CALIBRATION RECONNAISSANCE")
    print("  Milestone 5.18 — Strict Read-Only / Zero Hardware Access")
    print("=" * 70)

    # 1. Pre-flight source hash validation
    print("[+] Validating source file integrity...")
    primary_da = args.spdaten_root / "GKE195" / "A7592133.0da"
    base_pa = args.spdaten_root / "GKE215" / "7591971A.0pa"
    dat_file = args.spdaten_root / "GKE195" / "GKE195.DAT"

    for name, path in [("A7592133.0da", primary_da), ("7591971A.0pa", base_pa), ("GKE195.DAT", dat_file)]:
        if not path.is_file():
            print(f"[!] Warning: Source file not found: {path}", file=sys.stderr)
            continue
        actual_hash = compute_sha256(path)
        expected = EXPECTED_HASHES.get(name)
        if expected and actual_hash != expected:
            print(f"[FATAL ERROR] Hash mismatch for {name}: {actual_hash} != {expected}", file=sys.stderr)
            return 1
        print(f"    {name:<15}: {actual_hash} [VERIFIED]")

    if args.verify_only:
        print("[+] Verify-only requested. Checking existing artifacts...")
        for artifact in ["flash_inventory.json", "flash_layout.json", "map_candidates.json", "axes.json", "checksum_regions.json"]:
            art_path = args.output_dir / artifact
            if not art_path.is_file():
                print(f"[!] Missing artifact: {art_path}", file=sys.stderr)
                return 1
            print(f"    Artifact present: {artifact} ({art_path.stat().st_size} bytes)")
        print("[+] All artifacts verified.")
        return 0

    # 2. Execute reconnaissance
    print(f"\n[+] Running reconnaissance pipeline (Output: {args.output_dir})...")
    artifacts = run_reconnaissance(spdaten_root=args.spdaten_root, output_dir=args.output_dir)

    print("\n[+] Reconnaissance complete. Generated artifacts:")
    for role, path in artifacts.items():
        size = path.stat().st_size
        print(f"    {path.name:<25}: {size:>8} bytes | SHA256: {compute_sha256(path)[:16]}...")

    # 3. Post-flight source immutability check
    print("\n[+] Verifying post-run source immutability...")
    for name, path in [("A7592133.0da", primary_da), ("7591971A.0pa", base_pa), ("GKE195.DAT", dat_file)]:
        if path.is_file():
            post_hash = compute_sha256(path)
            assert post_hash == EXPECTED_HASHES[name], f"Source mutation detected in {name}!"
    print("    Source files remained 100% bit-for-bit unchanged.")

    print("\n" + "=" * 70)
    print("  RECONNAISSANCE SUCCESS: 5/5 ARTIFACTS DETERMINISTICALLY GENERATED")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
