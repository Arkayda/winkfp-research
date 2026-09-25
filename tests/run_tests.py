#!/usr/bin/env python3
"""Master test runner for the winkfp-research repository.

Executes test suites across verification tiers:
- KAT (Known-Answer Tests): Cryptographic algorithms and key derivation.
- Golden Tests: VDLE flash protocol state machines, EDIABAS adapters, FlashRunner orchestration.
- Differential Tests: Cross-verification against original binary code emulated via Unicorn x86.
"""

from __future__ import annotations

import argparse
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def run_suite(suite_dir: Path, pattern: str = "test_*.py", verbose: int = 1) -> unittest.TestResult:
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=str(suite_dir), pattern=pattern, top_level_dir=str(ROOT))
    runner = unittest.TextTestRunner(verbosity=verbose)
    return runner.run(suite)


def main():
    parser = argparse.ArgumentParser(description="Execute winkfp-research test suites.")
    parser.add_argument("--tier", choices=["all", "kat", "golden", "differential"], default="all",
                        help="Select test tier to execute (default: all)")
    parser.add_argument("-v", "--verbose", action="count", default=1, help="Increase output verbosity")
    args = parser.parse_args()

    tests_dir = ROOT / "tests"
    tiers = {
        "kat": tests_dir / "kat",
        "golden": tests_dir / "golden",
        "differential": tests_dir / "differential",
    }

    selected = tiers if args.tier == "all" else {args.tier: tiers[args.tier]}

    print("=" * 70)
    print("  WinKFP Research — Automated Verification Suite")
    print("=" * 70)
    print(f"Python interpreter: {sys.executable}")
    print(f"Repository root:    {ROOT}\n")

    overall_ran = 0
    overall_failures = 0
    overall_errors = 0
    overall_skipped = 0
    start_time = time.time()

    tier_results = {}

    for name, path in selected.items():
        print(f"\n--- Running Tier: {name.upper()} ({path.relative_to(ROOT)}) ---")
        res = run_suite(path, verbose=args.verbose)
        tier_results[name] = res
        overall_ran += res.testsRun
        overall_failures += len(res.failures)
        overall_errors += len(res.errors)
        overall_skipped += len(res.skipped)

    elapsed = time.time() - start_time

    print("\n" + "=" * 70)
    print("  VERIFICATION SUMMARY")
    print("=" * 70)
    for name, res in tier_results.items():
        status = "PASSED" if res.wasSuccessful() else "FAILED"
        print(f"  {name.upper():<15} : {res.testsRun:3d} run, "
              f"{res.testsRun - len(res.failures) - len(res.errors) - len(res.skipped):3d} passed, "
              f"{len(res.skipped):3d} skipped, "
              f"{len(res.failures) + len(res.errors):3d} failed  [{status}]")

    print("-" * 70)
    total_passed = overall_ran - overall_failures - overall_errors - overall_skipped
    print(f"TOTAL: {overall_ran} tests in {elapsed:.3f}s | "
          f"{total_passed} passed | {overall_skipped} skipped | {overall_failures + overall_errors} failed")
    print("=" * 70)

    if overall_failures > 0 or overall_errors > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
