#!/usr/bin/env python3
"""Demonstration of event-log differential comparison using bench_diff.

Compares benchmark JSONL logs against each other to evaluate:
- L1 Choreography: Diagnostic job call sequence equality.
- L2 Semantics: Per-event argument strings, payload sha256 digests, and JOB_STATUS return codes.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DIFF_TOOL = ROOT / "tools" / "bench_diff" / "bench_diff.py"
CONTACT_LOG = ROOT / "traces" / "expected" / "bench_contact_mock.jsonl"
FULL_LOG = ROOT / "traces" / "expected" / "bench_full_mock.jsonl"


def main():
    print("=== WinKFP Research: Bench Differential Demo ===\n")

    if not CONTACT_LOG.is_file() or not FULL_LOG.is_file():
        print("Trace files not found. Ensure traces/expected/ contains bench logs.")
        return

    print("[1] Self-Differential Verification (Contact Log vs Contact Log):")
    cmd = [sys.executable, str(DIFF_TOOL), str(CONTACT_LOG), str(CONTACT_LOG)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    print(res.stdout)

    print("[2] Differential Across Scenarios (Contact vs Full Flash):")
    cmd2 = [sys.executable, str(DIFF_TOOL), str(CONTACT_LOG), str(FULL_LOG)]
    res2 = subprocess.run(cmd2, capture_output=True, text=True)
    # Output first few lines to show choreography divergence
    lines = res2.stdout.splitlines()[:15]
    print("\n".join(lines))
    print("    ... (divergence report truncated)")

    print("\nDemo completed successfully.")


if __name__ == "__main__":
    main()
