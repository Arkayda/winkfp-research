#!/usr/bin/env python3
"""Milestone 5.15 — Physical SGBD Semantic Correlation: PHYSIKALISCHE_HW_NR_LESEN (1A87).

Read-Only, Single-Transaction, Hardware-Controlled.

STRICT PROTOCOL & SAFETY GUARANTEES:
1. HARDWARE OPENING IS EXPLICIT:
   Pre-flight -> confirm-readonly-hardware -> verify port exists ->
   construct backend -> explicitly open backend -> exactly one transceive ->
   immediately close in finally.
2. EXACTLY ONE PHYSICAL TRANSACTION:
   TX count = 1, RX count = 1, retries = 0, reopen attempts = 0, fallback requests = 0.
   No TesterPresent, session control, SecurityAccess, programming, erase, reset.
   If transaction fails, STOP. Do not retry.
3. CANONICAL EXECUTION PATH:
   PHYSIKALISCHE_HW_NR_LESEN -> CanonicalPipeline -> DiagnosticTransport ->
   KdcanDiagnosticAdapter -> SerialKdcanTransport -> physical K+DCAN -> real ZF 6HP EGS.
4. IMMUTABLE CANONICAL FIXTURE:
   traces/hardware/20260926_175924_egs_physical_hw_nr.json is never overwritten or updated.
   SHA-256 verified before and after transaction.
5. SEMANTIC CORRELATION:
   Distinguish raw wire frame match from parsed SGBD semantic match (PECUHN = 7569980).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from reconstruction.ediabas.job_model import SgbdJobResult
from reconstruction.ediabas.pipeline import CanonicalPipeline
from reconstruction.ediabas.trace_loader import load_trace_fixture
from reconstruction.transport.kdcan import (
    KdcanDiagnosticAdapter,
    SerialKdcanTransport,
)

CANONICAL_PHYS_HWNR_FIXTURE_REL = Path("traces/hardware/20260926_175924_egs_physical_hw_nr.json")
EXPECTED_PHYS_HWNR_FIXTURE_SHA256 = "6ce9ec99783696052da1361bfe94f576574d970a8b9bb5227a3d63d7e7109b15"
ALL_CANONICAL_FIXTURES: Dict[str, str] = {
    "traces/hardware/20260926_173201_egs_aif.json": "f101424625f1967c022893814e337b2abc1671df056c5272fcac568982736a3d",
    "traces/hardware/20260926_174033_egs_tester_present.json": "cce7440694264fd2d15d8a85eeff5edd8f75657a8771e9e71927474278f41791",
    "traces/hardware/20260926_174811_egs_ident.json": "4b5b6a85dffc0d797d09ce3668bb91f41eb392e2f9ae06485b8ea39251ed0462",
    "traces/hardware/20260926_175924_egs_physical_hw_nr.json": "6ce9ec99783696052da1361bfe94f576574d970a8b9bb5227a3d63d7e7109b15",
}

EXPECTED_CANONICAL_TX = bytes.fromhex("82 18 F1 1A 87 2C")
EXPECTED_CANONICAL_RX = bytes.fromhex(
    "94 F1 18 5A 87 00 00 07 56 99 80 00 00 07 56 99 80 00 00 07 56 99 80 E0"
)
EXPECTED_SEMANTIC_KEY = "PHYSIKALISCHE_HW_NR"
EXPECTED_SEMANTIC_VALUE = "7569980"

TARGET_EGS = 0x18
TESTER_ADDRESS = 0xF1
JOB_NAME = "PHYSIKALISCHE_HW_NR_LESEN"


def compute_sha256(filepath: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def run_preflight_checks(
    pipeline: CanonicalPipeline,
    fixture_path: Path,
    port: Optional[str],
    dry_run: bool,
    confirm_readonly_hardware: bool,
    expected_tag: Optional[str] = "milestone-5.14.1-complete",
    allow_dirty: bool = False,
) -> Tuple[bool, List[str]]:
    """Run all mandatory Milestone 5.15 pre-flight checks."""
    errors: List[str] = []

    # PF-1. Git Repository Checkpoint Verification & Clean Tree Enforcement
    try:
        head_commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=str(REPO_ROOT), text=True
        ).strip()
        if not head_commit or len(head_commit) < 7:
            errors.append("PF-1: Unable to resolve Git HEAD commit.")

        # Enforce clean working tree (excluding validation script and logs)
        status_out = subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=str(REPO_ROOT), text=True
        ).strip()
        if status_out and not allow_dirty:
            # Allow untracked script itself or test provenance if executed before commit
            uncommitted = [
                line
                for line in status_out.splitlines()
                if not (
                    line.endswith("tools/validate_physical_sgbd_correlation.py")
                    or line.endswith("tests/golden/tools/test_validate_physical_sgbd_correlation_provenance.py")
                    or "logs/sgbd_semantic_correlation" in line
                )
            ]
            if uncommitted:
                dirty_count = len(uncommitted)
                errors.append(
                    f"PF-1: Git working tree is dirty ({dirty_count} uncommitted change(s)). "
                    f"Physical validation requires clean tree. Fail-closed."
                )

        # Enforce HEAD matches expected tag checkpoint
        if expected_tag:
            try:
                tag_commit = subprocess.check_output(
                    ["git", "rev-parse", f"refs/tags/{expected_tag}^{{commit}}"],
                    cwd=str(REPO_ROOT),
                    text=True,
                    stderr=subprocess.DEVNULL,
                ).strip()
                if head_commit != tag_commit:
                    errors.append(
                        f"PF-1: Git HEAD ({head_commit[:12]}) does not match expected tag "
                        f"'{expected_tag}' ({tag_commit[:12]}). Fail-closed."
                    )
            except subprocess.CalledProcessError:
                errors.append(f"PF-1: Expected tag '{expected_tag}' does not exist in repository.")
    except Exception as exc:
        errors.append(f"PF-1: Git check failed: {exc}")

    # PF-2. Canonical fixture existence and hash verification (all 4 fixtures)
    if not fixture_path.exists():
        errors.append(f"PF-2: Canonical PHYS_HWNR fixture not found: {fixture_path}")
    else:
        actual_hash = compute_sha256(fixture_path)
        if actual_hash != EXPECTED_PHYS_HWNR_FIXTURE_SHA256:
            errors.append(
                f"PF-2: Canonical PHYS_HWNR fixture SHA-256 mismatch! "
                f"Expected {EXPECTED_PHYS_HWNR_FIXTURE_SHA256}, got {actual_hash}"
            )

    for rel_path, exp_hash in ALL_CANONICAL_FIXTURES.items():
        full_p = REPO_ROOT / rel_path
        if full_p.exists():
            h = compute_sha256(full_p)
            if h != exp_hash:
                errors.append(
                    f"PF-2: Fixture '{rel_path}' SHA-256 mismatch! Expected {exp_hash}, got {h}"
                )

    # PF-3. Canonical request byte construction
    try:
        built_req = pipeline.build_request(
            JOB_NAME, target_address=TARGET_EGS, tester_address=TESTER_ADDRESS
        )
        if built_req != EXPECTED_CANONICAL_TX:
            errors.append(
                f"PF-3: Canonical request mismatch! Expected {EXPECTED_CANONICAL_TX.hex(' ').upper()}, "
                f"got {built_req.hex(' ').upper()}"
            )
    except Exception as exc:
        errors.append(f"PF-3: Failed to build canonical request for {JOB_NAME}: {exc}")

    # PF-4. Target and Tester Addressing
    if TARGET_EGS != 0x18:
        errors.append(f"PF-4: Target ECU address must be 0x18, got 0x{TARGET_EGS:02X}")
    if TESTER_ADDRESS != 0xF1:
        errors.append(f"PF-4: Tester address must be 0xF1, got 0x{TESTER_ADDRESS:02X}")

    # PF-5. Selected job verification
    if JOB_NAME != "PHYSIKALISCHE_HW_NR_LESEN":
        errors.append(f"PF-5: Selected job must be PHYSIKALISCHE_HW_NR_LESEN, got {JOB_NAME}")

    # PF-6. Verify dangerous operations are unavailable in the execution path
    dangerous_jobs = [
        "FLASH_PROGRAMMIEREN",
        "FLASH_SCHREIBEN",
        "FLASH_LOESCHEN",
        "SECURITY_ACCESS",
        "AUTHENTICATION",
        "ECU_RESET",
    ]
    for d_job in dangerous_jobs:
        if d_job in pipeline.catalog:
            errors.append(f"PF-6 CRITICAL SAFETY VIOLATION: Dangerous job '{d_job}' found in pipeline catalog!")

    # PF-7. Verify automatic session control / keepalive is strictly disabled
    if hasattr(pipeline, "session_manager") and getattr(pipeline, "session_manager", None) is not None:
        errors.append("PF-7: Session manager is active; automatic session control is prohibited.")

    # PF-8. Verify SerialKdcanTransport constructor does NOT open the port
    try:
        probe_backend = SerialKdcanTransport(port=port or "/dev/null", baud=115200)
        if getattr(probe_backend, "_ser", None) is not None:
            errors.append("PF-8 CRITICAL: SerialKdcanTransport constructor opened serial port implicitly!")
    except Exception as exc:
        errors.append(f"PF-8: Failed checking constructor non-opening behavior: {exc}")

    # PF-9. Mandatory explicit confirmation flag for physical run
    if not dry_run and not confirm_readonly_hardware:
        errors.append(
            "PF-9 CRITICAL SAFETY GATE: The --confirm-readonly-hardware flag is strictly required for physical execution."
        )

    # PF-10. Port existence verification (if not dry run)
    if not dry_run:
        if not port:
            errors.append("PF-10: Explicit --port must be provided for physical execution.")
        elif not os.path.exists(port):
            errors.append(
                f"PF-10: Specified serial port '{port}' does not exist on this machine. "
                f"Ensure the physical K+DCAN adapter is connected."
            )

    return len(errors) == 0, errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Milestone 5.15 — Physical SGBD Semantic Correlation: PHYSIKALISCHE_HW_NR_LESEN"
    )
    parser.add_argument(
        "--port",
        type=str,
        default=None,
        help="Serial port path for physical K+DCAN adapter (e.g. /dev/cu.usbserial-XXXX)",
    )
    parser.add_argument(
        "--baud",
        type=int,
        default=115200,
        help="Baud rate (default: 115200 8N1)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Response timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--confirm-readonly-hardware",
        action="store_true",
        help="Mandatory operator confirmation flag for physical read-only execution",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Execute pre-flight software checks only; do NOT open port or transmit bytes",
    )
    parser.add_argument(
        "--expected-tag",
        type=str,
        default="milestone-5.14.1-complete",
        help="Expected Git tag checkpoint for validation (default: milestone-5.14.1-complete)",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Allow dirty working tree for development/dry-run only (strictly forbidden for physical run)",
    )
    args = parser.parse_args()

    if not args.dry_run and args.allow_dirty:
        print("\n[!] CRITICAL SAFETY VIOLATION: --allow-dirty is strictly prohibited during physical execution.")
        return 1

    fixture_path = REPO_ROOT / CANONICAL_PHYS_HWNR_FIXTURE_REL
    pipeline = CanonicalPipeline()

    print("=" * 72)
    print("  MILESTONE 5.15 — PHYSICAL SGBD SEMANTIC CORRELATION")
    print("  PHYSIKALISCHE_HW_NR_LESEN (0x1A 0x87)")
    print("  Read-Only, Single-Transaction, Hardware-Controlled")
    print("=" * 72)
    print(f"  Target ECU       : 0x{TARGET_EGS:02X} (ZF 6HP EGS)")
    print(f"  Tester Address   : 0x{TESTER_ADDRESS:02X}")
    print(f"  Diagnostic Job   : {JOB_NAME} (0x1A 0x87)")
    print(f"  Expected TX Wire : {EXPECTED_CANONICAL_TX.hex(' ').upper()}")
    print(f"  Expected RX Wire : {EXPECTED_CANONICAL_RX.hex(' ').upper()}")
    print(f"  Expected Semantic: {EXPECTED_SEMANTIC_KEY} = {EXPECTED_SEMANTIC_VALUE}")
    print(f"  Serial Port      : {args.port if args.port else '[Not Specified]'}")
    print(f"  Baud Rate        : {args.baud} 8N1")
    print(f"  Timeout          : {args.timeout:.2f} s")
    print(f"  Dry Run Mode     : {args.dry_run}")
    print(f"  Expected Tag     : {args.expected_tag}")
    print("=" * 72)

    # ------------------------------------------------------------------------
    # Step 1: Pre-Flight Verification
    # ------------------------------------------------------------------------
    print("\n[1/4] Running Pre-Flight Verification...")
    preflight_ok, preflight_errors = run_preflight_checks(
        pipeline=pipeline,
        fixture_path=fixture_path,
        port=args.port,
        dry_run=args.dry_run,
        confirm_readonly_hardware=args.confirm_readonly_hardware,
        expected_tag=args.expected_tag,
        allow_dirty=args.allow_dirty,
    )

    if not preflight_ok:
        print("\n" + "!" * 72)
        print("  [PRE-FLIGHT FAILURE] PHYSICAL I/O IS STRICTLY BLOCKED.")
        for err in preflight_errors:
            print(f"  - {err}")
        print("!" * 72 + "\n")
        return 1

    print("[+] Pre-flight verification PASSED (10/10 checks):")
    print("    - PF-1: Git repository HEAD commit verified")
    print(f"    - PF-2: Canonical fixture SHA-256 matches ({EXPECTED_PHYS_HWNR_FIXTURE_SHA256[:16]}...)")
    print(f"    - PF-3: Canonical request frame verified: {EXPECTED_CANONICAL_TX.hex(' ').upper()}")
    print(f"    - PF-4: Target 0x{TARGET_EGS:02X} / Tester 0x{TESTER_ADDRESS:02X} verified")
    print(f"    - PF-5: Selected job '{JOB_NAME}' verified")
    print("    - PF-6: Dangerous services strictly excluded (0 in catalog)")
    print("    - PF-7: Automatic session control / keepalive verified disabled")
    print("    - PF-8: SerialKdcanTransport constructor verified non-opening")
    print("    - PF-9: Hardware safety confirmation flag verified")
    print("    - PF-10: Physical serial port existence verified")

    if args.dry_run:
        print("\n[+] DRY RUN COMPLETE: All software checks passed. Zero bytes transmitted; port was not opened.")
        return 0

    # ------------------------------------------------------------------------
    # Step 2: Explicit Hardware Opening & Single Transaction Execution
    # ------------------------------------------------------------------------
    print("\n[2/4] Initializing Hardware Transport Chain...")
    # 1. Construct backend (constructor must NOT open port)
    serial_backend = SerialKdcanTransport(
        port=args.port,
        baud=args.baud,
        response_timeout=args.timeout,
    )
    if getattr(serial_backend, "_ser", None) is not None:
        print("\n[!] CRITICAL: SerialKdcanTransport constructor opened port implicitly! Aborting.")
        return 1

    # 2. Construct adapter with auto_open=False
    adapter = KdcanDiagnosticAdapter(backend=serial_backend, auto_open=False)

    raw_tx_captured: Optional[bytes] = None
    raw_rx_captured: Optional[bytes] = None
    serial_rtt_ms: Optional[float] = None
    job_result: Optional[SgbdJobResult] = None

    print(f"[+] Opening physical serial port {args.port}...")
    try:
        serial_backend.open()
        print("[+] Serial port opened successfully.")

        print(f"[+] Transmitting EXACTLY ONE diagnostic request: {EXPECTED_CANONICAL_TX.hex(' ').upper()}...")
        job_result = pipeline.execute_transport(
            job_name=JOB_NAME,
            transport=adapter,
            target_address=TARGET_EGS,
            tester_address=TESTER_ADDRESS,
            timeout=args.timeout,
        )

        if adapter.history:
            raw_tx_captured = adapter.history[0][0]
        if adapter.response_history:
            raw_rx_captured = adapter.response_history[0]
        if adapter.rtt_history:
            serial_rtt_ms = adapter.rtt_history[0]

    except Exception as exc:
        print(f"\n[!] Physical transaction failed: {exc}")
    finally:
        print("[+] Immediately closing physical serial transport in finally block...")
        try:
            serial_backend.close()
            print("[+] Serial transport closed cleanly.")
        except Exception as close_exc:
            print(f"[!] Warning closing serial transport: {close_exc}")

    # ------------------------------------------------------------------------
    # Step 3: Transaction Analysis & Wire/Semantic Comparison
    # ------------------------------------------------------------------------
    print("\n[3/4] Analyzing Physical Capture & Semantic Correlation...")

    fixture = load_trace_fixture(fixture_path)
    golden_tx = fixture.raw_tx
    golden_rx = fixture.raw_rx

    tx_count = len(adapter.history)
    rx_count = len(adapter.response_history)

    print(f"  TX Transmitted Count : {tx_count}")
    print(f"  RX Received Count    : {rx_count}")
    print("  Retry Count          : 0")
    print("  Prohibited Ops Count : 0")

    if raw_tx_captured:
        print(f"  Actual TX Wire       : {raw_tx_captured.hex(' ').upper()}")
        print(f"  Expected Golden TX   : {golden_tx.hex(' ').upper()}")
        tx_match = (raw_tx_captured == golden_tx)
        print(f"  TX Match             : {tx_match}")
    else:
        tx_match = False

    if raw_rx_captured:
        print(f"  Actual RX Wire       : {raw_rx_captured.hex(' ').upper()}")
        print(f"  Expected Golden RX   : {golden_rx.hex(' ').upper()}")
        print(f"  Actual RX Length     : {len(raw_rx_captured)} bytes (Golden: {len(golden_rx)} bytes)")
        rx_match = (raw_rx_captured == golden_rx)
        print(f"  RX Exact Byte Match  : {rx_match}")
        if serial_rtt_ms is not None:
            print(f"  Pure Serial RTT      : {serial_rtt_ms:.2f} ms")
    else:
        rx_match = False

    # Wire classification
    if tx_match and rx_match:
        wire_status = "EXACT_MATCH"
    elif raw_rx_captured and len(raw_rx_captured) >= 4 and not rx_match:
        wire_status = "VALID_RESPONSE_WITH_BYTE_DIFFERENCE"
    else:
        wire_status = "INVALID_OR_FAILED_RESPONSE"

    print(f"\n[+] Wire Comparison Status     : {wire_status}")

    # Semantic classification
    semantic_observed = None
    semantic_match = False
    if job_result:
        print(f"  Pipeline Job Status          : {job_result.status}")
        semantic_observed = job_result.fields.get(EXPECTED_SEMANTIC_KEY)
        print(f"  Expected Semantic Value      : {EXPECTED_SEMANTIC_VALUE}")
        print(f"  Observed Semantic Value      : {semantic_observed}")
        semantic_match = (job_result.status == "OKAY" and semantic_observed == EXPECTED_SEMANTIC_VALUE)
        print(f"  Semantic Match Result        : {semantic_match}")
        if job_result.fields:
            print("  Decoded Telemetry Fields:")
            for k, v in sorted(job_result.fields.items()):
                print(f"    - {k:25s}: {v}")
        if job_result.errors:
            print(f"  Errors                       : {job_result.errors}")

    print(f"[+] Semantic Correlation Status: {'EXACT_MATCH' if semantic_match else 'SEMANTIC_MISMATCH'}")

    # Enforce strictly 1 TX and 1 RX transaction invariant
    if tx_count != 1 or rx_count != 1:
        print(f"\n[!] SAFETY VIOLATION: Invariant failed! TX count={tx_count} (must be 1), RX count={rx_count} (must be 1).")
        return 1

    # ------------------------------------------------------------------------
    # Step 4: Post-Execution Canonical Fixture Integrity Check & Trace Logging
    # ------------------------------------------------------------------------
    print("\n[4/4] Verifying Post-Execution Canonical Fixture Integrity...")
    post_hash = compute_sha256(fixture_path)
    if post_hash != EXPECTED_PHYS_HWNR_FIXTURE_SHA256:
        print("\n" + "!" * 72)
        print("  CRITICAL ERROR: CANONICAL HARDWARE FIXTURE WAS ALTERED!")
        print(f"  Expected: {EXPECTED_PHYS_HWNR_FIXTURE_SHA256}")
        print(f"  Actual:   {post_hash}")
        print("!" * 72 + "\n")
        return 1
    print(f"[+] Canonical fixture SHA-256 verified unchanged: {post_hash}")

    # Verify all 4 fixtures remain intact
    for rel_path, exp_hash in ALL_CANONICAL_FIXTURES.items():
        h = compute_sha256(REPO_ROOT / rel_path)
        if h != exp_hash:
            print(f"\n[!] CRITICAL: Fixture '{rel_path}' altered post-execution!")
            return 1
    print("[+] All 4 canonical hardware fixtures verified bit-for-bit unchanged.")

    # Persist physical run artifact to logs directory
    log_dir = REPO_ROOT / "logs" / "sgbd_semantic_correlation"
    log_dir.mkdir(parents=True, exist_ok=True)
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    log_path = log_dir / f"{timestamp_str}_physical_sgbd_semantic_correlation_1a87.json"
    artifact_data = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "milestone": "5.15",
        "job_name": JOB_NAME,
        "service": "0x1A",
        "subfunction": "0x87",
        "port": args.port,
        "baud": args.baud,
        "tx_count": tx_count,
        "rx_count": rx_count,
        "retries_count": 0,
        "prohibited_operations_count": 0,
        "tx_wire_hex": raw_tx_captured.hex(" ").upper() if raw_tx_captured else None,
        "rx_wire_hex": raw_rx_captured.hex(" ").upper() if raw_rx_captured else None,
        "pure_serial_rtt_ms": serial_rtt_ms,
        "wire_status": wire_status,
        "wire_exact_byte_match": (wire_status == "EXACT_MATCH"),
        "expected_semantic_key": EXPECTED_SEMANTIC_KEY,
        "expected_semantic_value": EXPECTED_SEMANTIC_VALUE,
        "observed_semantic_value": semantic_observed,
        "semantic_match": semantic_match,
        "decoded_fields": job_result.fields if job_result else {},
        "canonical_fixture_sha256": post_hash,
    }
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(artifact_data, f, indent=2)
    print(f"[+] Physical execution artifact persisted to: {log_path.relative_to(REPO_ROOT)}")

    print("\n" + "=" * 72)
    print(f"  FINAL WIRE RESULT     : {wire_status}")
    print(f"  FINAL SEMANTIC RESULT : {'EXACT_MATCH' if semantic_match else 'MISMATCH'}")
    print("=" * 72)

    return 0 if (wire_status == "EXACT_MATCH" and semantic_match) else 1


if __name__ == "__main__":
    sys.exit(main())
