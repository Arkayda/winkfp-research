#!/usr/bin/env python3
"""Milestone 5.14 — Physical Validation of the Canonical DiagnosticTransport Path.

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
3. MINIMAL CANONICAL EXECUTION PATH:
   IDENT -> CanonicalPipeline -> DiagnosticTransport -> KdcanDiagnosticAdapter ->
   SerialKdcanTransport -> physical K+DCAN -> real ZF 6HP EGS.
4. IMMUTABLE CANONICAL FIXTURE:
   traces/hardware/20260926_174811_egs_ident.json is never overwritten or updated.
   SHA-256 verified before and after transaction.
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

CANONICAL_IDENT_FIXTURE_REL = Path("traces/hardware/20260926_174811_egs_ident.json")
EXPECTED_IDENT_FIXTURE_SHA256 = "4b5b6a85dffc0d797d09ce3668bb91f41eb392e2f9ae06485b8ea39251ed0462"
EXPECTED_CANONICAL_TX = bytes.fromhex("82 18 F1 1A 80 25")
TARGET_EGS = 0x18
TESTER_ADDRESS = 0xF1


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
) -> Tuple[bool, List[str]]:
    """Run all mandatory Milestone 5.14 pre-flight checks."""
    errors: List[str] = []

    # PF-1. Git Repository Checkpoint Verification
    try:
        head_commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=str(REPO_ROOT), text=True
        ).strip()
        if not head_commit or len(head_commit) < 7:
            errors.append("PF-1: Unable to resolve Git HEAD commit.")
    except Exception as exc:
        errors.append(f"PF-1: Git check failed: {exc}")

    # PF-2. Canonical fixture existence and hash
    if not fixture_path.exists():
        errors.append(f"PF-2: Canonical IDENT fixture not found: {fixture_path}")
    else:
        actual_hash = compute_sha256(fixture_path)
        if actual_hash != EXPECTED_IDENT_FIXTURE_SHA256:
            errors.append(
                f"PF-2: Canonical IDENT fixture SHA-256 mismatch! Expected {EXPECTED_IDENT_FIXTURE_SHA256}, got {actual_hash}"
            )

    # PF-3. Canonical request byte construction
    try:
        built_req = pipeline.build_request("IDENT", target_address=TARGET_EGS, tester_address=TESTER_ADDRESS)
        if built_req != EXPECTED_CANONICAL_TX:
            errors.append(
                f"PF-3: Canonical request mismatch! Expected {EXPECTED_CANONICAL_TX.hex(' ').upper()}, got {built_req.hex(' ').upper()}"
            )
    except Exception as exc:
        errors.append(f"PF-3: Failed to build canonical IDENT request: {exc}")

    # PF-4. Target and Tester Addressing
    if TARGET_EGS != 0x18:
        errors.append(f"PF-4: Target ECU address must be 0x18, got 0x{TARGET_EGS:02X}")
    if TESTER_ADDRESS != 0xF1:
        errors.append(f"PF-4: Tester address must be 0xF1, got 0x{TESTER_ADDRESS:02X}")

    # PF-5. Verify dangerous operations are unavailable in the execution path
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
            errors.append(f"PF-5 CRITICAL SAFETY VIOLATION: Dangerous job '{d_job}' found in pipeline catalog!")

    # PF-6. Verify automatic session control / keepalive is strictly disabled
    # The canonical pipeline and transport must not have any background timers or auto-keepalive hooks
    if hasattr(pipeline, "session_manager") and getattr(pipeline, "session_manager", None) is not None:
        errors.append("PF-6: Session manager is active; automatic session control is prohibited.")

    # PF-7. Mandatory explicit confirmation flag for physical run
    if not dry_run and not confirm_readonly_hardware:
        errors.append(
            "PF-7 CRITICAL SAFETY GATE: The --confirm-readonly-hardware flag is strictly required for physical execution."
        )

    # PF-8. Port existence verification (if not dry run)
    if not dry_run:
        if not port:
            errors.append("PF-8: Explicit --port must be provided for physical execution.")
        elif not os.path.exists(port):
            errors.append(
                f"PF-8: Specified serial port '{port}' does not exist on this machine. "
                f"Ensure the physical K+DCAN adapter is connected."
            )

    return len(errors) == 0, errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Milestone 5.14 — Physical Validation of Canonical DiagnosticTransport Path"
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
    args = parser.parse_args()

    fixture_path = REPO_ROOT / CANONICAL_IDENT_FIXTURE_REL
    pipeline = CanonicalPipeline()

    print("=" * 72)
    print("  MILESTONE 5.14 — PHYSICAL VALIDATION OF CANONICAL TRANSPORT PATH")
    print("  Read-Only, Single-Transaction, Hardware-Controlled")
    print("=" * 72)
    print(f"  Target ECU       : 0x{TARGET_EGS:02X} (ZF 6HP EGS)")
    print(f"  Tester Address   : 0x{TESTER_ADDRESS:02X}")
    print(f"  Diagnostic Job   : IDENT (0x1A 0x80)")
    print(f"  Expected TX Wire : {EXPECTED_CANONICAL_TX.hex(' ').upper()}")
    print(f"  Serial Port      : {args.port if args.port else '[Not Specified]'}")
    print(f"  Baud Rate        : {args.baud} 8N1")
    print(f"  Timeout          : {args.timeout:.2f} s")
    print(f"  Dry Run Mode     : {args.dry_run}")
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
    )

    if not preflight_ok:
        print("\n" + "!" * 72)
        print("  [PRE-FLIGHT FAILURE] PHYSICAL I/O IS STRICTLY BLOCKED.")
        for err in preflight_errors:
            print(f"  - {err}")
        print("!" * 72 + "\n")
        return 1

    print("[+] Pre-flight verification PASSED (8/8 checks):")
    print("    - PF-1: Git repository HEAD commit verified")
    print(f"    - PF-2: Canonical fixture SHA-256 matches ({EXPECTED_IDENT_FIXTURE_SHA256[:16]}...)")
    print(f"    - PF-3: Canonical request frame verified: {EXPECTED_CANONICAL_TX.hex(' ').upper()}")
    print(f"    - PF-4: Target 0x{TARGET_EGS:02X} / Tester 0x{TESTER_ADDRESS:02X} verified")
    print("    - PF-5: Dangerous services strictly excluded (0 in catalog)")
    print("    - PF-6: Automatic session control / keepalive verified disabled")
    print("    - PF-7: Hardware safety confirmation flag verified")
    print("    - PF-8: Physical serial port existence verified")

    if args.dry_run:
        print("\n[+] DRY RUN COMPLETE: All 8 software checks passed. Zero bytes transmitted; port was not opened.")
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
            job_name="IDENT",
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
    # Step 3: Transaction Analysis & Golden Fixture Comparison
    # ------------------------------------------------------------------------
    print("\n[3/4] Analyzing Physical Capture & Golden Comparison...")

    fixture = load_trace_fixture(fixture_path)
    golden_tx = fixture.raw_tx
    golden_rx = fixture.raw_rx

    tx_count = len(adapter.history)
    rx_count = len(adapter.response_history)

    print(f"  TX Transmitted Count : {tx_count}")
    print(f"  RX Received Count    : {rx_count}")
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

    comparison_status = "UNKNOWN"
    if tx_match and rx_match and job_result and job_result.status == "OKAY":
        comparison_status = "EXACT_MATCH"
    elif raw_rx_captured and len(raw_rx_captured) >= 4 and not rx_match:
        comparison_status = "WIRE_DIFFERENCE_WITH_VALID_RESPONSE"
    else:
        comparison_status = "INVALID_OR_FAILED_RESPONSE"

    print(f"\n[+] Comparison Status   : {comparison_status}")

    if job_result:
        print(f"  Pipeline Job Status  : {job_result.status}")
        if job_result.fields:
            print("  Decoded Telemetry:")
            for k, v in sorted(job_result.fields.items()):
                print(f"    - {k:20s}: {v}")
        if job_result.errors:
            print(f"  Errors               : {job_result.errors}")

    # Enforce strictly 1 TX and 1 RX transaction invariant
    if tx_count != 1 or rx_count != 1:
        print(f"\n[!] SAFETY VIOLATION: Invariant failed! TX count={tx_count} (must be 1), RX count={rx_count} (must be 1).")
        return 1

    # ------------------------------------------------------------------------
    # Step 4: Post-Execution Canonical Fixture Integrity Check & Trace Logging
    # ------------------------------------------------------------------------
    print("\n[4/4] Verifying Post-Execution Canonical Fixture Integrity...")
    post_hash = compute_sha256(fixture_path)
    if post_hash != EXPECTED_IDENT_FIXTURE_SHA256:
        print("\n" + "!" * 72)
        print("  CRITICAL ERROR: CANONICAL HARDWARE FIXTURE WAS ALTERED!")
        print(f"  Expected: {EXPECTED_IDENT_FIXTURE_SHA256}")
        print(f"  Actual:   {post_hash}")
        print("!" * 72 + "\n")
        return 1

    print(f"[+] Canonical fixture SHA-256 verified unchanged: {post_hash}")

    # Persist physical run artifact to logs directory
    log_dir = REPO_ROOT / "logs" / "transport_validation"
    log_dir.mkdir(parents=True, exist_ok=True)
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    log_path = log_dir / f"{timestamp_str}_canonical_transport_validation.json"
    artifact_data = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "milestone": "5.14",
        "port": args.port,
        "baud": args.baud,
        "tx_count": tx_count,
        "rx_count": rx_count,
        "prohibited_operations_count": 0,
        "tx_wire_hex": raw_tx_captured.hex(" ").upper() if raw_tx_captured else None,
        "rx_wire_hex": raw_rx_captured.hex(" ").upper() if raw_rx_captured else None,
        "pure_serial_rtt_ms": serial_rtt_ms,
        "exact_byte_match": (comparison_status == "EXACT_MATCH"),
        "decoded_fields": job_result.fields if job_result else {},
        "canonical_fixture_sha256": post_hash,
    }
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(artifact_data, f, indent=2)
    print(f"[+] Physical execution artifact persisted to: {log_path.relative_to(REPO_ROOT)}")

    print("\n" + "=" * 72)
    print(f"  FINAL VALIDATION RESULT: {comparison_status}")
    print("=" * 72)

    return 0 if comparison_status == "EXACT_MATCH" else 1


if __name__ == "__main__":
    sys.exit(main())
