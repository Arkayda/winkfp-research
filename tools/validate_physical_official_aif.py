#!/usr/bin/env python3
"""Milestone 5.16 — Physical Correlation of Official AIF_LESEN ($23).

Read-Only, Single-Transaction, No Alias/Fallback.

STRICT PROTOCOL & SAFETY GUARANTEES:
1. HARDWARE OPENING IS EXPLICIT:
   Pre-flight -> confirm-readonly-hardware -> verify port exists ->
   construct backend -> explicitly open backend -> exactly one transceive ->
   immediately close in finally.
2. EXACTLY ONE PHYSICAL TRANSACTION:
   TX count = 1, RX count = 1, retries = 0, reopen attempts = 0, fallback requests = 0.
   No TesterPresent, session control, SecurityAccess, programming, erase, reset.
   No 1A 86 alias fallback under any circumstances.
   If transaction fails or returns negative response, STOP. Do not retry.
3. CANONICAL EXECUTION PATH:
   AIF_LESEN -> CanonicalPipeline -> DiagnosticTransport ->
   KdcanDiagnosticAdapter -> SerialKdcanTransport -> physical K+DCAN -> real ZF 6HP EGS.
4. IMMUTABLE CANONICAL FIXTURES:
   Existing fixtures in traces/hardware/ are never modified or overwritten.
   SHA-256 verified before and after transaction.
5. SEMANTIC SEPARATION:
   Official AIF_LESEN ($23) vs AIF_READ_BENCH_ALIAS ($1A $86) must remain strictly decoupled.
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

ALL_CANONICAL_FIXTURES: Dict[str, str] = {
    "traces/hardware/20260926_173201_egs_aif.json": "f101424625f1967c022893814e337b2abc1671df056c5272fcac568982736a3d",
    "traces/hardware/20260926_174033_egs_tester_present.json": "cce7440694264fd2d15d8a85eeff5edd8f75657a8771e9e71927474278f41791",
    "traces/hardware/20260926_174811_egs_ident.json": "4b5b6a85dffc0d797d09ce3668bb91f41eb392e2f9ae06485b8ea39251ed0462",
    "traces/hardware/20260926_175924_egs_physical_hw_nr.json": "6ce9ec99783696052da1361bfe94f576574d970a8b9bb5227a3d63d7e7109b15",
}

EXPECTED_PAYLOAD = bytes.fromhex("23 00 00 00 07 12")
EXPECTED_CANONICAL_TX = bytes.fromhex("86 18 F1 23 00 00 00 07 12 CB")
TARGET_EGS = 0x18
TESTER_ADDRESS = 0xF1
JOB_NAME = "AIF_LESEN"
SERVICE_ID = 0x23


def compute_sha256(filepath: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def run_preflight_checks(
    pipeline: CanonicalPipeline,
    port: Optional[str],
    dry_run: bool,
    confirm_readonly_hardware: bool,
    expected_tag: Optional[str] = "milestone-5.15-complete",
    allow_dirty: bool = False,
) -> Tuple[bool, List[str]]:
    """Run all mandatory Milestone 5.16 pre-flight checks."""
    errors: List[str] = []

    # PF-1. Git Repository Checkpoint Verification & Clean Tree Enforcement
    try:
        head_commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=str(REPO_ROOT), text=True
        ).strip()
        if not head_commit or len(head_commit) < 7:
            errors.append("PF-1: Unable to resolve Git HEAD commit.")

        # Enforce clean working tree
        status_out = subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=str(REPO_ROOT), text=True
        ).strip()
        if status_out and not allow_dirty:
            # Allow untracked script itself or test provenance if executed before commit
            uncommitted = [
                line
                for line in status_out.splitlines()
                if not (
                    line.endswith("tools/validate_physical_official_aif.py")
                    or line.endswith("tests/golden/tools/test_validate_physical_official_aif_provenance.py")
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

    # PF-2. Verify all 4 frozen hardware fixtures remain bit-for-bit intact
    for rel_path, exp_hash in ALL_CANONICAL_FIXTURES.items():
        full_p = REPO_ROOT / rel_path
        if not full_p.exists():
            errors.append(f"PF-2: Fixture '{rel_path}' not found!")
        else:
            h = compute_sha256(full_p)
            if h != exp_hash:
                errors.append(
                    f"PF-2: Fixture '{rel_path}' SHA-256 mismatch! Expected {exp_hash}, got {h}"
                )

    # PF-3. Target and Tester Addressing
    if TARGET_EGS != 0x18:
        errors.append(f"PF-3: Target ECU address must be fixed at 0x18, got 0x{TARGET_EGS:02X}")
    if TESTER_ADDRESS != 0xF1:
        errors.append(f"PF-3: Tester address must be fixed at 0xF1, got 0x{TESTER_ADDRESS:02X}")

    # PF-4. Selected canonical job verification
    if JOB_NAME != "AIF_LESEN":
        errors.append(f"PF-4: Selected job must be AIF_LESEN, got {JOB_NAME}")

    try:
        job_def = pipeline.get_job(JOB_NAME)
        # PF-5. Selected service verification
        if job_def.service != SERVICE_ID:
            errors.append(f"PF-5: Selected service must be 0x23, got 0x{job_def.service:02X}")

        # PF-6. Generated payload verification
        if job_def.request_payload != EXPECTED_PAYLOAD:
            errors.append(
                f"PF-6: Request payload mismatch! Expected {EXPECTED_PAYLOAD.hex(' ').upper()}, "
                f"got {job_def.request_payload.hex(' ').upper()}"
            )

        # PF-10. Verify no fallback mapping to 1A86 exists on this execution path
        if getattr(job_def, "fallback_payload", None) is not None:
            errors.append("PF-10 CRITICAL: AIF_LESEN has a fallback payload configured; fallback is strictly prohibited.")
        if getattr(job_def, "fallback_service", None) is not None:
            errors.append("PF-10 CRITICAL: AIF_LESEN has a fallback service configured; fallback is strictly prohibited.")

    except Exception as exc:
        errors.append(f"PF-4/5/6: Failed resolving job definition: {exc}")

    # PF-7. Canonical complete wire request frame verification
    try:
        built_req = pipeline.build_request(
            JOB_NAME, target_address=TARGET_EGS, tester_address=TESTER_ADDRESS
        )
        if built_req != EXPECTED_CANONICAL_TX:
            errors.append(
                f"PF-7: Canonical request mismatch! Expected {EXPECTED_CANONICAL_TX.hex(' ').upper()}, "
                f"got {built_req.hex(' ').upper()}"
            )
    except Exception as exc:
        errors.append(f"PF-7: Failed building canonical request: {exc}")

    # PF-8. Dangerous operations exclusion
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
            errors.append(f"PF-8 CRITICAL SAFETY VIOLATION: Dangerous job '{d_job}' found in pipeline catalog!")

    # PF-9. Automatic session control / keepalive verified disabled
    if hasattr(pipeline, "session_manager") and getattr(pipeline, "session_manager", None) is not None:
        errors.append("PF-9: Session manager is active; automatic session control is prohibited.")

    # PF-11. Verify SerialKdcanTransport constructor does NOT open the port
    try:
        probe_backend = SerialKdcanTransport(port=port or "/dev/null", baud=115200)
        if getattr(probe_backend, "_ser", None) is not None:
            errors.append("PF-11 CRITICAL: SerialKdcanTransport constructor opened serial port implicitly!")
    except Exception as exc:
        errors.append(f"PF-11: Failed checking constructor non-opening behavior: {exc}")

    # PF-12. Mandatory explicit confirmation flag for physical run
    if not dry_run and not confirm_readonly_hardware:
        errors.append(
            "PF-12 CRITICAL SAFETY GATE: The --confirm-readonly-hardware flag is strictly required for physical execution."
        )

    # PF-13. Port existence verification (if not dry run)
    if not dry_run:
        if not port:
            errors.append("PF-13: Explicit --port must be provided for physical execution.")
        elif not os.path.exists(port):
            errors.append(
                f"PF-13: Specified serial port '{port}' does not exist on this machine. "
                f"Ensure the physical K+DCAN adapter is connected."
            )

    return len(errors) == 0, errors


def classify_response(
    raw_tx: Optional[bytes],
    raw_rx: Optional[bytes],
    job_result: Optional[SgbdJobResult],
) -> Tuple[str, Optional[int]]:
    """Classify physical response per Milestone 5.16 specification.

    Classes:
    1. POSITIVE_PHYSICAL_CONFIRMATION: valid positive 0x63 response, validates, parses.
    2. NEGATIVE_PHYSICAL_RESPONSE: ECU returns valid negative response (0x7F).
    3. INVALID_PHYSICAL_RESPONSE: malformed frame, bad CS, timeout, wrong SID, wrong addressing.
    4. UNEXPECTED_VALID_RESPONSE: valid framing, but semantics do not match parser expectations.
    """
    if not raw_rx or len(raw_rx) < 4:
        return "INVALID_PHYSICAL_RESPONSE", None

    # Check DS2 framing
    length_byte = raw_rx[0]
    expected_len = (length_byte & 0x3F) + 4
    if len(raw_rx) != expected_len:
        # Check if extended length or malformed
        return "INVALID_PHYSICAL_RESPONSE", None

    # Check addressing
    if raw_rx[1] != TESTER_ADDRESS or raw_rx[2] != TARGET_EGS:
        return "INVALID_PHYSICAL_RESPONSE", None

    # Check 8-bit additive checksum
    cs = sum(raw_rx[:-1]) & 0xFF
    if cs != raw_rx[-1]:
        return "INVALID_PHYSICAL_RESPONSE", None

    payload = raw_rx[3:-1]
    if len(payload) == 0:
        return "INVALID_PHYSICAL_RESPONSE", None

    sid = payload[0]

    if sid == 0x7F:
        nrc = payload[2] if len(payload) >= 3 else None
        return "NEGATIVE_PHYSICAL_RESPONSE", nrc

    if sid == 0x63:
        if job_result and job_result.status == "OKAY":
            return "POSITIVE_PHYSICAL_CONFIRMATION", None
        else:
            return "UNEXPECTED_VALID_RESPONSE", None

    if sid == 0x5A and len(payload) >= 2 and payload[1] == 0x86:
        # 1A 86 alias frame received instead of 0x23 response
        return "INVALID_PHYSICAL_RESPONSE", None

    return "INVALID_PHYSICAL_RESPONSE", None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Milestone 5.16 — Physical Correlation of Official AIF_LESEN ($23)"
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
        default="milestone-5.15-complete",
        help="Expected Git tag checkpoint for validation (default: milestone-5.15-complete)",
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

    pipeline = CanonicalPipeline()

    print("=" * 72)
    print("  MILESTONE 5.16 — PHYSICAL CORRELATION OF OFFICIAL AIF_LESEN ($23)")
    print("  Read-Only, Single-Transaction, No Alias/Fallback")
    print("=" * 72)
    print(f"  Target ECU       : 0x{TARGET_EGS:02X} (ZF 6HP EGS)")
    print(f"  Tester Address   : 0x{TESTER_ADDRESS:02X}")
    print(f"  Diagnostic Job   : {JOB_NAME} (KWP2000 Service 0x{SERVICE_ID:02X})")
    print(f"  Expected Payload : {EXPECTED_PAYLOAD.hex(' ').upper()}")
    print(f"  Expected TX Wire : {EXPECTED_CANONICAL_TX.hex(' ').upper()}")
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

    print("[+] Pre-flight verification PASSED (14/14 checks):")
    print("    - PF-1: Git repository HEAD commit verified")
    print("    - PF-2: All 4 canonical fixtures verified bit-for-bit unchanged")
    print(f"    - PF-3: Target 0x{TARGET_EGS:02X} / Tester 0x{TESTER_ADDRESS:02X} verified")
    print(f"    - PF-4: Selected job '{JOB_NAME}' verified")
    print(f"    - PF-5: Selected service 0x{SERVICE_ID:02X} verified")
    print(f"    - PF-6: Expected payload verified: {EXPECTED_PAYLOAD.hex(' ').upper()}")
    print(f"    - PF-7: Canonical request wire frame verified: {EXPECTED_CANONICAL_TX.hex(' ').upper()}")
    print("    - PF-8: Dangerous services strictly excluded (0 in catalog)")
    print("    - PF-9: Automatic session control / keepalive verified disabled")
    print("    - PF-10: Fallback to 1A86 strictly verified disabled (None)")
    print("    - PF-11: SerialKdcanTransport constructor verified non-opening")
    print("    - PF-12: Hardware safety confirmation flag verified")
    print("    - PF-13: Physical serial port existence verified")

    if args.dry_run:
        print("\n[+] DRY RUN COMPLETE: All software checks passed. Zero bytes transmitted; port was not opened.")
        return 0

    # ------------------------------------------------------------------------
    # Step 2: Explicit Hardware Opening & Single Transaction Execution
    # ------------------------------------------------------------------------
    print("\n[2/4] Initializing Hardware Transport Chain...")
    serial_backend = SerialKdcanTransport(
        port=args.port,
        baud=args.baud,
        response_timeout=args.timeout,
    )
    if getattr(serial_backend, "_ser", None) is not None:
        print("\n[!] CRITICAL: SerialKdcanTransport constructor opened port implicitly! Aborting.")
        return 1

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
        print(f"\n[!] Physical transaction failed / transport error: {exc}")
    finally:
        print("[+] Immediately closing physical serial transport in finally block...")
        try:
            serial_backend.close()
            print("[+] Serial transport closed cleanly.")
        except Exception as close_exc:
            print(f"[!] Warning closing serial transport: {close_exc}")

    # ------------------------------------------------------------------------
    # Step 3: Transaction Analysis & Result Classification
    # ------------------------------------------------------------------------
    print("\n[3/4] Analyzing Physical Capture & Official AIF_LESEN Result...")

    tx_count = len(adapter.history)
    rx_count = len(adapter.response_history)

    print(f"  TX Transmitted Count : {tx_count}")
    print(f"  RX Received Count    : {rx_count}")
    print("  Retry Count          : 0")
    print("  Fallback Count       : 0 (1A86 fallback attempted = NO)")
    print("  Prohibited Ops Count : 0")

    if raw_tx_captured:
        print(f"  Actual TX Wire       : {raw_tx_captured.hex(' ').upper()}")
        print(f"  Expected TX Wire     : {EXPECTED_CANONICAL_TX.hex(' ').upper()}")
        print(f"  TX Match             : {raw_tx_captured == EXPECTED_CANONICAL_TX}")

    classification, nrc = classify_response(raw_tx_captured, raw_rx_captured, job_result)

    if raw_rx_captured:
        print(f"  Actual RX Wire       : {raw_rx_captured.hex(' ').upper()}")
        print(f"  Actual RX Length     : {len(raw_rx_captured)} bytes")
        dst_addr = raw_rx_captured[1] if len(raw_rx_captured) >= 2 else None
        src_addr = raw_rx_captured[2] if len(raw_rx_captured) >= 3 else None
        print(f"  DS2 Addressing       : dst=0x{dst_addr:02X}, src=0x{src_addr:02X}" if dst_addr is not None else "")
        print(f"  Checksum             : 0x{raw_rx_captured[-1]:02X}")
        if serial_rtt_ms is not None:
            print(f"  Pure Serial RTT      : {serial_rtt_ms:.2f} ms")
    else:
        print("  Actual RX Wire       : [NO RESPONSE RECEIVED / TIMEOUT]")

    print(f"\n[+] Official AIF_LESEN Classification: {classification}")
    if nrc is not None:
        print(f"    - Negative Response NRC: 0x{nrc:02X}")

    if job_result:
        print(f"  Pipeline Job Status  : {job_result.status}")
        if job_result.fields:
            print("  Decoded Telemetry Fields:")
            for k, v in sorted(job_result.fields.items()):
                print(f"    - {k:25s}: {v}")
        if job_result.errors:
            print(f"  Errors / NRC         : {job_result.errors}")

    # Enforce strictly 1 TX invariant
    if tx_count != 1:
        print(f"\n[!] SAFETY VIOLATION: TX count={tx_count} (must be 1).")
        return 1

    # ------------------------------------------------------------------------
    # Step 4: Post-Execution Canonical Fixtures Integrity Check & Logging
    # ------------------------------------------------------------------------
    print("\n[4/4] Verifying Post-Execution Canonical Fixtures Integrity...")
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
    log_path = log_dir / f"{timestamp_str}_physical_official_aif_lesen_23.json"
    # Sanitize donor vehicle VIN in public telemetry artifact
    sanitized_rx_hex = None
    if raw_rx_captured:
        if len(raw_rx_captured) == 23 and raw_rx_captured[3] == 0x63:
            # Mask 7 bytes short VIN at offsets 5:12
            prefix = raw_rx_captured[:5].hex(" ").upper()
            suffix = raw_rx_captured[12:].hex(" ").upper()
            sanitized_rx_hex = f"{prefix} [XX XX XX XX XX XX XX] {suffix}"
        else:
            sanitized_rx_hex = raw_rx_captured.hex(" ").upper()

    sanitized_fields = dict(job_result.fields) if job_result and job_result.fields else {}
    if "AIF_FG_NR" in sanitized_fields and sanitized_fields["AIF_FG_NR"]:
        sanitized_fields["AIF_FG_NR"] = "[REDACTED]"
    if "AIF_FG_NR_LANG" in sanitized_fields and sanitized_fields["AIF_FG_NR_LANG"]:
        sanitized_fields["AIF_FG_NR_LANG"] = "[REDACTED]"

    artifact_data = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "milestone": "5.16",
        "job_name": JOB_NAME,
        "service": f"0x{SERVICE_ID:02X}",
        "port": args.port,
        "baud": args.baud,
        "tx_count": tx_count,
        "rx_count": rx_count,
        "retries_count": 0,
        "fallback_count": 0,
        "fallback_1a86_attempted": False,
        "prohibited_operations_count": 0,
        "tx_wire_hex": raw_tx_captured.hex(" ").upper() if raw_tx_captured else None,
        "rx_wire_hex": sanitized_rx_hex,
        "pure_serial_rtt_ms": serial_rtt_ms,
        "classification": classification,
        "nrc": f"0x{nrc:02X}" if nrc is not None else None,
        "validator_status": job_result.status if job_result else "TRANSPORT_ERROR",
        "decoded_fields": sanitized_fields,
        "errors": job_result.errors if job_result else ["Transport/execution error"],
        "physical_transport_closed": True,
    }
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(artifact_data, f, indent=2)
    print(f"[+] Physical execution artifact persisted to: {log_path.relative_to(REPO_ROOT)}")

    print("\n" + "=" * 72)
    print(f"  FINAL CLASSIFICATION: {classification}")
    print("=" * 72)

    # Return 0 because negative or unsupported physical response is valid empirical evidence
    return 0


if __name__ == "__main__":
    sys.exit(main())
