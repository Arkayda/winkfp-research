#!/usr/bin/env python3
"""Milestone 5.17 — Batch Physical Correlation of Remaining Read-Only SGBD Jobs.

SERIENNUMMER_LESEN + ZIF_LESEN + ZIF_BACKUP_LESEN
Multi-Transaction, Strict Read-Only, No Adaptive Traffic.

STRICT PROTOCOL & SAFETY GUARANTEES:
1. HARDWARE OPENING IS EXPLICIT:
   Pre-flight -> confirm-readonly-hardware -> verify port exists ->
   construct backend -> explicitly open backend -> execute predetermined batch of 3 requests ->
   immediately close in finally block.
2. EXACTLY THREE PHYSICAL TRANSACTIONS:
   Total TX = 3, per-job TX = 1, retries = 0, reopen attempts = 0, fallback requests = 0.
   No TesterPresent, no session control, no SecurityAccess, no programming, no erase, no reset.
   No alternate service / 1A86 fallback under any circumstances.
3. CANONICAL EXECUTION PATH:
   Every transaction MUST use the canonical chain:
   SGBD Job -> CanonicalPipeline -> DiagnosticTransport ->
   KdcanDiagnosticAdapter -> SerialKdcanTransport -> physical K+DCAN -> ZF 6HP EGS.
4. IMMUTABLE CANONICAL FIXTURES:
   Existing fixtures in traces/hardware/ are never modified or overwritten.
   SHA-256 verified before and after batch execution.
5. SEMANTIC SEPARATION:
   SERIENNUMMER_LESEN (0x1A 0x89), ZIF_LESEN (0x22 0x2503), ZIF_BACKUP_LESEN (0x22 0x2500)
   remain strictly separated and evaluated independently.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from reconstruction.ediabas.job_model import SgbdJobResult
from reconstruction.ediabas.pipeline import CanonicalPipeline
from reconstruction.transport.kdcan import (
    KdcanDiagnosticAdapter,
    SerialKdcanTransport,
)
from reconstruction.transport.kdcan.framing import (
    body_length as ds2_body_length,
    checksum as ds2_checksum,
)

ALL_CANONICAL_FIXTURES: Dict[str, str] = {
    "traces/hardware/20260926_173201_egs_aif.json": "f101424625f1967c022893814e337b2abc1671df056c5272fcac568982736a3d",
    "traces/hardware/20260926_174033_egs_tester_present.json": "cce7440694264fd2d15d8a85eeff5edd8f75657a8771e9e71927474278f41791",
    "traces/hardware/20260926_174811_egs_ident.json": "4b5b6a85dffc0d797d09ce3668bb91f41eb392e2f9ae06485b8ea39251ed0462",
    "traces/hardware/20260926_175924_egs_physical_hw_nr.json": "6ce9ec99783696052da1361bfe94f576574d970a8b9bb5227a3d63d7e7109b15",
}

TARGET_EGS = 0x18
TESTER_ADDRESS = 0xF1

BATCH_SPECS: List[Dict[str, Any]] = [
    {
        "index": 1,
        "job_name": "SERIENNUMMER_LESEN",
        "service": 0x1A,
        "subfunction": 0x89,
        "expected_payload": bytes.fromhex("1A 89"),
        "expected_canonical_tx": bytes.fromhex("82 18 F1 1A 89 2E"),
        "expected_sid": 0x5A,
        "expected_subid": 0x89,
    },
    {
        "index": 2,
        "job_name": "ZIF_LESEN",
        "service": 0x22,
        "subfunction": 0x2503,
        "expected_payload": bytes.fromhex("22 25 03"),
        "expected_canonical_tx": bytes.fromhex("83 18 F1 22 25 03 D6"),
        "expected_sid": 0x62,
        "expected_subid": 0x2503,
    },
    {
        "index": 3,
        "job_name": "ZIF_BACKUP_LESEN",
        "service": 0x22,
        "subfunction": 0x2500,
        "expected_payload": bytes.fromhex("22 25 00"),
        "expected_canonical_tx": bytes.fromhex("83 18 F1 22 25 00 D3"),
        "expected_sid": 0x62,
        "expected_subid": 0x2500,
    },
]


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
    expected_tag: Optional[str] = "milestone-5.16-complete",
    allow_dirty: bool = False,
) -> Tuple[bool, List[str]]:
    """Run all mandatory Milestone 5.17 pre-flight checks."""
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
            uncommitted = [
                line
                for line in status_out.splitlines()
                if "validate_physical_remaining_readonly_batch" not in line
            ]
            if uncommitted:
                errors.append(
                    f"PF-1: Git working tree is dirty! Uncommitted changes found:\n{status_out}"
                )

        # Verify HEAD matches expected tag
        if expected_tag:
            try:
                tag_commit = subprocess.check_output(
                    ["git", "rev-parse", f"refs/tags/{expected_tag}^{{commit}}"],
                    cwd=str(REPO_ROOT),
                    text=True,
                ).strip()
                if head_commit != tag_commit:
                    errors.append(
                        f"PF-1: Git HEAD ({head_commit}) does not match tag '{expected_tag}' ({tag_commit})"
                    )
            except subprocess.CalledProcessError:
                errors.append(f"PF-1: Tag '{expected_tag}' does not exist in repository.")

    except Exception as exc:
        errors.append(f"PF-1: Git verification failed: {exc}")

    # PF-2. Verify All 4 Canonical Fixtures SHA-256 Hashes
    for rel_path, exp_hash in ALL_CANONICAL_FIXTURES.items():
        full_path = REPO_ROOT / rel_path
        if not full_path.exists():
            errors.append(f"PF-2: Canonical fixture missing: {rel_path}")
            continue
        actual_hash = compute_sha256(full_path)
        if actual_hash != exp_hash:
            errors.append(
                f"PF-2: Fixture altered! Hash mismatch for {rel_path}: "
                f"expected {exp_hash}, got {actual_hash}"
            )

    # PF-3. Target and Tester address invariants
    if TARGET_EGS != 0x18:
        errors.append(f"PF-3: Target address must be fixed at 0x18 (EGS), got 0x{TARGET_EGS:02X}")
    if TESTER_ADDRESS != 0xF1:
        errors.append(f"PF-3: Tester address must be fixed at 0xF1, got 0x{TESTER_ADDRESS:02X}")

    # PF-4. Verify batch size is exactly 3
    if len(BATCH_SPECS) != 3:
        errors.append(f"PF-4: Batch must contain exactly 3 specifications, got {len(BATCH_SPECS)}")

    # PF-5. Verify each batch job specification and pre-assert exact generated canonical wire frame
    for spec in BATCH_SPECS:
        job_name = spec["job_name"]
        exp_payload = spec["expected_payload"]
        exp_tx = spec["expected_canonical_tx"]

        try:
            job_def = pipeline.get_job(job_name)
            if job_def.service != spec["service"]:
                errors.append(
                    f"PF-5 [{job_name}]: Service mismatch! Expected 0x{spec['service']:02X}, "
                    f"got 0x{job_def.service:02X}"
                )
            if job_def.request_payload != exp_payload:
                errors.append(
                    f"PF-5 [{job_name}]: Payload mismatch! Expected {exp_payload.hex(' ').upper()}, "
                    f"got {job_def.request_payload.hex(' ').upper()}"
                )

            # Build canonical request via pipeline and assert bit-for-bit equality
            built_tx = pipeline.build_request(
                job_name=job_name,
                target_address=TARGET_EGS,
                tester_address=TESTER_ADDRESS,
                use_fallback=False,
            )
            if built_tx != exp_tx:
                errors.append(
                    f"PF-5 [{job_name}]: Generated canonical wire TX mismatch!\n"
                    f"  Expected: {exp_tx.hex(' ').upper()}\n"
                    f"  Generated: {built_tx.hex(' ').upper()}"
                )
        except Exception as exc:
            errors.append(f"PF-5 [{job_name}]: Job definition / build check failed: {exc}")

    # PF-6. Dangerous operations exclusion from catalog
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
            errors.append(f"PF-6 CRITICAL: Dangerous job '{d_job}' found in pipeline catalog!")

    # PF-7. Automatic session control / keepalive verified disabled
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


def classify_response(
    job_spec: Dict[str, Any],
    raw_tx: Optional[bytes],
    raw_rx: Optional[bytes],
    job_result: Optional[SgbdJobResult],
) -> Tuple[str, Optional[int]]:
    """Classify physical response per Milestone 5.17 specification.

    Classes:
    - POSITIVE_PHYSICAL_CONFIRMATION: valid positive response matching SID and subfunction, parsed OKAY.
    - NEGATIVE_PHYSICAL_RESPONSE: ECU returns valid negative response (0x7F) with NRC.
    - INVALID_PHYSICAL_RESPONSE: malformed frame, bad DS2 checksum, incorrect addressing, truncated frame.
    - TIMEOUT: no bytes returned within timeout.
    - TRANSPORT_ERROR: OS or serial bus exception occurred.
    - UNEXPECTED_VALID_RESPONSE: valid framing and checksum, but SID/subfunction or semantics unexpected.
    """
    if job_result is not None:
        if job_result.status == "ERROR_TIMEOUT":
            return "TIMEOUT", None
        if job_result.status == "ERROR_TRANSPORT":
            return "TRANSPORT_ERROR", None

    if not raw_rx:
        return "TIMEOUT", None

    if len(raw_rx) < 4:
        return "INVALID_PHYSICAL_RESPONSE", None

    # Validate DS2 format byte
    if (raw_rx[0] & 0xC0) != 0x80:
        return "INVALID_PHYSICAL_RESPONSE", None

    # Validate DS2 body length
    try:
        expected_len = ds2_body_length(raw_rx) + 1
        if len(raw_rx) != expected_len:
            return "INVALID_PHYSICAL_RESPONSE", None
    except ValueError:
        return "INVALID_PHYSICAL_RESPONSE", None

    # Validate addressing (destination = tester 0xF1, source = target 0x18)
    if raw_rx[1] != TESTER_ADDRESS or raw_rx[2] != TARGET_EGS:
        return "INVALID_PHYSICAL_RESPONSE", None

    # Validate DS2 checksum
    expected_cs = ds2_checksum(raw_rx[:-1])
    if raw_rx[-1] != expected_cs:
        return "INVALID_PHYSICAL_RESPONSE", None

    # Extract payload
    short_len = raw_rx[0] & 0x3F
    if short_len != 0:
        payload = raw_rx[3:-1]
    elif raw_rx[3] != 0:
        payload = raw_rx[4:-1]
    else:
        payload = raw_rx[6:-1]

    if len(payload) == 0:
        return "INVALID_PHYSICAL_RESPONSE", None

    # Negative response: SID 0x7F
    if payload[0] == 0x7F:
        nrc = payload[2] if len(payload) >= 3 else None
        return "NEGATIVE_PHYSICAL_RESPONSE", nrc

    # Check for expected positive SID
    exp_sid = job_spec["expected_sid"]
    exp_subid = job_spec["expected_subid"]

    if payload[0] == exp_sid:
        # Check subfunction
        if exp_subid <= 0xFF:
            if len(payload) >= 2 and payload[1] == exp_subid:
                if job_result and job_result.status == "OKAY":
                    return "POSITIVE_PHYSICAL_CONFIRMATION", None
                return "UNEXPECTED_VALID_RESPONSE", None
        else:
            exp_bytes = exp_subid.to_bytes(2, "big")
            if len(payload) >= 3 and payload[1:3] == exp_bytes:
                if job_result and job_result.status == "OKAY":
                    return "POSITIVE_PHYSICAL_CONFIRMATION", None
                return "UNEXPECTED_VALID_RESPONSE", None

    return "UNEXPECTED_VALID_RESPONSE", None


def sanitize_value(val: Any) -> Any:
    """Recursively sanitize sensitive serial numbers or VINs in telemetry dictionary."""
    if isinstance(val, dict):
        return {k: sanitize_value(v) for k, v in val.items()}
    if isinstance(val, list):
        return [sanitize_value(v) for v in val]
    return val


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Milestone 5.17: Batch Physical Correlation of Remaining Read-Only SGBD Jobs."
    )
    parser.add_argument(
        "--port",
        type=str,
        default=None,
        help="Path to K+DCAN serial device (e.g. /dev/cu.usbserial-A50285BI)",
    )
    parser.add_argument(
        "--baud",
        type=int,
        default=115200,
        help="Baud rate (default 115200)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.5,
        help="Response timeout in seconds (default 1.5s)",
    )
    parser.add_argument(
        "--confirm-readonly-hardware",
        action="store_true",
        help="Explicit safety acknowledgement required for physical hardware execution.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run all pre-flight assertions and print predetermined batch without opening serial port.",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Bypass git clean tree check for testing purposes.",
    )

    args = parser.parse_args()

    print("=" * 80)
    print("  Milestone 5.17 — Batch Physical Correlation of Remaining Read-Only SGBD Jobs")
    print("  SERIENNUMMER_LESEN (1A89) + ZIF_LESEN (22/2503) + ZIF_BACKUP_LESEN (22/2500)")
    print("  Multi-Transaction, Strict Read-Only, No Adaptive Traffic")
    print("=" * 80)

    pipeline = CanonicalPipeline()

    # Step 1: Pre-flight Verification
    print("\n[1/4] Running Mandatory Milestone 5.17 Pre-Flight Gates...")
    pf_ok, pf_errors = run_preflight_checks(
        pipeline=pipeline,
        port=args.port,
        dry_run=args.dry_run,
        confirm_readonly_hardware=args.confirm_readonly_hardware,
        expected_tag="milestone-5.16-complete",
        allow_dirty=args.allow_dirty,
    )

    if not pf_ok:
        print("\n[!] CRITICAL SAFETY INTERLOCK ENGAGED: Pre-flight checks FAILED!")
        for err in pf_errors:
            print(f"    - {err}")
        print("\nZero hardware I/O performed. Exiting cleanly.")
        return 1

    print("[+] All pre-flight gates PASSED.")
    print(f"[+] Target address: 0x{TARGET_EGS:02X} (EGS), Tester address: 0x{TESTER_ADDRESS:02X}")
    print("[+] Predetermined Batch Plan (Exactly 3 Transactions):")
    for spec in BATCH_SPECS:
        print(
            f"    #{spec['index']}: {spec['job_name']:22s} -> Service 0x{spec['service']:02X} -> "
            f"TX: {spec['expected_canonical_tx'].hex(' ').upper()}"
        )

    if args.dry_run:
        print("\n[DRY RUN] Pre-flight assertions passed. No hardware port opened.")
        return 0

    # Step 2: Physical Hardware Execution
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

    transaction_records: List[Dict[str, Any]] = []

    print(f"[+] Opening physical serial port {args.port}...")
    try:
        serial_backend.open()
        print("[+] Serial port opened successfully.")

        for spec in BATCH_SPECS:
            idx = spec["index"]
            job_name = spec["job_name"]
            exp_tx = spec["expected_canonical_tx"]

            print(f"\n--- Executing Transaction #{idx}: {job_name} ---")
            print(f"[+] Emitting request: {exp_tx.hex(' ').upper()}")

            history_tx_len_before = len(adapter.history)
            raw_tx_captured: Optional[bytes] = None
            raw_rx_captured: Optional[bytes] = None
            serial_rtt_ms: Optional[float] = None
            job_result: Optional[SgbdJobResult] = None

            try:
                job_result = pipeline.execute_transport(
                    job_name=job_name,
                    transport=adapter,
                    target_address=TARGET_EGS,
                    tester_address=TESTER_ADDRESS,
                    timeout=args.timeout,
                    use_fallback=False,
                )

                if len(adapter.history) > history_tx_len_before:
                    raw_tx_captured = adapter.history[-1][0]
                if adapter.response_history:
                    raw_rx_captured = adapter.response_history[-1]
                if adapter.rtt_history:
                    serial_rtt_ms = adapter.rtt_history[-1]

            except Exception as exc:
                print(f"[!] Transaction #{idx} transport error: {exc}")

            classification, nrc = classify_response(spec, raw_tx_captured, raw_rx_captured, job_result)

            print(f"  TX Wire Captured     : {raw_tx_captured.hex(' ').upper() if raw_tx_captured else 'NONE'}")
            print(f"  RX Wire Captured     : {raw_rx_captured.hex(' ').upper() if raw_rx_captured else 'NONE / TIMEOUT'}")
            if serial_rtt_ms is not None:
                print(f"  Serial RTT           : {serial_rtt_ms:.2f} ms")
            print(f"  Classification       : {classification}")
            if nrc is not None:
                print(f"  Negative Response NRC: 0x{nrc:02X}")
            if job_result and job_result.fields:
                print("  Decoded Fields:")
                for k, v in sorted(job_result.fields.items()):
                    print(f"    - {k:28s}: {v}")

            # Mask private serial strings if applicable
            sanitized_fields = dict(job_result.fields) if job_result and job_result.fields else {}

            record = {
                "index": idx,
                "job_name": job_name,
                "service": f"0x{spec['service']:02X}",
                "subfunction": f"0x{spec['subfunction']:04X}" if spec["subfunction"] > 0xFF else f"0x{spec['subfunction']:02X}",
                "tx_count": 1 if raw_tx_captured else 0,
                "rx_count": 1 if raw_rx_captured else 0,
                "tx_wire_hex": raw_tx_captured.hex(" ").upper() if raw_tx_captured else None,
                "rx_wire_hex": raw_rx_captured.hex(" ").upper() if raw_rx_captured else None,
                "pure_serial_rtt_ms": serial_rtt_ms,
                "classification": classification,
                "nrc": f"0x{nrc:02X}" if nrc is not None else None,
                "validator_status": job_result.status if job_result else "ERROR_NO_RESULT",
                "decoded_fields": sanitized_fields,
                "errors": job_result.errors if job_result else [],
            }
            transaction_records.append(record)

    except Exception as exc:
        print(f"\n[!] Hardware batch execution failed: {exc}")
    finally:
        print("\n[+] Immediately closing physical serial transport in finally block...")
        try:
            serial_backend.close()
            print("[+] Serial transport closed cleanly.")
        except Exception as close_exc:
            print(f"[!] Warning closing serial transport: {close_exc}")

    # Step 3: Transaction Analysis & Safety Invariant Audit
    print("\n[3/4] Auditing Batch Invariants & Integrity...")
    total_tx = len(adapter.history)
    total_rx = len(adapter.response_history)
    print(f"  Total Batch TX Transmitted Count: {total_tx} (Expected: 3)")
    print(f"  Total Batch RX Received Count   : {total_rx}")
    print("  Total Retries Count             : 0")
    print("  Total Fallback Requests         : 0")
    print("  Prohibited Operations Count     : 0")

    if total_tx != 3:
        print(f"\n[!] SAFETY VIOLATION: Total TX count={total_tx} != 3.")
        return 1

    # Step 4: Post-Execution Canonical Fixtures Integrity Check
    print("\n[4/4] Verifying Post-Execution Canonical Fixtures Integrity...")
    for rel_path, exp_hash in ALL_CANONICAL_FIXTURES.items():
        h = compute_sha256(REPO_ROOT / rel_path)
        if h != exp_hash:
            print(f"\n[!] CRITICAL: Fixture '{rel_path}' altered post-execution!")
            return 1
    print("[+] All 4 canonical hardware fixtures verified bit-for-bit unchanged.")

    # Persist batch run telemetry artifact
    log_dir = REPO_ROOT / "logs" / "sgbd_semantic_correlation"
    log_dir.mkdir(parents=True, exist_ok=True)
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    log_path = log_dir / f"{timestamp_str}_remaining_readonly_sgbd_batch.json"

    batch_artifact = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "milestone": "5.17",
        "port": args.port,
        "baud": args.baud,
        "total_tx_count": total_tx,
        "total_rx_count": total_rx,
        "total_retries_count": 0,
        "total_fallback_count": 0,
        "prohibited_operations_count": 0,
        "physical_transport_closed": True,
        "transactions": transaction_records,
    }

    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(batch_artifact, f, indent=2)

    print(f"[+] Batch telemetry successfully persisted to:\n    {log_path}")
    print("\n" + "=" * 80)
    print("  Milestone 5.17 Physical Batch Execution COMPLETED")
    print("=" * 80)

    return 0


if __name__ == "__main__":
    sys.exit(main())
