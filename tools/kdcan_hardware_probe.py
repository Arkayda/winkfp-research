#!/usr/bin/env python3
"""Safe physical K+DCAN hardware probe for BMW EGS (ZF 6HP) read-only diagnostics.

MILESTONE 5.0 — DIRECT HARDWARE CONNECTION / READ-ONLY BUS VALIDATION

HARD SAFETY BOUNDARY:
- STRICTLY READ-ONLY diagnostic validation.
- NO flashing, NO programming, NO erase, NO download, NO session changes (0x10),
  NO authentication / security access (0x27, 0x31), NO reset (0x11).
- Requires explicit confirmation flag: --confirm-readonly-hardware.
- Requires explicit --port flag when hardware execution is enabled.
- Emits EXACTLY ONE read-only probe (AIF 0x1A 0x86 or TesterPresent 0x3E 0x00).
- Zero automatic retries, zero command escalation.
- Raw-wire capture is authoritative.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from reconstruction.transport.kdcan import (
    KdcanError,
    SerialKdcanTransport,
    framing,
)

# Standard targets
DEFAULT_TARGET_EGS = 0x18
DEFAULT_TESTER = 0xF1

# Read-only probe definitions
PROBE_PAYLOADS = {
    "aif": bytes([0x1A, 0x86]),             # KWP2000 ReadECUIdentification (AIF)
    "tester_present": bytes([0x3E, 0x00]),   # KWP2000 TesterPresent
    "ident": bytes([0x1A, 0x80]),            # KWP2000 ReadECUIdentification (Standard Ident)
    "physical_hw_nr": bytes([0x1A, 0x87]),   # KWP2000 ReadECUIdentification (Physical HW Nr inquiry)
}


# Golden evidence references (OBSERVED_WIRE from physical bench runs in docs/DIRECT_KDCAN_VALIDATION.md)
GOLDEN_EVIDENCE = {
    "aif": {
        "tx_raw": bytes([0x82, 0x18, 0xF1, 0x1A, 0x86, 0x2B]),
        "rx_raw": bytes.fromhex(
            "80F118425A86404353363832393420081204000007592132000007592133"
            "0000000000000002404E465330310030343739533930543634315A"
            "5742414E583731303430FFFFFF0F"
        ),
        "rx_payload": bytes.fromhex(
            "5A86404353363832393420081204000007592132000007592133"
            "0000000000000002404E465330310030343739533930543634315A"
            "5742414E583731303430FFFFFF"
        ),
        "rx_len": 71,
        "payload_len": 66,
        "source": "docs/DIRECT_KDCAN_VALIDATION.md",
    },
    "tester_present": {
        "tx_raw": bytes([0x82, 0x18, 0xF1, 0x3E, 0x00, 0xC9]),
        "rx_raw": bytes([0x83, 0xF1, 0x18, 0x7F, 0x3E, 0x12, 0x5B]),
        "rx_payload": bytes([0x7F, 0x3E, 0x12]),
        "rx_len": 7,
        "payload_len": 3,
        "source": "docs/DIRECT_KDCAN_VALIDATION.md",
    },
}


def sanitize_vin(raw_vin: str) -> str:
    """Sanitize vehicle identification number for privacy (keeps first 10, masks last 7)."""
    if len(raw_vin) == 17:
        return raw_vin[:10] + "XXXXXXX"
    if len(raw_vin) > 10:
        return raw_vin[:10] + "..."
    return raw_vin


def parse_aif_payload(payload: bytes) -> Optional[Dict[str, Any]]:
    """Parse KWP2000 AIF response payload (0x5A 0x86 ...).

    Raw wire capture is authoritative; this decoder is secondary.
    Returns None if payload is not standard AIF response.
    """
    if len(payload) < 20 or payload[0] != 0x5A or payload[1] != 0x86:
        return None

    res: Dict[str, Any] = {}
    try:
        # Short VIN (7 ASCII chars at offset 3:10)
        short_raw = payload[3:10].decode("ascii", "ignore").strip()
        if re.match(r"^[A-HJ-NPR-Z0-9]{7}$", short_raw, re.IGNORECASE):
            res["short_vin"] = short_raw

        # Programming Date (BCD: YYYY.MM.DD at offset 10:14)
        if len(payload) >= 14:
            res["flash_date"] = f"{payload[10]:02X}{payload[11]:02X}.{payload[12]:02X}.{payload[13]:02X}"

        # ZB Number (4 bytes at offset 16:20)
        if len(payload) >= 20:
            zb_bytes = payload[16:20]
            zb_str = f"{zb_bytes[0]:02X}{zb_bytes[1]:02X}{zb_bytes[2]:02X}{zb_bytes[3]:02X}".lstrip("0")
            if zb_str:
                res["zb_number"] = zb_str

        # Software Number (4 bytes at offset 22:26)
        if len(payload) >= 26:
            sw_bytes = payload[22:26]
            sw_str = f"{sw_bytes[0]:02X}{sw_bytes[1]:02X}{sw_bytes[2]:02X}{sw_bytes[3]:02X}".lstrip("0")
            if sw_str:
                res["sw_number"] = sw_str

        # Full ASCII extraction for SGBD and Tool stamp
        ascii_text = payload.decode("ascii", "ignore")
        sgbd_match = re.search(r"(\d{4}[A-Z0-9]{8})", ascii_text)
        if sgbd_match:
            res["sgbd"] = sgbd_match.group(1)

        tool_match = re.search(r"(NFS\d{2}|BMW\w{2})", ascii_text)
        if tool_match:
            res["tool_marker"] = tool_match.group(1)

        # Chassis VIN prefix (10 ASCII chars at offset 53:63, e.g. WBANX71040)
        if len(payload) >= 63:
            chassis_prefix = payload[53:63].decode("ascii", "ignore").strip()
            if re.match(r"^[A-HJ-NPR-Z0-9]{10}$", chassis_prefix):
                res["chassis_prefix"] = chassis_prefix
                if "short_vin" in res:
                    full_vin = chassis_prefix + res["short_vin"]
                    res["chassis_vin_sanitized"] = sanitize_vin(full_vin)
                else:
                    res["chassis_vin_sanitized"] = sanitize_vin(chassis_prefix)


    except Exception as exc:
        res["parse_error"] = str(exc)

    return res


def compare_with_golden(probe_name: str, tx_raw: bytes, rx_raw: bytes) -> Dict[str, Any]:
    """Compare observed physical wire bytes against verified historical golden evidence.

    Distinguishes:
    - EXACT_BYTE_MATCH: Complete byte-for-byte match of TX and RX frames.
    - HEADER_MATCH_ONLY: Frame header matches historical reference, but payload differs.
    - PAYLOAD_MATCH_ONLY: Payload matches historical reference, but header differs.
    - MISMATCH: Neither header nor payload match, or corrupt frame.
    - UNKNOWN: No golden reference exists for the specified probe.
    """
    golden = GOLDEN_EVIDENCE.get(probe_name)
    if not golden:
        return {
            "status": "UNKNOWN",
            "tx_match": False,
            "rx_exact_match": False,
            "header_match": False,
            "payload_match": False,
            "expected_tx": None,
            "expected_rx": None,
            "reference_source": None,
            "details": f"No golden reference available for probe '{probe_name}'",
            "differences": [f"Unknown probe '{probe_name}'; reference not found"],
        }

    tx_match = (tx_raw == golden["tx_raw"])
    rx_exact_match = (rx_raw == golden["rx_raw"])

    diffs: list[str] = []
    if not tx_match:
        diffs.append(f"TX mismatch: observed {tx_raw.hex(' ')}, expected {golden['tx_raw'].hex(' ')}")
    if not rx_exact_match:
        diffs.append(f"RX length: observed {len(rx_raw)}, expected {len(golden['rx_raw'])}")
        if len(rx_raw) >= 4 and len(golden["rx_raw"]) >= 4:
            if rx_raw[:4] != golden["rx_raw"][:4]:
                diffs.append(f"Header mismatch: {rx_raw[:4].hex(' ')} vs {golden['rx_raw'][:4].hex(' ')}")
        if rx_raw and rx_raw[-1] != golden["rx_raw"][-1]:
            diffs.append(f"Checksum mismatch: 0x{rx_raw[-1]:02X} vs 0x{golden['rx_raw'][-1]:02X}")

    header_match = False
    if len(rx_raw) >= 4 and len(golden["rx_raw"]) >= 4:
        header_match = (rx_raw[:4] == golden["rx_raw"][:4])

    payload_match = False
    try:
        if len(rx_raw) >= 4:
            parsed = framing.parse(rx_raw)
            payload_match = (parsed.payload == golden["rx_payload"])
    except Exception:
        payload_match = False

    if tx_match and rx_exact_match:
        status = "EXACT_BYTE_MATCH"
    elif header_match and not payload_match:
        status = "HEADER_MATCH_ONLY"
    elif payload_match and not header_match:
        status = "PAYLOAD_MATCH_ONLY"
    else:
        status = "MISMATCH"

    return {
        "status": status,
        "tx_match": tx_match,
        "rx_exact_match": rx_exact_match,
        "header_match": header_match,
        "payload_match": payload_match,
        "expected_tx": golden["tx_raw"].hex(" "),
        "expected_rx": golden["rx_raw"].hex(" "),
        "reference_source": golden["source"],
        "differences": diffs,
    }



def save_hardware_trace(trace_dict: Dict[str, Any], trace_dir: Path) -> Path:
    """Save machine-readable JSON trace to trace_dir/<timestamp>_egs_<probe>.json."""
    trace_dir.mkdir(parents=True, exist_ok=True)
    ts_clean = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    probe = trace_dict.get("probe", "unknown")
    trace_file = trace_dir / f"{ts_clean}_egs_{probe}.json"
    with open(trace_file, "w", encoding="utf-8") as f:
        json.dump(trace_dict, f, indent=2)
    return trace_file


def execute_probe(
    port: Optional[str],
    baud: int = 115200,
    target: int = DEFAULT_TARGET_EGS,
    tester: int = DEFAULT_TESTER,
    probe: str = "aif",
    confirm_readonly_hardware: bool = False,
    golden_compare: bool = False,
    trace_dir: Path = Path("traces/hardware"),
    timeout: float = 1.0,
    transport_override: Optional[Any] = None,
) -> Tuple[int, Dict[str, Any]]:
    """Execute a single, controlled read-only hardware probe.

    Returns (exit_code, trace_record).
    """
    # Hard stop gate 1: target address must be 0x18
    if target != DEFAULT_TARGET_EGS:
        print(f"[FATAL ERROR] Target address 0x{target:02X} is not allowed. Only 0x18 (EGS) is permitted.")
        return 1, {"result": "ERROR_INVALID_TARGET", "evidence_class": "OBSERVED_WIRE"}

    # Hard stop gate 2: tester address must be 0xF1
    if tester != DEFAULT_TESTER:
        print(f"[FATAL ERROR] Tester address 0x{tester:02X} is not allowed. Only 0xF1 is permitted.")
        return 1, {"result": "ERROR_INVALID_TESTER", "evidence_class": "OBSERVED_WIRE"}

    # Hard stop gate 3: probe must be known safe read-only payload
    if probe not in PROBE_PAYLOADS:
        print(f"[FATAL ERROR] Probe '{probe}' is not recognized. Allowed: {list(PROBE_PAYLOADS.keys())}")
        return 1, {"result": "ERROR_UNKNOWN_PROBE", "evidence_class": "OBSERVED_WIRE"}

    # Hard stop gate 4: operator confirmation flag required
    if not confirm_readonly_hardware:
        print("\n" + "!" * 72)
        print("  [SAFETY INTERLOCK ENGAGED] Physical hardware access is BLOCKED.")
        print("  The --confirm-readonly-hardware flag is strictly required.")
        print("  No serial port opened; no bytes transmitted.")
        print("!" * 72 + "\n")
        return 1, {"result": "ERROR_CONFIRMATION_REQUIRED", "evidence_class": "OBSERVED_WIRE"}

    # Hard stop gate 5: explicit port required for physical hardware run (Requirement 4)
    if not port and transport_override is None:
        print("\n" + "!" * 72)
        print("  [SAFETY INTERLOCK ENGAGED] Explicit --port is required.")
        print("  Auto-detecting arbitrary serial ports is prohibited for hardware validation.")
        print("  Please specify: --port <device_path> (e.g. /dev/cu.usbserial-A50285BI)")
        print("!" * 72 + "\n")
        return 1, {"result": "ERROR_EXPLICIT_PORT_REQUIRED", "evidence_class": "OBSERVED_WIRE"}

    # Check port existence if physical port string provided
    if port and transport_override is None and not os.path.exists(port):
        print(f"[FATAL ERROR] Specified serial port '{port}' does not exist on this machine.")
        return 1, {"result": "ERROR_PORT_NOT_FOUND", "evidence_class": "OBSERVED_WIRE"}

    probe_payload = PROBE_PAYLOADS[probe]
    expected_tx = framing.build(target, tester, probe_payload)

    print("=" * 72)
    if probe == "tester_present":
        print("  READ-ONLY HARDWARE PROBE")
        print("  SECOND PHYSICAL PRIMITIVE")
        print("  ONE REQUEST ONLY")
        print("  NO FLASH / NO AUTH / NO RESET")
    elif probe == "ident":
        print("  READ-ONLY HARDWARE PROBE")
        print("  THIRD PHYSICAL PRIMITIVE (1A 80)")
        print("  ONE REQUEST ONLY")
        print("  NO FLASH / NO AUTH / NO RESET")
    elif probe == "physical_hw_nr":
        print("  READ-ONLY HARDWARE PROBE")
        print("  FOURTH PHYSICAL PRIMITIVE (1A 87)")
        print("  ONE REQUEST ONLY")
        print("  NO FLASH / NO AUTH / NO RESET")
    else:
        print("  READ-ONLY HARDWARE PROBE — NO FLASH / NO AUTH")
        print("  WinKFP Research — Target ZF 6HP EGS (0x18) via K+DCAN")
    print("=" * 72)

    print(f"  Target Port     : {port or '<transport override>'}")
    print(f"  Baud Rate       : {baud} 8N1")
    print(f"  Target Address  : 0x{target:02X} (EGS)")
    print(f"  Tester Address  : 0x{tester:02X}")
    print(f"  Probe Command   : {probe.upper()} (Payload: {probe_payload.hex(' ')})")
    print(f"  Expected TX Wire: {expected_tx.hex(' ')}")
    print(f"  Response Timeout: {timeout:.2f} s")
    print(f"  Safety Gate     : PASS (Strictly Read-Only, No Reset/Auth/Flash)")
    print("=" * 72)

    timestamp_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    trace_record: Dict[str, Any] = {
        "timestamp": timestamp_iso,
        "mode": "HARDWARE_READ_ONLY",
        "target": f"0x{target:02X}",
        "tester": f"0x{tester:02X}",
        "transport": "K+DCAN",
        "serial_port": port,
        "probe": probe,
        "raw_tx": expected_tx.hex(" "),
        "raw_rx": None,
        "tx": expected_tx.hex(" "),
        "rx": None,
        "rx_payload": None,
        "rx_len": 0,
        "checksum_valid": False,
        "rtt_ms": None,
        "result": "IN_PROGRESS",
        "parser_result": "IN_PROGRESS",
        "evidence_class": "OBSERVED_WIRE",
        "parsed": None,
        "golden_comparison": None,
    }

    transport = transport_override or SerialKdcanTransport(port=port, baud=baud, response_timeout=timeout)

    raw_tx: Optional[bytes] = None
    raw_rx: Optional[bytes] = None
    rx_payload: Optional[bytes] = None
    rtt_ms: Optional[float] = None
    exit_code = 0

    try:
        print(f"\n[+] Opening transport on {port or 'override'}...")
        transport.open()
        print("[+] Transport opened successfully.")

        print(f"\n[+] Emitting exactly ONE probe: {expected_tx.hex(' ')}...")
        raw_tx, raw_rx, rx_payload, rtt_ms = transport.send_job_raw(
            target, probe_payload, src=tester, timeout=timeout
        )

        trace_record["raw_tx"] = raw_tx.hex(" ")
        trace_record["raw_rx"] = raw_rx.hex(" ")
        trace_record["tx"] = raw_tx.hex(" ")
        trace_record["rx"] = raw_rx.hex(" ")
        trace_record["rx_payload"] = rx_payload.hex(" ")
        trace_record["rx_len"] = len(raw_rx)
        trace_record["rtt_ms"] = round(rtt_ms, 2)

        # Checksum validation on raw_rx
        expected_cs = framing.checksum(raw_rx[:-1])
        actual_cs = raw_rx[-1]
        cs_valid = (expected_cs == actual_cs)
        trace_record["checksum_valid"] = cs_valid

        print(f"[+] Response received in {rtt_ms:.2f} ms ({len(raw_rx)} bytes)")
        print(f"    Raw RX Wire: {raw_rx.hex(' ')}")
        print(f"    Checksum   : 0x{actual_cs:02X} ({'VALID' if cs_valid else 'INVALID - expected 0x{:02X}'.format(expected_cs)})")
        print(f"    Payload    : {rx_payload.hex(' ')}")

        if not cs_valid:
            trace_record["result"] = "ERROR_CHECKSUM_MISMATCH"
            trace_record["parser_result"] = "ERROR_CHECKSUM_MISMATCH"
            exit_code = 2
        else:
            trace_record["result"] = "SUCCESS"
            trace_record["parser_result"] = "SUCCESS"


        # Secondary: parse payload if probe is AIF
        if probe == "aif" and rx_payload:
            parsed = parse_aif_payload(rx_payload)
            trace_record["parsed"] = parsed
            if parsed:
                print("\n[+] Decoded AIF Parameters (Secondary):")
                for k, v in parsed.items():
                    print(f"    - {k:22s}: {v}")
            else:
                print("\n[!] AIF payload could not be parsed as standard format.")
        elif probe == "tester_present" and rx_payload:
            if len(rx_payload) >= 3 and rx_payload[0] == 0x7F:
                nrc = rx_payload[2]
                print(f"\n[+] TesterPresent response: Negative Response NRC 0x{nrc:02X} (ECU present on bus)")
                trace_record["parsed"] = {"nrc": f"0x{nrc:02X}", "raw_response": "NRC_SUBFUNCTION_NOT_SUPPORTED"}
            elif rx_payload[0] == 0x7E:
                print("\n[+] TesterPresent response: Positive ACK 0x7E")
                trace_record["parsed"] = {"ack": "0x7E"}
        elif probe == "ident" and rx_payload:
            if len(rx_payload) >= 3 and rx_payload[0] == 0x7F:
                nrc = rx_payload[2]
                print(f"\n[+] Ident (0x1A 0x80) response: Negative Response NRC 0x{nrc:02X}")
                trace_record["parsed"] = {"nrc": f"0x{nrc:02X}", "raw_response": "NEGATIVE_RESPONSE"}
            elif len(rx_payload) >= 2 and rx_payload[0] == 0x5A and rx_payload[1] == 0x80:
                print(f"\n[+] Ident (0x1A 0x80) response: Positive Response (0x5A 0x80, {len(rx_payload)} bytes)")
                ascii_preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in rx_payload[2:])
                print(f"    ASCII Preview: {ascii_preview}")
                trace_record["parsed"] = {
                    "sid": "0x5A",
                    "record_id": "0x80",
                    "payload_hex": rx_payload.hex(" "),
                    "ascii_preview": ascii_preview,
                }
        elif probe == "physical_hw_nr" and rx_payload:
            if len(rx_payload) >= 3 and rx_payload[0] == 0x7F:
                nrc = rx_payload[2]
                print(f"\n[+] Physical HW Nr (0x1A 0x87) response: Negative Response NRC 0x{nrc:02X}")
                trace_record["parsed"] = {"nrc": f"0x{nrc:02X}", "raw_response": "NEGATIVE_RESPONSE"}
            elif len(rx_payload) >= 2 and rx_payload[0] == 0x5A and rx_payload[1] == 0x87:
                print(f"\n[+] Physical HW Nr (0x1A 0x87) response: Positive Response (0x5A 0x87, {len(rx_payload)} bytes)")
                ascii_preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in rx_payload[2:])
                print(f"    ASCII Preview: {ascii_preview}")
                trace_record["parsed"] = {
                    "sid": "0x5A",
                    "record_id": "0x87",
                    "payload_hex": rx_payload.hex(" "),
                    "ascii_preview": ascii_preview,
                }


        # Golden comparison if enabled
        if golden_compare:
            golden_result = compare_with_golden(probe, raw_tx, raw_rx)
            trace_record["golden_comparison"] = golden_result
            print("\n[+] Golden Evidence Comparison:")
            print(f"    Status         : {golden_result['status']}")
            print(f"    TX Match       : {golden_result['tx_match']}")
            print(f"    RX Exact Match : {golden_result['rx_exact_match']}")
            if golden_result["differences"]:
                print(f"    Differences    : {golden_result['differences']}")

    except KdcanError as exc:
        print(f"\n[!] Transport error during probe: {exc}")
        trace_record["result"] = f"ERROR_TRANSPORT: {exc}"
        trace_record["parser_result"] = f"ERROR_TRANSPORT: {exc}"
        exit_code = 1
    except Exception as exc:
        print(f"\n[FATAL ERROR] Unexpected exception: {exc}")
        trace_record["result"] = f"ERROR_UNEXPECTED: {exc}"
        trace_record["parser_result"] = f"ERROR_UNEXPECTED: {exc}"
        exit_code = 1

    finally:
        # Guarantee transport closure
        try:
            transport.close()
            print("[+] Transport closed cleanly.")
        except Exception:
            pass

        # Requirement 5: Raw-wire capture is authoritative. Always persist the trace.
        try:
            saved_path = save_hardware_trace(trace_record, trace_dir)
            print(f"[+] Trace persisted to: {saved_path}")
            trace_record["saved_trace_path"] = str(saved_path)
        except Exception as exc:
            print(f"[!] Warning: failed to persist trace: {exc}")

    print("=" * 72)
    print(f"  PROBE FINAL STATUS: {'SUCCESS' if exit_code == 0 else 'FAILURE'}")
    print("=" * 72)
    return exit_code, trace_record


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WinKFP-Research Controlled Physical K+DCAN Diagnostic Probe"
    )
    parser.add_argument(
        "--port",
        default=None,
        help="Serial port (e.g. /dev/cu.usbserial-A50285BI). REQUIRED with --confirm-readonly-hardware.",
    )
    parser.add_argument(
        "--baud",
        type=int,
        default=115200,
        help="Serial baud rate (default 115200 8N1).",
    )
    parser.add_argument(
        "--target",
        type=lambda x: int(x, 0),
        default=DEFAULT_TARGET_EGS,
        help="Target ECU diagnostic address (default 0x18 for ZF 6HP EGS).",
    )
    parser.add_argument(
        "--tester",
        type=lambda x: int(x, 0),
        default=DEFAULT_TESTER,
        help="Tester diagnostic address (default 0xF1).",
    )
    parser.add_argument(
        "--probe",
        choices=["aif", "tester_present", "ident", "physical_hw_nr"],
        default="aif",
        help="Read-only diagnostic probe to send (default: aif).",
    )

    parser.add_argument(
        "--confirm-readonly-hardware",
        action="store_true",
        help="Mandatory operator safety flag authorizing physical read-only communication.",
    )
    parser.add_argument(
        "--golden-compare",
        action="store_true",
        help="Compare captured raw wire traffic against historical golden evidence.",
    )
    parser.add_argument(
        "--trace-dir",
        type=Path,
        default=Path("traces/hardware"),
        help="Directory to save machine-readable JSON trace (default traces/hardware).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Response timeout in seconds (default 1.0).",
    )

    args = parser.parse_args()

    exit_code, _ = execute_probe(
        port=args.port,
        baud=args.baud,
        target=args.target,
        tester=args.tester,
        probe=args.probe,
        confirm_readonly_hardware=args.confirm_readonly_hardware,
        golden_compare=args.golden_compare,
        trace_dir=args.trace_dir,
        timeout=args.timeout,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
