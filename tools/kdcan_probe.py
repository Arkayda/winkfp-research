#!/usr/bin/env python3
"""Safe physical K+DCAN probe for BMW ECU diagnostics.

This tool executes ONLY safe, read-only diagnostic inquiries:
- Device discovery and serial connection (115200 8N1)
- TesterPresent (0x3E) keep-alive
- KWP2000 ReadECUIdentification (AIF 0x1A 0x86, Ident 0x1A 0x80, DS2 0x02)
- High-resolution timing (RTT) and raw wire tracing

STRICT SAFETY POLICY:
- Flash writing (FLASH_SCHREIBEN, SEND_SEGMENT), erasing, and calibration
  writes are completely ABSENT from this tool.
"""

from __future__ import annotations

import argparse
import datetime
import re
import sys
import time
from pathlib import Path
from typing import Optional

# Ensure winkfp-research root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from reconstruction.transport.kdcan import (
    KdcanError,
    SerialKdcanTransport,
    SessionTracer,
    TracedKdcanTransport,
)

# Standard Safe Payloads (READ-ONLY)
PAYLOAD_TESTER_PRESENT = bytes([0x3E, 0x00])
PAYLOAD_KWP_AIF = bytes([0x1A, 0x86])
PAYLOAD_KWP_IDENT = bytes([0x1A, 0x80])
PAYLOAD_DS2_IDENT = bytes([0x02])


def parse_aif_response(payload: bytes) -> Optional[dict]:
    """Parse KWP2000 0x1A 0x86 (BMW AIF) response payload."""
    if len(payload) < 20 or payload[0] != 0x5A or payload[1] != 0x86:
        return None
    res = {}
    try:
        # Short VIN (7 ASCII chars)
        short_raw = payload[3:10].decode("ascii", "ignore").strip()
        if re.match(r"^[A-HJ-NPR-Z0-9]{7}$", short_raw, re.IGNORECASE):
            res["short_vin"] = short_raw

        # Flash Date (BCD: YYYY MM DD)
        if len(payload) >= 14:
            res["flash_date"] = f"{payload[10]:02X}{payload[11]:02X}.{payload[12]:02X}.{payload[13]:02X}"

        # ZB Number
        if len(payload) >= 20:
            zb_bytes = payload[16:20]
            zb_str = f"{zb_bytes[0]:02X}{zb_bytes[1]:02X}{zb_bytes[2]:02X}{zb_bytes[3]:02X}".lstrip("0")
            if zb_str:
                res["zb_number"] = zb_str

        # SW Number
        if len(payload) >= 26:
            sw_bytes = payload[22:26]
            sw_str = f"{sw_bytes[0]:02X}{sw_bytes[1]:02X}{sw_bytes[2]:02X}{sw_bytes[3]:02X}".lstrip("0")
            if sw_str:
                res["sw_number"] = sw_str

        # Full ASCII scan for SGBD or Tool markers
        ascii_text = payload.decode("ascii", "ignore")
        sgbd_match = re.search(r"(\d{4}[A-Z0-9]{8})", ascii_text)
        if sgbd_match:
            res["sgbd"] = sgbd_match.group(1)
    except Exception as e:
        res["parse_error"] = str(e)
    return res


def run_probe(port: Optional[str], ecu_address: int, timeout: float, log_path: Optional[str]) -> int:
    detected_port = port or SerialKdcanTransport.auto_detect_port()
    print("=" * 68)
    print("  WinKFP Research — Direct K+DCAN Physical ECU Probe")
    print("=" * 68)
    print(f"Target Port     : {detected_port or '<None detected>'}")
    print(f"Target ECU Addr : 0x{ecu_address:02X} (e.g. 0x18=EGS, 0x12=DME)")
    print(f"Response Timeout: {timeout:.2f} s")
    print(f"Safety Mode     : STRICT READ-ONLY (No flash writes or erasing)")

    if not detected_port:
        print("\n[ERROR] No physical K+DCAN serial port detected. Please connect your USB cable.")
        return 1

    tracer = SessionTracer(log_path=log_path)
    base_transport = SerialKdcanTransport(port=detected_port, response_timeout=timeout)
    traced_transport = TracedKdcanTransport(base_transport, tracer)

    try:
        traced_transport.open()
        print(f"\n[+] Opened port {detected_port} (115200 8N1).")
        tracer.log_comment(f"Probing ECU 0x{ecu_address:02X} on port {detected_port}")

        # Step 1: TesterPresent
        print("\n--- [Step 1] Sending TesterPresent (0x3E 0x00) ---")
        try:
            t0 = time.perf_counter()
            resp = traced_transport.send_job(ecu_address, PAYLOAD_TESTER_PRESENT, timeout=timeout)
            rtt = (time.perf_counter() - t0) * 1000.0
            print(f"    ECU Response: {resp.hex(' ')} (RTT: {rtt:.1f} ms)")
            if resp and resp[0] == 0x7E:
                print("    -> Positive response: TesterPresent ACK (0x7E)")
            elif resp and resp[0] == 0x7F:
                print(f"    -> Negative response: NRC 0x{resp[2]:02X}")
        except KdcanError as e:
            print(f"    [!] TesterPresent failed: {e}")

        # Step 2: Read Identification
        print("\n--- [Step 2] Reading ECU Identification ---")
        ident_success = False
        for name, query in [
            ("KWP2000 AIF (0x1A 0x86)", PAYLOAD_KWP_AIF),
            ("KWP2000 Ident (0x1A 0x80)", PAYLOAD_KWP_IDENT),
            ("Classic DS2 Ident (0x02)", PAYLOAD_DS2_IDENT),
        ]:
            try:
                print(f"    Querying {name}...")
                t0 = time.perf_counter()
                resp = traced_transport.send_job(ecu_address, query, timeout=timeout)
                rtt = (time.perf_counter() - t0) * 1000.0
                print(f"    Raw Response ({len(resp)} bytes, {rtt:.1f} ms): {resp.hex(' ')}")

                if resp and resp[0] == 0x7F:
                    print(f"    -> NRC 0x{resp[2]:02X} (Service Rejected)")
                    continue

                ident_success = True
                if query == PAYLOAD_KWP_AIF:
                    parsed = parse_aif_response(resp)
                    if parsed:
                        print("    [Decoded AIF Data]:")
                        for k, v in parsed.items():
                            print(f"      - {k:12s}: {v}")
                break
            except KdcanError as e:
                print(f"    [!] {name} failed: {e}")

        print("\n" + "=" * 68)
        if ident_success:
            print("  PROBE STATUS: SUCCESS (ECU communication established)")
        else:
            print("  PROBE STATUS: NO RESPONSE FROM ECU (Check power/ignition & K-Line)")
        print(f"  Complete wire trace saved to: {tracer.log_path}")
        print("=" * 68)
        return 0 if ident_success else 2

    except Exception as e:
        print(f"\n[FATAL ERROR] {e}")
        return 1
    finally:
        traced_transport.close()


def main():
    parser = argparse.ArgumentParser(description="WinKFP-Research Physical K+DCAN ECU Probe")
    parser.add_argument("--port", help="Serial port (e.g. /dev/cu.usbserial-A50285BI)")
    parser.add_argument("--address", type=lambda x: int(x, 0), default=0x18, help="Target ECU address (hex, default 0x18 for EGS)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Response timeout in seconds (default 1.0)")
    parser.add_argument("--log", help="Path to wire trace log file")
    args = parser.parse_args()

    sys.exit(run_probe(args.port, args.address, args.timeout, args.log))


if __name__ == "__main__":
    main()
