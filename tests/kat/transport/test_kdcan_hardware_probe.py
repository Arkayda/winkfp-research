"""Unit tests for tools/kdcan_hardware_probe.py and transport raw-wire capabilities.

STRICTLY OFF-HARDWARE:
- Uses mock transports and mock devices only.
- Never opens physical serial devices.
- Validates safety gates, golden comparison, JSON trace schema, and error paths.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from reconstruction.transport.kdcan import (
    KdcanError,
    KdcanTransport,
    SerialKdcanTransport,
    framing,
)
from tools.kdcan_hardware_probe import (
    DEFAULT_TARGET_EGS,
    DEFAULT_TESTER,
    GOLDEN_EVIDENCE,
    compare_with_golden,
    execute_probe,
    parse_aif_payload,
    sanitize_vin,
    save_hardware_trace,
)


class MockSafeKdcanTransport(KdcanTransport):
    """Deterministic in-memory mock transport for hardware probe unit tests."""

    def __init__(self, canned_response_frame: bytes | None = None, should_fail: bool = False):
        self.canned_response_frame = canned_response_frame
        self.should_fail = should_fail
        self.is_open = False
        self.sent_jobs: list[tuple[int, bytes, int]] = []

    def open(self) -> None:
        self.is_open = True

    def close(self) -> None:
        self.is_open = False

    def send_job_raw(
        self,
        dst: int,
        payload: bytes,
        src: int = 0xF1,
        timeout: float | None = None,
    ) -> tuple[bytes, bytes, bytes, float]:
        if not self.is_open:
            raise KdcanError("Transport is closed")
        self.sent_jobs.append((dst, payload, src))
        if self.should_fail:
            raise KdcanError("Simulated transport bus error")
        raw_tx = framing.build(dst, src, payload)
        if self.canned_response_frame is None:
            raise KdcanError("No response configured in mock")
        parsed = framing.parse(self.canned_response_frame)
        return raw_tx, self.canned_response_frame, parsed.payload, 25.5

    def send_job(
        self,
        dst: int,
        payload: bytes,
        src: int = 0xF1,
        timeout: float | None = None,
    ) -> bytes:
        _tx, _rx, parsed_payload, _rtt = self.send_job_raw(dst, payload, src=src, timeout=timeout)
        return parsed_payload


class TestHardwareProbeSafetyInterlocks(unittest.TestCase):
    """Test safety gates and parameter enforcement."""

    def test_gate_confirmation_flag_required(self):
        exit_code, trace = execute_probe(
            port="/dev/null",
            confirm_readonly_hardware=False,
        )
        self.assertEqual(exit_code, 1)
        self.assertEqual(trace["result"], "ERROR_CONFIRMATION_REQUIRED")

    def test_gate_explicit_port_required_when_confirmed(self):
        # Requirement 4: explicit --port required, auto-detect disallowed
        exit_code, trace = execute_probe(
            port=None,
            confirm_readonly_hardware=True,
        )
        self.assertEqual(exit_code, 1)
        self.assertEqual(trace["result"], "ERROR_EXPLICIT_PORT_REQUIRED")

    def test_gate_invalid_target_rejected(self):
        exit_code, trace = execute_probe(
            port="/dev/null",
            target=0x12,  # DME address instead of EGS 0x18
            confirm_readonly_hardware=True,
        )
        self.assertEqual(exit_code, 1)
        self.assertEqual(trace["result"], "ERROR_INVALID_TARGET")

    def test_gate_invalid_tester_rejected(self):
        exit_code, trace = execute_probe(
            port="/dev/null",
            tester=0xF2,
            confirm_readonly_hardware=True,
        )
        self.assertEqual(exit_code, 1)
        self.assertEqual(trace["result"], "ERROR_INVALID_TESTER")

    def test_gate_unknown_probe_rejected(self):
        exit_code, trace = execute_probe(
            port="/dev/null",
            probe="dangerous_flash_command",
            confirm_readonly_hardware=True,
        )
        self.assertEqual(exit_code, 1)
        self.assertEqual(trace["result"], "ERROR_UNKNOWN_PROBE")

    def test_exact_3e00_frame_construction(self):
        # Task 2: exact 82 18 F1 3E 00 C9 frame construction
        frame = framing.build(0x18, 0xF1, bytes([0x3E, 0x00]))
        self.assertEqual(frame, bytes([0x82, 0x18, 0xF1, 0x3E, 0x00, 0xC9]))
        self.assertEqual(frame[-1], 0xC9)
        self.assertEqual(framing.checksum(frame[:-1]), 0xC9)

    def test_exact_1a80_frame_construction(self):
        # Milestone 5.2 Phase 1: exact 82 18 F1 1A 80 25 frame construction
        frame = framing.build(0x18, 0xF1, bytes([0x1A, 0x80]))
        self.assertEqual(frame, bytes([0x82, 0x18, 0xF1, 0x1A, 0x80, 0x25]))
        self.assertEqual(frame[-1], 0x25)
        self.assertEqual(framing.checksum(frame[:-1]), 0x25)

    def test_exact_1a87_frame_construction(self):
        # Milestone 5.3 Phase 1: exact 82 18 F1 1A 87 2C frame construction
        frame = framing.build(0x18, 0xF1, bytes([0x1A, 0x87]))
        self.assertEqual(frame, bytes([0x82, 0x18, 0xF1, 0x1A, 0x87, 0x2C]))
        self.assertEqual(frame[-1], 0x2C)
        self.assertEqual(framing.checksum(frame[:-1]), 0x2C)


    def test_forbidden_services_blocked(self):
        # Task 5: 0x10, 0x27, 0x31, 0x11, reset, flash must be rejected
        for bad_probe in ("0x10", "0x27", "0x31", "0x11", "reset", "flash", "flash_schreiben"):
            with self.subTest(probe=bad_probe):
                exit_code, trace = execute_probe(
                    port="/dev/null",
                    probe=bad_probe,
                    confirm_readonly_hardware=True,
                )
                self.assertEqual(exit_code, 1)
                self.assertEqual(trace["result"], "ERROR_UNKNOWN_PROBE")

    def test_no_automatic_retry_on_failure(self):
        # Task 5: exactly one request sent, no automatic retry on error
        mock_transport = MockSafeKdcanTransport(should_fail=True)
        with tempfile.TemporaryDirectory() as tmpdir:
            trace_dir = Path(tmpdir)
            exit_code, trace = execute_probe(
                port="MOCK_PORT",
                probe="tester_present",
                confirm_readonly_hardware=True,
                trace_dir=trace_dir,
                transport_override=mock_transport,
            )
            self.assertEqual(exit_code, 1)
            # Verify trace persisted and only 1 trace file created
            trace_files = list(trace_dir.glob("*.json"))
            self.assertEqual(len(trace_files), 1)

    def test_no_retry_and_single_request_for_physical_hw_nr(self):
        # Milestone 5.3: exactly one 1A 87 request sent, no retry on error
        mock_transport = MockSafeKdcanTransport(should_fail=True)
        with tempfile.TemporaryDirectory() as tmpdir:
            trace_dir = Path(tmpdir)
            exit_code, trace = execute_probe(
                port="MOCK_PORT",
                probe="physical_hw_nr",
                confirm_readonly_hardware=True,
                trace_dir=trace_dir,
                transport_override=mock_transport,
            )
            self.assertEqual(exit_code, 1)
            self.assertEqual(len(mock_transport.sent_jobs), 1)
            trace_files = list(trace_dir.glob("*.json"))
            self.assertEqual(len(trace_files), 1)



class TestAifParsingAndSanitization(unittest.TestCase):
    """Test AIF payload decoding and vehicle privacy sanitization."""

    def test_sanitize_vin(self):
        # 17-char VIN masks last 7 characters
        self.assertEqual(sanitize_vin("WBANX71040CS68294"), "WBANX71040XXXXXXX")
        # Short strings
        self.assertEqual(sanitize_vin("CS68294"), "CS68294")

    def test_parse_valid_aif_payload(self):
        golden_payload = GOLDEN_EVIDENCE["aif"]["rx_payload"]
        parsed = parse_aif_payload(golden_payload)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["short_vin"], "CS68294")
        self.assertEqual(parsed["flash_date"], "2008.12.04")
        self.assertEqual(parsed["zb_number"], "7592132")
        self.assertEqual(parsed["sw_number"], "7592133")
        self.assertEqual(parsed["sgbd"], "0479S90T641Z")
        self.assertEqual(parsed["tool_marker"], "NFS01")
        self.assertEqual(parsed["chassis_vin_sanitized"], "WBANX71040XXXXXXX")

    def test_parse_invalid_aif_header(self):
        # Negative response or different service payload
        self.assertIsNone(parse_aif_payload(bytes([0x7F, 0x1A, 0x12])))
        self.assertIsNone(parse_aif_payload(bytes([0x5A, 0x80, 0x01])))


class TestGoldenEvidenceComparison(unittest.TestCase):
    """Test comparing live wire bytes against historical reference."""

    def test_exact_golden_match_aif(self):
        tx = GOLDEN_EVIDENCE["aif"]["tx_raw"]
        rx = GOLDEN_EVIDENCE["aif"]["rx_raw"]
        res = compare_with_golden("aif", tx, rx)
        self.assertEqual(res["status"], "EXACT_BYTE_MATCH")
        self.assertTrue(res["tx_match"])
        self.assertTrue(res["rx_exact_match"])
        self.assertEqual(len(res["differences"]), 0)

    def test_exact_golden_match_tester_present(self):
        tx = GOLDEN_EVIDENCE["tester_present"]["tx_raw"]
        rx = GOLDEN_EVIDENCE["tester_present"]["rx_raw"]
        res = compare_with_golden("tester_present", tx, rx)
        self.assertEqual(res["status"], "EXACT_BYTE_MATCH")
        self.assertTrue(res["tx_match"])
        self.assertTrue(res["rx_exact_match"])

    def test_mismatch_detection(self):
        tx = GOLDEN_EVIDENCE["aif"]["tx_raw"]
        # Corrupt both header and payload byte in rx to test MISMATCH
        rx = bytearray(GOLDEN_EVIDENCE["aif"]["rx_raw"])
        rx[1] ^= 0xFF  # Corrupt destination in header
        rx[10] ^= 0xFF # Corrupt payload
        res = compare_with_golden("aif", tx, bytes(rx))
        self.assertEqual(res["status"], "MISMATCH")
        self.assertFalse(res["rx_exact_match"])
        self.assertFalse(res["header_match"])
        self.assertFalse(res["payload_match"])
        self.assertTrue(len(res["differences"]) > 0)


    def test_golden_status_header_match_only(self):
        # Header matches (83 F1 18 ...), but payload differs (7F 10 22 instead of 7F 3E 12)
        tx = GOLDEN_EVIDENCE["tester_present"]["tx_raw"]
        diff_payload = bytes([0x7F, 0x10, 0x22])
        rx_diff_payload = framing.build(0xF1, 0x18, diff_payload)
        res = compare_with_golden("tester_present", tx, rx_diff_payload)
        self.assertEqual(res["status"], "HEADER_MATCH_ONLY")
        self.assertTrue(res["tx_match"])
        self.assertFalse(res["rx_exact_match"])
        self.assertTrue(res["header_match"])
        self.assertFalse(res["payload_match"])

    def test_golden_status_payload_match_only(self):
        # Long header format (0x80 F1 18 03) instead of short format (0x83 F1 18),
        # but payload is identical: 7F 3E 12
        tx = GOLDEN_EVIDENCE["tester_present"]["tx_raw"]
        payload = bytes([0x7F, 0x3E, 0x12])
        body = bytes([0x80, 0xF1, 0x18, len(payload)]) + payload
        long_frame = body + bytes([framing.checksum(body)])
        res = compare_with_golden("tester_present", tx, long_frame)
        self.assertEqual(res["status"], "PAYLOAD_MATCH_ONLY")
        self.assertTrue(res["tx_match"])
        self.assertFalse(res["rx_exact_match"])
        self.assertFalse(res["header_match"])
        self.assertTrue(res["payload_match"])

    def test_golden_status_unknown_when_no_reference(self):
        # Explicit test for UNKNOWN when no golden reference is available (Milestone 5.1 Requirement 1)
        res = compare_with_golden("nonexistent_probe_xyz", bytes([0x01]), bytes([0x02]))
        self.assertEqual(res["status"], "UNKNOWN")
        self.assertFalse(res["tx_match"])
        self.assertFalse(res["rx_exact_match"])
        self.assertIn("No golden reference available", res["details"])

    def test_golden_status_unknown_for_ident(self):
        # Milestone 5.2: No physical 1A 80 golden response exists yet, must return UNKNOWN
        tx = bytes([0x82, 0x18, 0xF1, 0x1A, 0x80, 0x25])
        rx = bytes([0x83, 0xF1, 0x18, 0x7F, 0x1A, 0x12, 0x53])
        res = compare_with_golden("ident", tx, rx)
        self.assertEqual(res["status"], "UNKNOWN")
        self.assertFalse(res["tx_match"])
        self.assertFalse(res["rx_exact_match"])
        self.assertIn("No golden reference available", res["details"])

    def test_golden_status_unknown_for_physical_hw_nr(self):
        # Milestone 5.3: No physical 1A 87 golden response exists yet, must return UNKNOWN
        tx = bytes([0x82, 0x18, 0xF1, 0x1A, 0x87, 0x2C])
        rx = bytes([0x83, 0xF1, 0x18, 0x7F, 0x1A, 0x12, 0x54])
        res = compare_with_golden("physical_hw_nr", tx, rx)
        self.assertEqual(res["status"], "UNKNOWN")
        self.assertFalse(res["tx_match"])
        self.assertFalse(res["rx_exact_match"])
        self.assertIn("No golden reference available", res["details"])




class TestHardwareProbeMockExecution(unittest.TestCase):
    """Test full probe execution flow with mock transport (100% off-hardware)."""

    def test_mock_successful_aif_run(self):
        canned_rx = GOLDEN_EVIDENCE["aif"]["rx_raw"]
        mock_transport = MockSafeKdcanTransport(canned_response_frame=canned_rx)

        with tempfile.TemporaryDirectory() as tmpdir:
            trace_dir = Path(tmpdir)
            exit_code, trace = execute_probe(
                port="MOCK_PORT",
                confirm_readonly_hardware=True,
                golden_compare=True,
                trace_dir=trace_dir,
                transport_override=mock_transport,
            )

            self.assertEqual(exit_code, 0)
            self.assertEqual(trace["result"], "SUCCESS")
            self.assertEqual(trace["evidence_class"], "OBSERVED_WIRE")
            self.assertTrue(trace["checksum_valid"])
            self.assertEqual(trace["rx_len"], 71)
            self.assertEqual(trace["parsed"]["short_vin"], "CS68294")
            self.assertEqual(trace["golden_comparison"]["status"], "EXACT_BYTE_MATCH")

            # Check JSON trace persisted on disk
            saved_trace = Path(trace["saved_trace_path"])
            self.assertTrue(saved_trace.exists())
            with open(saved_trace, encoding="utf-8") as f:
                loaded = json.load(f)
            self.assertEqual(loaded["mode"], "HARDWARE_READ_ONLY")
            self.assertEqual(loaded["target"], "0x18")
            self.assertEqual(loaded["tester"], "0xF1")
            self.assertEqual(loaded["tx"], "82 18 f1 1a 86 2b")
            self.assertIn("rx", loaded)
            self.assertEqual(loaded["evidence_class"], "OBSERVED_WIRE")

    def test_mock_successful_tester_present_run(self):
        canned_rx = GOLDEN_EVIDENCE["tester_present"]["rx_raw"]
        mock_transport = MockSafeKdcanTransport(canned_response_frame=canned_rx)

        with tempfile.TemporaryDirectory() as tmpdir:
            trace_dir = Path(tmpdir)
            exit_code, trace = execute_probe(
                port="MOCK_PORT",
                probe="tester_present",
                confirm_readonly_hardware=True,
                golden_compare=True,
                trace_dir=trace_dir,
                transport_override=mock_transport,
            )

            self.assertEqual(exit_code, 0)
            self.assertEqual(trace["result"], "SUCCESS")
            self.assertEqual(trace["parser_result"], "SUCCESS")
            self.assertEqual(trace["raw_tx"], "82 18 f1 3e 00 c9")
            self.assertEqual(trace["raw_rx"], "83 f1 18 7f 3e 12 5b")
            self.assertEqual(trace["tx"], "82 18 f1 3e 00 c9")
            self.assertEqual(trace["rx"], "83 f1 18 7f 3e 12 5b")
            self.assertTrue(trace["checksum_valid"])
            self.assertIsInstance(trace["rtt_ms"], float)
            self.assertEqual(trace["golden_comparison"]["status"], "EXACT_BYTE_MATCH")

            # Check JSON trace persisted on disk
            saved_trace = Path(trace["saved_trace_path"])
            self.assertTrue(saved_trace.exists())
            with open(saved_trace, encoding="utf-8") as f:
                loaded = json.load(f)
            self.assertEqual(loaded["mode"], "HARDWARE_READ_ONLY")
            self.assertEqual(loaded["probe"], "tester_present")
            self.assertEqual(loaded["raw_tx"], "82 18 f1 3e 00 c9")
            self.assertEqual(loaded["raw_rx"], "83 f1 18 7f 3e 12 5b")
            self.assertEqual(loaded["parser_result"], "SUCCESS")
            self.assertEqual(loaded["evidence_class"], "OBSERVED_WIRE")

    def test_mock_successful_ident_run(self):
        # Milestone 5.2: Ident (1A 80) mock run with positive response
        canned_payload = bytes([0x5A, 0x80, 0x30, 0x34, 0x37, 0x39])
        canned_rx = framing.build(0xF1, 0x18, canned_payload)
        mock_transport = MockSafeKdcanTransport(canned_response_frame=canned_rx)

        with tempfile.TemporaryDirectory() as tmpdir:
            trace_dir = Path(tmpdir)
            exit_code, trace = execute_probe(
                port="MOCK_PORT",
                probe="ident",
                confirm_readonly_hardware=True,
                golden_compare=True,
                trace_dir=trace_dir,
                transport_override=mock_transport,
            )

            self.assertEqual(exit_code, 0)
            self.assertEqual(trace["result"], "SUCCESS")
            self.assertEqual(trace["parser_result"], "SUCCESS")
            self.assertEqual(trace["raw_tx"], "82 18 f1 1a 80 25")
            self.assertEqual(trace["probe"], "ident")
            self.assertEqual(trace["evidence_class"], "OBSERVED_WIRE")
            self.assertEqual(trace["golden_comparison"]["status"], "UNKNOWN")
            self.assertEqual(trace["parsed"]["sid"], "0x5A")
            self.assertEqual(trace["parsed"]["record_id"], "0x80")

    def test_mock_successful_physical_hw_nr_run(self):
        # Milestone 5.3: Physical HW Nr (1A 87) mock run with positive response
        canned_payload = bytes([0x5A, 0x87, 0x00, 0x00, 0x09, 0x16, 0x56, 0x72])
        canned_rx = framing.build(0xF1, 0x18, canned_payload)
        mock_transport = MockSafeKdcanTransport(canned_response_frame=canned_rx)

        with tempfile.TemporaryDirectory() as tmpdir:
            trace_dir = Path(tmpdir)
            exit_code, trace = execute_probe(
                port="MOCK_PORT",
                probe="physical_hw_nr",
                confirm_readonly_hardware=True,
                golden_compare=True,
                trace_dir=trace_dir,
                transport_override=mock_transport,
            )

            self.assertEqual(exit_code, 0)
            self.assertEqual(trace["result"], "SUCCESS")
            self.assertEqual(trace["parser_result"], "SUCCESS")
            self.assertEqual(trace["raw_tx"], "82 18 f1 1a 87 2c")
            self.assertEqual(trace["probe"], "physical_hw_nr")
            self.assertEqual(trace["evidence_class"], "OBSERVED_WIRE")
            self.assertEqual(trace["golden_comparison"]["status"], "UNKNOWN")
            self.assertEqual(trace["parsed"]["sid"], "0x5A")
            self.assertEqual(trace["parsed"]["record_id"], "0x87")
            self.assertEqual(len(mock_transport.sent_jobs), 1)  # Exactly one request transmitted
            trace_files = list(trace_dir.glob("*_egs_physical_hw_nr.json"))
            self.assertEqual(len(trace_files), 1)



    def test_mock_transport_error_persists_raw_trace(self):
        # Requirement 5: Raw-wire capture is authoritative. Persist trace even on failure.
        mock_transport = MockSafeKdcanTransport(should_fail=True)

        with tempfile.TemporaryDirectory() as tmpdir:
            trace_dir = Path(tmpdir)
            exit_code, trace = execute_probe(
                port="MOCK_PORT",
                confirm_readonly_hardware=True,
                trace_dir=trace_dir,
                transport_override=mock_transport,
            )

            self.assertEqual(exit_code, 1)
            self.assertIn("ERROR_TRANSPORT", trace["result"])
            # Even on error, trace file must exist
            self.assertIn("saved_trace_path", trace)
            self.assertTrue(Path(trace["saved_trace_path"]).exists())


class TestSendJobRawAndCompatibility(unittest.TestCase):
    """Verify send_job_raw returns 4-tuple and send_job preserves existing API."""

    def test_send_job_raw_returns_4_tuple(self):
        mock_ser = MagicMock()
        # Mock canned response for 1A 86
        resp_payload = bytes([0x5A, 0x86, 0x11, 0x22])
        resp_frame = framing.build(0xF1, 0x18, resp_payload)

        # Mock serial device read behavior
        mock_ser.timeout = 0.15
        mock_ser.read.side_effect = [
            resp_frame[:4],     # header
            resp_frame[4:],     # rest of frame
        ]

        transport = SerialKdcanTransport(port="MOCK_PORT", regen_delay=0.0)
        transport._ser = mock_ser

        tx_frame, rx_frame, payload, rtt_ms = transport.send_job_raw(0x18, bytes([0x1A, 0x86]))
        self.assertEqual(tx_frame, bytes([0x82, 0x18, 0xF1, 0x1A, 0x86, 0x2B]))
        self.assertEqual(rx_frame, resp_frame)
        self.assertEqual(payload, resp_payload)
        self.assertIsInstance(rtt_ms, float)
        self.assertGreaterEqual(rtt_ms, 0.0)

    def test_send_job_preserves_payload_return(self):
        mock_ser = MagicMock()
        resp_payload = bytes([0x5A, 0x86, 0x33, 0x44])
        resp_frame = framing.build(0xF1, 0x18, resp_payload)

        mock_ser.timeout = 0.15
        mock_ser.read.side_effect = [
            resp_frame[:4],
            resp_frame[4:],
        ]

        transport = SerialKdcanTransport(port="MOCK_PORT", regen_delay=0.0)
        transport._ser = mock_ser

        # send_job must return bytes payload directly (existing API contract)
        result = transport.send_job(0x18, bytes([0x1A, 0x86]))
        self.assertEqual(result, resp_payload)
        self.assertIsInstance(result, bytes)


if __name__ == "__main__":
    unittest.main()
