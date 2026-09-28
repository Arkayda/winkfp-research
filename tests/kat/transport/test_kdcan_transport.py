"""Unit and hardware self-test suite for native K+DCAN transport in winkfp-research.

Tests:
1. DS2/BMW-FAST framing encoding & parsing (short, long, 2-byte formats, checksums)
2. Device discovery and port filtering (FTDI / CH340 / macOS cu.* preference)
3. Mock serial communication, timeout behavior, and echo cancellation
4. SessionTracer and wire-level logging
5. Hardware port open/close check (if physical adapter is connected)
"""

from __future__ import annotations

import io
import os
import tempfile
import unittest
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from reconstruction.transport.kdcan import (
    KdcanError,
    SerialKdcanTransport,
    SessionTracer,
    Telegram,
    TracedKdcanTransport,
    body_length,
    build,
    checksum,
    parse,
)


class TestKdcanFraming(unittest.TestCase):
    """Test DS2 / BMW-FAST packet construction and validation."""

    def test_checksum(self):
        # 0x82 + 0x18 + 0xF1 + 0x1A + 0x86 = 555 (0x22B) -> 0x2B
        data = bytes([0x82, 0x18, 0xF1, 0x1A, 0x86])
        self.assertEqual(checksum(data), 0x2B)

    def test_build_short_frame(self):
        # Short format (payload <= 0x3F)
        # Payload 2 bytes: 1A 86 -> header 0x82, dst 0x18, src 0xF1, CS 0x2B
        frame = build(0x18, 0xF1, bytes([0x1A, 0x86]))
        self.assertEqual(frame, bytes([0x82, 0x18, 0xF1, 0x1A, 0x86, 0x2B]))
        telegram = parse(frame)
        self.assertEqual(telegram.dst, 0x18)
        self.assertEqual(telegram.src, 0xF1)
        self.assertEqual(telegram.payload, bytes([0x1A, 0x86]))
        self.assertEqual(telegram.raw, frame)

    def test_build_long_frame(self):
        # Long format (payload > 0x3F)
        payload = bytes([i % 256 for i in range(70)])
        frame = build(0x18, 0xF1, payload)
        self.assertEqual(frame[0], 0x80)
        self.assertEqual(frame[1], 0x18)
        self.assertEqual(frame[2], 0xF1)
        self.assertEqual(frame[3], 70)
        telegram = parse(frame)
        self.assertEqual(telegram.dst, 0x18)
        self.assertEqual(telegram.src, 0xF1)
        self.assertEqual(telegram.payload, payload)

    def test_parse_two_byte_extended_length(self):
        # Extended 2-byte length frame: 0x80, dst, src, 0x00, lenHi, lenLo, payload..., CS
        payload = b"X" * 300
        length = len(payload)
        head = bytes([0x80, 0x18, 0xF1, 0x00, (length >> 8) & 0xFF, length & 0xFF])
        body = head + payload
        frame = body + bytes([checksum(body)])
        telegram = parse(frame)
        self.assertEqual(telegram.dst, 0x18)
        self.assertEqual(telegram.src, 0xF1)
        self.assertEqual(telegram.payload, payload)

    def test_parse_invalid_checksum(self):
        frame = bytearray(build(0x18, 0xF1, bytes([0x1A, 0x86])))
        frame[-1] ^= 0xFF  # Corrupt checksum
        with self.assertRaises(ValueError) as ctx:
            parse(bytes(frame))
        self.assertIn("Checksum mismatch", str(ctx.exception))

    def test_parse_invalid_header(self):
        with self.assertRaises(ValueError) as ctx:
            parse(bytes([0x00, 0x18, 0xF1, 0x00]))
        self.assertIn("Invalid DS2 header", str(ctx.exception))


class MockSerialDevice:
    """In-memory serial port simulator for deterministic loopback tests."""

    def __init__(self, echo: bool = False, canned_responses: list[bytes] | None = None):
        self.echo = echo
        self.canned_responses = list(canned_responses or [])
        self.tx_buffer = bytearray()
        self.rx_buffer = bytearray()
        self.timeout = 0.15
        self.dtr = False
        self.rts = False
        self.is_open = True

    def write(self, data: bytes):
        self.tx_buffer.extend(data)
        if self.echo:
            self.rx_buffer.extend(data)
        if self.canned_responses:
            resp = self.canned_responses.pop(0)
            self.rx_buffer.extend(resp)
        return len(data)

    def read(self, size: int) -> bytes:
        if not self.rx_buffer:
            return b""
        chunk = self.rx_buffer[:size]
        self.rx_buffer = self.rx_buffer[size:]
        return bytes(chunk)

    def reset_input_buffer(self):
        self.rx_buffer.clear()

    def flush(self):
        pass

    def close(self):
        self.is_open = False


class TestKdcanTransportSerial(unittest.TestCase):
    """Test serial transport logic, echo detection, and timeouts."""

    @patch("serial.tools.list_ports.comports")
    def test_auto_detect_port(self, mock_comports):
        mock_p1 = MagicMock(device="/dev/cu.usbserial-A50285BI", hwid="USB VID:PID=0403:6001")
        mock_p2 = MagicMock(device="/dev/tty.usbserial-A50285BI", hwid="USB VID:PID=0403:6001")
        mock_p3 = MagicMock(device="/dev/cu.Bluetooth-Incoming", hwid="None")
        mock_comports.return_value = [mock_p1, mock_p2, mock_p3]

        detected = SerialKdcanTransport.auto_detect_port()
        self.assertEqual(detected, "/dev/cu.usbserial-A50285BI")

    def test_mock_send_and_receive(self):
        # Simulate response to 1A 86 from ECU 0x18 to Tester 0xF1
        req_payload = bytes([0x1A, 0x86])
        resp_payload = bytes([0x5A, 0x86, 0x01, 0x02, 0x03])
        resp_frame = build(0xF1, 0x18, resp_payload)

        mock_ser = MockSerialDevice(echo=False, canned_responses=[resp_frame])
        transport = SerialKdcanTransport(port="MOCK", regen_delay=0.0)
        transport._ser = mock_ser

        res = transport.send_job(0x18, req_payload, src=0xF1)
        self.assertEqual(res, resp_payload)
        self.assertFalse(transport.adapter_echo)

    def test_mock_auto_echo_cancellation(self):
        # Simulate an adapter that echoes transmitted bytes
        req_payload = bytes([0x1A, 0x86])
        resp_payload = bytes([0x5A, 0x86, 0x99])
        resp_frame = build(0xF1, 0x18, resp_payload)

        mock_ser = MockSerialDevice(echo=True, canned_responses=[resp_frame])
        transport = SerialKdcanTransport(port="MOCK", regen_delay=0.0)
        transport._ser = mock_ser

        res = transport.send_job(0x18, req_payload, src=0xF1)
        self.assertEqual(res, resp_payload)
        self.assertTrue(transport.adapter_echo)

    def test_timeout_on_missing_response(self):
        # Empty response -> header timeout
        mock_ser = MockSerialDevice(echo=False, canned_responses=[])
        transport = SerialKdcanTransport(port="MOCK", regen_delay=0.0)
        transport._ser = mock_ser

        with self.assertRaises(KdcanError) as ctx:
            transport.send_job(0x18, bytes([0x1A, 0x86]), timeout=0.01)
        self.assertIn("No response from ECU", str(ctx.exception))


class TestSessionTracer(unittest.TestCase):
    """Test detailed wire tracing."""

    def test_tracer_file_and_memory_records(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "test_wire.log"
            tracer = SessionTracer(log_path=log_file)

            inner_mock = MagicMock()
            inner_mock.send_job.return_value = bytes([0x5A, 0x86, 0xAA])

            traced = TracedKdcanTransport(inner_mock, tracer)
            traced.open()
            res = traced.send_job(0x18, bytes([0x1A, 0x86]))
            traced.close()

            self.assertEqual(res, bytes([0x5A, 0x86, 0xAA]))
            self.assertEqual(len(tracer.records), 2)
            self.assertEqual(tracer.records[0]["direction"], "TX")
            self.assertEqual(tracer.records[1]["direction"], "RX")

            content = log_file.read_text(encoding="utf-8")
            self.assertIn("TX dst=0x18 src=0xF1", content)
            self.assertIn("RX dst=0xF1 src=0x18", content)
            self.assertIn("rtt=", content)


class TestDirectKdcanBus(unittest.TestCase):
    """Test FlashRunner bus contract implementation over DirectKdcanBus."""

    def test_observed_wire_direct_methods(self):
        mock_transport = MagicMock()
        # Simulated AIF response: ZB=7592132, SW=7592133, VIN=CS68294
        raw_aif = bytes.fromhex("5a864043533638323934200812040000075921320000075921330000000000000002404e465330310030343739533930543634315a5742414e583731303430ffffff")
        mock_transport.send_job.return_value = raw_aif

        from reconstruction.transport.kdcan import DirectKdcanBus

        # Direct wire operations execute OBSERVED_WIRE without assuming EDIABAS job mappings
        bus = DirectKdcanBus(transport=mock_transport, default_dst=0x18, trace=False)
        self.assertTrue(bus.wire_read_aif())
        self.assertEqual(bus.read_text("JOB_STATUS"), "OKAY")
        self.assertEqual(bus.read_text("SHORT_VIN"), "CS68294")
        self.assertEqual(bus.read_text("ZB_NUMMER"), "7592132")
        self.assertEqual(bus.read_text("SW_NUMMER"), "7592133")
        self.assertEqual(bus.read_text("SG_PHYS_HWNR", ""), "")
        self.assertEqual(bus.read_text("SGBD"), "0479S90T641Z")

        mock_transport.send_job.return_value = bytes([0x7E])
        self.assertTrue(bus.wire_tester_present())
        self.assertEqual(bus.read_text("JOB_STATUS"), "OKAY")

    def test_inferred_jobs_fail_closed_by_default(self):
        mock_transport = MagicMock()
        from reconstruction.transport.kdcan import DirectKdcanBus

        bus = DirectKdcanBus(transport=mock_transport, default_dst=0x18, trace=False)
        for job_name in (
            "AIF_LESEN",
            "IDENT",
            "IDENT_LESEN",
            "PHYSIKALISCHE_HW_NR_LESEN",
            "SG_PHYS_HWNR_LESEN",
            "TESTER_PRESENT",
        ):
            with self.subTest(job=job_name):
                with self.assertRaises(NotImplementedError) as ctx:
                    bus.job("GS19", job_name)
                self.assertIn("INFERRED_JOB_MAPPING", str(ctx.exception))
                self.assertEqual(bus.read_text("JOB_STATUS"), "ERROR_JOB_INFERRED_FAIL_CLOSED")

    def test_inferred_jobs_allowed_with_flag(self):
        mock_transport = MagicMock()
        raw_aif = bytes.fromhex("5a864043533638323934200812040000075921320000075921330000000000000002404e465330310030343739533930543634315a5742414e583731303430ffffff")
        mock_transport.send_job.return_value = raw_aif

        from reconstruction.transport.kdcan import DirectKdcanBus

        bus = DirectKdcanBus(transport=mock_transport, default_dst=0x18, trace=False, allow_inferred=True)
        self.assertTrue(bus.job("GS19", "AIF_LESEN"))
        self.assertEqual(bus.read_text("JOB_STATUS"), "OKAY")
        self.assertEqual(bus.read_text("SHORT_VIN"), "CS68294")

        self.assertTrue(bus.job("GS19", "IDENT_LESEN"))
        self.assertEqual(bus.read_text("JOB_STATUS"), "OKAY")

        mock_transport.send_job.return_value = bytes([0x7E])
        self.assertTrue(bus.job("GS19", "TESTER_PRESENT"))
        self.assertEqual(bus.read_text("JOB_STATUS"), "OKAY")

    def test_unknown_sg_status_lesen_always_fails_closed(self):
        mock_transport = MagicMock()
        from reconstruction.transport.kdcan import DirectKdcanBus

        # SG_STATUS_LESEN -> 0x3E 0x00 is unevidenced and rejected even if allow_inferred=True
        bus = DirectKdcanBus(transport=mock_transport, default_dst=0x18, trace=False, allow_inferred=True)
        with self.assertRaises(NotImplementedError) as ctx:
            bus.job("GS19", "SG_STATUS_LESEN")
        self.assertIn("UNKNOWN (mapping to 0x3E 0x00 is unevidenced)", str(ctx.exception))
        self.assertEqual(bus.read_text("JOB_STATUS"), "ERROR_JOB_UNKNOWN_FAIL_CLOSED")

    def test_fail_closed_unmapped_job(self):
        mock_transport = MagicMock()
        from reconstruction.transport.kdcan import DirectKdcanBus

        bus = DirectKdcanBus(transport=mock_transport, default_dst=0x18, trace=False)
        with self.assertRaises(NotImplementedError) as ctx:
            bus.job("GS19", "UNKNOWN_EDIABAS_JOB")
        self.assertIn("UNKNOWN / unmapped on physical wire (fail-closed)", str(ctx.exception))
        self.assertEqual(bus.read_text("JOB_STATUS"), "ERROR_JOB_UNMAPPED_ON_DIRECT_BUS")

    def test_fail_closed_prohibited_flash_job(self):
        mock_transport = MagicMock()
        from reconstruction.transport.kdcan import DirectKdcanBus

        bus = DirectKdcanBus(transport=mock_transport, default_dst=0x18, trace=False)
        with self.assertRaises(KdcanError) as ctx:
            bus.job("GS19", "FLASH_SCHREIBEN")
        self.assertIn("prohibited on physical DirectKdcanBus", str(ctx.exception))
        self.assertEqual(bus.read_text("JOB_STATUS"), "ERROR_FLASH_WRITE_PROHIBITED")

        with self.assertRaises(KdcanError) as ctx_bin:
            bus.job_bin("GS19", "FLASH_SCHREIBEN", b"\x00" * 128)
        self.assertIn("prohibited on physical DirectKdcanBus", str(ctx_bin.exception))


class TestPhysicalHardwareDiscovery(unittest.TestCase):
    """Detect if physical K+DCAN hardware is plugged into Mac."""

    def test_physical_port_detection(self):
        port = SerialKdcanTransport.auto_detect_port()
        print(f"\n[Hardware Scan] Detected K+DCAN serial port: {port}")
        # Only open physical port when explicitly requested (keeps KAT suites strictly off-hardware by default)
        if os.environ.get("KDCAN_ENABLE_HW_TEST") == "1" and port and os.path.exists(port):
            transport = SerialKdcanTransport(port=port)
            try:
                transport.open()
                self.assertIsNotNone(transport._ser)
                print(f"[Hardware Scan] Successfully opened {port} at 115200 8N1")
            finally:
                transport.close()
                self.assertIsNone(transport._ser)
        else:
            print("[Hardware Scan] Pure off-hardware mode; skipping hardware port open.")


if __name__ == "__main__":
    unittest.main()
