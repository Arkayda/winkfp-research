"""Deterministic Golden Tests for K+DCAN DiagnosticTransport Adapter (Milestone 5.13).

STRICT HARDWARE QUARANTINE:
- Zero serial port opening.
- Zero network or ECU communication.
- No live hardware interaction.
- Does not instantiate SerialKdcanTransport.
- Validates pure byte-level pass-through, timeout handling, exception translation,
  upstream rejection of unsupported jobs, and integration with CanonicalPipeline
  and EdiabasJobReplayEngine.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from reconstruction.ediabas.job_model import SgbdJobResult
from reconstruction.ediabas.pipeline import CanonicalPipeline, ResponseValidator
from reconstruction.ediabas.replay import (
    EdiabasJobReplayEngine,
    EdiabasJobResult,
    EvidenceDomain,
)
from reconstruction.ediabas.trace_loader import load_trace_fixture
from reconstruction.ediabas.transport import (
    DiagnosticTransport,
    TransportError,
    TransportTimeoutError,
)
from reconstruction.transport.kdcan import (
    KdcanDiagnosticAdapter,
    KdcanError,
    KdcanTransport,
    ScriptedKdcanBackend,
    build as build_ds2_frame,
    checksum as ds2_checksum,
)
from reconstruction.transport.kdcan import adapter as adapter_module


class TestKdcanDiagnosticAdapter(unittest.TestCase):
    """Test suite for KdcanDiagnosticAdapter (Milestone 5.13)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parents[3]
        cls.ident_fixture_path = cls.repo_root / "traces" / "hardware" / "20260926_174811_egs_ident.json"
        cls.hw_fixture_path = cls.repo_root / "traces" / "hardware" / "20260926_175924_egs_physical_hw_nr.json"

        cls.pipeline = CanonicalPipeline()
        cls.replay_engine = EdiabasJobReplayEngine(pipeline=cls.pipeline)

    # ------------------------------------------------------------------------
    # Test 1: Protocol Compliance
    # ------------------------------------------------------------------------
    def test_01_protocol_compliance(self) -> None:
        """KdcanDiagnosticAdapter conforms to DiagnosticTransport Protocol."""
        backend = ScriptedKdcanBackend()
        adapter = KdcanDiagnosticAdapter(backend)

        self.assertTrue(isinstance(adapter, DiagnosticTransport))
        self.assertTrue(hasattr(adapter, "transceive_ds2"))
        self.assertTrue(callable(adapter.transceive_ds2))

    # ------------------------------------------------------------------------
    # Test 2: Byte-for-Byte TX Pass-Through
    # ------------------------------------------------------------------------
    def test_02_byte_for_byte_tx_passthrough(self) -> None:
        """Raw DS2 request bytes reach the backend completely unmodified."""
        raw_tx = bytes.fromhex("82 18 F1 1A 80 25")
        raw_rx = bytes.fromhex("82 F1 18 5A 80 45")
        backend = ScriptedKdcanBackend(responses={raw_tx: raw_rx})
        adapter = KdcanDiagnosticAdapter(backend)

        _ = adapter.transceive_ds2(raw_tx, timeout=0.5)

        self.assertEqual(len(backend.history), 1)
        delivered_frame, delivered_timeout = backend.history[0]
        self.assertEqual(delivered_frame, raw_tx)
        self.assertEqual(delivered_timeout, 0.5)

        self.assertEqual(len(adapter.history), 1)
        self.assertEqual(adapter.history[0], (raw_tx, 0.5))

    # ------------------------------------------------------------------------
    # Test 3: Byte-for-Byte RX Pass-Through
    # ------------------------------------------------------------------------
    def test_03_byte_for_byte_rx_passthrough(self) -> None:
        """Raw DS2 response bytes from backend return completely unmodified."""
        raw_tx = bytes.fromhex("82 18 F1 1A 80 25")
        raw_rx = bytes.fromhex("84 F1 18 5A 80 01 02 A0")
        backend = ScriptedKdcanBackend(responses={raw_tx: raw_rx})
        adapter = KdcanDiagnosticAdapter(backend)

        response = adapter.transceive_ds2(raw_tx)

        self.assertEqual(response, raw_rx)

    # ------------------------------------------------------------------------
    # Test 4: Timeout Translation
    # ------------------------------------------------------------------------
    def test_04_timeout_translation(self) -> None:
        """Backend timeout error is cleanly mapped to TransportTimeoutError."""
        raw_tx = bytes.fromhex("82 18 F1 1A 80 25")
        backend = ScriptedKdcanBackend(timeout_error=True)
        adapter = KdcanDiagnosticAdapter(backend)

        with self.assertRaises(TransportTimeoutError) as ctx:
            adapter.transceive_ds2(raw_tx, timeout=0.75)

        self.assertIn("timeout", str(ctx.exception).lower())

    # ------------------------------------------------------------------------
    # Test 5: Bus Error Translation
    # ------------------------------------------------------------------------
    def test_05_bus_error_translation(self) -> None:
        """Backend framing/bus error is cleanly mapped to TransportError."""
        raw_tx = bytes.fromhex("82 18 F1 1A 80 25")
        backend = ScriptedKdcanBackend(bus_error=KdcanError("Corrupted frame on bus"))
        adapter = KdcanDiagnosticAdapter(backend)

        with self.assertRaises(TransportError) as ctx:
            adapter.transceive_ds2(raw_tx)

        # Must be TransportError, NOT TransportTimeoutError
        self.assertFalse(isinstance(ctx.exception, TransportTimeoutError))
        self.assertIn("Corrupted frame on bus", str(ctx.exception))

    # ------------------------------------------------------------------------
    # Test 6: Generic Exception Translation
    # ------------------------------------------------------------------------
    def test_06_generic_exception_translation(self) -> None:
        """Generic low-level I/O failure is mapped to TransportError."""
        raw_tx = bytes.fromhex("82 18 F1 1A 80 25")
        backend = ScriptedKdcanBackend(bus_error=IOError("USB device disconnected"))
        adapter = KdcanDiagnosticAdapter(backend)

        with self.assertRaises(TransportError) as ctx:
            adapter.transceive_ds2(raw_tx)

        self.assertIn("USB device disconnected", str(ctx.exception))

    # ------------------------------------------------------------------------
    # Test 7: Timeout Parameter Preservation
    # ------------------------------------------------------------------------
    def test_07_timeout_parameter_preservation(self) -> None:
        """Custom timeout parameter is preserved across adapter calls."""
        raw_tx = bytes.fromhex("82 18 F1 1A 80 25")
        raw_rx = bytes.fromhex("82 F1 18 5A 80 45")
        backend = ScriptedKdcanBackend(responses={raw_tx: raw_rx})
        adapter = KdcanDiagnosticAdapter(backend)

        _ = adapter.transceive_ds2(raw_tx, timeout=3.5)

        self.assertEqual(backend.history[0][1], 3.5)
        self.assertEqual(adapter.history[0][1], 3.5)

    # ------------------------------------------------------------------------
    # Test 8: Arbitrary DS2 Frame Support (Pure Byte-Level Boundary)
    # ------------------------------------------------------------------------
    def test_08_arbitrary_ds2_frame_support(self) -> None:
        """Adapter handles arbitrary DS2 frames without inspecting jobs or payloads."""
        # Custom diagnostic frame (e.g. TesterPresent 3E 00)
        req_frame = build_ds2_frame(dst=0x18, src=0xF1, payload=b"\x3E\x00")
        resp_frame = build_ds2_frame(dst=0xF1, src=0x18, payload=b"\x7E\x00")

        backend = ScriptedKdcanBackend(responses={req_frame: resp_frame})
        adapter = KdcanDiagnosticAdapter(backend)

        result = adapter.transceive_ds2(req_frame)
        self.assertEqual(result, resp_frame)

    # ------------------------------------------------------------------------
    # Test 9: No SGBD or Job Semantics in Adapter
    # ------------------------------------------------------------------------
    def test_09_no_sgbd_or_job_semantics_in_adapter(self) -> None:
        """Adapter module and class do not depend on SGBD jobs or WinKFP logic."""
        backend = ScriptedKdcanBackend()
        adapter = KdcanDiagnosticAdapter(backend)

        # Class/instance checks
        self.assertFalse(hasattr(adapter, "job_name"))
        self.assertFalse(hasattr(adapter, "catalog"))
        self.assertFalse(hasattr(adapter, "sgbd"))
        self.assertFalse(hasattr(adapter, "evidence_domain"))

        # Module import checks: adapter module must not import pipeline or job_model
        module_source = Path(adapter_module.__file__).read_text()
        self.assertNotIn("reconstruction.ediabas.job_model", module_source)
        self.assertNotIn("reconstruction.ediabas.sgbd", module_source)
        self.assertNotIn("reconstruction.ediabas.pipeline", module_source)
        self.assertNotIn("reconstruction.ediabas.replay", module_source)

    # ------------------------------------------------------------------------
    # Test 10: Upstream Rejection of Unsupported Jobs Before Transport Dispatch
    # ------------------------------------------------------------------------
    def test_10_unsupported_job_rejected_upstream(self) -> None:
        """Unsupported jobs (FLASH_PROGRAMMIEREN) are rejected upstream; transport is never called."""
        backend = ScriptedKdcanBackend()
        adapter = KdcanDiagnosticAdapter(backend)

        # 1. EdiabasJobReplayEngine rejects unsupported job and NEVER invokes adapter
        result = self.replay_engine.execute_job("FLASH_PROGRAMMIEREN", transport=adapter)
        self.assertEqual(result.status, "ERROR_JOB_UNSUPPORTED")
        self.assertIn("unknown or unsupported", result.errors[0])
        self.assertEqual(len(adapter.history), 0, "Transport was unexpectedly called for unsupported job!")
        self.assertEqual(len(backend.history), 0)

        # 2. CanonicalPipeline raises NotImplementedError and NEVER invokes adapter
        with self.assertRaises(NotImplementedError):
            self.pipeline.execute_transport("FLASH_PROGRAMMIEREN", transport=adapter)
        self.assertEqual(len(adapter.history), 0, "Transport was unexpectedly called for unsupported job!")
        self.assertEqual(len(backend.history), 0)

    # ------------------------------------------------------------------------
    # Test 11: CanonicalPipeline Integration (IDENT via Scripted Backend)
    # ------------------------------------------------------------------------
    def test_11_canonical_pipeline_integration_ident(self) -> None:
        """Execute IDENT through CanonicalPipeline via KdcanDiagnosticAdapter."""
        fixture = load_trace_fixture(self.ident_fixture_path)
        backend = ScriptedKdcanBackend(responses={fixture.raw_tx: fixture.raw_rx})
        adapter = KdcanDiagnosticAdapter(backend)

        result: SgbdJobResult = self.pipeline.execute_transport("IDENT", transport=adapter)

        self.assertEqual(result.status, "OKAY")
        self.assertEqual(result.job_name, "IDENT")
        self.assertEqual(result.errors, [])
        self.assertEqual(result.fields["ID_BMW_NR"], "7591972")
        self.assertEqual(result.fields["ID_HW_NR"], "10")
        self.assertEqual(result.fields["ID_SW_NR_FSV"], "195.64.1")

        self.assertEqual(len(adapter.history), 1)
        self.assertEqual(adapter.history[0][0], fixture.raw_tx)

    # ------------------------------------------------------------------------
    # Test 12: EdiabasJobReplayEngine Integration (PHYSIKALISCHE_HW_NR_LESEN)
    # ------------------------------------------------------------------------
    def test_12_ediabas_replay_engine_integration_hwnr(self) -> None:
        """Execute PHYSIKALISCHE_HW_NR_LESEN through EdiabasJobReplayEngine via adapter."""
        fixture = load_trace_fixture(self.hw_fixture_path)
        backend = ScriptedKdcanBackend(responses={fixture.raw_tx: fixture.raw_rx})
        adapter = KdcanDiagnosticAdapter(backend)

        result: EdiabasJobResult = self.replay_engine.execute_job(
            "PHYSIKALISCHE_HW_NR_LESEN", transport=adapter
        )

        self.assertEqual(result.status, "OKAY")
        self.assertEqual(result.job_name, "PHYSIKALISCHE_HW_NR_LESEN")
        self.assertEqual(result.errors, [])
        self.assertEqual(result["PHYSIKALISCHE_HW_NR"], "7569980")
        self.assertEqual(len(adapter.history), 1)
        self.assertEqual(adapter.history[0][0], fixture.raw_tx)

    # ------------------------------------------------------------------------
    # Test 13: Negative ECU Response Pass-Through & Fail-Closed Validation
    # ------------------------------------------------------------------------
    def test_13_negative_ecu_response_passthrough(self) -> None:
        """Negative response (NRC 0x12) passes through adapter and is rejected by validator."""
        req_frame = bytes.fromhex("82 18 F1 1A 80 25")
        # DS2 NRC 0x12: dst=0xF1, src=0x18, payload=7F 1A 12
        nrc_payload = b"\x7F\x1A\x12"
        nrc_frame = build_ds2_frame(dst=0xF1, src=0x18, payload=nrc_payload)

        backend = ScriptedKdcanBackend(responses={req_frame: nrc_frame})
        adapter = KdcanDiagnosticAdapter(backend)

        result = self.pipeline.execute_transport("IDENT", transport=adapter)

        self.assertEqual(result.status, "ERROR_ECU_NEGATIVE_RESPONSE_0x12")
        self.assertEqual(len(result.errors), 1)
        self.assertIn("Negative response received with NRC 0x12", result.errors[0])

    # ------------------------------------------------------------------------
    # Test 14: auto_open Quarantine Default and Explicit Enable
    # ------------------------------------------------------------------------
    def test_14_auto_open_quarantine_default_and_explicit(self) -> None:
        """auto_open is False by default (quarantined); backend.open() only called if explicit."""
        req_frame = bytes.fromhex("82 18 F1 1A 80 25")
        resp_frame = bytes.fromhex("82 F1 18 5A 80 45")

        # 1. Default auto_open = False
        backend1 = ScriptedKdcanBackend(responses={req_frame: resp_frame})
        adapter_default = KdcanDiagnosticAdapter(backend1)
        self.assertFalse(adapter_default.auto_open)

        _ = adapter_default.transceive_ds2(req_frame)
        self.assertFalse(backend1.is_open, "backend.open() was called despite auto_open=False!")

        # 2. Explicit auto_open = True
        backend2 = ScriptedKdcanBackend(responses={req_frame: resp_frame})
        adapter_explicit = KdcanDiagnosticAdapter(backend2, auto_open=True)
        self.assertTrue(adapter_explicit.auto_open)

        _ = adapter_explicit.transceive_ds2(req_frame)
        self.assertTrue(backend2.is_open, "backend.open() was not called with auto_open=True!")

    # ------------------------------------------------------------------------
    # Test 15: Zero Physical Serial Port Access
    # ------------------------------------------------------------------------
    def test_15_zero_physical_serial_access(self) -> None:
        """Verify SerialKdcanTransport is never instantiated during test execution."""
        from reconstruction.transport.kdcan.serial import SerialKdcanTransport

        with patch.object(SerialKdcanTransport, "__init__", side_effect=AssertionError("PHYSICAL HARDWARE ACCESS VIOLATION")) as mock_init:
            backend = ScriptedKdcanBackend()
            adapter = KdcanDiagnosticAdapter(backend)
            self.assertIsNotNone(adapter)
            mock_init.assert_not_called()


if __name__ == "__main__":
    unittest.main()
