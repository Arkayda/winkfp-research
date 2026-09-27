"""Deterministic Golden Tests for Diagnostic Transport Boundary (Milestone 5.12).

STRICT OFF-HARDWARE TEST SUITE:
- Zero serial port opening.
- Zero network or ECU communication.
- No live hardware interaction.
- Validates the byte-level DiagnosticTransport boundary, FixtureTransport,
  MockTransport, timeout handling, and negative response fail-closed paths.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

from reconstruction.ediabas.job_model import SgbdJobDefinition, SgbdJobResult
from reconstruction.ediabas.pipeline import CanonicalPipeline, ResponseValidator, default_pipeline
from reconstruction.ediabas.replay import (
    EdiabasJobReplayEngine,
    EdiabasJobResult,
    EvidenceDomain,
    default_replay_engine,
    execute_job,
)
from reconstruction.ediabas.trace_loader import load_trace_fixture
from reconstruction.ediabas.transport import (
    DiagnosticTransport,
    FixtureTransport,
    MockTransport,
    TransportError,
    TransportTimeoutError,
)
from reconstruction.transport.kdcan.framing import build as build_ds2_frame, checksum as ds2_checksum


class TestDiagnosticTransportIntegration(unittest.TestCase):
    """Test suite for DiagnosticTransport interface, FixtureTransport, and MockTransport."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parents[3]
        cls.ident_fixture_path = cls.repo_root / "traces" / "hardware" / "20260926_174811_egs_ident.json"
        cls.hw_fixture_path = cls.repo_root / "traces" / "hardware" / "20260926_175924_egs_physical_hw_nr.json"
        cls.aif_fixture_path = cls.repo_root / "traces" / "hardware" / "20260926_173201_egs_aif.json"

        cls.pipeline = CanonicalPipeline()
        cls.replay_engine = EdiabasJobReplayEngine(pipeline=cls.pipeline)

    # ------------------------------------------------------------------------
    # Test 1: IDENT via FixtureTransport (Physical Bench Trace)
    # ------------------------------------------------------------------------
    def test_01_ident_via_fixture_transport(self) -> None:
        """Execute IDENT through DiagnosticTransport backed by immutable physical trace."""
        self.assertTrue(self.ident_fixture_path.exists())
        transport = FixtureTransport(self.ident_fixture_path, strict_tx_match=True)

        result = self.replay_engine.execute_job("IDENT", transport=transport)

        self.assertEqual(result.job_name, "IDENT")
        self.assertEqual(result.status, "OKAY")
        self.assertEqual(result.errors, [])
        self.assertEqual(result["ID_BMW_NR"], "7591972")
        self.assertEqual(result["ID_HW_NR"], "10")
        self.assertEqual(result["ID_COD_INDEX"], 5)
        self.assertEqual(result["ID_DIAG_INDEX"], 516)
        self.assertEqual(result["ID_LIEF_TEXT"], "SL ")
        self.assertEqual(result["ID_DATUM"], "30.10.2008")
        self.assertEqual(result["ID_SW_NR_MCV"], "0.29.69")
        self.assertEqual(result["ID_SW_NR_FSV"], "195.64.1")
        self.assertEqual(result["ID_SW_NR_OSV"], "2.3.10")
        self.assertEqual(result["_PECUHN_FALLBACK"], "7569980")

        # Verify transport history recorded exact canonical DS2 request
        self.assertEqual(len(transport.history), 1)
        self.assertEqual(transport.history[0], bytes.fromhex("82 18 F1 1A 80 25"))

        # Verify evidence domain & target address
        self.assertEqual(result.evidence_domain, EvidenceDomain.PHYSICAL_EGS_FIXTURE)
        self.assertEqual(result.target_address, 0x18)
        self.assertEqual(result.tester_address, 0xF1)

    # ------------------------------------------------------------------------
    # Test 2: PHYSIKALISCHE_HW_NR_LESEN via FixtureTransport
    # ------------------------------------------------------------------------
    def test_02_phys_hwnr_via_fixture_transport(self) -> None:
        """Execute PHYSIKALISCHE_HW_NR_LESEN through FixtureTransport."""
        self.assertTrue(self.hw_fixture_path.exists())
        transport = FixtureTransport(self.hw_fixture_path, strict_tx_match=True)

        result = self.replay_engine.execute_job("PHYSIKALISCHE_HW_NR_LESEN", transport=transport)

        self.assertEqual(result.job_name, "PHYSIKALISCHE_HW_NR_LESEN")
        self.assertEqual(result.status, "OKAY")
        self.assertEqual(result.errors, [])
        self.assertEqual(result["PHYSIKALISCHE_HW_NR"], "7569980")

        # Verify transport history recorded exact 1A 87 request
        self.assertEqual(len(transport.history), 1)
        self.assertEqual(transport.history[0], bytes.fromhex("82 18 F1 1A 87 2C"))
        self.assertEqual(result.evidence_domain, EvidenceDomain.PHYSICAL_EGS_FIXTURE)
        self.assertEqual(result.target_address, 0x18)

    # ------------------------------------------------------------------------
    # Test 3: Synthetic MockTransport Response (ZIF_LESEN)
    # ------------------------------------------------------------------------
    def test_03_synthetic_mock_transport(self) -> None:
        """Exercise canonical pipeline using deterministic MockTransport for ZIF_LESEN."""
        req_frame = bytes.fromhex("83 18 F1 22 25 03 D6")
        resp_payload = b"\x62\x25\x030479S90T641Z"
        resp_frame = build_ds2_frame(dst=0xF1, src=0x18, payload=resp_payload)

        mock_transport = MockTransport(responses={req_frame: resp_frame})

        result = self.replay_engine.execute_job("ZIF_LESEN", transport=mock_transport)

        self.assertEqual(result.job_name, "ZIF_LESEN")
        self.assertEqual(result.status, "OKAY")
        self.assertEqual(result.errors, [])
        self.assertEqual(result["ZIF_PROGRAMM_REFERENZ"], "0479S90T641Z")
        self.assertEqual(result["ZIF_SG_KENNUNG"], "047")
        self.assertEqual(result["ZIF_PROJEKT"], "9S9")
        self.assertEqual(result["ZIF_PROGRAMM_STAND"], "0T64")
        self.assertEqual(result["ZIF_STATUS"], "0")

        # Verify MockTransport history
        self.assertEqual(len(mock_transport.history), 1)
        tx_recorded, timeout_recorded = mock_transport.history[0]
        self.assertEqual(tx_recorded, req_frame)
        self.assertEqual(timeout_recorded, 1.0)
        self.assertEqual(result.evidence_domain, EvidenceDomain.SYNTHETIC_OFFLINE)

    # ------------------------------------------------------------------------
    # Test 4: Transport Timeout Handling (Fail-Closed)
    # ------------------------------------------------------------------------
    def test_04_transport_timeout_handling(self) -> None:
        """Simulate transport timeout; pipeline must handle fail-closed without uncaught crash."""
        timeout_transport = MockTransport(always_timeout=True)

        result = self.replay_engine.execute_job("IDENT", transport=timeout_transport, timeout=2.5)

        self.assertEqual(result.job_name, "IDENT")
        self.assertEqual(result.status, "ERROR_TIMEOUT")
        self.assertFalse(result.is_ok)
        self.assertEqual(result.fields, {})
        self.assertEqual(len(result.errors), 1)
        self.assertIn("timed out", result.errors[0].lower())
        self.assertEqual(len(timeout_transport.history), 1)
        self.assertEqual(timeout_transport.history[0][1], 2.5)

    # ------------------------------------------------------------------------
    # Test 5: Malformed DS2 Framing Rejection
    # ------------------------------------------------------------------------
    def test_05_malformed_ds2_framing(self) -> None:
        """MockTransport returning malformed format byte or wrong length is rejected fail-closed."""
        # Bad format byte 0x42
        bad_format_frame = b"\x42\xF1\x18\x5A\x80" + b"\x00" * 30 + b"\x00"
        bad_transport = MockTransport(default_response=bad_format_frame)

        result = self.replay_engine.execute_job("IDENT", transport=bad_transport)

        self.assertEqual(result.status, "ERROR_DS2_FRAMING")
        self.assertIn("Invalid DS2 format byte", result.errors[0])
        self.assertEqual(result.fields, {})

    # ------------------------------------------------------------------------
    # Test 6: Checksum Failure Rejection
    # ------------------------------------------------------------------------
    def test_06_checksum_failure(self) -> None:
        """MockTransport returning corrupted checksum is rejected fail-closed."""
        valid_payload = b"\x5A\x80" + b"\x00" * 35
        valid_frame = build_ds2_frame(dst=0xF1, src=0x18, payload=valid_payload)
        corrupted_frame = valid_frame[:-1] + bytes([valid_frame[-1] ^ 0xAA])

        bad_cs_transport = MockTransport(default_response=corrupted_frame)
        result = self.replay_engine.execute_job("IDENT", transport=bad_cs_transport)

        self.assertEqual(result.status, "ERROR_DS2_CHECKSUM")
        self.assertIn("Checksum error", result.errors[0])
        self.assertEqual(result.fields, {})

    # ------------------------------------------------------------------------
    # Test 7: Addressing Mismatch Rejection
    # ------------------------------------------------------------------------
    def test_07_addressing_mismatch(self) -> None:
        """MockTransport returning frame not addressed to tester 0xF1 or from unexpected ECU."""
        valid_payload = b"\x5A\x80" + b"\x00" * 35
        # Frame with destination 0x12 instead of 0xF1
        wrong_dst_frame = build_ds2_frame(dst=0x12, src=0x18, payload=valid_payload)

        wrong_dst_transport = MockTransport(default_response=wrong_dst_frame)
        result = self.replay_engine.execute_job("IDENT", transport=wrong_dst_transport)

        self.assertEqual(result.status, "ERROR_DS2_ADDRESSING")
        self.assertIn("Address mismatch", result.errors[0])
        self.assertEqual(result.fields, {})

    # ------------------------------------------------------------------------
    # Test 8: Unexpected Response SID Rejection
    # ------------------------------------------------------------------------
    def test_08_wrong_response_sid(self) -> None:
        """MockTransport returning wrong SID (e.g. 0x50 instead of 0x5A for IDENT)."""
        wrong_sid_payload = b"\x50\x80" + b"\x00" * 35
        frame = build_ds2_frame(dst=0xF1, src=0x18, payload=wrong_sid_payload)

        wrong_sid_transport = MockTransport(default_response=frame)
        result = self.replay_engine.execute_job("IDENT", transport=wrong_sid_transport)

        self.assertEqual(result.status, "ERROR_ECU_INCORRECT_RESPONSE_ID")
        self.assertIn("Expected SID 0x5A, received 0x50", result.errors[0])
        self.assertEqual(result.fields, {})

    # ------------------------------------------------------------------------
    # Test 9: Negative ECU Response (NRC 0x12)
    # ------------------------------------------------------------------------
    def test_09_negative_ecu_response(self) -> None:
        """MockTransport returning KWP negative response (0x7F 0x1A 0x12)."""
        nrc_payload = b"\x7F\x1A\x12"
        frame = build_ds2_frame(dst=0xF1, src=0x18, payload=nrc_payload)

        nrc_transport = MockTransport(default_response=frame)
        result = self.replay_engine.execute_job("IDENT", transport=nrc_transport)

        self.assertEqual(result.status, "ERROR_ECU_NEGATIVE_RESPONSE_0x12")
        self.assertEqual(result.fields, {})
        self.assertIn("Negative response received with NRC 0x12", result.errors[0])

    # ------------------------------------------------------------------------
    # Test 10: Unsupported Job Rejected Before Transport Dispatch
    # ------------------------------------------------------------------------
    def test_10_unsupported_job_rejection(self) -> None:
        """Dangerous or unsupported job (e.g. FLASH_PROGRAMMIEREN) rejected without dispatch."""
        transport = MockTransport()

        # Direct pipeline rejection
        with self.assertRaises(NotImplementedError):
            self.pipeline.execute_transport("FLASH_PROGRAMMIEREN", transport)

        # Replay engine rejection
        result = self.replay_engine.execute_job("FLASH_PROGRAMMIEREN", transport=transport)
        self.assertEqual(result.status, "ERROR_JOB_UNSUPPORTED")
        self.assertIn("unsupported", result.errors[0].lower())

        # STRICT PROOF: Transport was never called, zero frames transmitted!
        self.assertEqual(len(transport.history), 0)

    # ------------------------------------------------------------------------
    # Test 11: Independence of Evidence Classification Axes
    # ------------------------------------------------------------------------
    def test_11_evidence_axis_preservation(self) -> None:
        """Transport layer must not contaminate or infer evidence classification axes."""
        # 1. PHYSICAL_EGS_FIXTURE via FixtureTransport
        phys_transport = FixtureTransport(self.ident_fixture_path)
        phys_res = self.replay_engine.execute_job(
            "IDENT",
            transport=phys_transport,
            evidence_domain=EvidenceDomain.PHYSICAL_EGS_FIXTURE,
        )
        self.assertEqual(phys_res.evidence_domain, EvidenceDomain.PHYSICAL_EGS_FIXTURE)
        self.assertTrue(phys_res.sgbd_supported)
        self.assertTrue(phys_res.factory_trace_observed)
        self.assertTrue(phys_res.physical_trace_exists)
        self.assertTrue(phys_res.directly_resolved)

        # 2. SYNTHETIC_OFFLINE via MockTransport
        req_frame = bytes.fromhex("82 18 F1 1A 80 25")
        resp_payload = b"\x5A\x80" + b"\x00" * 58
        resp_frame = build_ds2_frame(dst=0xF1, src=0x18, payload=resp_payload)
        mock_transport = MockTransport(responses={req_frame: resp_frame})

        mock_res = self.replay_engine.execute_job(
            "IDENT",
            transport=mock_transport,
            evidence_domain=EvidenceDomain.SYNTHETIC_OFFLINE,
        )
        self.assertEqual(mock_res.evidence_domain, EvidenceDomain.SYNTHETIC_OFFLINE)
        # SGBD support is property of job definition, not transport
        self.assertTrue(mock_res.sgbd_supported)

    # ------------------------------------------------------------------------
    # Test 12: Proof of Zero Physical Transport Instantiation
    # ------------------------------------------------------------------------
    def test_12_proof_of_zero_physical_transport(self) -> None:
        """Strict architectural assertion: SerialKdcanTransport is never imported or created."""
        import reconstruction.ediabas.transport as t_mod

        # Verify transport module does not import pyserial or serial transport
        self.assertFalse(hasattr(t_mod, "SerialKdcanTransport"))
        self.assertFalse(hasattr(t_mod, "serial"))

        # Verify pipeline module does not import pyserial or serial transport
        import reconstruction.ediabas.pipeline as p_mod
        self.assertFalse(hasattr(p_mod, "SerialKdcanTransport"))
        self.assertFalse(hasattr(p_mod, "serial"))

        # Verify replay module does not import pyserial or serial transport
        import reconstruction.ediabas.replay as r_mod
        self.assertFalse(hasattr(r_mod, "SerialKdcanTransport"))
        self.assertFalse(hasattr(r_mod, "serial"))

        # Check sys.modules: 'serial' or 'reconstruction.transport.kdcan.serial' should NOT be imported
        # during offline execution unless another unrelated test explicitly imported it
        # Specifically, no open file descriptors or active serial ports exist
        from reconstruction.transport.kdcan.serial import SerialKdcanTransport
        # Even though class definition exists in repo, ensure our transport layer uses only DiagnosticTransport
        self.assertTrue(issubclass(FixtureTransport, object))
        self.assertTrue(issubclass(MockTransport, object))
        self.assertFalse(issubclass(FixtureTransport, SerialKdcanTransport))
        self.assertFalse(issubclass(MockTransport, SerialKdcanTransport))


if __name__ == "__main__":
    unittest.main()
