"""Deterministic Golden Tests for Canonical Offline GKE195 Pipeline (Milestone 5.9).

STRICTLY OFF-HARDWARE:
- Zero serial port opening.
- Zero network or ECU communication.
- Validates the unified 4-stage pipeline against immutable physical fixtures
  and synthetic error vectors.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from reconstruction.ediabas.pipeline import CanonicalPipeline, ResponseValidator
from reconstruction.ediabas.trace_loader import load_trace_fixture
from reconstruction.transport.kdcan.framing import build as build_ds2_frame, checksum as ds2_checksum


class TestCanonicalOfflinePipeline(unittest.TestCase):
    """Test suite for CanonicalPipeline and ResponseValidator."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parents[3]
        cls.ident_fixture_path = cls.repo_root / "traces" / "hardware" / "20260926_174811_egs_ident.json"
        cls.hw_fixture_path = cls.repo_root / "traces" / "hardware" / "20260926_175924_egs_physical_hw_nr.json"
        cls.aif_fixture_path = cls.repo_root / "traces" / "hardware" / "20260926_173201_egs_aif.json"

        cls.pipeline = CanonicalPipeline()

    # ------------------------------------------------------------------------
    # Scenario 1: IDENT End-to-End Pipeline Against Immutable Physical Fixture
    # ------------------------------------------------------------------------
    def test_01_ident_pipeline_physical_trace(self) -> None:
        """Execute IDENT through the canonical pipeline using physical 1A 80 trace."""
        self.assertTrue(self.ident_fixture_path.exists())
        result = self.pipeline.execute("IDENT", self.ident_fixture_path)

        self.assertEqual(result.job_name, "IDENT")
        self.assertEqual(result.status, "OKAY")
        self.assertEqual(result.errors, [])

        # Decoded fields verification
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

        # Raw payload preserved without mutation
        self.assertEqual(len(result.raw_payload), 60)
        self.assertEqual(result.raw_payload[0:2], b"\x5A\x80")

        # Evidence classification axes
        self.assertTrue(result.sgbd_supported)
        self.assertTrue(result.factory_trace_observed)
        self.assertTrue(result.physical_trace_exists)
        self.assertTrue(result.directly_resolved)
        self.assertEqual(result.evidence_class, "DIRECTLY_RESOLVED")

    # ------------------------------------------------------------------------
    # Scenario 2: PHYS_HWNR End-to-End Pipeline Against Immutable Physical Fixture
    # ------------------------------------------------------------------------
    def test_02_phys_hwnr_pipeline_physical_trace(self) -> None:
        """Execute PHYSIKALISCHE_HW_NR_LESEN through pipeline using physical 1A 87 trace."""
        self.assertTrue(self.hw_fixture_path.exists())
        result = self.pipeline.execute("PHYSIKALISCHE_HW_NR_LESEN", self.hw_fixture_path)

        self.assertEqual(result.job_name, "PHYSIKALISCHE_HW_NR_LESEN")
        self.assertEqual(result.status, "OKAY")
        self.assertEqual(result.errors, [])

        # Decoded fields
        self.assertEqual(result["PHYSIKALISCHE_HW_NR"], "7569980")

        # Raw payload preserved
        self.assertEqual(len(result.raw_payload), 20)
        self.assertEqual(result.raw_payload[0:2], b"\x5A\x87")

        # Evidence classification axes
        self.assertTrue(result.sgbd_supported)
        self.assertTrue(result.factory_trace_observed)
        self.assertTrue(result.physical_trace_exists)
        self.assertTrue(result.directly_resolved)
        self.assertEqual(result.evidence_class, "DIRECTLY_RESOLVED")

    # ------------------------------------------------------------------------
    # Scenario 3: Malformed Response Rejection (Fail-Closed)
    # ------------------------------------------------------------------------
    def test_03_malformed_response_rejection(self) -> None:
        """Frame with invalid DS2 format byte or corrupted header is rejected before parsing."""
        # Invalid format byte: 0x42 instead of 0x80 | len
        corrupted_frame = b"\x42\xF1\x18\x5A\x80" + b"\x00" * 30 + b"\x00"
        result = self.pipeline.execute("IDENT", corrupted_frame)

        self.assertEqual(result.status, "ERROR_DS2_FRAMING")
        self.assertIn("Invalid DS2 format byte", result.errors[0])
        self.assertEqual(result.fields, {})

    # ------------------------------------------------------------------------
    # Scenario 4: Checksum Corruption Detection
    # ------------------------------------------------------------------------
    def test_04_checksum_rejection(self) -> None:
        """Frame with corrupted DS2 checksum byte is rejected fail-closed."""
        # Construct valid frame for IDENT
        valid_payload = b"\x5A\x80" + b"\x00" * 35
        valid_frame = build_ds2_frame(dst=0xF1, src=0x18, payload=valid_payload)

        # Corrupt checksum byte (last byte)
        corrupted_frame = valid_frame[:-1] + bytes([valid_frame[-1] ^ 0xFF])
        result = self.pipeline.execute("IDENT", corrupted_frame)

        self.assertEqual(result.status, "ERROR_DS2_CHECKSUM")
        self.assertIn("Checksum error", result.errors[0])
        self.assertEqual(result.fields, {})

    # ------------------------------------------------------------------------
    # Scenario 5: Wrong Response SID Rejection
    # ------------------------------------------------------------------------
    def test_05_wrong_response_sid(self) -> None:
        """Response with unexpected SID (e.g. 0x50 instead of 0x5A) is rejected."""
        wrong_sid_payload = b"\x50\x80" + b"\x00" * 35
        frame = build_ds2_frame(dst=0xF1, src=0x18, payload=wrong_sid_payload)
        result = self.pipeline.execute("IDENT", frame)

        self.assertEqual(result.status, "ERROR_ECU_INCORRECT_RESPONSE_ID")
        self.assertIn("Expected SID 0x5A, received 0x50", result.errors[0])
        self.assertEqual(result.fields, {})

    # ------------------------------------------------------------------------
    # Scenario 6: Wrong Local Identifier / Subfunction Rejection
    # ------------------------------------------------------------------------
    def test_06_wrong_local_identifier(self) -> None:
        """Response with wrong subfunction (e.g. 0x89 instead of 0x80) is rejected."""
        wrong_subid_payload = b"\x5A\x89" + b"\x00" * 35
        frame = build_ds2_frame(dst=0xF1, src=0x18, payload=wrong_subid_payload)
        result = self.pipeline.execute("IDENT", frame)

        self.assertEqual(result.status, "ERROR_ECU_INCORRECT_SUBID")
        self.assertIn("Expected SubID 0x80, received 0x89", result.errors[0])
        self.assertEqual(result.fields, {})

        # Test 2-byte common identifier rejection (e.g. 0x2599 instead of 0x2503 for ZIF_LESEN)
        wrong_zif_payload = b"\x62\x25\x99" + b"123456789012"
        zif_frame = build_ds2_frame(dst=0xF1, src=0x18, payload=wrong_zif_payload)
        zif_res = self.pipeline.execute("ZIF_LESEN", zif_frame)

        self.assertEqual(zif_res.status, "ERROR_ECU_INCORRECT_SUBID")
        self.assertIn("Expected CommonIdentifier 0x2503, received 0x2599", zif_res.errors[0])

    # ------------------------------------------------------------------------
    # Scenario 7: Wrong DS2 Length Rejection
    # ------------------------------------------------------------------------
    def test_07_wrong_ds2_length(self) -> None:
        """Length declared in DS2 header not matching actual frame length is rejected."""
        valid_payload = b"\x5A\x80" + b"\x00" * 35
        valid_frame = build_ds2_frame(dst=0xF1, src=0x18, payload=valid_payload)

        # Truncate frame by 3 bytes
        truncated_frame = valid_frame[:-3]
        result = self.pipeline.execute("IDENT", truncated_frame)

        self.assertEqual(result.status, "ERROR_DS2_FRAMING")
        self.assertIn("Frame length", result.errors[0])

    # ------------------------------------------------------------------------
    # Scenario 8: Fallback Metadata Handling and Request Builders
    # ------------------------------------------------------------------------
    def test_08_fallback_metadata_preservation(self) -> None:
        """Validate request building, complete DS2 frames, and checksums for all jobs."""
        # 1. IDENT: 82 18 F1 1A 80 25 (CS: 0x25)
        ident_tx = self.pipeline.build_request("IDENT")
        self.assertEqual(ident_tx, bytes.fromhex("82 18 F1 1A 80 25"))

        # 2. PHYSIKALISCHE_HW_NR_LESEN: Primary 1A 87 2C, Fallback 1A 80 25
        hw_tx = self.pipeline.build_request("PHYSIKALISCHE_HW_NR_LESEN")
        self.assertEqual(hw_tx, bytes.fromhex("82 18 F1 1A 87 2C"))
        hw_fallback_tx = self.pipeline.build_request("PHYSIKALISCHE_HW_NR_LESEN", use_fallback=True)
        self.assertEqual(hw_fallback_tx, bytes.fromhex("82 18 F1 1A 80 25"))

        # 3. SERIENNUMMER_LESEN: Primary 1A 89 2E (CS: 0x2E), Fallback 1A 80 25
        sn_tx = self.pipeline.build_request("SERIENNUMMER_LESEN")
        self.assertEqual(sn_tx, bytes.fromhex("82 18 F1 1A 89 2E"))
        sn_fallback_tx = self.pipeline.build_request("SERIENNUMMER_LESEN", use_fallback=True)
        self.assertEqual(sn_fallback_tx, bytes.fromhex("82 18 F1 1A 80 25"))

        # 4. ZIF_LESEN: Primary 22 25 03 D6 (CS: 0xD6), Fallback 1A 91 36 (CS: 0x36)
        zif_tx = self.pipeline.build_request("ZIF_LESEN")
        self.assertEqual(zif_tx, bytes.fromhex("83 18 F1 22 25 03 D6"))
        zif_fallback_tx = self.pipeline.build_request("ZIF_LESEN", use_fallback=True)
        self.assertEqual(zif_fallback_tx, bytes.fromhex("82 18 F1 1A 91 36"))

        # 5. ZIF_BACKUP_LESEN: Primary 22 25 00 D3 (CS: 0xD3), Fallback 1A 80 25
        zifb_tx = self.pipeline.build_request("ZIF_BACKUP_LESEN")
        self.assertEqual(zifb_tx, bytes.fromhex("83 18 F1 22 25 00 D3"))
        zifb_fallback_tx = self.pipeline.build_request("ZIF_BACKUP_LESEN", use_fallback=True)
        self.assertEqual(zifb_fallback_tx, bytes.fromhex("82 18 F1 1A 80 25"))

        # 6. HARDWARE_REFERENZ_LESEN: Primary 22 25 02 D5 (CS: 0xD5), Fallback 1A 80 25
        hwref_tx = self.pipeline.build_request("HARDWARE_REFERENZ_LESEN")
        self.assertEqual(hwref_tx, bytes.fromhex("83 18 F1 22 25 02 D5"))
        hwref_fallback = self.pipeline.build_request("HARDWARE_REFERENZ_LESEN", use_fallback=True)
        self.assertEqual(hwref_fallback, bytes.fromhex("82 18 F1 1A 80 25"))

        # 7. DATEN_REFERENZ_LESEN: Primary 22 25 04 D7 (CS: 0xD7)
        dref_tx = self.pipeline.build_request("DATEN_REFERENZ_LESEN")
        self.assertEqual(dref_tx, bytes.fromhex("83 18 F1 22 25 04 D7"))

        # 8. AIF_READ_BENCH_ALIAS: Primary 1A 86 2B (CS: 0x2B)
        aif_alias_tx = self.pipeline.build_request("AIF_READ_BENCH_ALIAS")
        self.assertEqual(aif_alias_tx, bytes.fromhex("82 18 F1 1A 86 2B"))

        # 9. AIF_LESEN: Primary 23 00 00 00 07 12 CB (Format: 0x86, CS: 0xCB)
        aif_tx = self.pipeline.build_request("AIF_LESEN")
        self.assertEqual(aif_tx, bytes.fromhex("86 18 F1 23 00 00 00 07 12 CB"))

    # ------------------------------------------------------------------------
    # Scenario 9: AIF $23 vs 1A86 Protocol Separation
    # ------------------------------------------------------------------------
    def test_09_aif_s23_vs_1a86_distinction(self) -> None:
        """Official AIF_LESEN strictly rejects 1A 86, while AIF_READ_BENCH_ALIAS decodes it."""
        self.assertTrue(self.aif_fixture_path.exists())

        # Passing 1A 86 trace into official AIF_LESEN must be rejected with explicit error
        official_res = self.pipeline.execute("AIF_LESEN", self.aif_fixture_path)
        self.assertEqual(official_res.status, "ERROR_SGBD_USES_SERVICE_0x23_NOT_0x1A86")
        self.assertEqual(official_res.fields, {})

        # Passing 1A 86 trace into AIF_READ_BENCH_ALIAS succeeds
        alias_res = self.pipeline.execute("AIF_READ_BENCH_ALIAS", self.aif_fixture_path)
        self.assertEqual(alias_res.status, "OKAY")
        self.assertEqual(alias_res["short_vin"], "CS68294")
        self.assertEqual(alias_res["zb_number"], "7592132")
        self.assertEqual(alias_res["sw_number"], "7592133")
        self.assertEqual(alias_res.evidence_class, "OBSERVED_WIRE / RECONSTRUCTION_ALIAS")

    # ------------------------------------------------------------------------
    # Scenario 10: Independence of Evidence Classification Axes
    # ------------------------------------------------------------------------
    def test_10_evidence_axis_independence(self) -> None:
        """Verify that SGBD support and factory observation never imply physical execution."""
        # 1. IDENT: all 4 axes True
        ident_res = self.pipeline.execute("IDENT", self.ident_fixture_path)
        self.assertTrue(ident_res.sgbd_supported)
        self.assertTrue(ident_res.factory_trace_observed)
        self.assertTrue(ident_res.physical_trace_exists)
        self.assertTrue(ident_res.directly_resolved)

        # 2. SERIENNUMMER_LESEN: sgbd_supported and factory_trace_observed, but NOT physical
        sn_res = self.pipeline.execute("SERIENNUMMER_LESEN", b"\x5A\x89080072856")
        self.assertTrue(sn_res.sgbd_supported)
        self.assertTrue(sn_res.factory_trace_observed)
        self.assertFalse(sn_res.physical_trace_exists)
        self.assertFalse(sn_res.directly_resolved)
        self.assertIn("UNKNOWN[target=0479S90T641Z]", sn_res.evidence_class)

        # 3. AIF_READ_BENCH_ALIAS: physical trace exists, but NOT sgbd_supported
        alias_res = self.pipeline.execute("AIF_READ_BENCH_ALIAS", self.aif_fixture_path)
        self.assertFalse(alias_res.sgbd_supported)
        self.assertFalse(alias_res.factory_trace_observed)
        self.assertTrue(alias_res.physical_trace_exists)
        self.assertFalse(alias_res.directly_resolved)


if __name__ == "__main__":
    unittest.main()
