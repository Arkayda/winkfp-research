"""Differential Verification Tests for GKE195 / 10FLASH SGBD Semantics (Milestone 5.8).

Compares reconstructed offline parser behavior field-by-field against recovered
SGBD bytecode specifications (10FLASH.prg, 03GKE195.ipo) and historical factory traces.

STRICTLY OFF-HARDWARE:
- Zero serial port opening.
- Zero network or ECU communication.
- No emulation of the ECU; reproduces SGBD-side parsing and semantics only.
- Canonical JSON traces are read as read-only fixtures.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from reconstruction.ediabas import (
    DifferentialStatus,
    Gke195JobCatalog,
    Gke195OfflineRunner,
    JobDifferentialReport,
    load_trace_fixture,
    run_aif_s23_differential,
    run_ident_differential,
    run_phys_hwnr_differential,
    run_seriennummer_differential,
    run_zif_differential,
)

ROOT = Path(__file__).resolve().parents[3]
TRACES_DIR = ROOT / "traces" / "hardware"


class TestDiffSgbdGke195(unittest.TestCase):
    """Differential verification test suite for GKE195 / 10FLASH SGBD semantics."""

    def setUp(self) -> None:
        self.catalog = Gke195JobCatalog()
        self.runner = Gke195OfflineRunner(self.catalog)

    # ------------------------------------------------------------------------
    # 1. IDENT field-by-field exact comparison
    # ------------------------------------------------------------------------
    def test_01_ident_field_by_field_exact_comparison(self) -> None:
        """Differentially validate all 12 IDENT fields against physical 1A 80 fixture."""
        trace_path = TRACES_DIR / "20260926_174811_egs_ident.json"
        self.assertTrue(trace_path.is_file(), f"Trace file missing: {trace_path}")

        fixture = load_trace_fixture(trace_path)
        report: JobDifferentialReport = run_ident_differential(fixture)

        self.assertEqual(report.job_name, "IDENT")
        self.assertEqual(report.request_service, "0x1A")
        self.assertEqual(report.local_identifier, "0x80")
        self.assertEqual(report.response_length, 60)
        self.assertEqual(report.job_status, "OKAY")
        self.assertEqual(report.evidence_class, "DIRECTLY_RESOLVED")
        self.assertEqual(report.fixture_source, "20260926_174811_egs_ident.json")

        # Every field must be EXACT_MATCH
        self.assertTrue(report.is_perfect_match)
        self.assertEqual(len(report.mismatches), 0)
        self.assertEqual(len(report.unknowns), 0)
        self.assertEqual(len(report.fields), 12)

        fields_dict = {f.field_name: f for f in report.fields}

        # Check critical fields
        self.assertEqual(fields_dict["ID_BMW_NR"].decoded_value, "7591972")
        self.assertEqual(fields_dict["ID_BMW_NR"].differential_status, DifferentialStatus.EXACT_MATCH)

        self.assertEqual(fields_dict["ID_HW_NR"].decoded_value, "10")
        self.assertEqual(fields_dict["ID_COD_INDEX"].decoded_value, 5)
        self.assertEqual(fields_dict["ID_DIAG_INDEX"].decoded_value, 516)
        self.assertEqual(fields_dict["ID_LIEF_TEXT"].decoded_value, "SL ")
        self.assertEqual(fields_dict["ID_DATUM"].decoded_value, "30.10.2008")
        self.assertEqual(fields_dict["ID_LIEF_NR"].decoded_value, 8)
        self.assertEqual(fields_dict["ID_SW_NR_MCV"].decoded_value, "0.29.69")
        self.assertEqual(fields_dict["ID_SW_NR_FSV"].decoded_value, "195.64.1")
        self.assertEqual(fields_dict["ID_SW_NR_OSV"].decoded_value, "2.3.10")
        self.assertEqual(fields_dict["ID_SW_NR_RES"].decoded_value, "0.0.0")

        self.assertEqual(fields_dict["_PECUHN_FALLBACK"].decoded_value, "7569980")
        self.assertEqual(fields_dict["_PECUHN_FALLBACK"].differential_status, DifferentialStatus.EXACT_MATCH)

    # ------------------------------------------------------------------------
    # 2. PHYSIKALISCHE_HW_NR_LESEN field-by-field exact comparison
    # ------------------------------------------------------------------------
    def test_02_phys_hwnr_field_by_field_exact_comparison(self) -> None:
        """Differentially validate PHYSIKALISCHE_HW_NR_LESEN on physical 1A 87 fixture."""
        trace_path = TRACES_DIR / "20260926_175924_egs_physical_hw_nr.json"
        self.assertTrue(trace_path.is_file(), f"Trace file missing: {trace_path}")

        fixture = load_trace_fixture(trace_path)
        report: JobDifferentialReport = run_phys_hwnr_differential(fixture)

        self.assertEqual(report.job_name, "PHYSIKALISCHE_HW_NR_LESEN")
        self.assertEqual(report.request_service, "0x1A")
        self.assertEqual(report.local_identifier, "0x87")
        self.assertEqual(report.response_length, 20)
        self.assertEqual(report.job_status, "OKAY")
        self.assertEqual(report.evidence_class, "DIRECTLY_RESOLVED")
        self.assertEqual(report.fixture_source, "20260926_175924_egs_physical_hw_nr.json")

        self.assertTrue(report.is_perfect_match)
        self.assertEqual(len(report.mismatches), 0)
        self.assertEqual(len(report.unknowns), 0)

        fields_dict = {f.field_name: f for f in report.fields}
        self.assertTrue(fields_dict["3_BLOCK_EQUALITY_RULE"].decoded_value)
        self.assertEqual(fields_dict["3_BLOCK_EQUALITY_RULE"].differential_status, DifferentialStatus.EXACT_MATCH)

        self.assertEqual(fields_dict["PHYSIKALISCHE_HW_NR"].decoded_value, "7569980")
        self.assertEqual(fields_dict["PHYSIKALISCHE_HW_NR"].differential_status, DifferentialStatus.EXACT_MATCH)

    # ------------------------------------------------------------------------
    # 3. PHYSIKALISCHE_HW_NR repeated-block mismatch
    # ------------------------------------------------------------------------
    def test_03_phys_hwnr_repeated_block_mismatch(self) -> None:
        """Validate error branch ERROR_CHECK_PECUHN when repeated blocks diverge."""
        # Block 2 diverges: 00 00 07 56 99 81 != 00 00 07 56 99 80
        corrupted_payload = bytes.fromhex(
            "5a 87 00 00 07 56 99 80 00 00 07 56 99 81 00 00 07 56 99 80"
        )
        report: JobDifferentialReport = run_phys_hwnr_differential(corrupted_payload)

        self.assertEqual(report.job_status, "ERROR_CHECK_PECUHN")
        fields_dict = {f.field_name: f for f in report.fields}
        self.assertFalse(fields_dict["3_BLOCK_EQUALITY_RULE"].decoded_value)
        self.assertEqual(fields_dict["3_BLOCK_EQUALITY_RULE"].differential_status, DifferentialStatus.EXACT_MATCH)
        self.assertIsNone(fields_dict["PHYSIKALISCHE_HW_NR"].decoded_value)

    # ------------------------------------------------------------------------
    # 4. Malformed DS2 response handling
    # ------------------------------------------------------------------------
    def test_04_malformed_ds2_response_handling(self) -> None:
        """Validate fail-closed error handling for truncated and malformed payloads."""
        # Truncated IDENT (< 31 bytes)
        truncated_ident = bytes.fromhex("5a 80 00 00 07 59 19 72 10")
        res_ident = self.runner.execute_job("IDENT", truncated_ident)
        self.assertFalse(res_ident.is_ok)
        self.assertEqual(res_ident.status, "ERROR_ECU_INCORRECT_LEN")

        # Wrong SID for 1A 87
        wrong_sid = bytes.fromhex("5b 87 00 00 07 56 99 80 00 00 07 56 99 80 00 00 07 56 99 80")
        res_sid = self.runner.execute_job("PHYSIKALISCHE_HW_NR_LESEN", wrong_sid)
        self.assertFalse(res_sid.is_ok)
        self.assertEqual(res_sid.status, "ERROR_ECU_INCORRECT_RESPONSE_ID")

        # NRC response 0x7F 0x1A 0x12
        nrc_payload = bytes.fromhex("7f 1a 12")
        res_nrc = self.runner.execute_job("PHYSIKALISCHE_HW_NR_LESEN", nrc_payload)
        self.assertFalse(res_nrc.is_ok)
        self.assertEqual(res_nrc.status, "ERROR_ECU_NEGATIVE_RESPONSE_0x12")

    # ------------------------------------------------------------------------
    # 5. Checksum corruption detection
    # ------------------------------------------------------------------------
    def test_05_checksum_corruption_detection(self) -> None:
        """Validate that corrupted checksums fail closed before semantic parsing."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            trace_content = {
                "tx": "82 18 f1 1a 80 25",
                "rx": "bc f1 18 5a 80 00 00 07 59 19 72 10 05 02 04 53 4c 20 08 10 30 08 00 1d 45 c3 40 01 02 03 0a 00 00 00 00 00 07 56 99 80 00 40 59 38 30 34 37 39 53 39 30 30 34 37 39 53 39 30 54 36 34 31 5a 00",  # Corrupted CS (0x00 != 0xD9)
                "rtt_ms": 80.01,
            }
            json.dump(trace_content, tf)
            tmp_path = tf.name

        try:
            with self.assertRaises(ValueError) as ctx:
                load_trace_fixture(tmp_path)
            self.assertIn("Invalid DS2 checksum", str(ctx.exception))
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    # ------------------------------------------------------------------------
    # 6. SERIENNUMMER semantic comparison against factory trace
    # ------------------------------------------------------------------------
    def test_06_seriennummer_semantic_comparison(self) -> None:
        """Validate SERIENNUMMER_LESEN against factory trace line 28."""
        factory_rx = bytes.fromhex("8B F1 78 5A 89 30 38 30 30 37 32 38 35 36 D7")
        report: JobDifferentialReport = run_seriennummer_differential(factory_rx)

        self.assertEqual(report.job_status, "OKAY")
        self.assertEqual(len(report.fields), 1)
        sn_field = report.fields[0]
        self.assertEqual(sn_field.field_name, "SERIENNUMMER")
        self.assertEqual(sn_field.decoded_value, "080072856")
        self.assertEqual(sn_field.differential_status, DifferentialStatus.SEMANTIC_MATCH)

        # Confirm evidence separation: physical trace remains UNKNOWN on EGS 0x18
        self.assertIn("UNKNOWN[target=0479S90T641Z]", report.evidence_class)
        self.assertIsNone(report.fixture_source)

    # ------------------------------------------------------------------------
    # 7. AIF $23 vs 1A86 distinction
    # ------------------------------------------------------------------------
    def test_07_aif_s23_vs_1a86_distinction(self) -> None:
        """Verify strict differential separation between official AIF_LESEN ($23) and 1A 86."""
        trace_path = TRACES_DIR / "20260926_173201_egs_aif.json"
        fixture = load_trace_fixture(trace_path)

        # Feeding 1A 86 to official AIF_LESEN must trigger explicit service isolation error
        report_s23: JobDifferentialReport = run_aif_s23_differential(fixture)
        self.assertEqual(report_s23.job_status, "ERROR_SGBD_USES_SERVICE_0x23_NOT_0x1A86")
        self.assertEqual(len(report_s23.fields), 1)
        iso_field = report_s23.fields[0]
        self.assertEqual(iso_field.differential_status, DifferentialStatus.EXACT_MATCH)

        # Feeding valid $23 memory block succeeds structurally
        synthetic_s23 = bytes.fromhex(
            "63 "
            "43 53 36 38 32 39 34 "  # VIN short: CS68294
            "57 42 41 4E 58 37 31 30 34 30 "  # Chassis prefix
            "04 12 08 "  # Date: 04.12.2008
            "00 07 59 21 "  # ZB: 7592132
            "00 07 59 21 "  # SW: 7592133
            "00 00 00 00 "  # Behoerden-Nr
        )
        report_valid_s23 = run_aif_s23_differential(synthetic_s23)
        self.assertEqual(report_valid_s23.job_status, "OKAY")
        self.assertEqual(report_valid_s23.fields[0].differential_status, DifferentialStatus.STRUCTURAL_MATCH)

    # ------------------------------------------------------------------------
    # 8. ZIF field comparison where source evidence is direct
    # ------------------------------------------------------------------------
    def test_08_zif_field_comparison(self) -> None:
        """Validate ZIF_LESEN field extraction against recovered SGBD layout."""
        # 62 25 03 + 12-byte program reference string "0479S90T641Z"
        synthetic_zif = bytes.fromhex("62 25 03 30 34 37 39 53 39 30 54 36 34 31 5A")
        report: JobDifferentialReport = run_zif_differential(synthetic_zif)

        self.assertEqual(report.job_status, "OKAY")
        self.assertEqual(len(report.fields), 1)
        zif_field = report.fields[0]
        self.assertEqual(zif_field.field_name, "ZIF_PROGRAMM_REFERENZ")
        self.assertEqual(zif_field.decoded_value, "0479S90T641Z")
        self.assertEqual(zif_field.differential_status, DifferentialStatus.STRUCTURAL_MATCH)
        self.assertEqual(report.evidence_class, "DIRECT_SGBD_MAPPING[10FLASH]")


if __name__ == "__main__":
    unittest.main()
