"""Deterministic Golden Tests for GKE195 Offline Read-Only Job Execution Model (Milestone 5.7).

Validates the full semantic pipeline:
    Job -> IPO procedure -> 10FLASH.prg parser -> wire response fixture -> decoded SGBD result fields
against immutable physical hardware traces and controlled synthetic fixtures.

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
    Gke195JobCatalog,
    Gke195OfflineRunner,
    SgbdJobResult,
    TraceFixture,
    load_trace_fixture,
)

ROOT = Path(__file__).resolve().parents[3]
TRACES_DIR = ROOT / "traces" / "hardware"


class TestGke195JobExecutionModel(unittest.TestCase):
    """Test suite for Milestone 5.7 GKE195 offline job execution model."""

    def setUp(self) -> None:
        self.catalog = Gke195JobCatalog()
        self.runner = Gke195OfflineRunner(self.catalog)

    # ------------------------------------------------------------------------
    # Task 3: IDENT offline execution from physical trace
    # ------------------------------------------------------------------------
    def test_01_ident_canonical_physical_fixture(self) -> None:
        """Reproduce IDENT decoding from canonical immutable physical trace (1A 80)."""
        trace_path = TRACES_DIR / "20260926_174811_egs_ident.json"
        self.assertTrue(trace_path.is_file(), f"Trace file missing: {trace_path}")

        fixture = load_trace_fixture(trace_path)
        self.assertEqual(fixture.rx_len, 64)
        self.assertEqual(fixture.payload_len, 60)
        self.assertEqual(fixture.rtt_ms, 80.01)
        self.assertTrue(fixture.checksum_valid)

        result: SgbdJobResult = self.runner.execute_job("IDENT", fixture)

        self.assertTrue(result.is_ok)
        self.assertEqual(result.status, "OKAY")
        self.assertEqual(result.evidence_class, "DIRECTLY_RESOLVED")
        self.assertEqual(result.trace_source, "20260926_174811_egs_ident.json")

        # Verify all 12 decoded SGBD result fields
        self.assertEqual(result["ID_BMW_NR"], "7591972")
        self.assertEqual(result["ID_HW_NR"], "10")
        self.assertEqual(result["ID_COD_INDEX"], 5)
        self.assertEqual(result["ID_DIAG_INDEX"], 516)
        self.assertEqual(result["ID_LIEF_TEXT"], "SL ")
        self.assertEqual(result["ID_DATUM"], "30.10.2008")
        self.assertEqual(result["ID_LIEF_NR"], 8)
        self.assertEqual(result["ID_SW_NR_MCV"], "0.29.69")
        self.assertEqual(result["ID_SW_NR_FSV"], "195.64.1")
        self.assertEqual(result["ID_SW_NR_OSV"], "2.3.10")
        self.assertEqual(result["ID_SW_NR_RES"], "0.0.0")
        self.assertEqual(result["_PECUHN_FALLBACK"], "7569980")

    # ------------------------------------------------------------------------
    # Task 4: PHYSIKALISCHE_HW_NR_LESEN offline execution from physical trace
    # ------------------------------------------------------------------------
    def test_02_phys_hwnr_canonical_physical_fixture(self) -> None:
        """Reproduce PHYSIKALISCHE_HW_NR_LESEN decoding from canonical physical trace (1A 87)."""
        trace_path = TRACES_DIR / "20260926_175924_egs_physical_hw_nr.json"
        self.assertTrue(trace_path.is_file(), f"Trace file missing: {trace_path}")

        fixture = load_trace_fixture(trace_path)
        self.assertEqual(fixture.rx_len, 24)
        self.assertEqual(fixture.payload_len, 20)
        self.assertEqual(fixture.rtt_ms, 48.29)
        self.assertTrue(fixture.checksum_valid)

        result: SgbdJobResult = self.runner.execute_job("PHYSIKALISCHE_HW_NR_LESEN", fixture)

        self.assertTrue(result.is_ok)
        self.assertEqual(result.status, "OKAY")
        self.assertEqual(result["PHYSIKALISCHE_HW_NR"], "7569980")
        self.assertEqual(result.evidence_class, "DIRECTLY_RESOLVED")
        self.assertEqual(result.trace_source, "20260926_175924_egs_physical_hw_nr.json")

    # ------------------------------------------------------------------------
    # Task 7.3: Corrupted Checksum Rejection
    # ------------------------------------------------------------------------
    def test_03_corrupted_checksum_rejection(self) -> None:
        """Trace loader strictly rejects corrupt DS2 checksums."""
        # Create a valid fixture then alter the checksum byte
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            trace_content = {
                "tx": "82 18 f1 1a 87 2c",
                "rx": "94 f1 18 5a 87 00 00 07 56 99 80 00 00 07 56 99 80 00 00 07 56 99 80 FF",  # Corrupted CS (0xFF != 0xE0)
                "rtt_ms": 48.29,
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
    # Task 7.4: Corrupted DS2 Framing Rejection
    # ------------------------------------------------------------------------
    def test_04_corrupted_framing_rejection(self) -> None:
        """Trace loader strictly rejects truncated or mismatching DS2 length framing."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            # Short header says length 20 (0x94) but only 10 bytes provided
            trace_content = {
                "tx": "82 18 f1 1a 87 2c",
                "rx": "94 f1 18 5a 87 00 00 07 56 99 E0",
                "rtt_ms": 48.29,
            }
            json.dump(trace_content, tf)
            tmp_path = tf.name

        try:
            with self.assertRaises(ValueError) as ctx:
                load_trace_fixture(tmp_path)
            self.assertIn("Invalid DS2", str(ctx.exception))
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    # ------------------------------------------------------------------------
    # Task 7.5: Mismatched 1A87 Block Rejection
    # ------------------------------------------------------------------------
    def test_05_phys_hwnr_block_mismatch_error(self) -> None:
        """PHYSIKALISCHE_HW_NR_LESEN rejects responses where 3-block agreement fails."""
        # Block 2 differs from Block 1 and 3
        mismatched_payload = bytes.fromhex(
            "5a 87 00 00 07 56 99 80 00 00 07 56 99 81 00 00 07 56 99 80"
        )
        result: SgbdJobResult = self.runner.execute_job("PHYSIKALISCHE_HW_NR_LESEN", mismatched_payload)
        self.assertFalse(result.is_ok)
        self.assertEqual(result.status, "ERROR_CHECK_PECUHN")
        self.assertIsNone(result.get("PHYSIKALISCHE_HW_NR"))
        self.assertIn("ERROR_CHECK_PECUHN", result.errors)

    # ------------------------------------------------------------------------
    # Task 7.6: Malformed Identification Field Handling
    # ------------------------------------------------------------------------
    def test_06_malformed_ident_field_error(self) -> None:
        """IDENT parser rejects truncated identification table gracefully."""
        truncated_payload = bytes.fromhex("5a 80 00 00 07 59 19 72 10")
        result: SgbdJobResult = self.runner.execute_job("IDENT", truncated_payload)
        self.assertFalse(result.is_ok)
        self.assertEqual(result.status, "ERROR_ECU_INCORRECT_LEN")

    # ------------------------------------------------------------------------
    # Task 7.7: Unknown Physical Job Mapping (Fail-Closed)
    # ------------------------------------------------------------------------
    def test_07_unknown_job_mapping_fail_closed(self) -> None:
        """Speculative or unsupported jobs raise NotImplementedError (fail-closed)."""
        for unsupported_job in ("FLASH_SCHREIBEN", "AUTHENTISIERUNG", "NON_EXISTENT_JOB"):
            with self.assertRaises(NotImplementedError):
                self.runner.execute_job(unsupported_job, b"\x00")

    # ------------------------------------------------------------------------
    # Task 7.8: Preservation of Evidence Classification Taxonomy
    # ------------------------------------------------------------------------
    def test_08_evidence_classification_taxonomy(self) -> None:
        """Assert multi-dimensional classification axes are strictly preserved across jobs."""
        # 1. IDENT: directly resolved, physical trace exists
        ident_def = self.catalog.get_job("IDENT")
        self.assertTrue(ident_def.sgbd_supported)
        self.assertTrue(ident_def.factory_trace_observed)
        self.assertTrue(ident_def.physical_trace_exists)
        self.assertTrue(ident_def.directly_resolved)
        self.assertEqual(ident_def.evidence_class, "DIRECTLY_RESOLVED")

        # 2. PHYSIKALISCHE_HW_NR_LESEN: directly resolved, physical trace exists
        hw_def = self.catalog.get_job("PHYSIKALISCHE_HW_NR_LESEN")
        self.assertTrue(hw_def.sgbd_supported)
        self.assertTrue(hw_def.factory_trace_observed)
        self.assertTrue(hw_def.physical_trace_exists)
        self.assertTrue(hw_def.directly_resolved)
        self.assertEqual(hw_def.evidence_class, "DIRECTLY_RESOLVED")

        # 3. SERIENNUMMER_LESEN: factory observed, but physical trace does NOT exist
        sn_def = self.catalog.get_job("SERIENNUMMER_LESEN")
        self.assertTrue(sn_def.sgbd_supported)
        self.assertTrue(sn_def.factory_trace_observed)
        self.assertFalse(sn_def.physical_trace_exists)
        self.assertFalse(sn_def.directly_resolved)
        self.assertIn("UNKNOWN[target=0479S90T641Z]", sn_def.evidence_class)

        # 4. AIF_LESEN: SGBD job using service $23; observed in factory trace (line 11960)
        aif_def = self.catalog.get_job("AIF_LESEN")
        self.assertTrue(aif_def.sgbd_supported)
        self.assertTrue(aif_def.factory_trace_observed)
        self.assertFalse(aif_def.physical_trace_exists)
        self.assertFalse(aif_def.directly_resolved)
        self.assertEqual(aif_def.evidence_class, "DIRECT_SGBD_MAPPING[10FLASH]")

        # 5. AIF_READ_BENCH_ALIAS: physical trace exists; NOT an official SGBD job
        bench_def = self.catalog.get_job("AIF_READ_BENCH_ALIAS")
        self.assertFalse(bench_def.sgbd_supported)
        self.assertFalse(bench_def.factory_trace_observed)
        self.assertTrue(bench_def.physical_trace_exists)
        self.assertFalse(bench_def.directly_resolved)
        self.assertEqual(bench_def.evidence_class, "OBSERVED_WIRE / RECONSTRUCTION_ALIAS")

        # Query filters
        phys_jobs = [j.job_name for j in self.catalog.get_physical_jobs()]
        self.assertIn("IDENT", phys_jobs)
        self.assertIn("PHYSIKALISCHE_HW_NR_LESEN", phys_jobs)
        self.assertIn("AIF_READ_BENCH_ALIAS", phys_jobs)
        self.assertNotIn("SERIENNUMMER_LESEN", phys_jobs)
        self.assertNotIn("AIF_LESEN", phys_jobs)

        unknown_phys = [j.job_name for j in self.catalog.get_unknown_jobs()]
        self.assertIn("SERIENNUMMER_LESEN", unknown_phys)
        self.assertIn("AIF_LESEN", unknown_phys)
        self.assertIn("ZIF_LESEN", unknown_phys)

    # ------------------------------------------------------------------------
    # Task 6: AIF Official ($23) vs Bench Alias ($1A $86) Distinction
    # ------------------------------------------------------------------------
    def test_09_aif_official_vs_bench_alias_distinction(self) -> None:
        """Verify strict separation between official SGBD AIF_LESEN ($23) and bench alias ($1A $86)."""
        trace_path = TRACES_DIR / "20260926_173201_egs_aif.json"
        fixture = load_trace_fixture(trace_path)

        # 1. Bench alias parses physical 1A 86 trace successfully
        bench_res = self.runner.execute_job("AIF_READ_BENCH_ALIAS", fixture)
        self.assertTrue(bench_res.is_ok)
        self.assertEqual(bench_res["short_vin"], "CS68294")
        self.assertEqual(bench_res["zb_number"], "7592132")
        self.assertEqual(bench_res["sw_number"], "7592133")
        self.assertEqual(bench_res["flash_date"], "2008.12.04")
        self.assertEqual(bench_res["sgbd"], "0479S90T641Z")
        self.assertEqual(bench_res["tool_marker"], "NFS01")
        self.assertEqual(bench_res.evidence_class, "OBSERVED_WIRE / RECONSTRUCTION_ALIAS")

        # 2. Official SGBD AIF_LESEN explicitly rejects the 1A 86 frame
        sgbd_res = self.runner.execute_job("AIF_LESEN", fixture)
        self.assertFalse(sgbd_res.is_ok)
        self.assertEqual(sgbd_res.status, "ERROR_SGBD_USES_SERVICE_0x23_NOT_0x1A86")

        # 3. Official SGBD AIF_LESEN succeeds when provided valid service $23 (0x63) payload
        # Synthetic $23 memory response: 0x63 + 32 bytes AIF data
        synthetic_s23 = bytes.fromhex(
            "63 "
            "43 53 36 38 32 39 34 "  # VIN short: CS68294 (7B)
            "57 42 41 4E 58 37 31 30 34 30 "  # Remainder of VIN (10B)
            "04 12 08 "  # Date: 04.12.2008 (3B)
            "00 07 59 21 "  # ZB: 7592132 (4B)
            "00 07 59 21 "  # SW: 7592133 (4B)
            "00 00 00 00 "  # Behoerden-Nr (4B)
        )
        s23_res = self.runner.execute_job("AIF_LESEN", synthetic_s23)
        self.assertTrue(s23_res.is_ok)
        self.assertEqual(s23_res["AIF_FG_NR"], "CS68294")

    # ------------------------------------------------------------------------
    # Task 5: SERIENNUMMER_LESEN parser against factory trace evidence
    # ------------------------------------------------------------------------
    def test_10_seriennummer_factory_evidence(self) -> None:
        """SERIENNUMMER_LESEN parses factory trace 1A 89 response without fabricating physical trace."""
        # Factory trace line 28 payload: 5A 89 followed by ASCII "080072856"
        factory_rx = bytes.fromhex("8B F1 78 5A 89 30 38 30 30 37 32 38 35 36 D7")
        res = self.runner.execute_job("SERIENNUMMER_LESEN", factory_rx)
        self.assertTrue(res.is_ok)
        self.assertEqual(res["SERIENNUMMER"], "080072856")
        self.assertIn("UNKNOWN[target=0479S90T641Z]", res.evidence_class)
        self.assertIsNone(res.trace_source)


if __name__ == "__main__":
    unittest.main()
