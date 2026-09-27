"""Deterministic golden tests for SGBD 10FLASH.prg parsing semantics.

Verifies off-hardware offline decoding of KWP2000 1A 87 (PHYSIKALISCHE_HW_NR_LESEN)
and 1A 80 (IDENT) responses against synthetic fixtures and captured immutable
physical traces from Milestones 5.2 and 5.3.

STRICTLY OFF-HARDWARE:
- No serial port is opened.
- No hardware access occurs.
- No network/bus bytes are transmitted.
- Traces are read as read-only fixtures.
"""

import json
from pathlib import Path
import unittest

from reconstruction.ediabas import (
    Sgbd10FlashOffline,
    decode_10flash_ident,
    decode_10flash_phys_hw_nr,
    decode_10flash_seriennummer,
)

ROOT = Path(__file__).resolve().parents[3]
TRACES_DIR = ROOT / "traces" / "hardware"


class TestGoldenSgbd10Flash(unittest.TestCase):
    """Test offline decoding of SGBD 10FLASH.prg identification jobs."""

    def test_phys_hw_nr_synthetic_valid(self):
        """Synthetic 1A 87 response with 3 identical 6-byte blocks decodes correctly."""
        # 5A 87 + 3x (00 00 07 56 99 80)
        payload = bytes.fromhex(
            "5a 87 00 00 07 56 99 80 00 00 07 56 99 80 00 00 07 56 99 80"
        )
        res = decode_10flash_phys_hw_nr(payload)
        self.assertEqual(res["JOB_STATUS"], "OKAY")
        self.assertEqual(res["PHYSIKALISCHE_HW_NR"], "7569980")
        self.assertTrue(res["_BLOCK_MATCH"])
        self.assertEqual(res["_BLOCK_COUNT"], 3)
        self.assertEqual(res["_RAW_BLOCK_HEX"], "000007569980")

    def test_phys_hw_nr_synthetic_block_mismatch(self):
        """Synthetic 1A 87 response with mismatched blocks triggers ERROR_CHECK_PECUHN."""
        # Block 2 differs from Block 1 and 3
        payload = bytes.fromhex(
            "5a 87 00 00 07 56 99 80 00 00 07 56 99 81 00 00 07 56 99 80"
        )
        res = decode_10flash_phys_hw_nr(payload)
        self.assertEqual(res["JOB_STATUS"], "ERROR_CHECK_PECUHN")
        self.assertIsNone(res["PHYSIKALISCHE_HW_NR"])
        self.assertFalse(res["_BLOCK_MATCH"])

    def test_phys_hw_nr_synthetic_invalid_length(self):
        """Synthetic 1A 87 response with truncated payload triggers ERROR_ECU_INCORRECT_LEN."""
        payload = bytes.fromhex("5a 87 00 00 07 56 99 80")
        res = decode_10flash_phys_hw_nr(payload)
        self.assertEqual(res["JOB_STATUS"], "ERROR_ECU_INCORRECT_LEN")
        self.assertIsNone(res["PHYSIKALISCHE_HW_NR"])

    def test_phys_hw_nr_synthetic_nrc(self):
        """Synthetic negative response (0x7F 0x1A 0x12) is recognized."""
        payload = bytes.fromhex("7f 1a 12")
        res = decode_10flash_phys_hw_nr(payload)
        self.assertEqual(res["JOB_STATUS"], "ERROR_ECU_NEGATIVE_RESPONSE_0x12")
        self.assertIsNone(res["PHYSIKALISCHE_HW_NR"])

    def test_phys_hw_nr_captured_physical_trace(self):
        """Offline execution against immutable physical trace from Milestone 5.3."""
        trace_path = TRACES_DIR / "20260926_175924_egs_physical_hw_nr.json"
        self.assertTrue(trace_path.is_file(), f"Trace file missing: {trace_path}")

        with open(trace_path, "r", encoding="utf-8") as f:
            trace = json.load(f)

        # Feed trace dictionary directly into decoder
        res = decode_10flash_phys_hw_nr(trace)
        self.assertEqual(res["JOB_STATUS"], "OKAY")
        self.assertEqual(res["PHYSIKALISCHE_HW_NR"], "7569980")
        self.assertTrue(res["_BLOCK_MATCH"])
        self.assertEqual(res["_BLOCK_COUNT"], 3)

    def test_ident_synthetic_valid(self):
        """Synthetic 1A 80 response extracts all named result fields according to 10FLASH.prg."""
        payload = bytes.fromhex(
            "5a 80 00 00 07 59 19 72 10 05 02 04 53 4c 20 08 10 30 08 00 1d 45 c3 40 01 02 03 0a 00 00 00 00 00 07 56 99 80 00 40 59 38 30 34 37 39 53 39 30 30 34 37 39 53 39 30 54 36 34 31 5a"
        )
        res = decode_10flash_ident(payload)
        self.assertEqual(res["JOB_STATUS"], "OKAY")
        self.assertEqual(res["ID_BMW_NR"], "7591972")
        self.assertEqual(res["ID_HW_NR"], "10")
        self.assertEqual(res["ID_COD_INDEX"], 5)
        self.assertEqual(res["ID_DIAG_INDEX"], 516)
        self.assertEqual(res["ID_DATUM_JAHR"], 2008)
        self.assertEqual(res["ID_DATUM_MONAT"], 10)
        self.assertEqual(res["ID_DATUM_TAG"], 30)
        self.assertEqual(res["ID_DATUM"], "30.10.2008")
        self.assertEqual(res["ID_LIEF_NR"], 8)
        self.assertEqual(res["ID_LIEF_TEXT"], "SL ")
        self.assertEqual(res["ID_SW_NR_MCV"], "0.29.69")
        self.assertEqual(res["ID_SW_NR_FSV"], "195.64.1")
        self.assertEqual(res["ID_SW_NR_OSV"], "2.3.10")
        self.assertEqual(res["ID_SW_NR_RES"], "0.0.0")
        self.assertEqual(res["_PECUHN_FALLBACK"], "7569980")

    def test_ident_captured_physical_trace(self):
        """Offline execution against immutable physical trace from Milestone 5.2."""
        trace_path = TRACES_DIR / "20260926_174811_egs_ident.json"
        self.assertTrue(trace_path.is_file(), f"Trace file missing: {trace_path}")

        with open(trace_path, "r", encoding="utf-8") as f:
            trace = json.load(f)

        # Feed trace dictionary directly into decoder
        res = decode_10flash_ident(trace)
        self.assertEqual(res["JOB_STATUS"], "OKAY")
        self.assertEqual(res["ID_BMW_NR"], "7591972")
        self.assertEqual(res["ID_HW_NR"], "10")
        self.assertEqual(res["ID_COD_INDEX"], 5)
        self.assertEqual(res["ID_DIAG_INDEX"], 516)
        self.assertEqual(res["ID_DATUM"], "30.10.2008")
        self.assertEqual(res["ID_LIEF_TEXT"], "SL ")
        self.assertEqual(res["ID_SW_NR_MCV"], "0.29.69")
        self.assertEqual(res["ID_SW_NR_FSV"], "195.64.1")
        self.assertEqual(res["ID_SW_NR_OSV"], "2.3.10")
        self.assertEqual(res["ID_SW_NR_RES"], "0.0.0")
        self.assertEqual(res["_PECUHN_FALLBACK"], "7569980")

    def test_sgbd_offline_interpreter(self):
        """Sgbd10FlashOffline interpreter executes both jobs offline and exposes results."""
        interpreter = Sgbd10FlashOffline(target_address=0x18, sg_family="GKE195")

        trace_hw_nr = TRACES_DIR / "20260926_175924_egs_physical_hw_nr.json"
        with open(trace_hw_nr, "r", encoding="utf-8") as f:
            trace_87 = json.load(f)

        results_87 = interpreter.execute_job("PHYSIKALISCHE_HW_NR_LESEN", trace_87)
        self.assertEqual(results_87["JOB_STATUS"], "OKAY")
        self.assertEqual(interpreter.read_result("PHYSIKALISCHE_HW_NR"), "7569980")

        trace_ident = TRACES_DIR / "20260926_174811_egs_ident.json"
        with open(trace_ident, "r", encoding="utf-8") as f:
            trace_80 = json.load(f)

        results_80 = interpreter.execute_job("IDENT", trace_80)
        self.assertEqual(results_80["JOB_STATUS"], "OKAY")
        self.assertEqual(interpreter.read_result("ID_BMW_NR"), "7591972")
        self.assertEqual(interpreter.read_result("ID_DATUM"), "30.10.2008")

    def test_seriennummer_synthetic_and_factory_trace(self):
        """SERIENNUMMER_LESEN decodes synthetic payload and factory trace payload."""
        # Factory trace line 28 payload: 5A 89 followed by ASCII "080072856"
        factory_rx = bytes.fromhex("8B F1 78 5A 89 30 38 30 30 37 32 38 35 36 D7")
        res = decode_10flash_seriennummer(factory_rx)
        self.assertEqual(res["JOB_STATUS"], "OKAY")
        self.assertEqual(res["SERIENNUMMER"], "080072856")

        # Test via offline interpreter
        interpreter = Sgbd10FlashOffline()
        res_interp = interpreter.execute_job("SERIENNUMMER_LESEN", factory_rx)
        self.assertEqual(res_interp["JOB_STATUS"], "OKAY")
        self.assertEqual(interpreter.read_result("SERIENNUMMER"), "080072856")


if __name__ == "__main__":
    unittest.main()
