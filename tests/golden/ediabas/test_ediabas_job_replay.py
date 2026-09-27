"""Deterministic Golden Tests for Offline EDIABAS-Compatible Job Replay (Milestone 5.10).

STRICTLY OFF-HARDWARE:
- Zero serial port opening (/dev/cu.usbserial-A50285BI must NEVER be opened).
- Zero network or ECU communication.
- Validates the offline replay engine, logical request vs DS2 wire frame separation,
  evidence domain isolation, AIF_NUMMER parameter modeling, and fail-closed error handling.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from reconstruction.ediabas.replay import (
    EdiabasJobReplayEngine,
    EdiabasJobResult,
    EdiabasTelegram,
    EvidenceDomain,
    default_replay_engine,
    execute_job,
)
from reconstruction.ediabas.trace_loader import load_trace_fixture
from reconstruction.transport.kdcan.framing import (
    build as build_ds2_frame,
    checksum as ds2_checksum,
)


class TestEdiabasJobReplay(unittest.TestCase):
    """Test suite for offline EDIABAS-compatible job replay layer."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parents[3]
        cls.ident_fixture_path = (
            cls.repo_root / "traces" / "hardware" / "20260926_174811_egs_ident.json"
        )
        cls.hw_fixture_path = (
            cls.repo_root
            / "traces"
            / "hardware"
            / "20260926_175924_egs_physical_hw_nr.json"
        )
        cls.aif_fixture_path = (
            cls.repo_root / "traces" / "hardware" / "20260926_173201_egs_aif.json"
        )
        cls.engine = default_replay_engine

    # ------------------------------------------------------------------------
    # Test 1: IDENT End-to-End Replay Against Physical Fixture
    # ------------------------------------------------------------------------
    def test_01_ident_replay_physical_fixture(self) -> None:
        """Replay IDENT from immutable physical trace 20260926_174811_egs_ident.json."""
        self.assertTrue(self.ident_fixture_path.exists())
        result: EdiabasJobResult = execute_job("IDENT", self.ident_fixture_path)

        self.assertTrue(result.is_ok)
        self.assertEqual(result.status, "OKAY")
        self.assertEqual(result.job_name, "IDENT")
        self.assertEqual(result.errors, [])

        # Protocol distinction
        self.assertEqual(result.logical_request, bytes.fromhex("82 18 F1 1A 80"))
        self.assertEqual(result.canonical_ds2_request, bytes.fromhex("82 18 F1 1A 80 25"))
        self.assertEqual(len(result.logical_request), 5)
        self.assertEqual(len(result.canonical_ds2_request), 6)

        # Decoded fields
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

        # Evidence taxonomy
        self.assertEqual(result.evidence_domain, EvidenceDomain.PHYSICAL_EGS_FIXTURE)
        self.assertEqual(result.trace_source, "20260926_174811_egs_ident.json")
        self.assertTrue(result.sgbd_supported)
        self.assertTrue(result.factory_trace_observed)
        self.assertTrue(result.physical_trace_exists)
        self.assertTrue(result.directly_resolved)

    # ------------------------------------------------------------------------
    # Test 2: PHYSIKALISCHE_HW_NR_LESEN Replay Against Physical Fixture
    # ------------------------------------------------------------------------
    def test_02_phys_hwnr_replay_physical_fixture(self) -> None:
        """Replay PHYSIKALISCHE_HW_NR_LESEN from immutable physical trace 20260926_175924_egs_physical_hw_nr.json."""
        self.assertTrue(self.hw_fixture_path.exists())
        result: EdiabasJobResult = execute_job(
            "PHYSIKALISCHE_HW_NR_LESEN", self.hw_fixture_path
        )

        self.assertTrue(result.is_ok)
        self.assertEqual(result.status, "OKAY")
        self.assertEqual(result.job_name, "PHYSIKALISCHE_HW_NR_LESEN")
        self.assertEqual(result.errors, [])

        # Protocol distinction
        self.assertEqual(result.logical_request, bytes.fromhex("82 18 F1 1A 87"))
        self.assertEqual(result.canonical_ds2_request, bytes.fromhex("82 18 F1 1A 87 2C"))
        self.assertEqual(len(result.logical_request), 5)
        self.assertEqual(len(result.canonical_ds2_request), 6)

        # Decoded fields
        self.assertEqual(result["PHYSIKALISCHE_HW_NR"], "7569980")

        # Evidence taxonomy
        self.assertEqual(result.evidence_domain, EvidenceDomain.PHYSICAL_EGS_FIXTURE)
        self.assertEqual(result.trace_source, "20260926_175924_egs_physical_hw_nr.json")
        self.assertTrue(result.sgbd_supported)
        self.assertTrue(result.factory_trace_observed)
        self.assertTrue(result.physical_trace_exists)
        self.assertTrue(result.directly_resolved)

    # ------------------------------------------------------------------------
    # Test 3: SERIENNUMMER_LESEN Replay Against Factory Trace Evidence
    # ------------------------------------------------------------------------
    def test_03_factory_serial_replay(self) -> None:
        """Replay SERIENNUMMER_LESEN against factory trace line 12577 frame (5A 89 + '080072856')."""
        # Factory frame from sanitized_flash_session.trc: line 12577
        # 8B F1 78 5A 89 30 38 30 30 37 32 38 35 36 AB
        factory_frame = bytes.fromhex("8B F1 78 5A 89 30 38 30 30 37 32 38 35 36 AB")

        result: EdiabasJobResult = execute_job(
            "SERIENNUMMER_LESEN",
            factory_frame,
            evidence_domain=EvidenceDomain.FACTORY_TRACE,
            target_address=0x78,
        )

        self.assertTrue(result.is_ok)
        self.assertEqual(result.status, "OKAY")
        self.assertEqual(result["SERIENNUMMER"], "080072856")

        # Logical request for target 0x78
        self.assertEqual(result.logical_request, bytes.fromhex("82 78 F1 1A 89"))
        self.assertEqual(result.canonical_ds2_request, bytes.fromhex("82 78 F1 1A 89 8E"))

        # Strict evidence boundary: factory observation does NOT create physical EGS trace
        self.assertEqual(result.evidence_domain, EvidenceDomain.FACTORY_TRACE)
        self.assertTrue(result.sgbd_supported)
        self.assertTrue(result.factory_trace_observed)
        self.assertFalse(result.physical_trace_exists)
        self.assertFalse(result.directly_resolved)

    # ------------------------------------------------------------------------
    # Test 4: Official AIF_LESEN ($23) Replay with AIF_NUMMER Argument
    # ------------------------------------------------------------------------
    def test_04_aif_s23_replay(self) -> None:
        """Replay official AIF_LESEN with AIF_NUMMER=0 against factory trace line 11956 frame."""
        # Factory frame from sanitized_flash_session.trc: line 11956
        # 93 F1 78 63 12 FF FF FF FF FF FF FF 20 08 10 07 00 00 09 16 56 72 90
        factory_frame = bytes.fromhex(
            "93 F1 78 63 12 FF FF FF FF FF FF FF 20 08 10 07 00 00 09 16 56 72 90"
        )

        result: EdiabasJobResult = execute_job(
            "AIF_LESEN",
            factory_frame,
            arguments={"AIF_NUMMER": 0},
            evidence_domain=EvidenceDomain.FACTORY_TRACE,
            target_address=0x78,
        )

        self.assertTrue(result.is_ok)
        self.assertEqual(result.status, "OKAY")

        # Explicit AIF_NUMMER=0 logical request: 23 00 00 00 07 12
        self.assertEqual(result.logical_request, bytes.fromhex("86 78 F1 23 00 00 00 07 12"))
        self.assertEqual(
            result.canonical_ds2_request, bytes.fromhex("86 78 F1 23 00 00 00 07 12 2B")
        )

        # Decoded fields matching factory trace lines 11946-11953
        self.assertEqual(result["AIF_DATUM"], "07.10.2008")
        self.assertEqual(result["AIF_ZB_NR"], "9165672")
        self.assertEqual(result["AIF_GROESSE"], 18)
        self.assertEqual(result["AIF_FG_NR"], "")

        # Strict evidence boundary
        self.assertEqual(result.evidence_domain, EvidenceDomain.FACTORY_TRACE)
        self.assertFalse(result.physical_trace_exists)

    # ------------------------------------------------------------------------
    # Test 5: ZIF_LESEN ($22 $2503) Replay Against Factory Trace Evidence
    # ------------------------------------------------------------------------
    def test_05_zif_s22_replay(self) -> None:
        """Replay ZIF_LESEN against factory trace line 11654 response."""
        # Factory frame from sanitized_flash_session.trc: line 11654
        factory_frame = bytes.fromhex(
            "A7 F1 78 62 25 03 30 35 36 31 42 46 31 46 31 38 31 41 "
            "30 35 36 31 42 46 31 46 31 38 31 41 "
            "30 35 36 31 42 46 31 46 31 38 31 41 8C"
        )

        result: EdiabasJobResult = execute_job(
            "ZIF_LESEN",
            factory_frame,
            evidence_domain=EvidenceDomain.FACTORY_TRACE,
            target_address=0x78,
        )

        self.assertTrue(result.is_ok)
        self.assertEqual(result.status, "OKAY")

        # Logical vs DS2 wire frame
        self.assertEqual(result.logical_request, bytes.fromhex("83 78 F1 22 25 03"))
        self.assertEqual(result.canonical_ds2_request, bytes.fromhex("83 78 F1 22 25 03 36"))

        # Decoded fields matching decoder slice offsets
        self.assertEqual(result["ZIF_PROGRAMM_REFERENZ"], "0561BF1F181A")
        self.assertEqual(result["ZIF_SG_KENNUNG"], "056")
        self.assertEqual(result["ZIF_PROJEKT"], "1BF")
        self.assertEqual(result["ZIF_PROGRAMM_STAND"], "1F18")

        # Evidence boundary
        self.assertEqual(result.evidence_domain, EvidenceDomain.FACTORY_TRACE)
        self.assertFalse(result.physical_trace_exists)

    # ------------------------------------------------------------------------
    # Test 6: Malformed Response Rejection (Fail-Closed)
    # ------------------------------------------------------------------------
    def test_06_malformed_response_rejection(self) -> None:
        """Response frame with invalid DS2 format byte is rejected with ERROR_DS2_FRAMING."""
        corrupted_frame = b"\x42\xF1\x18\x5A\x80" + b"\x00" * 30 + b"\x00"
        result: EdiabasJobResult = execute_job("IDENT", corrupted_frame)

        self.assertFalse(result.is_ok)
        self.assertEqual(result.status, "ERROR_DS2_FRAMING")
        self.assertIn("Invalid DS2 format byte", result.errors[0])
        self.assertEqual(result.fields, {})

    # ------------------------------------------------------------------------
    # Test 7: Checksum Failure Rejection
    # ------------------------------------------------------------------------
    def test_07_checksum_failure_rejection(self) -> None:
        """Response frame with corrupted checksum byte is rejected with ERROR_DS2_CHECKSUM."""
        valid_payload = b"\x5A\x80" + b"\x00" * 35
        valid_frame = build_ds2_frame(dst=0xF1, src=0x18, payload=valid_payload)
        corrupted_frame = valid_frame[:-1] + bytes([valid_frame[-1] ^ 0xFF])

        result: EdiabasJobResult = execute_job("IDENT", corrupted_frame)

        self.assertFalse(result.is_ok)
        self.assertEqual(result.status, "ERROR_DS2_CHECKSUM")
        self.assertIn("Checksum error", result.errors[0])
        self.assertEqual(result.fields, {})

    # ------------------------------------------------------------------------
    # Test 8: Negative ECU Response (Fail-Closed)
    # ------------------------------------------------------------------------
    def test_08_negative_ecu_response(self) -> None:
        """Negative response from ECU (NRC 0x12) returns fail-closed error status."""
        nrc_payload = bytes.fromhex("7F 1A 12")
        frame = build_ds2_frame(dst=0xF1, src=0x18, payload=nrc_payload)

        result: EdiabasJobResult = execute_job("IDENT", frame)

        self.assertFalse(result.is_ok)
        self.assertEqual(result.status, "ERROR_ECU_NEGATIVE_RESPONSE_0x12")
        self.assertIn("NRC 0x12", result.errors[0])
        self.assertEqual(result.fields, {})

    # ------------------------------------------------------------------------
    # Test 9: Unsupported Job Rejection
    # ------------------------------------------------------------------------
    def test_09_unsupported_job_rejection(self) -> None:
        """Attempting to execute an unknown or uncatalogued job returns ERROR_JOB_UNSUPPORTED."""
        result: EdiabasJobResult = execute_job("FLASH_PROGRAM_START", b"\x00")

        self.assertFalse(result.is_ok)
        self.assertEqual(result.status, "ERROR_JOB_UNSUPPORTED")
        self.assertEqual(result.evidence_class, "UNSUPPORTED")
        self.assertFalse(result.sgbd_supported)
        self.assertEqual(result.fields, {})
        self.assertEqual(result.logical_request, b"")
        self.assertEqual(result.canonical_ds2_request, b"")

    # ------------------------------------------------------------------------
    # Test 10: Official AIF ($23) vs Bench Alias ($1A $86) Protocol Separation
    # ------------------------------------------------------------------------
    def test_10_aif_s23_vs_bench_alias_separation(self) -> None:
        """Feeding physical 1A 86 trace into official AIF_LESEN fails with explicit service error."""
        self.assertTrue(self.aif_fixture_path.exists())

        # Passing 1A 86 trace to official AIF_LESEN fails with ERROR_SGBD_USES_SERVICE_0x23_NOT_0x1A86
        official_res: EdiabasJobResult = execute_job("AIF_LESEN", self.aif_fixture_path)
        self.assertFalse(official_res.is_ok)
        self.assertEqual(
            official_res.status, "ERROR_SGBD_USES_SERVICE_0x23_NOT_0x1A86"
        )
        self.assertEqual(official_res.fields, {})

        # Passing 1A 86 trace to AIF_READ_BENCH_ALIAS succeeds
        alias_res: EdiabasJobResult = execute_job(
            "AIF_READ_BENCH_ALIAS", self.aif_fixture_path
        )
        self.assertTrue(alias_res.is_ok)
        self.assertEqual(alias_res.status, "OKAY")
        self.assertEqual(alias_res["short_vin"], "CS68294")
        self.assertEqual(alias_res["zb_number"], "7592132")
        self.assertEqual(alias_res["sw_number"], "7592133")
        self.assertEqual(
            alias_res.evidence_class, "OBSERVED_WIRE / RECONSTRUCTION_ALIAS"
        )

    # ------------------------------------------------------------------------
    # Test 11: EDIABAS Buffer vs Physical DS2 Wire Frame Distinction
    # ------------------------------------------------------------------------
    def test_11_ediabas_buffer_vs_wire_frame_distinction(self) -> None:
        """Verify that logical_request (_TEL_AUFTRAG) and canonical_ds2_request are strictly separated."""
        test_cases = [
            ("IDENT", None, 5, 6, 0x25),
            ("PHYSIKALISCHE_HW_NR_LESEN", None, 5, 6, 0x2C),
            ("SERIENNUMMER_LESEN", None, 5, 6, 0x2E),
            ("ZIF_LESEN", None, 6, 7, 0xD6),
            ("ZIF_BACKUP_LESEN", None, 6, 7, 0xD3),
            ("HARDWARE_REFERENZ_LESEN", None, 6, 7, 0xD5),
            ("DATEN_REFERENZ_LESEN", None, 6, 7, 0xD7),
            ("AIF_READ_BENCH_ALIAS", None, 5, 6, 0x2B),
            ("AIF_LESEN", {"AIF_NUMMER": 0}, 9, 10, 0xCB),
        ]

        for job_name, args, exp_log_len, exp_wire_len, exp_cs in test_cases:
            telegram: EdiabasTelegram = self.engine.build_logical_telegram(
                job_name, arguments=args, target_address=0x18, tester_address=0xF1
            )
            wire_frame = telegram.to_wire_frame()

            # Buffer without checksum
            self.assertEqual(
                len(telegram.raw_buffer),
                exp_log_len,
                f"Logical telegram length mismatch for {job_name}",
            )
            # Frame with trailing checksum
            self.assertEqual(
                len(wire_frame),
                exp_wire_len,
                f"Wire frame length mismatch for {job_name}",
            )
            self.assertEqual(wire_frame[:-1], telegram.raw_buffer)
            self.assertEqual(wire_frame[-1], exp_cs)
            self.assertEqual(ds2_checksum(telegram.raw_buffer), exp_cs)

    # ------------------------------------------------------------------------
    # Test 12: Evidence Axis Independence Across Domains
    # ------------------------------------------------------------------------
    def test_12_evidence_axis_independence(self) -> None:
        """Verify orthogonal evidence axes across physical, factory, and synthetic domains."""
        # 1. PHYSICAL_EGS_FIXTURE domain (IDENT)
        phys_res = execute_job("IDENT", self.ident_fixture_path)
        self.assertEqual(phys_res.evidence_domain, EvidenceDomain.PHYSICAL_EGS_FIXTURE)
        self.assertTrue(phys_res.sgbd_supported)
        self.assertTrue(phys_res.factory_trace_observed)
        self.assertTrue(phys_res.physical_trace_exists)
        self.assertTrue(phys_res.directly_resolved)

        # 2. FACTORY_TRACE domain (SERIENNUMMER_LESEN)
        sn_res = execute_job(
            "SERIENNUMMER_LESEN",
            b"\x5A\x89080072856",
            evidence_domain=EvidenceDomain.FACTORY_TRACE,
            target_address=0x78,
        )
        self.assertEqual(sn_res.evidence_domain, EvidenceDomain.FACTORY_TRACE)
        self.assertTrue(sn_res.sgbd_supported)
        self.assertTrue(sn_res.factory_trace_observed)
        self.assertFalse(sn_res.physical_trace_exists)
        self.assertFalse(sn_res.directly_resolved)

        # 3. OBSERVED_WIRE alias domain (AIF_READ_BENCH_ALIAS)
        alias_res = execute_job("AIF_READ_BENCH_ALIAS", self.aif_fixture_path)
        self.assertEqual(alias_res.evidence_domain, EvidenceDomain.PHYSICAL_EGS_FIXTURE)
        self.assertFalse(alias_res.sgbd_supported)
        self.assertFalse(alias_res.factory_trace_observed)
        self.assertTrue(alias_res.physical_trace_exists)
        self.assertFalse(alias_res.directly_resolved)

        # 4. SYNTHETIC_OFFLINE domain (ZIF_LESEN with synthetic buffer)
        synth_res = execute_job(
            "ZIF_LESEN",
            bytes.fromhex("62 25 03 30 34 37 39 53 39 30 54 36 34 31 5A"),
            evidence_domain=EvidenceDomain.SYNTHETIC_OFFLINE,
        )
        self.assertEqual(synth_res.evidence_domain, EvidenceDomain.SYNTHETIC_OFFLINE)
        self.assertTrue(synth_res.sgbd_supported)
        self.assertTrue(synth_res.factory_trace_observed)
        self.assertFalse(synth_res.physical_trace_exists)
        self.assertFalse(synth_res.directly_resolved)

    # ------------------------------------------------------------------------
    # Test 13: Factory Trace Target Provenance Preservation (0x78)
    # ------------------------------------------------------------------------
    def test_13_target_provenance_factory_trace_preservation(self) -> None:
        """Verify that FACTORY_TRACE replay preserves target 0x78 even when target_address is omitted."""
        factory_frame = bytes.fromhex("8B F1 78 5A 89 30 38 30 30 37 32 38 35 36 AB")
        # Call execute_job with evidence_domain=FACTORY_TRACE without passing target_address
        res: EdiabasJobResult = execute_job(
            "SERIENNUMMER_LESEN",
            factory_frame,
            evidence_domain=EvidenceDomain.FACTORY_TRACE,
        )

        self.assertTrue(res.is_ok)
        self.assertEqual(res.target_address, 0x78)
        self.assertEqual(res.logical_request[1], 0x78)
        self.assertEqual(res.canonical_ds2_request[1], 0x78)
        self.assertEqual(res.evidence_domain, EvidenceDomain.FACTORY_TRACE)
        self.assertFalse(res.physical_trace_exists)
        self.assertFalse(res.directly_resolved)
        self.assertIn("0x78", res.as_dict()["target_address"])

    # ------------------------------------------------------------------------
    # Test 14: Physical EGS Target Provenance Preservation (0x18)
    # ------------------------------------------------------------------------
    def test_14_target_provenance_physical_egs_preservation(self) -> None:
        """Verify that PHYSICAL_EGS_FIXTURE replay preserves target 0x18."""
        res: EdiabasJobResult = execute_job(
            "IDENT",
            self.ident_fixture_path,
            evidence_domain=EvidenceDomain.PHYSICAL_EGS_FIXTURE,
        )

        self.assertTrue(res.is_ok)
        self.assertEqual(res.target_address, 0x18)
        self.assertEqual(res.logical_request[1], 0x18)
        self.assertEqual(res.canonical_ds2_request[1], 0x18)
        self.assertEqual(res.evidence_domain, EvidenceDomain.PHYSICAL_EGS_FIXTURE)
        self.assertTrue(res.physical_trace_exists)
        self.assertTrue(res.directly_resolved)
        self.assertEqual(res.as_dict()["target_address"], "0x18")

    # ------------------------------------------------------------------------
    # Test 15: Target Rewriting Provenance Violation Rejection
    # ------------------------------------------------------------------------
    def test_15_factory_target_rewriting_rejection(self) -> None:
        """Verify that attempting to rewrite the target of a FACTORY_TRACE to 0x18 is strictly rejected."""
        factory_frame = bytes.fromhex("8B F1 78 5A 89 30 38 30 30 37 32 38 35 36 AB")

        # Attempting to force target_address=0x18 on a FACTORY_TRACE must raise ValueError
        with self.assertRaises(ValueError) as ctx:
            execute_job(
                "SERIENNUMMER_LESEN",
                factory_frame,
                evidence_domain=EvidenceDomain.FACTORY_TRACE,
                target_address=0x18,
            )
        self.assertIn("FACTORY_TRACE provenance violation", str(ctx.exception))
        self.assertIn("0x18", str(ctx.exception))

        # Attempting to force target_address=0x78 on a PHYSICAL_EGS_FIXTURE must raise ValueError
        with self.assertRaises(ValueError) as ctx2:
            execute_job(
                "IDENT",
                self.ident_fixture_path,
                evidence_domain=EvidenceDomain.PHYSICAL_EGS_FIXTURE,
                target_address=0x78,
            )
        self.assertIn("PHYSICAL_EGS_FIXTURE provenance violation", str(ctx2.exception))
        self.assertIn("0x78", str(ctx2.exception))

    # ------------------------------------------------------------------------
    # Test 16: Raw Frame Auto-Detection of Target Address
    # ------------------------------------------------------------------------
    def test_16_raw_frame_target_auto_detection(self) -> None:
        """Verify that raw frame bytes automatically detect target 0x78 for factory and 0x18 for bench."""
        factory_frame = bytes.fromhex("8B F1 78 5A 89 30 38 30 30 37 32 38 35 36 AB")
        res_factory = execute_job("SERIENNUMMER_LESEN", factory_frame)
        self.assertEqual(res_factory.evidence_domain, EvidenceDomain.FACTORY_TRACE)
        self.assertEqual(res_factory.target_address, 0x78)
        self.assertEqual(res_factory.logical_request[1], 0x78)

        bench_frame = build_ds2_frame(dst=0xF1, src=0x18, payload=b"\x5A\x80" + b"\x00" * 35)
        res_bench = execute_job("IDENT", bench_frame)
        self.assertEqual(res_bench.evidence_domain, EvidenceDomain.PHYSICAL_EGS_FIXTURE)
        self.assertEqual(res_bench.target_address, 0x18)
        self.assertEqual(res_bench.logical_request[1], 0x18)

    # ------------------------------------------------------------------------
    # Test 17: Canonical DS2 Request Addressing Semantics (Destination vs Source)
    # ------------------------------------------------------------------------
    def test_17_canonical_ds2_request_addressing_semantics(self) -> None:
        """Explicitly verify canonical DS2 request addressing:
            raw_frame[1] == destination / target
            raw_frame[2] == source / tester
        for both FACTORY_TRACE (0x78 / 0xF1) and PHYSICAL_EGS_FIXTURE (0x18 / 0xF1).
        """
        # 1. FACTORY_TRACE: destination/target = 0x78, source/tester = 0xF1
        factory_telegram = self.engine.build_logical_telegram(
            "SERIENNUMMER_LESEN", target_address=0x78, tester_address=0xF1
        )
        factory_wire = factory_telegram.to_wire_frame()

        # Logical telegram buffer (_TEL_AUFTRAG)
        self.assertEqual(factory_telegram.raw_buffer[1], 0x78)  # destination / target
        self.assertEqual(factory_telegram.raw_buffer[2], 0xF1)  # source / tester
        self.assertEqual(factory_telegram.destination, 0x78)
        self.assertEqual(factory_telegram.destination_address, 0x78)
        self.assertEqual(factory_telegram.source, 0xF1)
        self.assertEqual(factory_telegram.source_address, 0xF1)

        # Canonical DS2 wire frame
        self.assertEqual(factory_wire[1], 0x78)  # destination / target
        self.assertEqual(factory_wire[2], 0xF1)  # source / tester

        # Executed Replay Result
        factory_frame = bytes.fromhex("8B F1 78 5A 89 30 38 30 30 37 32 38 35 36 AB")
        factory_res = execute_job(
            "SERIENNUMMER_LESEN", factory_frame, evidence_domain=EvidenceDomain.FACTORY_TRACE
        )
        self.assertEqual(factory_res.logical_request[1], 0x78)  # destination / target
        self.assertEqual(factory_res.logical_request[2], 0xF1)  # source / tester
        self.assertEqual(factory_res.canonical_ds2_request[1], 0x78)  # destination / target
        self.assertEqual(factory_res.canonical_ds2_request[2], 0xF1)  # source / tester
        self.assertEqual(factory_res.destination_address, 0x78)
        self.assertEqual(factory_res.source_address, 0xF1)

        # 2. PHYSICAL_EGS_FIXTURE: destination/target = 0x18, source/tester = 0xF1
        egs_telegram = self.engine.build_logical_telegram(
            "IDENT", target_address=0x18, tester_address=0xF1
        )
        egs_wire = egs_telegram.to_wire_frame()

        # Logical telegram buffer (_TEL_AUFTRAG)
        self.assertEqual(egs_telegram.raw_buffer[1], 0x18)  # destination / target
        self.assertEqual(egs_telegram.raw_buffer[2], 0xF1)  # source / tester
        self.assertEqual(egs_telegram.destination, 0x18)
        self.assertEqual(egs_telegram.destination_address, 0x18)
        self.assertEqual(egs_telegram.source, 0xF1)
        self.assertEqual(egs_telegram.source_address, 0xF1)

        # Canonical DS2 wire frame
        self.assertEqual(egs_wire[1], 0x18)  # destination / target
        self.assertEqual(egs_wire[2], 0xF1)  # source / tester

        # Executed Replay Result
        egs_res = execute_job(
            "IDENT", self.ident_fixture_path, evidence_domain=EvidenceDomain.PHYSICAL_EGS_FIXTURE
        )
        self.assertEqual(egs_res.logical_request[1], 0x18)  # destination / target
        self.assertEqual(egs_res.logical_request[2], 0xF1)  # source / tester
        self.assertEqual(egs_res.canonical_ds2_request[1], 0x18)  # destination / target
        self.assertEqual(egs_res.canonical_ds2_request[2], 0xF1)  # source / tester
        self.assertEqual(egs_res.destination_address, 0x18)
        self.assertEqual(egs_res.source_address, 0xF1)

        # 3. Explicit destination_address and source_address kwargs
        alias_telegram = self.engine.build_logical_telegram(
            "IDENT", destination_address=0x18, source_address=0xF1
        )
        self.assertEqual(alias_telegram.destination, 0x18)
        self.assertEqual(alias_telegram.source, 0xF1)

        alias_res = execute_job(
            "IDENT",
            self.ident_fixture_path,
            evidence_domain=EvidenceDomain.PHYSICAL_EGS_FIXTURE,
            destination_address=0x18,
            source_address=0xF1,
        )
        self.assertEqual(alias_res.destination_address, 0x18)
        self.assertEqual(alias_res.source_address, 0xF1)


if __name__ == "__main__":
    unittest.main()
