"""Comprehensive Golden Test Suite for Milestone 5.19 Forensic Provenance Resolution.

Validates all 10 test requirements from the specification:
1. ZB 7592132 provenance
2. SW 7592133 correlation
3. Physical AIF anchor correlation
4. A7592133.0da provenance
5. GKE195/GKE196/GKE215 classification
6. 6HP19 vs 6HP26 vs 6HP28 classification
7. 7591971A.0PA applicability
8. Evidence class correctness
9. Deterministic output
10. Source file immutability
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from reconstruction.ecu.graph import build_default_egs_provenance_graph
from reconstruction.ecu.provenance import (
    CANONICAL_SOURCE_HASHES,
    CANONICAL_TRACE_HASHES,
    DEFAULT_E60_DATEN_ROOT,
    DEFAULT_SPDATEN_ROOT,
    build_egs_6hp28_software_lineage,
    build_egs_family_matrix,
    build_zb_7592132_provenance,
    compute_sha256,
    export_provenance_artifacts,
    verify_source_integrity,
    verify_trace_integrity,
)


class TestEcuProvenance(unittest.TestCase):
    """Test suite verifying all 10 Milestone 5.19 provenance requirements."""

    def test_01_zb_7592132_provenance(self) -> None:
        """Req 1: Verify ZB 7592132 is an assembly number (not serial), belongs to GKE195."""
        data = build_zb_7592132_provenance()
        assembly = data["assembly_number"]
        self.assertEqual(assembly["value"], "7592132")
        self.assertEqual(assembly["canonical_name"], "ZB-Nummer")
        self.assertFalse(assembly["is_serial_number"])
        self.assertIn("Zusammenbaunummer", assembly["german_designation"])

        diag = data["diagnostic_and_tooling_chain"]
        self.assertEqual(diag["sgbd_family"], "GKE195")
        self.assertEqual(diag["ecu_address_hex"], "0x18")
        self.assertEqual(diag["prg_file"], "10FLASH.prg")
        self.assertEqual(diag["ipo_script"], "03GKE195.ipo")

        hw = data["hardware_numbers"]
        self.assertEqual(hw["programmed_hardware"]["value"], "7591972")
        self.assertEqual(hw["unprogrammed_hardware"]["value"], "7569980")

        verdict = data["classification_verdict"]
        self.assertEqual(verdict["determination"], "TARGET_EGS_6HP28")

    def test_02_sw_7592133_correlation(self) -> None:
        """Req 2: Verify SW 7592133 correlates with A7592133.0da and 0479S90T641Z1ZY02."""
        data = build_zb_7592132_provenance()
        cal = data["calibration_artifact"]
        self.assertEqual(cal["file_name"], "A7592133.0da")
        self.assertEqual(cal["software_number"], "7592133DA")
        self.assertEqual(cal["referenz_string"], "0479S90T641Z1ZY02")
        self.assertEqual(cal["header_application"], "E60 M57D30TU2")
        self.assertEqual(cal["header_system"], "GS19.11.0")

    def test_03_physical_aif_anchor_correlation(self) -> None:
        """Req 3: Verify exact correlation with physical bench EGS anchors."""
        data = build_zb_7592132_provenance()
        bench = data["bench_anchor_correlation"]

        self.assertEqual(bench["aif_zb_nr"]["bench_observed"], "7592132")
        self.assertEqual(bench["aif_zb_nr"]["status"], "EXACT_MATCH")

        self.assertEqual(bench["aif_sw_nr"]["bench_observed"], "7592133")
        self.assertEqual(bench["aif_sw_nr"]["status"], "EXACT_MATCH")

        self.assertEqual(bench["aif_fg_nr"]["bench_observed"], "CS68294")
        self.assertEqual(bench["aif_datum"]["bench_observed"], "04.12.2008")

        self.assertEqual(bench["ident_hwnr"]["bench_observed"], "7591972")
        self.assertEqual(bench["ident_hwnr"]["source_service"], "IDENT (0x1A 0x80)")
        self.assertEqual(bench["ident_fsv"]["bench_observed"], "195.64.1")

        self.assertEqual(bench["phys_hw_nr"]["bench_observed"], "7569980")
        self.assertEqual(bench["zif_reference"]["bench_observed"], "0479S90T641Z")

    def test_04_a7592133_0da_provenance(self) -> None:
        """Req 4: Verify A7592133.0da is the genuine target EGS 6HP28 calibration."""
        data = build_zb_7592132_provenance()
        cal = data["calibration_artifact"]
        self.assertEqual(cal["lineage_role"], "TARGET_CALIBRATION_DATA")
        self.assertEqual(cal["cvn_mode9"], "0000F41E")
        self.assertEqual(cal["ediabas_checksum"], "2352 H")

        powertrain = data["vehicle_and_powertrain_applicability"]
        self.assertEqual(powertrain["engine"]["generation"], "M57D30TU2 (M57TU2)")
        self.assertEqual(powertrain["transmission"]["zf_model"], "ZF 6HP28")
        self.assertEqual(powertrain["transmission"]["max_input_torque"], "750 Nm")

    def test_05_gke195_gke196_gke215_classification(self) -> None:
        """Req 5: Verify GKE195 = 6HP28, GKE215 = 6HP19TU/21, GKE196 = Non-existent."""
        matrix = build_egs_family_matrix()

        # GKE196 refutation
        gke196 = matrix["gke196_refutation"]
        self.assertEqual(gke196["status"], "NON_EXISTENT")
        self.assertEqual(gke196["spdaten_count"], 0)
        self.assertEqual(gke196["kmm_count"], 0)

        # GKE195 vs GKE215
        families = {f["gke_type"]: f for f in matrix["transmission_families"]}
        self.assertIn("GKE195", families)
        self.assertIn("GKE215", families)

        gke195 = families["GKE195"]
        self.assertIn("6HP28", gke195["transmission_variant"])
        self.assertEqual(gke195["max_torque_nm"], 750)
        self.assertEqual(gke195["ipo_file"], "03GKE195.ipo")

        gke215 = families["GKE215"]
        self.assertIn("6HP21", gke215["transmission_variant"])
        self.assertEqual(gke215["max_torque_nm"], 450)
        self.assertEqual(gke215["ipo_file"], "11GKE215.ipo")

    def test_06_6hp_variant_classification(self) -> None:
        """Req 6: Verify 6HP19 vs 6HP19TU vs 6HP26 vs 6HP28 separation."""
        matrix = build_egs_family_matrix()
        variants = {f["transmission_variant"]: f for f in matrix["transmission_families"]}

        self.assertTrue(any("6HP19 (" in v for v in variants))
        self.assertTrue(any("6HP19TU" in v for v in variants))
        self.assertTrue(any("6HP26 (" in v for v in variants))
        self.assertTrue(any("6HP28" in v for v in variants))

        hp28 = next(v for k, v in variants.items() if "6HP28" in k)
        self.assertEqual(hp28["shifter_type"], "Electronic joystick shifter (GWS)")
        self.assertEqual(hp28["generation"], "2nd Gen 6HP (LCI / 'TÜ')")

    def test_07_7591971a_0pa_applicability(self) -> None:
        """Req 7: Verify 7591971A.0pa is classified as RELATED_BASE_PROGRAM_GS19_11."""
        data = build_zb_7592132_provenance()
        prog = data["operating_program_artifact"]
        self.assertEqual(prog["file_name"], "7591971A.0pa")
        self.assertEqual(prog["lineage_role"], "RELATED_BASE_PROGRAM_GS19_11")
        self.assertEqual(prog["header_system"], "GS19.11.0")
        self.assertEqual(prog["referenz_string"], "0479SA0T641Z")
        self.assertIn("6HP19/TÜ", prog["comment_gearbox_string"])
        self.assertIn("0x000500A0", prog["internal_pointers"])

    def test_08_evidence_class_correctness(self) -> None:
        """Req 8: Verify all provenance fields are strictly labeled with valid evidence classes."""
        data = build_zb_7592132_provenance()
        allowed = {"[C]", "[O]", "[W]", "[R]", "[U]"}

        self.assertIn(data["assembly_number"]["evidence_class"], allowed)
        self.assertIn(data["calibration_artifact"]["evidence_class"], allowed)
        self.assertIn(data["operating_program_artifact"]["evidence_class"], allowed)
        self.assertIn(data["classification_verdict"]["evidence_class"], allowed)
        self.assertIn(data["vehicle_and_powertrain_applicability"]["engine"]["evidence_class"], allowed)

        for item in data["secondary_web_evidence"]:
            self.assertEqual(item["evidence_class"], "[W]")

        for anchor in data["bench_anchor_correlation"].values():
            self.assertEqual(anchor["evidence_class"], "[O]")

    def test_09_deterministic_output(self) -> None:
        """Req 9: Verify export produces byte-identical JSON outputs across repeated runs."""
        with tempfile.TemporaryDirectory() as tmpdir1, tempfile.TemporaryDirectory() as tmpdir2:
            out1 = Path(tmpdir1)
            out2 = Path(tmpdir2)

            export_provenance_artifacts(output_dir=out1)
            export_provenance_artifacts(output_dir=out2)

            for filename in [
                "zb_7592132_provenance.json",
                "egs_6hp28_software_lineage.json",
                "egs_6hp19_6hp26_6hp28_family_matrix.json",
            ]:
                f1 = out1 / filename
                f2 = out2 / filename
                self.assertTrue(f1.is_file(), f"Missing {filename} in run 1")
                self.assertTrue(f2.is_file(), f"Missing {filename} in run 2")

                h1 = hashlib.sha256(f1.read_bytes()).hexdigest()
                h2 = hashlib.sha256(f2.read_bytes()).hexdigest()
                self.assertEqual(h1, h2, f"Artifact {filename} is not byte-identical across runs!")

    def test_10_source_file_immutability(self) -> None:
        """Req 10: Verify SP-Daten files and frozen traces remain 100% bit-for-bit unchanged."""
        src_status = verify_source_integrity()
        for name, ok in src_status.items():
            self.assertTrue(ok, f"Source file {name} failed SHA-256 verification!")

        trace_status = verify_trace_integrity()
        for rel_path, ok in trace_status.items():
            self.assertTrue(ok, f"Hardware trace {rel_path} failed SHA-256 verification!")


if __name__ == "__main__":
    unittest.main()
