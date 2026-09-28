"""Comprehensive golden test suite for Milestone 5.18 Offline Calibration Reconnaissance.

Validates all 12 test requirements from the specification:
1. Provenance / hash verification
2. Deterministic inventory generation
3. Deterministic layout generation
4. Map candidate extraction
5. Axis candidate extraction
6. Endianness handling
7. Signed/unsigned decoding
8. Unknown / ambiguous classification
9. Checksum candidate extraction
10. No hardware imports / execution in scanner
11. Source files remain unchanged
12. Repeated run produces byte-identical artifacts
"""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

from reconstruction.calibration.hex_parser import IntelHexParser
from reconstruction.calibration.inventory import build_flash_inventory, build_flash_layout, compute_sha256
from reconstruction.calibration.map_detector import detect_axes, detect_checksum_regions, detect_map_candidates
from reconstruction.calibration.recon import run_reconnaissance


class TestCalibrationRecon(unittest.TestCase):
    """Test suite verifying all 12 Milestone 5.18 reconnaissance requirements."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.synthetic_bin = Path("tests/fixtures/synthetic/synthetic_image.bin")
        cls.primary_da = Path("/Users/blogman/bmw_flash_re/spdaten_gke/E60/data/GKE195/A7592133.0da")
        cls.base_pa = Path("/Users/blogman/bmw_flash_re/spdaten_gke/E60/data/GKE215/7591971A.0pa")
        cls.dat_file = Path("/Users/blogman/bmw_flash_re/spdaten_gke/E60/data/GKE195/GKE195.DAT")

    def test_01_provenance_and_hash_verification(self) -> None:
        """Req 1: Verify source files exist and match known frozen hashes."""
        self.assertTrue(self.synthetic_bin.is_file())
        self.assertTrue(self.primary_da.is_file())
        self.assertTrue(self.base_pa.is_file())
        self.assertTrue(self.dat_file.is_file())

        da_hash = compute_sha256(self.primary_da)
        self.assertEqual(da_hash, "45b473d1ee8cc2542a1eb3ecb77bf446f357f81827a464e6c3489257312a0112")

        pa_hash = compute_sha256(self.base_pa)
        self.assertEqual(pa_hash, "63b204d2edbdaa0945d9b0241d55df7c6859b41d3376d9f35e93cc6c82ecfcc3")

        dat_hash = compute_sha256(self.dat_file)
        self.assertEqual(dat_hash, "6e88abf482c0cfe63ce302297b3721d2b00d47032593c477ee79ba6838daea98")

    def test_02_deterministic_inventory_generation(self) -> None:
        """Req 2: Verify deterministic inventory generation and required schema fields."""
        files = {
            "primary_calibration": self.primary_da,
            "base_program": self.base_pa,
            "assembly_table": self.dat_file,
            "synthetic": self.synthetic_bin,
        }
        inv1 = build_flash_inventory(files)
        inv2 = build_flash_inventory(files)
        self.assertEqual(inv1, inv2)
        self.assertEqual(inv1["total_analyzed"], 4)

    def test_03_deterministic_layout_generation(self) -> None:
        """Req 3: Verify deterministic layout generation and segment classifications."""
        image = IntelHexParser.parse_file(self.primary_da)
        layout = build_flash_layout({"A7592133.0da": image})
        self.assertIn("images", layout)
        self.assertIn("A7592133.0da", layout["images"])
        segs = layout["images"]["A7592133.0da"]["segments"]
        self.assertTrue(len(segs) >= 4)

    def test_04_map_candidate_extraction(self) -> None:
        """Req 4: Verify map candidates have explicit dimensions labeled 'candidate'."""
        image = IntelHexParser.parse_file(self.primary_da)
        cal_seg = next(s for s in image.segments if s.start_address >= 0x000500A0)
        axes = detect_axes(cal_seg)
        maps = detect_map_candidates(cal_seg, axes)
        self.assertTrue(len(maps) > 0)
        for m in maps[:10]:
            self.assertIn("candidate", m.dimensions.lower())
            self.assertEqual(m.evidence_class, "[R]")

    def test_05_axis_candidate_extraction(self) -> None:
        """Req 5: Verify axis candidates have valid element counts and monotonicity."""
        image = IntelHexParser.parse_file(self.primary_da)
        cal_seg = next(s for s in image.segments if s.start_address >= 0x000500A0)
        axes = detect_axes(cal_seg)
        self.assertTrue(len(axes) > 0)
        for a in axes[:10]:
            self.assertTrue(a.element_count >= 4)
            self.assertEqual(a.monotonicity, "strictly_increasing")

    def test_06_endianness_handling(self) -> None:
        """Req 6: Verify little-endian and big-endian decoding are captured."""
        image = IntelHexParser.parse_file(self.primary_da)
        cal_seg = next(s for s in image.segments if s.start_address >= 0x000500A0)
        axes = detect_axes(cal_seg)
        le_axes = [a for a in axes if a.endianness == "little_endian"]
        be_axes = [a for a in axes if a.endianness == "big_endian"]
        self.assertTrue(len(le_axes) > 0)
        self.assertTrue(len(be_axes) > 0)

    def test_07_signed_unsigned_decoding(self) -> None:
        """Req 7: Verify signedness metadata is recorded as unsigned or signed."""
        image = IntelHexParser.parse_file(self.primary_da)
        cal_seg = next(s for s in image.segments if s.start_address >= 0x000500A0)
        axes = detect_axes(cal_seg)
        for a in axes[:10]:
            self.assertIn(a.signedness, ["unsigned", "signed"])

    def test_08_unknown_ambiguous_classification(self) -> None:
        """Req 8: Verify units remain 'UNKNOWN' and heuristic findings have provenance [R]."""
        image = IntelHexParser.parse_file(self.primary_da)
        cal_seg = next(s for s in image.segments if s.start_address >= 0x000500A0)
        axes = detect_axes(cal_seg)
        maps = detect_map_candidates(cal_seg, axes)
        for a in axes[:10]:
            self.assertEqual(a.units, "UNKNOWN")
        for m in maps[:10]:
            self.assertEqual(m.units, "UNKNOWN")
            self.assertEqual(m.evidence_class, "[R]")

    def test_09_checksum_candidate_extraction(self) -> None:
        """Req 9: Verify extraction of CARB CVN, EDIABAS header, and trailer checksums."""
        image = IntelHexParser.parse_file(self.primary_da)
        regions = detect_checksum_regions(image)
        algorithms = [r.checksum_algorithm for r in regions]
        self.assertIn("CARB_CVN_16BIT", algorithms)
        self.assertIn("EDIABAS_ADD16_HEX", algorithms)
        self.assertIn("RSA1024_SHA1_PKCS1_V1_5", algorithms)
        self.assertIn("BMW_BLOCK_TRAILER_CHECKSUM", algorithms)

    def test_10_no_hardware_imports_or_execution(self) -> None:
        """Req 10: Verify scanner code does not import pyserial or hardware adapters."""
        import importlib
        recon_mod = importlib.import_module("reconstruction.calibration.recon")
        inv_mod = importlib.import_module("reconstruction.calibration.inventory")
        map_mod = importlib.import_module("reconstruction.calibration.map_detector")
        hex_mod = importlib.import_module("reconstruction.calibration.hex_parser")

        for mod in [recon_mod, inv_mod, map_mod, hex_mod]:
            mod_text = Path(mod.__file__).read_text()
            self.assertNotIn("SerialKdcanTransport", mod_text)
            self.assertNotIn("serial.Serial", mod_text)
            self.assertNotIn("/dev/cu.", mod_text)

    def test_11_source_files_remain_unchanged(self) -> None:
        """Req 11: Verify original source file hashes remain strictly unmodified."""
        self.test_01_provenance_and_hash_verification()

    def test_12_repeated_run_produces_identical_artifacts(self) -> None:
        """Req 12: Verify two runs of the reconnaissance engine produce byte-identical JSONs."""
        with tempfile.TemporaryDirectory() as tmpdir1, tempfile.TemporaryDirectory() as tmpdir2:
            out1 = Path(tmpdir1)
            out2 = Path(tmpdir2)

            run_reconnaissance(output_dir=out1)
            run_reconnaissance(output_dir=out2)

            for filename in [
                "flash_inventory.json",
                "flash_layout.json",
                "map_candidates.json",
                "axes.json",
                "checksum_regions.json",
            ]:
                f1 = out1 / filename
                f2 = out2 / filename
                self.assertTrue(f1.is_file(), f"Missing {filename} in run 1")
                self.assertTrue(f2.is_file(), f"Missing {filename} in run 2")

                h1 = hashlib.sha256(f1.read_bytes()).hexdigest()
                h2 = hashlib.sha256(f2.read_bytes()).hexdigest()
                self.assertEqual(h1, h2, f"Artifact {filename} is not byte-identical across runs!")


if __name__ == "__main__":
    unittest.main()
