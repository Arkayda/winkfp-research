"""Golden tests for Milestone 5.23 Calibration Function Reconstruction Pipeline.

Tests Task 5: Pipeline orchestration, 17 deterministic JSON artifacts,
non-circular manifest integrity, bit-for-bit determinism, and change log.
"""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from reconstruction.calibration.code_regions_v522 import (
    DEFAULT_DA_PATH,
    DEFAULT_PA_PATH,
)
from reconstruction.calibration.recon_v523 import (
    Milestone523Pipeline,
    run_milestone_523_pipeline,
)


class TestCalibrationFunctionV523(unittest.TestCase):
    """Test suite for Milestone 5.23 calibration function reconstruction pipeline."""

    @classmethod
    def setUpClass(cls):
        cls.pa_path = DEFAULT_PA_PATH if DEFAULT_PA_PATH.exists() else Path("spdaten_gke/E60/data/GKE215/7591971A.0pa")
        cls.da_path = DEFAULT_DA_PATH if DEFAULT_DA_PATH.exists() else Path("spdaten_gke/E60/data/GKE195/A7592133.0da")
        if not cls.pa_path.exists() or not cls.da_path.exists():
            raise unittest.SkipTest("Target SP-Daten binaries not found.")

    def test_pipeline_execution_and_artifacts(self):
        """Verify pipeline execution produces all 17 required artifacts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            pipeline = Milestone523Pipeline(
                da_path=self.da_path,
                pa_path=self.pa_path,
                output_dir=out_dir,
            )
            manifest = pipeline.execute()

            # Verify manifest properties
            self.assertEqual(manifest["total_artifacts"], 18)
            self.assertEqual(manifest["total_indexed_artifacts"], 17)
            self.assertEqual(manifest["self_hash_policy"], "EXCLUDED")
            self.assertEqual(manifest["integrity_model"], "DETERMINISTIC_ARTIFACT_MANIFEST")
            self.assertEqual(len(manifest["artifacts"]), 17)

            expected_indexed = [
                "function_inventory_v523.json",
                "callgraph_v523.json",
                "control_flow_v523.json",
                "function_call_paths_v523.json",
                "descriptor_traces_v523.json",
                "input_semantics_v523.json",
                "axis_semantics_v523.json",
                "curve_semantics_v523.json",
                "interpolation_runtime_v523.json",
                "arithmetic_analysis_v523.json",
                "scaling_functions_v523.json",
                "output_semantics_v523.json",
                "engineering_units_v523.json",
                "cross_validation_v523.json",
                "semantic_alternatives_v523.json",
                "rejected_semantic_hypotheses_v523.json",
                "change_log_v523.json",
            ]
            indexed_names = [art["filename"] for art in manifest["artifacts"]]
            self.assertEqual(indexed_names, expected_indexed)

            # Verify all 16 indexed artifacts match on disk
            for entry in manifest["artifacts"]:
                art_file = out_dir / entry["filename"]
                self.assertTrue(art_file.exists(), f"Missing artifact: {entry['filename']}")
                content = art_file.read_bytes()
                self.assertEqual(len(content), entry["size_bytes"])
                self.assertEqual(hashlib.sha256(content).hexdigest(), entry["sha256"])

            # Verify manifest itself exists
            manifest_path = out_dir / "artifact_manifest_v523.json"
            self.assertTrue(manifest_path.exists())
            self.assertGreater(manifest_path.stat().st_size, 0)

            # Verify change log
            with open(out_dir / "change_log_v523.json", "r", encoding="utf-8") as f:
                cl = json.load(f)
                self.assertGreaterEqual(len(cl["changes"]), 2)

    def test_pipeline_determinism(self):
        """Verify pipeline is 100% bit-for-bit identical across runs."""
        with tempfile.TemporaryDirectory() as tmp1, tempfile.TemporaryDirectory() as tmp2:
            out_dir1 = Path(tmp1)
            out_dir2 = Path(tmp2)

            pipe1 = Milestone523Pipeline(da_path=self.da_path, pa_path=self.pa_path, output_dir=out_dir1)
            pipe1.execute()

            pipe2 = Milestone523Pipeline(da_path=self.da_path, pa_path=self.pa_path, output_dir=out_dir2)
            pipe2.execute()

            all_files = [
                "function_inventory_v523.json",
                "callgraph_v523.json",
                "control_flow_v523.json",
                "function_call_paths_v523.json",
                "descriptor_traces_v523.json",
                "input_semantics_v523.json",
                "axis_semantics_v523.json",
                "curve_semantics_v523.json",
                "interpolation_runtime_v523.json",
                "arithmetic_analysis_v523.json",
                "scaling_functions_v523.json",
                "output_semantics_v523.json",
                "engineering_units_v523.json",
                "cross_validation_v523.json",
                "semantic_alternatives_v523.json",
                "rejected_semantic_hypotheses_v523.json",
                "change_log_v523.json",
                "artifact_manifest_v523.json",
            ]
            for fname in all_files:
                b1 = (out_dir1 / fname).read_bytes()
                b2 = (out_dir2 / fname).read_bytes()
                self.assertEqual(b1, b2, f"Determinism failure for {fname}")


if __name__ == "__main__":
    unittest.main()
