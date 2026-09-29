"""Golden tests for Milestone 5.22 Calibration Reconstruction Pipeline.

Tests Task 4 (Milestone522Pipeline orchestration), artifact generation,
determinism, change log entries, and artifact manifest completeness.
"""

import json
import tempfile
import unittest
from pathlib import Path

from reconstruction.calibration.code_regions_v522 import (
    DEFAULT_DA_PATH,
    DEFAULT_PA_PATH,
)
from reconstruction.calibration.recon_v522 import (
    Milestone522Pipeline,
    run_milestone_522_pipeline,
)


class TestCalibrationRuntimeV522(unittest.TestCase):
    """Test suite for full Milestone 5.22 calibration runtime pipeline."""

    @classmethod
    def setUpClass(cls):
        cls.pa_path = DEFAULT_PA_PATH if DEFAULT_PA_PATH.exists() else Path("spdaten_gke/E60/data/GKE215/7591971A.0pa")
        cls.da_path = DEFAULT_DA_PATH if DEFAULT_DA_PATH.exists() else Path("spdaten_gke/E60/data/GKE195/A7592133.0da")
        if not cls.pa_path.exists() or not cls.da_path.exists():
            raise unittest.SkipTest("Target SP-Daten binaries not found in workspace.")

    def test_pipeline_execution_and_artifacts(self):
        """Verify pipeline execution produces all 14 required artifacts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            pipeline = Milestone522Pipeline(
                da_path=self.da_path,
                pa_path=self.pa_path,
                output_dir=out_dir,
            )
            manifest = pipeline.execute()

            # Verify manifest
            self.assertEqual(manifest["total_artifacts"], 14)
            self.assertEqual(manifest["total_indexed_artifacts"], 13)
            self.assertEqual(manifest["self_hash_policy"], "EXCLUDED")
            self.assertEqual(manifest["integrity_model"], "DETERMINISTIC_ARTIFACT_MANIFEST")
            self.assertEqual(len(manifest["artifacts"]), 13)

            expected_indexed_artifacts = [
                "architecture_validation_v522.json",
                "code_regions_v522.json",
                "descriptor_traces_v522.json",
                "code_references_v522.json",
                "axis_lookup_v522.json",
                "curve_access_v522.json",
                "interpolation_analysis_v522.json",
                "scaling_runtime_v522.json",
                "output_consumers_v522.json",
                "execution_graph_v522.json",
                "semantic_runtime_candidates_v522.json",
                "rejected_runtime_hypotheses_v522.json",
                "change_log_v522.json",
            ]
            indexed_names = [art["filename"] for art in manifest["artifacts"]]
            self.assertEqual(indexed_names, expected_indexed_artifacts)

            # Verify every indexed artifact exists on disk and has matching size and sha256
            import hashlib
            for art_entry in manifest["artifacts"]:
                art_file = out_dir / art_entry["filename"]
                self.assertTrue(art_file.exists(), f"Missing indexed artifact: {art_entry['filename']}")
                file_bytes = art_file.read_bytes()
                self.assertEqual(len(file_bytes), art_entry["size_bytes"])
                self.assertEqual(hashlib.sha256(file_bytes).hexdigest(), art_entry["sha256"])

            # Verify manifest file itself exists on disk and is non-empty
            manifest_file = out_dir / "artifact_manifest_v522.json"
            self.assertTrue(manifest_file.exists())
            self.assertGreater(manifest_file.stat().st_size, 0)

            # Check change log contents
            with open(out_dir / "change_log_v522.json", "r", encoding="utf-8") as f:
                cl = json.load(f)
                self.assertGreaterEqual(len(cl["changes"]), 3)
                self.assertTrue(any("KL_CURVE" in c["new_value"] for c in cl["changes"]))

            # Check rejected hypotheses contents
            with open(out_dir / "rejected_runtime_hypotheses_v522.json", "r", encoding="utf-8") as f:
                rej = json.load(f)
                self.assertGreaterEqual(len(rej["rejected_hypotheses"]), 3)

    def test_pipeline_determinism(self):
        """Verify pipeline execution is 100% bit-for-bit deterministic across runs."""
        with tempfile.TemporaryDirectory() as tmp1, tempfile.TemporaryDirectory() as tmp2:
            out_dir1 = Path(tmp1)
            out_dir2 = Path(tmp2)

            pipe1 = Milestone522Pipeline(da_path=self.da_path, pa_path=self.pa_path, output_dir=out_dir1)
            pipe1.execute()

            pipe2 = Milestone522Pipeline(da_path=self.da_path, pa_path=self.pa_path, output_dir=out_dir2)
            pipe2.execute()

            all_files = [
                "architecture_validation_v522.json",
                "code_regions_v522.json",
                "descriptor_traces_v522.json",
                "code_references_v522.json",
                "axis_lookup_v522.json",
                "curve_access_v522.json",
                "interpolation_analysis_v522.json",
                "scaling_runtime_v522.json",
                "output_consumers_v522.json",
                "execution_graph_v522.json",
                "semantic_runtime_candidates_v522.json",
                "rejected_runtime_hypotheses_v522.json",
                "change_log_v522.json",
                "artifact_manifest_v522.json",
            ]
            for fname in all_files:
                f1 = (out_dir1 / fname).read_bytes()
                f2 = (out_dir2 / fname).read_bytes()
                self.assertEqual(f1, f2, f"Determinism failure for {fname}")


if __name__ == "__main__":
    unittest.main()
