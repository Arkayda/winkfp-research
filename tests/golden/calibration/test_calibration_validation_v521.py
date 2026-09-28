"""Comprehensive Golden Test Suite for Milestone 5.21 Calibration Object Validation.

Verifies:
1. Exact Segment 4 accounting identities and canonical indexing
2. Reference taxonomy partitioning and validation
3. Separation of base-program references from runtime code references
4. Descriptor table recovery at 0x000454A0
5. Axis validation and ownership hierarchy
6. Table topology (12x8 descriptor-bound and 10x13 structural grids)
7. Reconstructed 6-stage execution role pipeline
8. Scaling analysis with evidence-bounded constants (750, 500, 6800)
9. Semantic candidates with strict confidence ceilings
10. Negative evidence and false-positive rejections preservation
11. Change log traceability from Milestone 5.20
12. Deterministic dual-pass serialization and source immutability
"""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from reconstruction.calibration.recon_v521 import (
    DEFAULT_DA_PATH,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_PA_PATH,
    CalibrationValidationV521,
)

FROZEN_DA_SHA256 = "45b473d1ee8cc2542a1eb3ecb77bf446f357f81827a464e6c3489257312a0112"


class TestCalibrationValidationV521(unittest.TestCase):
    """Golden regression test suite for Milestone 5.21."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.orchestrator = CalibrationValidationV521(
            da_path=DEFAULT_DA_PATH,
            pa_path=DEFAULT_PA_PATH,
            output_dir=DEFAULT_OUTPUT_DIR,
        )
        cls.artifacts = cls.orchestrator.run_all()

    # -------------------------------------------------------------------------
    # Gate 1: Canonical Object Index & Accounting Identity
    # -------------------------------------------------------------------------
    def test_01_canonical_accounting_identity(self) -> None:
        """Verify the exact mathematical accounting identities for Segment 4 pointers."""
        data = json.loads(self.artifacts["object_index"].read_text(encoding="utf-8"))
        acct = data["accounting"]

        self.assertEqual(acct["directory_entries"], 9176)
        self.assertEqual(acct["unique_target_addresses"], 6017)
        self.assertEqual(acct["alias_groups"], 1197)
        self.assertEqual(acct["alias_entries"], 3159)

        # Primary accounting identity: unique + alias = total
        self.assertEqual(
            acct["unique_target_addresses"] + acct["alias_entries"],
            acct["directory_entries"],
        )

        # Functional breakdown identity: payload + indirect + gap = total
        self.assertEqual(acct["pointers_into_payload"], 8451)
        self.assertEqual(acct["pointers_into_directory"], 720)
        self.assertEqual(acct["pointers_into_gap"], 5)
        self.assertEqual(
            acct["pointers_into_payload"] + acct["pointers_into_directory"] + acct["pointers_into_gap"],
            acct["directory_entries"],
        )

        # Explicit ENTRY METRICS and classification model
        self.assertIn("metrics", data)
        self.assertEqual(data["classification_model"], "MUTUALLY_EXCLUSIVE")
        self.assertEqual(data["metrics"]["directory_entries"], 9176)
        self.assertEqual(data["metrics"]["unique_target_addresses"], 6017)
        self.assertEqual(data["metrics"]["alias_entries"], 3159)

    # -------------------------------------------------------------------------
    # Gate 2 & 3: Reference Taxonomy and Base/Runtime Separation
    # -------------------------------------------------------------------------
    def test_02_reference_taxonomy_partitioning(self) -> None:
        """Verify recovered references belong to the required taxonomy classes."""
        data = json.loads(self.artifacts["reference_validation"].read_text(encoding="utf-8"))
        summary = data["summary_by_class"]

        valid_classes = {
            "DIRECT_CODE_REFERENCE",
            "INDIRECT_CODE_REFERENCE",
            "DESCRIPTOR_REFERENCE",
            "DATA_POINTER",
            "BASE_PROGRAM_REFERENCE",
            "CALIBRATION_INTERNAL_REFERENCE",
            "STRUCTURAL_REFERENCE",
            "HEURISTIC_POINTER",
            "FALSE_POSITIVE",
        }
        self.assertTrue(set(summary.keys()).issubset(valid_classes))
        self.assertTrue(summary.get("BASE_PROGRAM_REFERENCE", 0) >= 4)
        self.assertTrue(summary.get("DESCRIPTOR_REFERENCE", 0) >= 3)
        self.assertTrue(summary.get("CALIBRATION_INTERNAL_REFERENCE", 0) >= 720)

        # Distinguish ENTRY METRICS from REFERENCE CATEGORIES
        self.assertIn("entry_metrics", data)
        self.assertIn("reference_metrics", data)
        self.assertEqual(data["classification_model"], "MUTUALLY_EXCLUSIVE")
        self.assertEqual(data["entry_metrics"]["directory_entries"], 9176)
        self.assertEqual(data["entry_metrics"]["unique_target_addresses"], 6017)
        self.assertEqual(data["entry_metrics"]["alias_entries"], 3159)

    # -------------------------------------------------------------------------
    # Gate 4: Descriptor Record Validation
    # -------------------------------------------------------------------------
    def test_03_descriptor_table_binding(self) -> None:
        """Verify descriptor binding at 0x000454A0 linking Axis X, Axis Y, and Table."""
        data = json.loads(self.artifacts["reference_validation"].read_text(encoding="utf-8"))
        desc_refs = [
            r for r in data["references"]
            if r["reference_class"] == "DESCRIPTOR_REFERENCE"
        ]
        targets = {r["target_address"] for r in desc_refs}
        self.assertIn("0x00063AD6", targets)  # Axis X (12 elements)
        self.assertIn("0x00063AF0", targets)  # Axis Y (8 elements)
        self.assertIn("0x0006418A", targets)  # Table candidate

    # -------------------------------------------------------------------------
    # Gate 5 & 6: Axis Validation & Ownership Hierarchy
    # -------------------------------------------------------------------------
    def test_04_axis_validation_and_ownership(self) -> None:
        """Verify axis validation and ownership graph with strict epistemic ceilings."""
        axes_data = json.loads(self.artifacts["axis_validation"].read_text(encoding="utf-8"))
        links_data = json.loads(self.artifacts["axis_ownership"].read_text(encoding="utf-8"))

        for ax in axes_data["axes"]:
            # Epistemic invariant: all axes maintain UNKNOWN semantics
            self.assertEqual(ax["semantic_hypothesis"], "UNKNOWN")

        # Descriptor link is STRONGLY_SUPPORTED
        desc_links = [l for l in links_data["links"] if l["linkage_type"] == "DESCRIPTOR_BINDING"]
        self.assertTrue(len(desc_links) > 0)
        for l in desc_links:
            self.assertEqual(l["confidence"], "STRONGLY_SUPPORTED")

        # Dimension-only links are UNCONFIRMED
        dim_links = [l for l in links_data["links"] if l["linkage_type"] == "DIMENSIONAL_MATCH_ONLY"]
        self.assertTrue(len(dim_links) > 0)
        for l in dim_links:
            self.assertEqual(l["confidence"], "UNCONFIRMED")

    # -------------------------------------------------------------------------
    # Gate 7 & 8: Table Topology and Execution-Role Pipeline
    # -------------------------------------------------------------------------
    def test_05_table_topology_and_execution_roles(self) -> None:
        """Verify table topology and reconstructed 6-stage execution pipeline."""
        topo_data = json.loads(self.artifacts["table_topology"].read_text(encoding="utf-8"))
        role_data = json.loads(self.artifacts["execution_roles"].read_text(encoding="utf-8"))

        # Verify descriptor-bound topology
        desc_topo = next(t for t in topo_data["topologies"] if t["address"] == "0x0006418A")
        self.assertEqual(desc_topo["dimensions"], [12, 8])
        self.assertEqual(desc_topo["width_bits"], 16)
        self.assertEqual(desc_topo["stride_bytes"], 24)

        # Verify 7-stage execution role pipeline
        role = role_data["roles"][0]
        self.assertEqual(role["table_address"], "0x0006418A")
        self.assertEqual(len(role["execution_pipeline"]["stages"]), 7)
        self.assertEqual(
            role["execution_pipeline"]["stages"],
            ["INPUT", "INDEX", "AXIS LOOKUP", "TABLE ACCESS", "INTERPOLATION", "SCALE/OFFSET", "OUTPUT"],
        )
        self.assertEqual(role["confidence"], "SUPPORTED")
        self.assertEqual(role["execution_pipeline"]["pipeline_definition"], "PROVEN")
        self.assertEqual(role["execution_pipeline"]["structural_pipeline"], "STRONGLY_SUPPORTED")
        self.assertEqual(role["execution_pipeline"]["runtime_execution_pipeline"], "UNCONFIRMED")
        self.assertEqual(desc_topo["structural_interpolation_compatibility"], "SUPPORTED")
        self.assertEqual(desc_topo["runtime_interpolation_status"], "UNCONFIRMED")

        # Verify concrete binary evidence chain
        self.assertIn("pipeline_evidence_chain", role)
        chain = role["pipeline_evidence_chain"]
        self.assertEqual(len(chain), 7)
        levels = [t["evidence_level"] for t in chain]
        self.assertEqual(levels[0], "PROVEN")            # CODE_OR_DESCRIPTOR
        self.assertEqual(levels[1], "PROVEN")            # AXIS_X
        self.assertEqual(levels[2], "PROVEN")            # AXIS_Y
        self.assertEqual(levels[3], "UNCONFIRMED")       # INDEX_AND_INTERPOLATION (runtime unconfirmed; structural supported)
        self.assertEqual(levels[4], "PROVEN")            # TABLE
        self.assertEqual(levels[5], "UNCONFIRMED")       # SCALE_AND_OFFSET
        self.assertEqual(levels[6], "UNCONFIRMED")       # OUTPUT_AND_CONSUMER

    # -------------------------------------------------------------------------
    # Gate 9 & 10: Scaling Analysis and Semantic Hypotheses
    # -------------------------------------------------------------------------
    def test_06_scaling_and_semantics(self) -> None:
        """Verify scaling constants, 3-layer evidence separation, and hypotheses."""
        scale_data = json.loads(self.artifacts["scaling_candidates"].read_text(encoding="utf-8"))
        sem_data = json.loads(self.artifacts["semantic_candidates"].read_text(encoding="utf-8"))

        # Invariant: No PROVEN semantic claims
        for s in scale_data["candidates"]:
            self.assertIn(s["confidence"], ("SUPPORTED", "UNCONFIRMED", "HEURISTIC"))
            self.assertNotEqual(s["confidence"], "PROVEN")
            # Tri-layer separation check
            self.assertIn("layer_a_binary_evidence", s)
            self.assertIn("layer_b_external_corroboration", s)
            self.assertIn("layer_c_semantic_hypothesis", s)
            self.assertEqual(s["layer_a_binary_evidence"]["decoded_value"], s["raw_value_decimal"])

        # Constant 6800 must have UNKNOWN Layer C semantic hypothesis
        scale_6800 = next(s for s in scale_data["candidates"] if s["raw_value_decimal"] == 6800)
        self.assertEqual(scale_6800["confidence"], "UNCONFIRMED")
        self.assertEqual(scale_6800["layer_c_semantic_hypothesis"]["semantic_hypothesis"], "UNKNOWN")
        self.assertEqual(scale_6800["layer_c_semantic_hypothesis"]["confidence"], "UNCONFIRMED")

        for c in sem_data["candidates"]:
            self.assertIn(c["confidence"], ("PROVEN", "STRONGLY_SUPPORTED", "SUPPORTED", "UNCONFIRMED", "HEURISTIC", "REJECTED"))

    # -------------------------------------------------------------------------
    # Gate 11: Negative Evidence & Change Log Traceability
    # -------------------------------------------------------------------------
    def test_07_negative_evidence_and_change_log(self) -> None:
        """Verify rejected candidates and change log traceability from 5.20."""
        rej_data = json.loads(self.artifacts["rejected_candidates"].read_text(encoding="utf-8"))
        log_data = json.loads(self.artifacts["change_log"].read_text(encoding="utf-8"))

        # Preserved negative evidence
        self.assertTrue(len(rej_data["rejected"]) >= 3)
        for r in rej_data["rejected"]:
            self.assertTrue(len(r["rejection_reason"]) > 0)
            self.assertTrue(len(r["failed_test"]) > 0)

        # Traceable change log
        self.assertEqual(log_data["baseline_milestone"], "5.20")
        self.assertEqual(log_data["target_milestone"], "5.21")
        self.assertTrue(len(log_data["changes"]) >= 11)

        # Verify all review blocker corrections are recorded in change log
        items = {c.get("item") for c in log_data["changes"]}
        self.assertIn("SEGMENT_4_ADDRESS_RANGE", items)
        self.assertIn("REFERENCE_COUNT_MODEL", items)
        self.assertIn("AIF_SERVICE_IDENTIFIER", items)
        self.assertIn("EXECUTION_PIPELINE_STAGES", items)
        self.assertIn("SCALING_EVIDENCE_LAYERING", items)
        self.assertIn("INDEX_AND_INTERPOLATION_EVIDENCE_LEVEL", items)
        self.assertIn("EXECUTION_PIPELINE_CONFIDENCE", items)
        self.assertIn("SCALAR_6800_SEMANTIC_HYPOTHESIS", items)

    # -------------------------------------------------------------------------
    # Gate 12: Determinism & Immutability Check
    # -------------------------------------------------------------------------
    def test_08_determinism_across_executions(self) -> None:
        """Verify bit-for-bit identity across repeated pipeline runs."""
        hashes_pass1 = {
            name: hashlib.sha256(p.read_bytes()).hexdigest()
            for name, p in self.artifacts.items()
        }

        orchestrator_pass2 = CalibrationValidationV521(
            da_path=DEFAULT_DA_PATH,
            pa_path=DEFAULT_PA_PATH,
            output_dir=DEFAULT_OUTPUT_DIR,
        )
        artifacts_pass2 = orchestrator_pass2.run_all()
        hashes_pass2 = {
            name: hashlib.sha256(p.read_bytes()).hexdigest()
            for name, p in artifacts_pass2.items()
        }

        for name in hashes_pass1:
            self.assertEqual(
                hashes_pass1[name],
                hashes_pass2[name],
                f"Non-deterministic serialization in {name}!",
            )

    def test_09_source_immutability(self) -> None:
        """Verify source calibration binary remains bit-for-bit unchanged."""
        digest = hashlib.sha256(DEFAULT_DA_PATH.read_bytes()).hexdigest()
        self.assertEqual(digest, FROZEN_DA_SHA256)

    def test_10_artifact_manifest(self) -> None:
        """Verify artifact manifest indexes all v520 and v521 artifacts."""
        self.assertIn("artifact_manifest", self.artifacts)
        manifest = json.loads(self.artifacts["artifact_manifest"].read_text(encoding="utf-8"))
        self.assertEqual(manifest["metadata"]["milestone"], "5.21")
        self.assertEqual(manifest["summary"]["total_v520_artifacts"], 8)
        self.assertEqual(manifest["summary"]["total_v521_artifacts"], 12)
        self.assertTrue(manifest["summary"]["deterministic"])


if __name__ == "__main__":
    unittest.main()
