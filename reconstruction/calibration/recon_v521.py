"""Reconstruction Orchestrator for Milestone 5.21 Calibration Object Validation.

Generates the 12 mandatory deterministic JSON artifacts in artifacts/calibration/:
1. object_index_v521.json
2. object_references_v521.json
3. reference_validation_v521.json
4. object_families_v521.json
5. axis_validation_v521.json
6. axis_ownership_v521.json
7. table_topology_v521.json
8. execution_roles_v521.json
9. scaling_candidates_v521.json
10. semantic_candidates_v521.json
11. rejected_candidates_v521.json
12. change_log_v521.json

Pure offline reverse-engineering. Zero hardware access.
Principle: STRUCTURE FIRST -> REFERENCE SECOND -> EXECUTION ROLE THIRD -> SEMANTICS LAST.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict

from reconstruction.calibration.axis_validation_v521 import AxisValidationEngine
from reconstruction.calibration.code_references_v521 import CodeReferenceEngine
from reconstruction.calibration.hex_parser import IntelHexParser, ParsedHexImage
from reconstruction.calibration.object_index_v521 import CanonicalObjectIndexBuilder
from reconstruction.calibration.semantic_recon_v521 import SemanticReconstructionEngine

DEFAULT_DA_PATH = Path("/Users/blogman/bmw_flash_re/spdaten_gke/E60/data/GKE195/A7592133.0da")
DEFAULT_PA_PATH = Path("/Users/blogman/bmw_flash_re/spdaten_gke/E60/data/GKE215/7591971A.0pa")
DEFAULT_OUTPUT_DIR = Path("artifacts/calibration")


class CalibrationValidationV521:
    """Orchestrator for Milestone 5.21 calibration object validation."""

    def __init__(
        self,
        da_path: Path = DEFAULT_DA_PATH,
        pa_path: Path = DEFAULT_PA_PATH,
        output_dir: Path = DEFAULT_OUTPUT_DIR,
    ) -> None:
        self.da_path = da_path
        self.pa_path = pa_path
        self.output_dir = output_dir

        self.da_image: ParsedHexImage = IntelHexParser.parse_file(self.da_path)
        self.pa_image: ParsedHexImage = IntelHexParser.parse_file(self.pa_path)

        # Gate 1: Canonical Object Index
        self.index_builder = CanonicalObjectIndexBuilder(self.da_image)
        self.index_catalog = self.index_builder.build_catalog()

        # Gate 2 & 3: Reference Recovery & Validation
        self.ref_engine = CodeReferenceEngine(self.da_image, self.pa_image)
        self.ref_catalog = self.ref_engine.recover_references()

        # Gate 5 & 6: Axis Validation & Ownership
        self.axis_engine = AxisValidationEngine(self.index_catalog, self.ref_catalog)
        self.axis_catalog = self.axis_engine.build_catalog()

        # Gate 7, 8, 9, 10, 11: Topology, Roles, Scaling, Semantics, Rejections
        self.semantic_engine = SemanticReconstructionEngine(
            self.index_catalog, self.ref_catalog, self.axis_catalog
        )
        self.semantic_catalog = self.semantic_engine.build_catalog()

    def run_all(self) -> Dict[str, Path]:
        """Execute full validation pipeline and write all 12 artifacts."""
        self.output_dir.mkdir(parents=True, exist_ok=True)

        results = {
            "object_index": self._write_json("object_index_v521.json", self.index_catalog.to_dict()),
            "object_references": self._write_json("object_references_v521.json", {
                "summary": self.ref_catalog.summary_by_class,
                "total_references": len(self.ref_catalog.references),
                "references": [r.to_dict() for r in self.ref_catalog.references],
            }),
            "reference_validation": self._write_json("reference_validation_v521.json", self.ref_catalog.to_dict()),
            "object_families": self._write_json("object_families_v521.json", {
                "distribution": self.index_catalog.family_distribution,
                "total_objects": len(self.index_catalog.entries),
            }),
            "axis_validation": self._write_json("axis_validation_v521.json", {
                "summary": self.axis_catalog.summary,
                "total_axes": len(self.axis_catalog.axes),
                "axes": [a.to_dict() for a in self.axis_catalog.axes],
            }),
            "axis_ownership": self._write_json("axis_ownership_v521.json", {
                "total_links": len(self.axis_catalog.ownership_links),
                "links": [l.to_dict() for l in self.axis_catalog.ownership_links],
            }),
            "table_topology": self._write_json("table_topology_v521.json", {
                "total_topologies": len(self.semantic_catalog.table_topologies),
                "topologies": [t.to_dict() for t in self.semantic_catalog.table_topologies],
            }),
            "execution_roles": self._write_json("execution_roles_v521.json", {
                "total_roles": len(self.semantic_catalog.execution_roles),
                "roles": [r.to_dict() for r in self.semantic_catalog.execution_roles],
            }),
            "scaling_candidates": self._write_json("scaling_candidates_v521.json", {
                "total_candidates": len(self.semantic_catalog.scaling_candidates),
                "candidates": [s.to_dict() for s in self.semantic_catalog.scaling_candidates],
            }),
            "semantic_candidates": self._write_json("semantic_candidates_v521.json", {
                "total_candidates": len(self.semantic_catalog.semantic_candidates),
                "candidates": [s.to_dict() for s in self.semantic_catalog.semantic_candidates],
            }),
            "rejected_candidates": self._write_json("rejected_candidates_v521.json", {
                "total_rejected": len(self.semantic_catalog.rejected_candidates),
                "rejected": [r.to_dict() for r in self.semantic_catalog.rejected_candidates],
            }),
            "change_log": self._write_json("change_log_v521.json", self._generate_change_log()),
        }
        results["artifact_manifest"] = self._write_json(
            "artifact_manifest_v521.json",
            self._generate_artifact_manifest(results),
        )
        return results

    def _write_json(self, filename: str, data: Any) -> Path:
        path = self.output_dir / filename
        content = json.dumps(data, indent=2, sort_keys=True) + "\n"
        path.write_text(content, encoding="utf-8")
        return path

    def _generate_artifact_manifest(self, current_results: Dict[str, Path]) -> Dict[str, Any]:
        """Generate comprehensive manifest of all Milestone 5.20 and 5.21 artifacts."""
        v520_files = [
            ("axis_candidates_v520.json", "Candidate monotonic breakpoint axes (1D arrays)"),
            ("axis_table_links_v520.json", "Structural linkage between axes and table candidates"),
            ("checksum_regions_v520.json", "Checksum and integrity regions identified in calibration segments"),
            ("flash_inventory_v520.json", "Complete inventory of flash segments and address boundaries"),
            ("map_semantics_v520.json", "Initial semantic candidates and structural classifications"),
            ("reference_graph_v520.json", "Cross-reference graph of pointers and targets"),
            ("segment_layout_v520.json", "Detailed layout and memory mapping of segments 1-4"),
            ("table_candidates_v520.json", "Candidate 2D table arrays and payload sizes"),
        ]
        v520_manifest = []
        for filename, desc in sorted(v520_files):
            p = self.output_dir / filename
            if p.exists():
                content = p.read_bytes()
                v520_manifest.append({
                    "description": desc,
                    "filename": filename,
                    "milestone": "5.20",
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "size_bytes": len(content),
                })

        v521_files = [
            ("axis_ownership_v521.json", "Axis-to-table ownership hierarchy separating descriptors from heuristics"),
            ("axis_validation_v521.json", "Validated monotonic breakpoint axes with bounded UNKNOWN semantics"),
            ("change_log_v521.json", "Traceable record of refinements, extensions, and corrections from 5.20"),
            ("execution_roles_v521.json", "Reconstructed 7-stage execution pipeline with per-transition evidence"),
            ("object_families_v521.json", "Normalized taxonomic distribution across object classes"),
            ("object_index_v521.json", "Full canonical index of 9,176 Segment 4 objects with accounting identities"),
            ("object_references_v521.json", "Recovered code and structural references partitioned by taxonomy"),
            ("reference_validation_v521.json", "Validation status, metrics, and evidence for every reference"),
            ("rejected_candidates_v521.json", "Preserved negative evidence and false-positive rejections"),
            ("scaling_candidates_v521.json", "Numeric constants (750, 500, 6800) with 3-layer evidence separation"),
            ("semantic_candidates_v521.json", "Evidence-bounded semantic hypotheses adhering to confidence ceilings"),
            ("table_topology_v521.json", "Topological models: dimensions, layouts, strides, clamp behaviors"),
        ]
        v521_manifest = []
        for filename, desc in sorted(v521_files):
            p = self.output_dir / filename
            if p.exists():
                content = p.read_bytes()
                v521_manifest.append({
                    "description": desc,
                    "filename": filename,
                    "milestone": "5.21",
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "size_bytes": len(content),
                })

        return {
            "epistemic_law": "SEMANTIC HYPOTHESIS != FACT. UNKNOWN REMAINS UNKNOWN.",
            "execution_mode": "100% OFFLINE ONLY — ZERO HARDWARE I/O",
            "metadata": {
                "donor_reference_program": str(self.pa_path),
                "milestone": "5.21",
                "sgbd": "GKE195 (address 0x18)",
                "target_calibration": str(self.da_path),
                "target_vehicle": "BMW E60 / M57D30TU2 / ZF 6HP28 / GS19.11",
            },
            "methodology": "STRUCTURE FIRST -> REFERENCE SECOND -> EXECUTION ROLE THIRD -> SEMANTICS LAST",
            "summary": {
                "deterministic": True,
                "total_indexed_artifacts": len(v520_manifest) + len(v521_manifest),
                "total_v520_artifacts": len(v520_manifest),
                "total_v521_artifacts": len(v521_manifest),
            },
            "v520_artifacts": v520_manifest,
            "v521_artifacts": v521_manifest,
        }

    def _generate_change_log(self) -> Dict[str, Any]:
        """Generate traceable record of modifications, refinements, and extensions from 5.20."""
        changes = [
            {
                "item": "SEGMENT_4_POINTER_DIRECTORY",
                "object_id": "SEGMENT_4_POINTER_DIRECTORY",
                "change_type": "REFINEMENT",
                "evidence": "Binary auditing of Segment 4 pointer addresses against loaded Intel HEX segments",
                "new_confidence": "PROVEN",
                "new_value": "8,451 direct data payload pointers + 720 indirect directory pointers + 5 gap pointers",
                "old_value": "9,176 direct calibration data payload pointers",
                "previous_confidence": "SUPPORTED",
                "reason": "Discovery of 720 nested indirect directory pointers and 5 alignment gap targets",
            },
            {
                "item": "MAP_DESC_0001_BINDING",
                "object_id": "MAP_DESC_0001_BINDING",
                "change_type": "EXTENSION",
                "evidence": "Descriptor block at 0x000454A0 in base program 7591971A.0pa",
                "new_confidence": "STRONGLY_SUPPORTED",
                "new_value": "Direct descriptor record binding Axis X (0x00063AD6, 12 points), Axis Y (0x00063AF0, 8 points), and Table (0x0006418A, 12x8 elements)",
                "old_value": "Heuristic cardinality matching for map and axes",
                "previous_confidence": "UNCONFIRMED",
                "reason": "Discovered multi-axis descriptor record in donor base program",
            },
            {
                "item": "MAPS_10x13_GROUP",
                "object_id": "MAPS_10x13_GROUP",
                "change_type": "REFINEMENT",
                "evidence": "Zero descriptor records linking 10x13 tables directly to pedal/speed axes",
                "new_confidence": "UNCONFIRMED",
                "new_value": "Dimensional match only without direct descriptor link; semantic hypothesis UNKNOWN",
                "old_value": "Possibly shift schedule maps (LOW / UNCONFIRMED)",
                "previous_confidence": "LOW",
                "reason": "Epistemic tightening to prevent unproven semantic promotion without execution evidence",
            },
            {
                "item": "SEGMENT_4_ADDRESS_RANGE",
                "object_id": "SEGMENT_4_ADDRESS_RANGE",
                "change_type": "CORRECTION",
                "evidence": "Intel HEX records in A7592133.0da: lines 8614-10907, base 0x00070000, start offset 0x6000, 36,704 bytes (0x8F60), end 0x0007EF60, exactly 9,176 32-bit entries",
                "new_confidence": "PROVEN",
                "new_value": "0x00076000 - 0x0007EF60 (canonical Intel HEX Segment 4 load address)",
                "old_value": "0x50000 - 0x58F7F (inadvertent report summary address)",
                "previous_confidence": "FACT",
                "reason": "Resolve report address discrepancy against raw binary source",
            },
            {
                "item": "REFERENCE_COUNT_MODEL",
                "object_id": "REFERENCE_COUNT_MODEL",
                "change_type": "REFINEMENT",
                "evidence": "Directory entry accounting identities vs cross-image code reference catalogs",
                "new_confidence": "PROVEN",
                "new_value": "Explicit separation between ENTRY METRICS (9,176 entries: 6,017 unique, 3,159 aliases, 8,451 payload, 720 indirect, 5 gap) and REFERENCE CATEGORIES (736 recovered code/structural references)",
                "old_value": "Unpartitioned scalar counts mixing directory entry metrics with code reference taxonomy",
                "previous_confidence": "SUPPORTED",
                "reason": "Prevent conflation of orthogonal measurement dimensions and enforce strict taxonomy",
            },
            {
                "item": "AIF_SERVICE_IDENTIFIER",
                "object_id": "AIF_SERVICE_IDENTIFIER",
                "change_type": "CORRECTION",
                "evidence": "GKE195 SGBD PRG inspection (Milestone 5.9 canonical pipeline) vs physical bench wire trace",
                "new_confidence": "PROVEN",
                "new_value": "Official AIF_LESEN ($23); 0x1A 0x86 preserved strictly as AIF_READ_BENCH_ALIAS",
                "old_value": "AIF (0x1A 0x86) presented as official SGBD read path",
                "previous_confidence": "FACT",
                "reason": "Distinguish official EDIABAS/SGBD diagnostic service ($23) from physical K+DCAN bench alias (0x1A 0x86)",
            },
            {
                "item": "EXECUTION_PIPELINE_STAGES",
                "object_id": "EXECUTION_PIPELINE_STAGES",
                "change_type": "CORRECTION",
                "evidence": "Enumeration of all 7 runtime pipeline stages with concrete binary evidence chain at 0x000454A0",
                "new_confidence": "PROVEN",
                "new_value": "7-stage execution pipeline (INPUT -> INDEX -> AXIS LOOKUP -> TABLE ACCESS -> INTERPOLATION -> SCALE/OFFSET -> OUTPUT)",
                "old_value": "6-stage execution pipeline",
                "previous_confidence": "STRONGLY_SUPPORTED",
                "reason": "Correct arithmetic misnomer in pipeline stage count and provide per-transition evidence levels",
            },
            {
                "item": "SCALING_EVIDENCE_LAYERING",
                "object_id": "SCALING_EVIDENCE_LAYERING",
                "change_type": "REFINEMENT",
                "evidence": "Binary constants at 0x000505BA (0x02EE=750), 0x000505BC (0x01F4=500), 0x000505BE (0x1A90=6800) vs vehicle physical specifications",
                "new_confidence": "SUPPORTED",
                "new_value": "Tri-layer separation: Layer A (Binary Evidence), Layer B (External Corroboration), Layer C (Semantic Hypothesis)",
                "old_value": "Unified scalar candidate records combining binary constants with vehicle ratings",
                "previous_confidence": "SUPPORTED",
                "reason": "Prevent unproven physical engineering units from being asserted as binary facts",
            },
            {
                "item": "INDEX_AND_INTERPOLATION_EVIDENCE_LEVEL",
                "object_id": "INDEX_AND_INTERPOLATION_EVIDENCE_LEVEL",
                "change_type": "REFINEMENT",
                "evidence": "Monotonic breakpoint geometry provides structural compatibility for 2D surface interpolation, but opcode trace of execution routine is absent in offline analysis",
                "new_confidence": "UNCONFIRMED",
                "new_value": "Runtime interpolation status UNCONFIRMED; structural_interpolation_compatibility remains SUPPORTED",
                "old_value": "Runtime interpolation labeled STRONGLY_SUPPORTED",
                "previous_confidence": "STRONGLY_SUPPORTED",
                "reason": "Prevent overclaiming runtime execution status without dynamic opcode trace while preserving structural compatibility",
            },
            {
                "item": "EXECUTION_PIPELINE_CONFIDENCE",
                "object_id": "EXECUTION_PIPELINE_CONFIDENCE",
                "change_type": "REFINEMENT",
                "evidence": "Downstream pipeline stages 4 (interpolation), 6 (scale/offset), and 7 (output consumer) are UNCONFIRMED in offline static analysis",
                "new_confidence": "SUPPORTED",
                "new_value": "Partitioned pipeline confidence: pipeline_definition=PROVEN, structural_pipeline=STRONGLY_SUPPORTED, runtime_execution_pipeline=UNCONFIRMED; overall execution role=SUPPORTED",
                "old_value": "Overall execution role labeled STRONGLY_SUPPORTED",
                "previous_confidence": "STRONGLY_SUPPORTED",
                "reason": "Overall execution role cannot exceed the confidence of its unconfirmed runtime stages",
            },
            {
                "item": "SCALAR_6800_SEMANTIC_HYPOTHESIS",
                "object_id": "SCALAR_6800_SEMANTIC_HYPOTHESIS",
                "change_type": "CORRECTION",
                "evidence": "Binary constant 0x1A90 (6800) in Segment 1 header lacks execution comparisons or arithmetic in base program",
                "new_confidence": "UNCONFIRMED",
                "new_value": "Layer C semantic_hypothesis=UNKNOWN, candidate_unit=UNKNOWN, confidence=UNCONFIRMED; external overspeed discussions relegated strictly to Layer B",
                "old_value": "Layer C semantic_hypothesis=turbine_overspeed_safety_ceiling",
                "previous_confidence": "UNCONFIRMED",
                "reason": "Eliminate speculative semantic preference without binary execution evidence",
            },
        ]
        return {
            "baseline_milestone": "5.20",
            "changes": changes,
            "target_milestone": "5.21",
            "total_changes": len(changes),
        }
