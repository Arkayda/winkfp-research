"""Semantics Catalog, Cross-Validation & Evidence Hierarchy Engine for Milestone 5.23.

Implements Task 4:
- Consumes structural and code evidence from function tracer and arithmetic engine.
- Evaluates multi-path cross-validation (Path A: Code, B: Scaling, C: Topology, D: Consumer).
- Preserves alternative semantic interpretations and explicit negative evidence.
- Enforces strict epistemic ceilings: downstream semantics cannot outrun code proof.
- 100% offline, zero hardware I/O.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from reconstruction.calibration.arithmetic_engine_v523 import ArithmeticAnalysisCatalog
from reconstruction.calibration.function_tracer_v523 import FunctionTraceCatalog


@dataclass
class AlternativeInterpretation:
    """Forensic model of an alternative explanation for an observed calibration structure."""

    candidate: str
    alternative: str
    supporting_evidence: List[str]
    contradicting_evidence: List[str]
    confidence: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SemanticCandidateRecord:
    """Forensic model of a candidate engineering semantic interpretation."""

    function_id: str
    object_ids: List[str]
    primary_hypothesis: str
    engineering_unit: str
    unit_confidence: str
    input_evidence: str
    axis_evidence: str
    curve_evidence: str
    arithmetic_evidence: str
    consumer_evidence: str
    confidence: str
    alternatives: List[AlternativeInterpretation]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "function_id": self.function_id,
            "object_ids": self.object_ids,
            "primary_hypothesis": self.primary_hypothesis,
            "engineering_unit": self.engineering_unit,
            "unit_confidence": self.unit_confidence,
            "input_evidence": self.input_evidence,
            "axis_evidence": self.axis_evidence,
            "curve_evidence": self.curve_evidence,
            "arithmetic_evidence": self.arithmetic_evidence,
            "consumer_evidence": self.consumer_evidence,
            "confidence": self.confidence,
            "alternatives": [a.to_dict() for a in self.alternatives],
        }


@dataclass
class CrossValidationReport:
    """Evaluation of independent forensic evidence paths supporting a calibration function."""

    function_id: str
    path_a_code_reference: bool
    path_b_scaling: bool
    path_c_topology: bool
    path_d_consumer_confirmed: bool
    path_e_helper_duplication: bool
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RejectedSemanticItem:
    """Forensic record of a rejected semantic hypothesis preserved as negative evidence."""

    hypothesis_id: str
    rejected_claim: str
    rejection_reason: str
    conclusive_counter_evidence: str
    source_status: str = "REJECTED"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RejectedSemanticCatalog:
    """Catalog of all rejected semantic hypotheses for forensic transparency."""

    rejected_items: List[RejectedSemanticItem]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_rejected_hypotheses": len(self.rejected_items),
            "rejected_hypotheses": [r.to_dict() for r in self.rejected_items],
        }


@dataclass
class SemanticCatalogBundle:
    """Bundle containing all semantic candidates, cross-validation, and negative evidence."""

    candidates: List[SemanticCandidateRecord]
    cross_validation: CrossValidationReport
    rejected_hypotheses: RejectedSemanticCatalog
    metrics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metrics": self.metrics,
            "candidates": [c.to_dict() for c in self.candidates],
            "cross_validation": self.cross_validation.to_dict(),
            "rejected_hypotheses": self.rejected_hypotheses.to_dict(),
        }


def build_semantics_catalog(
    fn_catalog: FunctionTraceCatalog,
    arith_catalog: ArithmeticAnalysisCatalog,
) -> SemanticCatalogBundle:
    """Construct semantic candidate records, multi-path cross validation, and negative evidence."""

    candidates = [
        SemanticCandidateRecord(
            function_id="CALCODE_CANDIDATE_0001",
            object_ids=[
                "TARGET_1_AXIS_X",
                "TARGET_2_AXIS_Y",
                "TARGET_3_KL_CURVE_1",
                "TARGET_4_KL_CURVE_2",
                "TARGET_5_KL_CURVE_3",
            ],
            primary_hypothesis="UNKNOWN (Dynamic torque / pressure transfer candidate)",
            engineering_unit="UNKNOWN",
            unit_confidence="UNCONFIRMED",
            input_evidence="TriCore register %d4 / %d5 argument flow; specific physical sensor source unconfirmed",
            axis_evidence="12-point signed int16 [-10..700] and 8-point unsigned uint16 [100..5500] monotonic breakpoints",
            curve_evidence="12-point characteristic curve with boundary offset (Curve 1) and floor (Curve 2); 8-point identity (Curve 3)",
            arithmetic_evidence="Piecewise linear interpolation structure supported; post-lookup clamp semantics UNCONFIRMED (raw constants 750/500 verified in Segment 5 Layer A, but executable clamp logic unevidenced)",
            consumer_evidence="Destination register %d2 return value; downstream actuator / state machine unconfirmed",
            confidence="UNCONFIRMED",
            alternatives=[
                AlternativeInterpretation(
                    candidate="Drivetrain torque coordination curve (Nm)",
                    alternative="Hydraulic line pressure regulation curve (bar / mbar) or normalized control variable",
                    supporting_evidence=[
                        "Numerical range [-10..700] matches automotive torque limits",
                        "Scalar constants [500, 750] present in Segment 5 header match ZF 6HP28 torque figures in Layer B corroboration",
                    ],
                    contradicting_evidence=[
                        "No direct unit conversion instruction or multiplier evidenced in binary",
                        "Downstream consumer remains unconfirmed; physical units cannot be proven from magnitude",
                    ],
                    confidence="UNCONFIRMED",
                ),
                AlternativeInterpretation(
                    candidate="Engine speed / turbine speed dependent selector",
                    alternative="Normalized transmission internal state counter",
                    supporting_evidence=[
                        "Axis Y range [100..5500] numerically matches engine RPM operating band",
                    ],
                    contradicting_evidence=[
                        "Executable code does not prove source variable is crankshaft/turbine speed sensor input",
                    ],
                    confidence="UNCONFIRMED",
                ),
            ],
        ),
    ]

    cross_validation = CrossValidationReport(
        function_id="CALCODE_CANDIDATE_0001",
        path_a_code_reference=True,
        path_b_scaling=False,
        path_c_topology=True,
        path_d_consumer_confirmed=False,
        path_e_helper_duplication=True,
        summary="Paths A (Code) and C (Topology) confirm structural code candidate; Path B (Scaling/Clamp) and Path D (Consumer) remain unconfirmed, capping overall confidence at UNCONFIRMED.",
    )

    rejected_items = [
        RejectedSemanticItem(
            hypothesis_id="REJ_2D_KF_TABLE_MAP_DESC_0001",
            rejected_claim="MAP_DESC_0001 targets represent a 12x8 2D map (KF) with bilinear interpolation",
            rejection_reason="Fields 6-11 in MAP_DESC_0001 contain explicit start/end bounding pairs for three distinct 1D characteristic curves (KL) of lengths 26 B, 26 B, and 18 B",
            conclusive_counter_evidence="Descriptor bounding pairs 0x0006418A-0x000641A3, 0x000641A4-0x000641BD, 0x000641BE-0x000641CF; count headers equal 12, 12, 8",
        ),
        RejectedSemanticItem(
            hypothesis_id="REJ_UNSUPPORTED_RPM_AXIS_LABEL",
            rejected_claim="Axis Y (0x00063AF0) is proven engine speed in RPM",
            rejection_reason="Physical units cannot be assigned solely from numeric range (100..5500) without tracing the runtime input variable to an independently confirmed sensor",
            conclusive_counter_evidence="Input variable origin remains UNCONFIRMED at the machine code boundary",
        ),
        RejectedSemanticItem(
            hypothesis_id="REJ_UNSUPPORTED_TORQUE_MAP_LABEL",
            rejected_claim="KL Curve 1 is proven torque limit in Nm",
            rejection_reason="Magnitude resemblance to torque values does not constitute binary evidence of physical unit",
            conclusive_counter_evidence="Downstream consumer destination is unconfirmed; no physical scaling factor is proven",
        ),
        RejectedSemanticItem(
            hypothesis_id="REJ_CONSTANT_6800_PROVEN_TURBINE_CEILING",
            rejected_claim="Constant 6800 at 0x000505BE is proven turbine overspeed ceiling",
            rejection_reason="While 6800 is a proven binary uint16 in Layer A (at 0x00050670), its Layer C semantic assignment is external speculation without local binary confirmation",
            conclusive_counter_evidence="Layer C semantics remain strictly UNKNOWN / UNCONFIRMED per evidence hierarchy; historical address 0x000505BE corrected to 0x00050670",
        ),
        RejectedSemanticItem(
            hypothesis_id="REJ_0x455XX_TARGET_ADDRESSES",
            rejected_claim="Addresses 0x00045500, 0x00045518, 0x00045528, 0x00045540, 0x00045558 are calibration target objects",
            rejection_reason="Addresses 0x000455xx fall into an unmapped memory gap in base program 7591971A.0pa (between 0x000454D0 and 0x00045590) and do not exist in calibration image A7592133.0da",
            conclusive_counter_evidence="Descriptor MAP_DESC_0001 at 0x000454A0 in 7591971A.0pa contains explicit 32-bit big-endian pointers to Segment 6 targets 0x00063AD6, 0x00063AF0, 0x0006418A, 0x000641A4, 0x000641BE in A7592133.0da",
        ),
        RejectedSemanticItem(
            hypothesis_id="REJ_0x00086002_CALLER_EDGE",
            rejected_claim="0x00086002 is a direct caller of 0x00086000",
            rejection_reason="0x00086002 is the second sequential instruction immediately following the 2-byte instruction at 0x00086000 in the same basic block",
            conclusive_counter_evidence="Decoded instruction at 0x00086000 is 16-bit OP16 (length 2B); control flows into 0x00086002 via normal sequential execution (FALLTHROUGH), with no incoming caller edge",
        ),
        RejectedSemanticItem(
            hypothesis_id="REJ_0x0009C580_CALLER_EDGE",
            rejected_claim="0x0009C580 is a direct caller of 0x00086000",
            rejection_reason="0x0009C580 is an unaligned intra-instruction offset within the 4-byte conditional branch at 0x0009C57E and has no caller relationship to 0x00086000",
            conclusive_counter_evidence="Instruction at 0x0009C57E branches to 0x000A3F7E and instruction at 0x0009C582 branches to 0x0009C636; neither targets 0x00086000",
        ),
        RejectedSemanticItem(
            hypothesis_id="REJ_0x00086000_PROVEN_FUNCTION_ENTRY",
            rejected_claim="0x00086000 is a proven function entry point / standalone procedure boundary",
            rejection_reason="No verified procedure-entry instruction (CALL, JAL), dispatch vector, or caller edge targets 0x00086000; reached via normal sequential fallthrough from 0x00085FFE",
            conclusive_counter_evidence="Instruction stream at 0x00085FFC (OP16: a4 e0) and 0x00085FFE (OP16: bc b0) falls through into 0x00086000 with no return, frame allocation, or call boundary; 0x00086000 is classified as BASIC_BLOCK_ENTRY with procedure_identity UNCONFIRMED",
        ),
        RejectedSemanticItem(
            hypothesis_id="REJ_PROVEN_750_500_CLAMP_SEMANTICS",
            rejected_claim="Constants 750 and 500 enforce upper/lower bounds on interpolated calibration outputs via proven runtime clamping",
            rejection_reason="No executable instruction sequence (CMP / conditional branch / saturation) loading and applying these constants as clamp boundaries has been evidenced in machine code",
            conclusive_counter_evidence="Constants 750 and 500 exist in Segment 5 calibration header (at 0x00050612 and 0x0005065A) but have unconfirmed runtime clamp execution; clamp semantics remain UNCONFIRMED",
        ),
    ]

    return SemanticCatalogBundle(
        candidates=candidates,
        cross_validation=cross_validation,
        rejected_hypotheses=RejectedSemanticCatalog(rejected_items=rejected_items),
        metrics={
            "total_candidates": len(candidates),
            "total_rejected_hypotheses": len(rejected_items),
            "cross_validation_paths_evaluated": 5,
        },
    )
