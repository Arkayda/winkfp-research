"""Structural Data Models for Milestone 5.20 Calibration Reconstruction.

Strictly offline, deterministic structural representations of calibration objects,
axes, tables, links, reference graph, and integrity regions.

Principle: STRUCTURE FIRST. SEMANTICS SECOND.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AxisCandidate:
    """Reconstructed 1D Monotonic Breakpoint Axis candidate."""

    id: str
    offset: str
    address: str
    width_bits: int
    signedness: str  # "unsigned", "signed"
    endian: str      # "big", "none"
    element_count: int
    raw_values: List[int]
    differences: List[int]
    monotonicity: str  # "strictly_increasing", "weakly_increasing"
    spacing: str       # "uniform", "non_uniform"
    possible_linkage_targets: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    semantic_hypothesis: str = "UNKNOWN"
    confidence: str = "UNCONFIRMED"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TableCandidate:
    """Reconstructed calibration map / table candidate."""

    id: str
    file: str
    file_offset: str
    address: str
    width_bits: int
    endianness: str
    signed: bool
    dimensions: List[int]
    axis_x: Optional[str]
    axis_y: Optional[str]
    references: List[str] = field(default_factory=list)
    structural_evidence: List[str] = field(default_factory=list)
    semantic_hypothesis: Optional[str] = None
    confidence: str = "UNCONFIRMED"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TableAxisLink:
    """Proven or candidate dimensional/structural linkage between a table and its axes."""

    table_id: str
    table_address: str
    table_dimensions: List[int]
    axis_x_id: str
    axis_x_address: str
    axis_x_count: int
    axis_y_id: Optional[str] = None
    axis_y_address: Optional[str] = None
    axis_y_count: Optional[int] = None
    link_type: str = "DIMENSIONAL_MATCH"  # DIMENSIONAL_MATCH, DESCRIPTOR_BINDING, EMBEDDED_AXIS
    evidence: List[str] = field(default_factory=list)
    confidence: str = "UNCONFIRMED"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ReferenceGraphEntry:
    """A cross-reference between code/data segments or between files."""

    source_file: str
    source_address: str
    target_file: str
    target_address: str
    reference_type: str  # DIRECT_REFERENCE, INDIRECT_REFERENCE, STRUCTURAL_CORRELATION
    description: str
    verified_binary_bytes: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ChecksumRegion:
    """Forensic record of a checksum, CVN, or integrity region."""

    region_id: str
    start_address: str
    end_address: str
    length_bytes: int
    region_type: str  # RSA_SIGNATURE, CARB_CVN, TRAILER_BLOCK, SEGMENT_PAYLOAD
    algorithm: str    # RSA-1024/SHA-1, CRC-32, CRC-16, N/A
    stored_value: str
    evidence_class: str  # FACT, INFERENCE
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SemanticHypothesis:
    """Strictly bounded engineering hypothesis for a calibration structure."""

    candidate_id: str
    address: str
    structure: str
    hypothesis: str
    confidence: str  # LOW, UNCONFIRMED (never FACT without dual independent proof)
    reasoning: str
    unresolved_questions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
