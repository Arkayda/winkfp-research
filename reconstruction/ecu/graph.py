"""Directed Provenance Graph Builder for ECU and Firmware Lineage (Milestone 5.19).

Pure offline topological representation of vehicle-to-firmware relationships.
Zero hardware I/O.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass(frozen=True)
class ProvenanceNode:
    """A node in the provenance graph representing an entity or artifact."""

    node_id: str
    node_type: str  # e.g., 'vehicle', 'ecu_domain', 'sgbd', 'hardware', 'assembly_zb', 'software_da', 'base_pa'
    label: str
    evidence_class: str  # '[C]', '[O]', '[W]', '[R]', '[U]'
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attributes": dict(sorted(self.attributes.items())),
            "evidence_class": self.evidence_class,
            "label": self.label,
            "node_id": self.node_id,
            "node_type": self.node_type,
        }


@dataclass(frozen=True)
class ProvenanceEdge:
    """A directed edge in the provenance graph representing a confirmed relation."""

    source_id: str
    target_id: str
    relation: str  # e.g., 'equipped_with', 'controlled_by', 'assembled_from', 'contains_calibration'
    evidence_class: str
    citation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "citation": self.citation,
            "evidence_class": self.evidence_class,
            "relation": self.relation,
            "source_id": self.source_id,
            "target_id": self.target_id,
        }


class ProvenanceGraph:
    """Directed graph capturing ECU, hardware, and flash artifact relations."""

    def __init__(self) -> None:
        self._nodes: Dict[str, ProvenanceNode] = {}
        self._edges: List[ProvenanceEdge] = []

    def add_node(
        self,
        node_id: str,
        node_type: str,
        label: str,
        evidence_class: str,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> ProvenanceNode:
        node = ProvenanceNode(
            node_id=node_id,
            node_type=node_type,
            label=label,
            evidence_class=evidence_class,
            attributes=attributes or {},
        )
        self._nodes[node_id] = node
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation: str,
        evidence_class: str,
        citation: str,
    ) -> ProvenanceEdge:
        if source_id not in self._nodes:
            raise KeyError(f"Source node '{source_id}' not found in graph.")
        if target_id not in self._nodes:
            raise KeyError(f"Target node '{target_id}' not found in graph.")
        edge = ProvenanceEdge(
            source_id=source_id,
            target_id=target_id,
            relation=relation,
            evidence_class=evidence_class,
            citation=citation,
        )
        self._edges.append(edge)
        return edge

    def to_dict(self) -> Dict[str, Any]:
        sorted_nodes = [self._nodes[k].to_dict() for k in sorted(self._nodes.keys())]
        sorted_edges = [
            e.to_dict()
            for e in sorted(self._edges, key=lambda x: (x.source_id, x.target_id, x.relation))
        ]
        return {
            "edge_count": len(sorted_edges),
            "edges": sorted_edges,
            "node_count": len(sorted_nodes),
            "nodes": sorted_nodes,
        }


def build_default_egs_provenance_graph() -> ProvenanceGraph:
    """Build the canonical directed graph for E60 M57D30TU2 / 6HP28."""
    graph = ProvenanceGraph()

    # 1. Vehicle & Powertrain
    graph.add_node(
        "VEH_E60_530D_LCI",
        "vehicle",
        "BMW E60 530d LCI (NX71)",
        "[C]",
        {"engine": "M57D30TU2", "transmission": "GA6HP28Z", "option": "205"},
    )
    graph.add_node(
        "TRANS_ZF_6HP28",
        "transmission",
        "ZF 6HP28 (GA6HP26Z TU)",
        "[C]",
        {"generation": "2nd Gen 6HP", "max_torque_nm": 750, "mechatronic": "GS19.11"},
    )

    # 2. ECU Domain & SGBD
    graph.add_node(
        "ECU_EGS_0X18",
        "ecu_domain",
        "Electronic Transmission Control (0x18)",
        "[O]",
        {"address": "0x18", "diagnostic_bus": "Serial / K+DCAN"},
    )
    graph.add_node(
        "SGBD_GKE195",
        "sgbd",
        "GKE195 SGBD Family",
        "[C]",
        {"ipo": "03GKE195.ipo", "prg": "10FLASH.prg", "protocol": "XXFLKP"},
    )

    # 3. Hardware Units
    graph.add_node(
        "HW_UNPROG_7569980",
        "hardware_raw",
        "Raw Mechatronic HW 7569980",
        "[O]",
        {"citation": "1A 87 / kmm_SG.txt:6290 / HWNR.DA2:7076"},
    )
    graph.add_node(
        "HW_PROG_7591972",
        "hardware_programmed",
        "Programmed Mechatronic HW 7591972",
        "[O]",
        {"citation": "IDENT (0x1A 0x80) / GKE195.DAT:16 / HWNR.DA2:7085"},
    )

    # 4. Assembly ZB & Software Numbers
    graph.add_node(
        "ZB_7592132",
        "assembly_zb",
        "Assembly Part Number ZB 7592132",
        "[O]",
        {"citation": "AIF ($23) / kmm_ATSH.txt:9709 / GKE195.DAT:16"},
    )
    graph.add_node(
        "SW_7592133DA",
        "software_number",
        "Calibration Software 7592133DA",
        "[O]",
        {"citation": "AIF ($23) / GKE195.DAT:16 / A7592133.0da"},
    )

    # 5. Flash Artifacts
    graph.add_node(
        "ARTIFACT_A7592133_0DA",
        "calibration_artifact",
        "Calibration File A7592133.0da",
        "[C]",
        {"referenz": "0479S90T641Z1ZY02", "sha256": "45b473d1ee8cc2542a1eb3ecb77bf446f357f81827a464e6c3489257312a0112"},
    )
    graph.add_node(
        "ARTIFACT_7591971A_0PA",
        "operating_program_artifact",
        "Shared Base Program 7591971A.0pa",
        "[C]",
        {"platform": "GS19.11", "referenz": "0479SA0T641Z", "role": "RELATED_BASE_PROGRAM_GS19_11"},
    )

    # Edges
    graph.add_edge("VEH_E60_530D_LCI", "TRANS_ZF_6HP28", "equipped_with", "[C]", "kmm_ATSH.txt:9709")
    graph.add_edge("TRANS_ZF_6HP28", "ECU_EGS_0X18", "controlled_by", "[C]", "KFCONF10.DA2:292")
    graph.add_edge("ECU_EGS_0X18", "SGBD_GKE195", "managed_by_sgbd", "[C]", "KFCONF10.DA2:292")
    graph.add_edge("SGBD_GKE195", "HW_PROG_7591972", "targets_hardware", "[C]", "HWNR.DA2:7085")
    graph.add_edge("HW_PROG_7591972", "HW_UNPROG_7569980", "flashed_onto", "[C]", "kmm_SG.txt:6290")
    graph.add_edge("HW_PROG_7591972", "ZB_7592132", "assembled_as", "[C]", "GKE195.DAT:16")
    graph.add_edge("ZB_7592132", "SW_7592133DA", "contains_software", "[C]", "GKE195.DAT:16")
    graph.add_edge("SW_7592133DA", "ARTIFACT_A7592133_0DA", "stored_in", "[C]", "spdaten_gke/E60/data/GKE195/A7592133.0da")
    graph.add_edge("SGBD_GKE195", "ARTIFACT_7591971A_0PA", "shares_executive_base", "[R]", "GS19.11 mechatronic common architecture")

    return graph
