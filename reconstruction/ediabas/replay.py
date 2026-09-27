"""Offline EDIABAS-Compatible Read-Only Job Replay Layer (Milestone 5.10).

Builds a logical replay layer above the canonical GKE195 read-only pipeline:
    EDIABAS Job Invocation
        ->
    GKE195 Job Definition
        ->
    Canonical Request Builder
        ->
    Offline Response Fixture
        ->
    Response Validator
        ->
    SGBD Semantic Parser
        ->
    EDIABAS-like Result

CRITICAL PROTOCOL DISTINCTIONS:
- logical_request: EDIABAS/SGBD _TEL_AUFTRAG buffer without trailing checksum.
- canonical_ds2_request: Physical DS2 wire frame including additive 8-bit checksum.

EVIDENCE DOMAINS:
- FACTORY_TRACE: Historical factory WinKFP/EDIABAS session observations.
- PHYSICAL_EGS_FIXTURE: Immutable physical bench traces on target 0x18.
- SYNTHETIC_OFFLINE: Synthetic fixtures and negative test vectors.

STRICTLY OFF-HARDWARE:
- Zero serial port opening.
- Zero network or ECU communication.
- No live hardware interaction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from reconstruction.transport.kdcan.framing import (
    body_length as ds2_body_length,
    build as build_ds2_frame,
    checksum as ds2_checksum,
)

from .job_model import SgbdJobDefinition, SgbdJobResult
from .pipeline import CanonicalPipeline, ResponseValidator, default_pipeline
from .trace_loader import TraceFixture, load_trace_fixture
from .transport import (
    DiagnosticTransport,
    FixtureTransport,
    MockTransport,
    TransportError,
    TransportTimeoutError,
)


# ============================================================================
# Evidence Domain Taxonomy
# ============================================================================


class EvidenceDomain(str, Enum):
    """Execution evidence domains (strictly separated, never merged)."""

    FACTORY_TRACE = "FACTORY_TRACE"
    PHYSICAL_EGS_FIXTURE = "PHYSICAL_EGS_FIXTURE"
    SYNTHETIC_OFFLINE = "SYNTHETIC_OFFLINE"


# ============================================================================
# Protocol Representations
# ============================================================================


@dataclass(frozen=True)
class EdiabasTelegram:
    """Logical telegram buffer as managed by the EDIABAS kernel (_TEL_AUFTRAG).

    In EDIABAS, the telegram buffer contains the header and payload, but does NOT
    contain the trailing physical transport checksum byte. The checksum byte is
    appended exclusively by the physical bus driver (IFH-OBD / K+DCAN).
    """

    raw_buffer: bytes
    format_byte: int
    target: int
    tester: int
    payload: bytes

    @property
    def destination(self) -> int:
        """Destination / target address (byte[1] in canonical DS2 request)."""
        return self.target

    @property
    def destination_address(self) -> int:
        """Destination / target address (byte[1] in canonical DS2 request)."""
        return self.target

    @property
    def source(self) -> int:
        """Source / tester address (byte[2] in canonical DS2 request)."""
        return self.tester

    @property
    def source_address(self) -> int:
        """Source / tester address (byte[2] in canonical DS2 request)."""
        return self.tester

    @classmethod
    def from_payload(
        cls,
        payload: bytes,
        target: int = 0x18,
        tester: int = 0xF1,
        destination: Optional[int] = None,
        source: Optional[int] = None,
    ) -> "EdiabasTelegram":
        """Construct an EDIABAS logical telegram buffer from payload and addresses.

        Canonical DS2 request telegram addressing:
            byte[0]: format byte (0x80 | len)
            byte[1]: destination / target ECU address (0x18 for EGS, 0x78 for factory trace)
            byte[2]: source / tester address (0xF1)
        """
        dst = destination if destination is not None else target
        src = source if source is not None else tester
        if not payload:
            raise ValueError("Empty payload prohibited in EDIABAS telegram")
        if len(payload) <= 0x3F:
            head = bytes([0x80 | len(payload), dst, src])
        else:
            head = bytes([0x80, dst, src, len(payload)])
        raw_buffer = head + payload
        return cls(
            raw_buffer=raw_buffer,
            format_byte=raw_buffer[0],
            target=dst,
            tester=src,
            payload=payload,
        )

    def to_wire_frame(self) -> bytes:
        """Produce the complete physical DS2 wire frame with trailing checksum."""
        cs = ds2_checksum(self.raw_buffer)
        return self.raw_buffer + bytes([cs])

    def __len__(self) -> int:
        return len(self.raw_buffer)

    def hex(self, sep: str = " ") -> str:
        return self.raw_buffer.hex(sep).upper()


# ============================================================================
# EDIABAS-like Replay Result
# ============================================================================


@dataclass
class EdiabasJobResult:
    """EDIABAS-compatible structured result from an offline job replay."""

    job_name: str
    status: str
    logical_request: bytes
    canonical_ds2_request: bytes
    response_fixture: Any
    fields: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    evidence_class: str = "UNKNOWN"
    evidence_domain: EvidenceDomain = EvidenceDomain.SYNTHETIC_OFFLINE
    trace_source: Optional[str] = None
    target_address: int = 0x18
    tester_address: int = 0xF1
    sgbd_supported: bool = False
    factory_trace_observed: bool = False
    physical_trace_exists: bool = False
    directly_resolved: bool = False

    @property
    def is_ok(self) -> bool:
        """Return True if job completed with status OKAY and zero errors."""
        return self.status == "OKAY" and len(self.errors) == 0

    @property
    def destination_address(self) -> int:
        """Destination / target address (byte[1] in canonical DS2 request)."""
        return self.target_address

    @property
    def source_address(self) -> int:
        """Source / tester address (byte[2] in canonical DS2 request)."""
        return self.tester_address

    def __getitem__(self, key: str) -> Any:
        return self.fields[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.fields.get(key, default)

    def as_dict(self) -> Dict[str, Any]:
        """Convert result to serializable dictionary."""
        return {
            "job_name": self.job_name,
            "status": self.status,
            "logical_request": self.logical_request.hex(" ").upper() if self.logical_request else "",
            "canonical_ds2_request": self.canonical_ds2_request.hex(" ").upper() if self.canonical_ds2_request else "",
            "target_address": f"0x{self.target_address:02X}",
            "tester_address": f"0x{self.tester_address:02X}",
            "fields": dict(self.fields),
            "errors": list(self.errors),
            "evidence_class": self.evidence_class,
            "evidence_domain": self.evidence_domain.value,
            "trace_source": self.trace_source,
            "sgbd_supported": self.sgbd_supported,
            "factory_trace_observed": self.factory_trace_observed,
            "physical_trace_exists": self.physical_trace_exists,
            "directly_resolved": self.directly_resolved,
        }


# ============================================================================
# Offline Job Replay Engine
# ============================================================================


class EdiabasJobReplayEngine:
    """Offline EDIABAS-compatible execution engine reproducing SGBD job flows."""

    def __init__(self, pipeline: Optional[CanonicalPipeline] = None):
        self.pipeline = pipeline or default_pipeline

    def build_logical_telegram(
        self,
        job_name: str,
        arguments: Optional[Dict[str, Any]] = None,
        target_address: int = 0x18,
        tester_address: int = 0xF1,
        destination_address: Optional[int] = None,
        source_address: Optional[int] = None,
    ) -> EdiabasTelegram:
        """Construct the exact EDIABAS logical telegram buffer (_TEL_AUFTRAG).

        Canonical DS2 request addressing:
            byte[1]: destination / target ECU address (default: 0x18)
            byte[2]: source / tester address (default: 0xF1)

        Models canonical SGBD arguments per 10FLASH.prg:
        - AIF_LESEN: Takes AIF_NUMMER (int, default 0: current AIF).
          AIF_NUMMER == 0 -> address 0x00000007, length 0x12 (18 bytes).
        - All other identification jobs: zero arguments.
        """
        dst = destination_address if destination_address is not None else target_address
        src = source_address if source_address is not None else tester_address
        job_key = job_name.strip().upper()
        if job_key not in self.pipeline.catalog:
            raise NotImplementedError(
                f"Job '{job_name}' unknown or unsupported for GKE195 replay. "
                f"Available: {sorted(list(self.pipeline.catalog.keys()))}"
            )

        job_def = self.pipeline.catalog[job_key]
        args = arguments or {}

        # Canonical Argument Modeling
        if job_key == "AIF_LESEN":
            aif_nummer = args.get("AIF_NUMMER", 0)
            if not isinstance(aif_nummer, int) or aif_nummer < 0:
                raise ValueError(f"AIF_NUMMER must be non-negative int, got {aif_nummer}")

            # If explicit address and length are passed, preserve them; otherwise use canonical defaults
            if "custom_payload" in args:
                payload = bytes(args["custom_payload"])
            elif aif_nummer == 0:
                # Default current AIF record in 10FLASH.prg / factory trace
                payload = bytes.fromhex("23 00 00 00 07 12")
            else:
                # Indexed AIF record offset
                addr = 0x07 + (aif_nummer * 0x12)
                addr_bytes = addr.to_bytes(4, "big")
                payload = b"\x23" + addr_bytes + b"\x12"
        else:
            payload = job_def.request_payload

        return EdiabasTelegram.from_payload(
            payload=payload,
            target=dst,
            tester=src,
        )

    def execute_job(
        self,
        job_name: str,
        fixture_or_data: Any = None,
        arguments: Optional[Dict[str, Any]] = None,
        evidence_domain: Optional[EvidenceDomain] = None,
        target_address: Optional[int] = None,
        tester_address: int = 0xF1,
        destination_address: Optional[int] = None,
        source_address: Optional[int] = None,
        transport: Optional[DiagnosticTransport] = None,
        timeout: float = 1.0,
    ) -> EdiabasJobResult:
        """Execute an offline job replay against fixture data or transport with provenance enforcement.

        Flow:
            1. Resolve Evidence Domain and enforce target address provenance:
               - FACTORY_TRACE: target is canonically 0x78.
               - PHYSICAL_EGS_FIXTURE: target is canonically 0x18.
               - Cannot silently rewrite or cross-contaminate targets.
            2. Resolve SGBD Job Definition.
            3. Build EDIABAS logical request (_TEL_AUFTRAG) with provenanced target.
            4. Build canonical physical DS2 wire request (with checksum).
            5. Validate response fixture (fail-closed DS2 framing, SID, SubID, length).
            6. Parse validated response through canonical semantic parser.
            7. Return EdiabasJobResult with full evidence separation.
        """
        if transport is not None and fixture_or_data is None:
            fixture_or_data = transport

        if fixture_or_data is None:
            raise ValueError("Either fixture_or_data or transport must be provided.")

        if destination_address is not None and target_address is None:
            target_address = destination_address
        if source_address is not None and tester_address == 0xF1:
            tester_address = source_address
        job_key = job_name.strip().upper()

        # 1. Determine Evidence Domain & Source
        domain = evidence_domain
        trace_source: Optional[str] = None

        if isinstance(fixture_or_data, FixtureTransport):
            trace_source = fixture_or_data.source_name
            if domain is None:
                if trace_source and ("hardware" in trace_source or "egs" in trace_source):
                    domain = EvidenceDomain.PHYSICAL_EGS_FIXTURE
                elif trace_source and ("sanitized" in trace_source or "factory" in trace_source):
                    domain = EvidenceDomain.FACTORY_TRACE
                else:
                    domain = EvidenceDomain.SYNTHETIC_OFFLINE
        elif isinstance(fixture_or_data, MockTransport):
            if domain is None:
                domain = EvidenceDomain.SYNTHETIC_OFFLINE

        if isinstance(fixture_or_data, (str, Path)):
            p = Path(fixture_or_data)
            trace_source = p.name
            if domain is None:
                if "hardware" in p.parts:
                    domain = EvidenceDomain.PHYSICAL_EGS_FIXTURE
                elif "sanitized" in p.parts or "factory" in p.parts:
                    domain = EvidenceDomain.FACTORY_TRACE
                else:
                    domain = EvidenceDomain.SYNTHETIC_OFFLINE

        if isinstance(fixture_or_data, TraceFixture):
            trace_source = fixture_or_data.path.name
            if domain is None:
                if "hardware" in fixture_or_data.path.parts:
                    domain = EvidenceDomain.PHYSICAL_EGS_FIXTURE
                else:
                    domain = EvidenceDomain.SYNTHETIC_OFFLINE

        raw_frame = None
        if isinstance(fixture_or_data, FixtureTransport):
            raw_frame = fixture_or_data.raw_response
        else:
            raw_frame = ResponseValidator.extract_raw_frame(fixture_or_data)

        if domain is None and raw_frame is not None and len(raw_frame) >= 4:
            frame_dst = raw_frame[1]
            frame_src = raw_frame[2]
            # Canonical DS2 addressing semantics:
            # - Request frame:  byte[1] = destination/target ECU, byte[2] = source/tester (0xF1)
            # - Response frame: byte[1] = destination/tester (0xF1), byte[2] = source/target ECU
            target_candidate = frame_dst if frame_dst != 0xF1 else frame_src
            if target_candidate == 0x78:
                domain = EvidenceDomain.FACTORY_TRACE
            elif target_candidate == 0x18:
                domain = EvidenceDomain.PHYSICAL_EGS_FIXTURE

        if domain is None:
            domain = EvidenceDomain.SYNTHETIC_OFFLINE

        # 2. Strict Target Provenance Resolution
        if domain == EvidenceDomain.FACTORY_TRACE:
            effective_target = 0x78
            if target_address is not None and target_address != 0x78:
                raise ValueError(
                    f"FACTORY_TRACE provenance violation: target address must be 0x78, "
                    f"got 0x{target_address:02X}. Factory trace replay cannot be silently rewritten "
                    f"to target 0x18 or mistaken for EGS execution."
                )
        elif domain == EvidenceDomain.PHYSICAL_EGS_FIXTURE:
            effective_target = 0x18
            if target_address is not None and target_address != 0x18:
                raise ValueError(
                    f"PHYSICAL_EGS_FIXTURE provenance violation: target address must be 0x18, "
                    f"got 0x{target_address:02X}."
                )
        else:
            effective_target = target_address if target_address is not None else 0x18

        # 3. Check for unsupported job
        if job_key not in self.pipeline.catalog:
            return EdiabasJobResult(
                job_name=job_name,
                status="ERROR_JOB_UNSUPPORTED",
                logical_request=b"",
                canonical_ds2_request=b"",
                response_fixture=fixture_or_data,
                fields={},
                errors=[f"Job '{job_name}' unknown or unsupported for GKE195 replay."],
                evidence_class="UNSUPPORTED",
                evidence_domain=domain,
                trace_source=trace_source,
                target_address=effective_target,
                tester_address=tester_address,
                sgbd_supported=False,
                factory_trace_observed=False,
                physical_trace_exists=False,
                directly_resolved=False,
            )

        job_def = self.pipeline.catalog[job_key]

        # 4. Build logical request and canonical DS2 wire frame
        telegram = self.build_logical_telegram(
            job_name=job_key,
            arguments=arguments,
            target_address=effective_target,
            tester_address=tester_address,
        )
        logical_req = telegram.raw_buffer
        canonical_ds2_req = telegram.to_wire_frame()

        # 5. Execute via Canonical Pipeline (validates response and parses fields)
        if hasattr(fixture_or_data, "transceive_ds2"):
            pipeline_res: SgbdJobResult = self.pipeline.execute_transport(
                job_name=job_key,
                transport=fixture_or_data,
                target_address=effective_target,
                tester_address=tester_address,
                destination_address=destination_address,
                source_address=source_address,
                timeout=timeout,
            )
        else:
            pipeline_res = self.pipeline.execute(
                job_name=job_key,
                fixture_or_data=fixture_or_data,
                target_address=effective_target,
                tester_address=tester_address,
                destination_address=destination_address,
                source_address=source_address,
            )

        # 6. Synthesize final EdiabasJobResult with provenance preservation
        physical_trace_exists = pipeline_res.physical_trace_exists
        factory_trace_observed = pipeline_res.factory_trace_observed
        directly_resolved = pipeline_res.directly_resolved

        if domain == EvidenceDomain.FACTORY_TRACE:
            # Replaying against factory trace explicitly isolates evidence from physical wire
            physical_trace_exists = False
            directly_resolved = False

        return EdiabasJobResult(
            job_name=job_def.job_name,
            status=pipeline_res.status,
            logical_request=logical_req,
            canonical_ds2_request=canonical_ds2_req,
            response_fixture=fixture_or_data,
            fields=pipeline_res.fields,
            errors=pipeline_res.errors,
            evidence_class=pipeline_res.evidence_class,
            evidence_domain=domain,
            trace_source=trace_source or pipeline_res.trace_source,
            target_address=effective_target,
            tester_address=tester_address,
            sgbd_supported=pipeline_res.sgbd_supported,
            factory_trace_observed=factory_trace_observed,
            physical_trace_exists=physical_trace_exists,
            directly_resolved=directly_resolved,
        )


# Global singleton replay engine instance
default_replay_engine = EdiabasJobReplayEngine()


def execute_job(
    job_name: str,
    fixture_or_data: Any = None,
    arguments: Optional[Dict[str, Any]] = None,
    evidence_domain: Optional[EvidenceDomain] = None,
    target_address: Optional[int] = None,
    tester_address: int = 0xF1,
    destination_address: Optional[int] = None,
    source_address: Optional[int] = None,
    transport: Optional[DiagnosticTransport] = None,
    timeout: float = 1.0,
) -> EdiabasJobResult:
    """Convenience functional interface for offline EDIABAS job execution."""
    return default_replay_engine.execute_job(
        job_name=job_name,
        fixture_or_data=fixture_or_data,
        arguments=arguments,
        evidence_domain=evidence_domain,
        target_address=target_address,
        tester_address=tester_address,
        destination_address=destination_address,
        source_address=source_address,
        transport=transport,
        timeout=timeout,
    )
