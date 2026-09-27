"""GKE195 SGBD Job Definition and Result Data Structures.

Provides structured definitions for EDIABAS SGBD jobs and their execution
results under a multi-dimensional evidence taxonomy.

STRICTLY OFF-HARDWARE: Contains pure data structures and interfaces.
No hardware access or serial dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple, Union


@dataclass(frozen=True)
class SgbdJobDefinition:
    """Canonical specification of an SGBD job under GKE195 / 10FLASH.prg.

    Maintains 4 orthogonal classification axes:
      1. sgbd_supported: SGBD bytecode explicitly defines and implements this job.
      2. factory_trace_observed: Factory WinKFP/EDIABAS trace captures execution of this job.
      3. physical_trace_exists: Direct wire trace on physical EGS (0x18) exists on disk.
      4. directly_resolved: The semantic meaning and mapping are directly resolved on EGS.
    """

    job_name: str
    ipo_procedure: Optional[str]
    sgbd_routine: Optional[str]
    request_payload: bytes
    expected_response_shape: str
    parser: Callable[[Any], "SgbdJobResult"]
    result_fields: Tuple[str, ...]
    evidence_class: str
    sgbd_supported: bool
    factory_trace_observed: bool
    physical_trace_exists: bool
    directly_resolved: bool
    description: str = ""
    # Canonical diagnostic request attributes
    service: int = 0
    subfunction: Optional[int] = None
    parameters: bytes = b""
    fallback_service: Optional[int] = None
    fallback_subfunction: Optional[int] = None
    fallback_payload: Optional[bytes] = None
    expected_response_sid: Optional[int] = None
    expected_response_subfunction: Optional[int] = None
    min_payload_len: int = 1
    exact_payload_len: Optional[int] = None

    def validate_request(self, actual_payload: bytes) -> bool:
        """Check whether the provided request payload matches this job's specification."""
        return actual_payload.startswith(self.request_payload)

    def build_request(
        self,
        target_address: int = 0x18,
        tester_address: int = 0xF1,
        use_fallback: bool = False,
        custom_params: Optional[bytes] = None,
        destination_address: Optional[int] = None,
        source_address: Optional[int] = None,
    ) -> bytes:
        """Construct full DS2 wire request frame for this job.

        Canonical DS2 request addressing:
            byte[1]: destination / target ECU address (default: 0x18)
            byte[2]: source / tester address (default: 0xF1)
        """
        from reconstruction.transport.kdcan.framing import build as build_ds2_frame

        dst = destination_address if destination_address is not None else target_address
        src = source_address if source_address is not None else tester_address

        if use_fallback and self.fallback_payload:
            payload = self.fallback_payload
        else:
            payload = self.request_payload

        if custom_params is not None:
            payload = payload + custom_params

        return build_ds2_frame(dst=dst, src=src, payload=payload)


@dataclass
class SgbdJobResult:
    """Execution and decoding result from an SGBD job parser."""

    job_name: str
    status: str
    fields: Dict[str, Any] = field(default_factory=dict)
    raw_payload: bytes = b""
    evidence_class: str = "UNKNOWN"
    trace_source: Optional[str] = None
    errors: List[str] = field(default_factory=list)
    sgbd_supported: bool = False
    factory_trace_observed: bool = False
    physical_trace_exists: bool = False
    directly_resolved: bool = False

    @property
    def is_ok(self) -> bool:
        """Return True if job completed successfully with status OKAY."""
        return self.status == "OKAY"

    def __getitem__(self, key: str) -> Any:
        """Access decoded field by name."""
        return self.fields[key]

    def get(self, key: str, default: Any = None) -> Any:
        """Access decoded field by name with fallback."""
        return self.fields.get(key, default)

    def as_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary representation."""
        return {
            "job_name": self.job_name,
            "status": self.status,
            "fields": dict(self.fields),
            "raw_payload_hex": self.raw_payload.hex().upper(),
            "evidence_class": self.evidence_class,
            "trace_source": self.trace_source,
            "errors": list(self.errors),
            "sgbd_supported": self.sgbd_supported,
            "factory_trace_observed": self.factory_trace_observed,
            "physical_trace_exists": self.physical_trace_exists,
            "directly_resolved": self.directly_resolved,
        }
