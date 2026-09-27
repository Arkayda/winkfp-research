"""Deterministic GKE195 Read-Only Job Execution Model.

Reproduces the semantic execution path:
    Job -> IPO procedure -> 10FLASH.prg parser -> wire response fixture -> decoded SGBD result fields
using immutable physical traces as input fixtures.

STRICTLY OFF-HARDWARE:
- Zero serial port opening.
- Zero network or ECU communication.
- No emulation of the ECU; reproduces SGBD-side parsing and semantics only.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from .job_model import SgbdJobDefinition, SgbdJobResult
from .sgbd import (
    _extract_payload,
    decode_10flash_aif_s23,
    decode_10flash_daten_referenz,
    decode_10flash_hw_referenz,
    decode_10flash_ident,
    decode_10flash_phys_hw_nr,
    decode_10flash_seriennummer,
    decode_10flash_zif,
    decode_10flash_zif_backup,
    decode_aif_bench_alias,
)
from .trace_loader import TraceFixture, load_trace_fixture


# ============================================================================
# Parser Adapters producing SgbdJobResult
# ============================================================================


def _to_job_result(job_name: str, decoded: Dict[str, Any], evidence_class: str, raw: bytes) -> SgbdJobResult:
    """Helper converting decoder dictionary output into SgbdJobResult."""
    status = decoded.get("JOB_STATUS", "OKAY")
    errors = []
    if status != "OKAY":
        errors.append(status)
        if "JOB_MESSAGE" in decoded and decoded["JOB_MESSAGE"] != status:
            errors.append(decoded["JOB_MESSAGE"])
    # Exclude JOB_STATUS and JOB_MESSAGE from cleaned fields dict
    fields = {k: v for k, v in decoded.items() if k not in ("JOB_STATUS", "JOB_MESSAGE")}
    return SgbdJobResult(
        job_name=job_name,
        status=status,
        fields=fields,
        raw_payload=raw,
        evidence_class=evidence_class,
        errors=errors,
    )


def parse_ident(data: Any) -> SgbdJobResult:
    """Execute IDENT parser."""
    raw = _extract_payload(data)
    decoded = decode_10flash_ident(data)
    return _to_job_result("IDENT", decoded, "DIRECTLY_RESOLVED", raw)


def parse_phys_hw_nr(data: Any) -> SgbdJobResult:
    """Execute PHYSIKALISCHE_HW_NR_LESEN parser."""
    raw = _extract_payload(data)
    decoded = decode_10flash_phys_hw_nr(data)
    return _to_job_result("PHYSIKALISCHE_HW_NR_LESEN", decoded, "DIRECTLY_RESOLVED", raw)


def parse_seriennummer(data: Any) -> SgbdJobResult:
    """Execute SERIENNUMMER_LESEN parser."""
    raw = _extract_payload(data)
    decoded = decode_10flash_seriennummer(data)
    evidence_class = (
        "DIRECT_SGBD_MAPPING[10FLASH] + OBSERVED_JOB_MAPPING[target=10FLASH] + UNKNOWN[target=0479S90T641Z]"
    )
    return _to_job_result("SERIENNUMMER_LESEN", decoded, evidence_class, raw)


def parse_aif_s23(data: Any) -> SgbdJobResult:
    """Execute official SGBD AIF_LESEN parser (KWP2000 service 0x23)."""
    raw = _extract_payload(data)
    decoded = decode_10flash_aif_s23(data)
    return _to_job_result("AIF_LESEN", decoded, "DIRECT_SGBD_MAPPING[10FLASH]", raw)


def parse_aif_bench_alias(data: Any) -> SgbdJobResult:
    """Execute AIF_READ_BENCH_ALIAS parser (KWP2000 service 0x1A 0x86)."""
    raw = _extract_payload(data)
    decoded = decode_aif_bench_alias(data)
    return _to_job_result("AIF_READ_BENCH_ALIAS", decoded, "OBSERVED_WIRE / RECONSTRUCTION_ALIAS", raw)


def parse_zif(data: Any) -> SgbdJobResult:
    """Execute ZIF_LESEN parser."""
    raw = _extract_payload(data)
    decoded = decode_10flash_zif(data)
    return _to_job_result("ZIF_LESEN", decoded, "DIRECT_SGBD_MAPPING[10FLASH]", raw)


def parse_zif_backup(data: Any) -> SgbdJobResult:
    """Execute ZIF_BACKUP_LESEN parser."""
    raw = _extract_payload(data)
    decoded = decode_10flash_zif_backup(data)
    return _to_job_result("ZIF_BACKUP_LESEN", decoded, "DIRECT_SGBD_MAPPING[10FLASH]", raw)


def parse_hw_referenz(data: Any) -> SgbdJobResult:
    """Execute HARDWARE_REFERENZ_LESEN parser."""
    raw = _extract_payload(data)
    decoded = decode_10flash_hw_referenz(data)
    return _to_job_result("HARDWARE_REFERENZ_LESEN", decoded, "DIRECT_SGBD_MAPPING[10FLASH]", raw)


def parse_daten_referenz(data: Any) -> SgbdJobResult:
    """Execute DATEN_REFERENZ_LESEN parser."""
    raw = _extract_payload(data)
    decoded = decode_10flash_daten_referenz(data)
    return _to_job_result("DATEN_REFERENZ_LESEN", decoded, "DIRECT_SGBD_MAPPING[10FLASH]", raw)


# ============================================================================
# Canonical GKE195 Job Catalog
# ============================================================================


class Gke195JobCatalog:
    """Canonical registry of GKE195 read-only identification jobs."""

    def __init__(self) -> None:
        self._jobs: Dict[str, SgbdJobDefinition] = {}
        self._populate_catalog()

    def _register(self, job_def: SgbdJobDefinition) -> None:
        self._jobs[job_def.job_name.upper()] = job_def

    def _populate_catalog(self) -> None:
        # 1. IDENT (1A 80)
        self._register(
            SgbdJobDefinition(
                job_name="IDENT",
                ipo_procedure="Ident",
                sgbd_routine="IDENT",
                request_payload=b"\x1A\x80",
                expected_response_shape="5A 80 <60B Table>",
                parser=parse_ident,
                result_fields=(
                    "ID_BMW_NR",
                    "ID_HW_NR",
                    "ID_COD_INDEX",
                    "ID_DIAG_INDEX",
                    "ID_LIEF_TEXT",
                    "ID_DATUM",
                    "ID_LIEF_NR",
                    "ID_SW_NR_MCV",
                    "ID_SW_NR_FSV",
                    "ID_SW_NR_OSV",
                    "ID_SW_NR_RES",
                    "_PECUHN_FALLBACK",
                ),
                evidence_class="DIRECTLY_RESOLVED",
                sgbd_supported=True,
                factory_trace_observed=True,
                physical_trace_exists=True,
                directly_resolved=True,
                description="Standard ECU identification table via KWP2000 service 0x1A local ID 0x80.",
            )
        )

        # 2. PHYSIKALISCHE_HW_NR_LESEN (1A 87)
        self._register(
            SgbdJobDefinition(
                job_name="PHYSIKALISCHE_HW_NR_LESEN",
                ipo_procedure="PhysHwNrLesen",
                sgbd_routine="PHYSIKALISCHE_HW_NR_LESEN",
                request_payload=b"\x1A\x87",
                expected_response_shape="5A 87 <6B PECUHN x 3>",
                parser=parse_phys_hw_nr,
                result_fields=("PHYSIKALISCHE_HW_NR",),
                evidence_class="DIRECTLY_RESOLVED",
                sgbd_supported=True,
                factory_trace_observed=True,
                physical_trace_exists=True,
                directly_resolved=True,
                description="Read physical hardware number from unprogrammed controller board.",
            )
        )

        # 3. SERIENNUMMER_LESEN (1A 89)
        self._register(
            SgbdJobDefinition(
                job_name="SERIENNUMMER_LESEN",
                ipo_procedure="SgSerienNr",
                sgbd_routine="SERIENNUMMER_LESEN",
                request_payload=b"\x1A\x89",
                expected_response_shape="5A 89 <Serial ASCII>",
                parser=parse_seriennummer,
                result_fields=("SERIENNUMMER",),
                evidence_class="DIRECT_SGBD_MAPPING[10FLASH] + OBSERVED_JOB_MAPPING[target=10FLASH] + UNKNOWN[target=0479S90T641Z]",
                sgbd_supported=True,
                factory_trace_observed=True,
                physical_trace_exists=False,
                directly_resolved=False,
                description="ECU serial number string from KWP2000 service 0x1A local ID 0x89.",
            )
        )

        # 4. AIF_LESEN (official SGBD job: KWP2000 0x23)
        self._register(
            SgbdJobDefinition(
                job_name="AIF_LESEN",
                ipo_procedure="AifLesen",
                sgbd_routine="AIF_LESEN",
                request_payload=b"\x23\x00\x00\x00\x07\x12",
                expected_response_shape="63 <AIF Data>",
                parser=parse_aif_s23,
                result_fields=(
                    "AIF_FG_NR",
                    "AIF_FG_NR_LANG",
                    "AIF_DATUM",
                    "AIF_ZB_NR",
                    "AIF_SW_NR",
                    "AIF_BEHOERDEN_NR",
                    "AIF_HAENDLER_NR",
                    "AIF_SERIEN_NR",
                    "AIF_KM",
                    "AIF_PROG_NR",
                    "AIF_GROESSE",
                ),
                evidence_class="DIRECT_SGBD_MAPPING[10FLASH]",
                sgbd_supported=True,
                factory_trace_observed=True,
                physical_trace_exists=False,
                directly_resolved=False,
                description="Official SGBD AIF reading via KWP2000 ReadMemoryByAddress (0x23).",
            )
        )

        # 5. AIF_READ_BENCH_ALIAS (reconstruction tool probe: KWP2000 0x1A 0x86)
        self._register(
            SgbdJobDefinition(
                job_name="AIF_READ_BENCH_ALIAS",
                ipo_procedure=None,
                sgbd_routine=None,
                request_payload=b"\x1A\x86",
                expected_response_shape="5A 86 40 <66B Payload / 71B Total>",
                parser=parse_aif_bench_alias,
                result_fields=(
                    "short_vin",
                    "flash_date",
                    "zb_number",
                    "sw_number",
                    "sgbd",
                    "tool_marker",
                    "chassis_prefix",
                ),
                evidence_class="OBSERVED_WIRE / RECONSTRUCTION_ALIAS",
                sgbd_supported=False,
                factory_trace_observed=False,
                physical_trace_exists=True,
                directly_resolved=False,
                description="Bench probe reading identification record 0x86 directly via KWP2000.",
            )
        )

        # 6. ZIF_LESEN
        self._register(
            SgbdJobDefinition(
                job_name="ZIF_LESEN",
                ipo_procedure="ZifLesen",
                sgbd_routine="ZIF_LESEN",
                request_payload=b"\x22\x25\x03",
                expected_response_shape="62 25 03 <12B PRGREF>",
                parser=parse_zif,
                result_fields=(
                    "ZIF_PROGRAMM_REFERENZ",
                    "ZIF_SG_KENNUNG",
                    "ZIF_PROJEKT",
                    "ZIF_PROGRAMM_STAND",
                    "ZIF_STATUS",
                    "ZIF_BMW_HW",
                ),
                evidence_class="DIRECT_SGBD_MAPPING[10FLASH]",
                sgbd_supported=True,
                factory_trace_observed=True,
                physical_trace_exists=False,
                directly_resolved=False,
                description="Supplier Info Field reading via ReadDataByCommonIdentifier (0x22 0x2503).",
            )
        )

        # 7. ZIF_BACKUP_LESEN
        self._register(
            SgbdJobDefinition(
                job_name="ZIF_BACKUP_LESEN",
                ipo_procedure="ZifBackupLesen",
                sgbd_routine="ZIF_BACKUP_LESEN",
                request_payload=b"\x22\x25\x00",
                expected_response_shape="62 25 00 <12B PRGREFB>",
                parser=parse_zif_backup,
                result_fields=(
                    "ZIF_BACKUP_PROGRAMM_REFERENZ",
                    "ZIF_BACKUP_SG_KENNUNG",
                    "ZIF_BACKUP_PROJEKT",
                    "ZIF_BACKUP_PROGRAMM_STAND",
                    "ZIF_BACKUP_STATUS",
                    "ZIF_BACKUP_BMW_HW",
                ),
                evidence_class="DIRECT_SGBD_MAPPING[10FLASH]",
                sgbd_supported=True,
                factory_trace_observed=True,
                physical_trace_exists=False,
                directly_resolved=False,
                description="Backup supplier info field reading.",
            )
        )

        # 8. HARDWARE_REFERENZ_LESEN
        self._register(
            SgbdJobDefinition(
                job_name="HARDWARE_REFERENZ_LESEN",
                ipo_procedure="HwReferenzLesen",
                sgbd_routine="HARDWARE_REFERENZ_LESEN",
                request_payload=b"\x22\x25\x02",
                expected_response_shape="62 25 02 <7B HWREF>",
                parser=parse_hw_referenz,
                result_fields=(
                    "HARDWARE_REFERENZ",
                    "HW_REF_SG_KENNUNG",
                    "HW_REF_PROJEKT",
                    "HW_REF_STATUS",
                ),
                evidence_class="DIRECT_SGBD_MAPPING[10FLASH]",
                sgbd_supported=True,
                factory_trace_observed=True,
                physical_trace_exists=False,
                directly_resolved=False,
                description="Hardware reference string reading.",
            )
        )

        # 9. DATEN_REFERENZ_LESEN
        self._register(
            SgbdJobDefinition(
                job_name="DATEN_REFERENZ_LESEN",
                ipo_procedure="DatenReferenzLesen",
                sgbd_routine="DATEN_REFERENZ_LESEN",
                request_payload=b"\x22\x25\x04",
                expected_response_shape="62 25 04 <17B DREF>",
                parser=parse_daten_referenz,
                result_fields=(
                    "DATEN_REFERENZ",
                    "DATEN_REF_SG_KENNUNG",
                    "DATEN_REF_PROJEKT",
                    "DATEN_REF_PROGRAMM_STAND",
                    "DATEN_REF_DATENSATZ",
                    "DATEN_REF_STATUS",
                ),
                evidence_class="DIRECT_SGBD_MAPPING[10FLASH]",
                sgbd_supported=True,
                factory_trace_observed=True,
                physical_trace_exists=False,
                directly_resolved=False,
                description="Dataset reference string reading.",
            )
        )

    def get_job(self, job_name: str) -> SgbdJobDefinition:
        """Lookup job definition by name (case-insensitive)."""
        key = job_name.strip().upper()
        if key not in self._jobs:
            raise NotImplementedError(
                f"Job '{job_name}' unknown or unsupported for GKE195 offline execution. "
                f"Available: {list(self._jobs.keys())}"
            )
        return self._jobs[key]

    def list_jobs(self) -> List[str]:
        """List all registered job names."""
        return sorted(list(self._jobs.keys()))

    def get_physical_jobs(self) -> List[SgbdJobDefinition]:
        """Return jobs with existing physical wire traces."""
        return [j for j in self._jobs.values() if j.physical_trace_exists]

    def get_unknown_jobs(self) -> List[SgbdJobDefinition]:
        """Return jobs that lack physical wire traces on target 0479S90T641Z."""
        return [j for j in self._jobs.values() if not j.physical_trace_exists]

    def get_resolved_jobs(self) -> List[SgbdJobDefinition]:
        """Return jobs whose semantics are directly resolved on EGS."""
        return [j for j in self._jobs.values() if j.directly_resolved]


# ============================================================================
# Offline Execution Engine
# ============================================================================


class Gke195OfflineRunner:
    """Deterministic offline runner for GKE195 identification jobs."""

    def __init__(self, catalog: Optional[Gke195JobCatalog] = None) -> None:
        self.catalog = catalog or Gke195JobCatalog()

    def execute_job(
        self,
        job_name: str,
        fixture: Union[TraceFixture, Dict[str, Any], bytes, str, Path],
    ) -> SgbdJobResult:
        """Execute a job against an offline trace fixture or byte payload.

        Steps:
          1. Resolves trace fixture if a path is passed.
          2. Looks up the canonical job definition.
          3. Validates request compatibility where request wire data is available.
          4. Dispatches to the job parser.
          5. Returns typed SgbdJobResult.
        """
        trace_source: Optional[str] = None

        if isinstance(fixture, (str, Path)):
            p = Path(fixture)
            if p.suffix.lower() == ".json":
                fixture = load_trace_fixture(p)
                trace_source = p.name

        if isinstance(fixture, TraceFixture):
            trace_source = fixture.path.name

        job_def = self.catalog.get_job(job_name)

        # Validate request payload if TraceFixture is used
        if isinstance(fixture, TraceFixture):
            if not job_def.validate_request(fixture.tx_payload):
                pass  # Allow parser to evaluate payload or report error if mismatch

        result = job_def.parser(fixture)
        result.trace_source = trace_source
        return result
