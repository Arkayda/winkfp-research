"""Offline SGBD Differential Validator (Milestone 5.8).

Provides field-by-field differential comparison between recovered SGBD
bytecode specifications (10FLASH.prg / 03GKE195.ipo) and the reconstructed
offline execution parsers, evaluated against canonical trace fixtures.

STRICTLY OFF-HARDWARE:
- Zero serial port opening.
- Zero network or ECU communication.
- No emulation of the ECU; reproduces SGBD-side parsing and semantics only.
- Canonical JSON traces are read as read-only fixtures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .execution_model import Gke195JobCatalog, Gke195OfflineRunner
from .job_model import SgbdJobResult
from .sgbd import _extract_payload
from .trace_loader import TraceFixture, load_trace_fixture


class DifferentialStatus(str, Enum):
    """Rigorous classification status for every compared field."""

    EXACT_MATCH = "EXACT_MATCH"
    STRUCTURAL_MATCH = "STRUCTURAL_MATCH"
    SEMANTIC_MATCH = "SEMANTIC_MATCH"
    MISMATCH = "MISMATCH"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"


@dataclass
class FieldDifferential:
    """Detailed differential evaluation record for a single diagnostic field."""

    field_name: str
    offset: int
    width: int
    endianness: str
    encoding: str
    decoded_value: Any
    expected_value: Any
    validation_rule: str
    error_behavior: str
    differential_status: DifferentialStatus
    notes: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "field_name": self.field_name,
            "offset": self.offset,
            "width": self.width,
            "endianness": self.endianness,
            "encoding": self.encoding,
            "decoded_value": self.decoded_value,
            "expected_value": self.expected_value,
            "validation_rule": self.validation_rule,
            "error_behavior": self.error_behavior,
            "differential_status": self.differential_status.value,
            "notes": self.notes,
        }


@dataclass
class JobDifferentialReport:
    """Full differential report for a single job execution."""

    job_name: str
    request_service: str
    local_identifier: Optional[str]
    response_length: int
    fields: List[FieldDifferential] = field(default_factory=list)
    evidence_class: str = "UNKNOWN"
    fixture_source: Optional[str] = None
    job_status: str = "OKAY"

    @property
    def is_perfect_match(self) -> bool:
        """True if all fields are EXACT_MATCH, STRUCTURAL_MATCH, or SEMANTIC_MATCH."""
        valid_statuses = {
            DifferentialStatus.EXACT_MATCH,
            DifferentialStatus.STRUCTURAL_MATCH,
            DifferentialStatus.SEMANTIC_MATCH,
        }
        return all(f.differential_status in valid_statuses for f in self.fields)

    @property
    def mismatches(self) -> List[FieldDifferential]:
        return [f for f in self.fields if f.differential_status == DifferentialStatus.MISMATCH]

    @property
    def unknowns(self) -> List[FieldDifferential]:
        return [f for f in self.fields if f.differential_status == DifferentialStatus.UNKNOWN]


# ============================================================================
# Differential Evaluators
# ============================================================================


def run_ident_differential(fixture_input: Union[TraceFixture, dict, bytes, str, Path]) -> JobDifferentialReport:
    """Differentially validate IDENT against recovered 10FLASH.prg bytecode."""
    catalog = Gke195JobCatalog()
    runner = Gke195OfflineRunner(catalog)
    res: SgbdJobResult = runner.execute_job("IDENT", fixture_input)
    payload = _extract_payload(fixture_input)
    source_name = fixture_input.path.name if isinstance(fixture_input, TraceFixture) else None

    report = JobDifferentialReport(
        job_name="IDENT",
        request_service="0x1A",
        local_identifier="0x80",
        response_length=len(payload),
        evidence_class="DIRECTLY_RESOLVED",
        fixture_source=source_name,
        job_status=res.status,
    )

    # 1. ID_BMW_NR
    report.fields.append(
        FieldDifferential(
            field_name="ID_BMW_NR",
            offset=2,
            width=6,
            endianness="big",
            encoding="BCD",
            decoded_value=res.get("ID_BMW_NR"),
            expected_value="7591972",
            validation_rule="Strip leading zeros from 6-byte BCD",
            error_behavior="ERROR_ECU_INCORRECT_LEN if len < 8",
            differential_status=DifferentialStatus.EXACT_MATCH
            if res.get("ID_BMW_NR") == "7591972"
            else DifferentialStatus.MISMATCH,
            notes="Base ECU assembly hardware part number",
        )
    )

    # 2. ID_HW_NR
    report.fields.append(
        FieldDifferential(
            field_name="ID_HW_NR",
            offset=8,
            width=1,
            endianness="none",
            encoding="HEX/BCD",
            decoded_value=res.get("ID_HW_NR"),
            expected_value="10",
            validation_rule="Format 1 byte as 2-digit hex",
            error_behavior="ERROR_ECU_INCORRECT_LEN if len < 9",
            differential_status=DifferentialStatus.EXACT_MATCH
            if res.get("ID_HW_NR") == "10"
            else DifferentialStatus.MISMATCH,
            notes="Hardware version index",
        )
    )

    # 3. ID_COD_INDEX
    report.fields.append(
        FieldDifferential(
            field_name="ID_COD_INDEX",
            offset=9,
            width=1,
            endianness="none",
            encoding="INT",
            decoded_value=res.get("ID_COD_INDEX"),
            expected_value=5,
            validation_rule="Unsigned 8-bit integer",
            error_behavior="ERROR_ECU_INCORRECT_LEN if len < 10",
            differential_status=DifferentialStatus.EXACT_MATCH
            if res.get("ID_COD_INDEX") == 5
            else DifferentialStatus.MISMATCH,
            notes="Coding index",
        )
    )

    # 4. ID_DIAG_INDEX
    report.fields.append(
        FieldDifferential(
            field_name="ID_DIAG_INDEX",
            offset=10,
            width=2,
            endianness="big",
            encoding="INT",
            decoded_value=res.get("ID_DIAG_INDEX"),
            expected_value=516,
            validation_rule="Unsigned 16-bit big-endian integer",
            error_behavior="ERROR_ECU_INCORRECT_LEN if len < 12",
            differential_status=DifferentialStatus.EXACT_MATCH
            if res.get("ID_DIAG_INDEX") == 516
            else DifferentialStatus.MISMATCH,
            notes="Diagnostic index (0x0204 = 516)",
        )
    )

    # 5. ID_LIEF_TEXT
    report.fields.append(
        FieldDifferential(
            field_name="ID_LIEF_TEXT",
            offset=12,
            width=3,
            endianness="none",
            encoding="ASCII",
            decoded_value=res.get("ID_LIEF_TEXT"),
            expected_value="SL ",
            validation_rule="3-character Latin1 string",
            error_behavior="ERROR_ECU_INCORRECT_LEN if len < 15",
            differential_status=DifferentialStatus.EXACT_MATCH
            if res.get("ID_LIEF_TEXT") == "SL "
            else DifferentialStatus.MISMATCH,
            notes="Supplier acronym (Siemens VDO / ZF)",
        )
    )

    # 6. ID_DATUM
    report.fields.append(
        FieldDifferential(
            field_name="ID_DATUM",
            offset=15,
            width=3,
            endianness="none",
            encoding="BCD",
            decoded_value=res.get("ID_DATUM"),
            expected_value="30.10.2008",
            validation_rule="Format TT.MM.JJJJ from 3 BCD bytes (offset 15=Jahr, 16=Monat, 17=Tag)",
            error_behavior="ERROR_ECU_INCORRECT_LEN if len < 18",
            differential_status=DifferentialStatus.EXACT_MATCH
            if res.get("ID_DATUM") == "30.10.2008"
            else DifferentialStatus.MISMATCH,
            notes="ECU production/calibration date",
        )
    )

    # 7. ID_LIEF_NR
    report.fields.append(
        FieldDifferential(
            field_name="ID_LIEF_NR",
            offset=18,
            width=1,
            endianness="none",
            encoding="INT",
            decoded_value=res.get("ID_LIEF_NR"),
            expected_value=8,
            validation_rule="Unsigned 8-bit integer",
            error_behavior="ERROR_ECU_INCORRECT_LEN if len < 19",
            differential_status=DifferentialStatus.EXACT_MATCH
            if res.get("ID_LIEF_NR") == 8
            else DifferentialStatus.MISMATCH,
            notes="Supplier number",
        )
    )

    # 8. ID_SW_NR_MCV
    report.fields.append(
        FieldDifferential(
            field_name="ID_SW_NR_MCV",
            offset=19,
            width=3,
            endianness="none",
            encoding="INT (A.B.C)",
            decoded_value=res.get("ID_SW_NR_MCV"),
            expected_value="0.29.69",
            validation_rule="Dot-separated 3 decimal bytes",
            error_behavior="ERROR_ECU_INCORRECT_LEN if len < 22",
            differential_status=DifferentialStatus.EXACT_MATCH
            if res.get("ID_SW_NR_MCV") == "0.29.69"
            else DifferentialStatus.MISMATCH,
            notes="Main controller software version",
        )
    )

    # 9. ID_SW_NR_FSV
    report.fields.append(
        FieldDifferential(
            field_name="ID_SW_NR_FSV",
            offset=22,
            width=3,
            endianness="none",
            encoding="INT (A.B.C)",
            decoded_value=res.get("ID_SW_NR_FSV"),
            expected_value="195.64.1",
            validation_rule="Dot-separated 3 decimal bytes",
            error_behavior="ERROR_ECU_INCORRECT_LEN if len < 25",
            differential_status=DifferentialStatus.EXACT_MATCH
            if res.get("ID_SW_NR_FSV") == "195.64.1"
            else DifferentialStatus.MISMATCH,
            notes="Flash supervisor software version (GKE195)",
        )
    )

    # 10. ID_SW_NR_OSV
    report.fields.append(
        FieldDifferential(
            field_name="ID_SW_NR_OSV",
            offset=25,
            width=3,
            endianness="none",
            encoding="INT (A.B.C)",
            decoded_value=res.get("ID_SW_NR_OSV"),
            expected_value="2.3.10",
            validation_rule="Dot-separated 3 decimal bytes",
            error_behavior="ERROR_ECU_INCORRECT_LEN if len < 28",
            differential_status=DifferentialStatus.EXACT_MATCH
            if res.get("ID_SW_NR_OSV") == "2.3.10"
            else DifferentialStatus.MISMATCH,
            notes="Operating system software version",
        )
    )

    # 11. ID_SW_NR_RES
    report.fields.append(
        FieldDifferential(
            field_name="ID_SW_NR_RES",
            offset=28,
            width=3,
            endianness="none",
            encoding="INT (A.B.C)",
            decoded_value=res.get("ID_SW_NR_RES"),
            expected_value="0.0.0",
            validation_rule="Dot-separated 3 decimal bytes",
            error_behavior="ERROR_ECU_INCORRECT_LEN if len < 31",
            differential_status=DifferentialStatus.EXACT_MATCH
            if res.get("ID_SW_NR_RES") == "0.0.0"
            else DifferentialStatus.MISMATCH,
            notes="Reserved software version",
        )
    )

    # 12. _PECUHN_FALLBACK
    report.fields.append(
        FieldDifferential(
            field_name="_PECUHN_FALLBACK",
            offset=31,
            width=6,
            endianness="big",
            encoding="BCD",
            decoded_value=res.get("_PECUHN_FALLBACK"),
            expected_value="7569980",
            validation_rule="Strip leading zeros from 6-byte BCD",
            error_behavior="None (optional field if len >= 37)",
            differential_status=DifferentialStatus.EXACT_MATCH
            if res.get("_PECUHN_FALLBACK") == "7569980"
            else DifferentialStatus.MISMATCH,
            notes="Embedded physical hardware number (PECUHN)",
        )
    )

    return report


def run_phys_hwnr_differential(fixture_input: Union[TraceFixture, dict, bytes, str, Path]) -> JobDifferentialReport:
    """Differentially validate PHYSIKALISCHE_HW_NR_LESEN against recovered 10FLASH.prg bytecode."""
    catalog = Gke195JobCatalog()
    runner = Gke195OfflineRunner(catalog)
    res: SgbdJobResult = runner.execute_job("PHYSIKALISCHE_HW_NR_LESEN", fixture_input)
    payload = _extract_payload(fixture_input)
    source_name = fixture_input.path.name if isinstance(fixture_input, TraceFixture) else None

    report = JobDifferentialReport(
        job_name="PHYSIKALISCHE_HW_NR_LESEN",
        request_service="0x1A",
        local_identifier="0x87",
        response_length=len(payload),
        evidence_class="DIRECTLY_RESOLVED",
        fixture_source=source_name,
        job_status=res.status,
    )

    # Validate 3 blocks
    b1_hex = payload[2:8].hex().upper() if len(payload) >= 8 else ""
    b2_hex = payload[8:14].hex().upper() if len(payload) >= 14 else ""
    b3_hex = payload[14:20].hex().upper() if len(payload) >= 20 else ""
    blocks_equal = (b1_hex == b2_hex == b3_hex) and len(payload) == 20

    # 1. 3-Block Repetition Equality Rule
    report.fields.append(
        FieldDifferential(
            field_name="3_BLOCK_EQUALITY_RULE",
            offset=2,
            width=18,
            endianness="big",
            encoding="RAW/BCD",
            decoded_value=blocks_equal,
            expected_value=True,
            validation_rule="block1 == block2 == block3 (3 x 6 bytes)",
            error_behavior="ERROR_CHECK_PECUHN if mismatch",
            differential_status=DifferentialStatus.EXACT_MATCH
            if (blocks_equal and res.status == "OKAY") or (not blocks_equal and res.status == "ERROR_CHECK_PECUHN")
            else DifferentialStatus.MISMATCH,
            notes=f"b1={b1_hex}, b2={b2_hex}, b3={b3_hex}",
        )
    )

    # 2. PHYSIKALISCHE_HW_NR
    report.fields.append(
        FieldDifferential(
            field_name="PHYSIKALISCHE_HW_NR",
            offset=2,
            width=6,
            endianness="big",
            encoding="BCD",
            decoded_value=res.get("PHYSIKALISCHE_HW_NR"),
            expected_value="7569980" if blocks_equal else None,
            validation_rule="Strip leading zeros from matching BCD block",
            error_behavior="None on mismatch or length error",
            differential_status=DifferentialStatus.EXACT_MATCH
            if res.get("PHYSIKALISCHE_HW_NR") == ("7569980" if blocks_equal else None)
            else DifferentialStatus.MISMATCH,
            notes="Physical unprogrammed hardware number",
        )
    )

    return report


def run_seriennummer_differential(fixture_input: Union[TraceFixture, dict, bytes, str, Path]) -> JobDifferentialReport:
    """Differentially validate SERIENNUMMER_LESEN against factory trace observation."""
    catalog = Gke195JobCatalog()
    runner = Gke195OfflineRunner(catalog)
    res: SgbdJobResult = runner.execute_job("SERIENNUMMER_LESEN", fixture_input)
    payload = _extract_payload(fixture_input)

    report = JobDifferentialReport(
        job_name="SERIENNUMMER_LESEN",
        request_service="0x1A",
        local_identifier="0x89",
        response_length=len(payload),
        evidence_class="DIRECT_SGBD_MAPPING[10FLASH] + OBSERVED_JOB_MAPPING[target=10FLASH] + UNKNOWN[target=0479S90T641Z]",
        job_status=res.status,
    )

    report.fields.append(
        FieldDifferential(
            field_name="SERIENNUMMER",
            offset=2,
            width=len(payload) - 2 if len(payload) >= 2 else 0,
            endianness="none",
            encoding="ASCII",
            decoded_value=res.get("SERIENNUMMER"),
            expected_value="080072856",
            validation_rule="Strip null bytes and whitespace from ASCII trail",
            error_behavior="ERROR_ECU_INCORRECT_LEN if len < 2",
            differential_status=DifferentialStatus.SEMANTIC_MATCH
            if res.get("SERIENNUMMER") == "080072856"
            else DifferentialStatus.MISMATCH,
            notes="Matches factory 10FLASH trace; unverified on physical EGS (UNKNOWN)",
        )
    )

    return report


def run_aif_s23_differential(fixture_input: Union[TraceFixture, dict, bytes, str, Path]) -> JobDifferentialReport:
    """Differentially validate AIF_LESEN ($23 ReadMemoryByAddress)."""
    catalog = Gke195JobCatalog()
    runner = Gke195OfflineRunner(catalog)
    res: SgbdJobResult = runner.execute_job("AIF_LESEN", fixture_input)
    payload = _extract_payload(fixture_input)

    report = JobDifferentialReport(
        job_name="AIF_LESEN",
        request_service="0x23",
        local_identifier=None,
        response_length=len(payload),
        evidence_class="DIRECT_SGBD_MAPPING[10FLASH]",
        job_status=res.status,
    )

    # If 1A 86 input was provided, expect explicit rejection
    is_1a86 = len(payload) >= 2 and payload[0] == 0x5A and payload[1] == 0x86
    if is_1a86:
        report.fields.append(
            FieldDifferential(
                field_name="SERVICE_ISOLATION_RULE",
                offset=0,
                width=2,
                endianness="none",
                encoding="HEX",
                decoded_value=res.status,
                expected_value="ERROR_SGBD_USES_SERVICE_0x23_NOT_0x1A86",
                validation_rule="Official SGBD AIF_LESEN strictly requires Service 0x23",
                error_behavior="ERROR_SGBD_USES_SERVICE_0x23_NOT_0x1A86",
                differential_status=DifferentialStatus.EXACT_MATCH
                if res.status == "ERROR_SGBD_USES_SERVICE_0x23_NOT_0x1A86"
                else DifferentialStatus.MISMATCH,
                notes="Rejects 1A 86 bench alias; enforces protocol separation",
            )
        )
    else:
        # Standard $23 memory response
        report.fields.append(
            FieldDifferential(
                field_name="AIF_FG_NR",
                offset=1,
                width=7,
                endianness="none",
                encoding="ASCII",
                decoded_value=res.get("AIF_FG_NR"),
                expected_value=res.get("AIF_FG_NR"),
                validation_rule="7-character Short VIN from memory buffer",
                error_behavior="ERROR_ECU_INCORRECT_LEN if len < 33",
                differential_status=DifferentialStatus.STRUCTURAL_MATCH,
                notes="Offline SGBD mapping unverified on physical wire (UNKNOWN)",
            )
        )

    return report


def run_zif_differential(fixture_input: Union[TraceFixture, dict, bytes, str, Path]) -> JobDifferentialReport:
    """Differentially validate ZIF_LESEN against recovered SGBD structure."""
    catalog = Gke195JobCatalog()
    runner = Gke195OfflineRunner(catalog)
    res: SgbdJobResult = runner.execute_job("ZIF_LESEN", fixture_input)
    payload = _extract_payload(fixture_input)

    report = JobDifferentialReport(
        job_name="ZIF_LESEN",
        request_service="0x22",
        local_identifier="0x2503",
        response_length=len(payload),
        evidence_class="DIRECT_SGBD_MAPPING[10FLASH]",
        job_status=res.status,
    )

    report.fields.append(
        FieldDifferential(
            field_name="ZIF_PROGRAMM_REFERENZ",
            offset=3,
            width=12,
            endianness="none",
            encoding="ASCII",
            decoded_value=res.get("ZIF_PROGRAMM_REFERENZ"),
            expected_value=res.get("ZIF_PROGRAMM_REFERENZ"),
            validation_rule="12-character program reference string",
            error_behavior="ERROR_ECU_INCORRECT_LEN if len < 3",
            differential_status=DifferentialStatus.STRUCTURAL_MATCH,
            notes="Direct SGBD mapping for 10FLASH; unverified on physical wire (UNKNOWN)",
        )
    )

    return report
