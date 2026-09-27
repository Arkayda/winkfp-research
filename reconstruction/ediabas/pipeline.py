"""Canonical Offline GKE195 Read-Only Job Execution Pipeline.

Eliminates fragmented and duplicated orchestration logic by unifying:
    SgbdJobDefinition
        ->
    Request Builder (build_request)
        ->
    Response Validator (validate_response)
        ->
    Semantic Parser (decode_*)
        ->
    SgbdJobResult

STRICTLY OFF-HARDWARE:
- Zero serial port opening.
- Zero network or ECU communication.
- No emulation of the ECU; reproduces SGBD-side request construction,
  wire response validation, and parsing only.
- Canonical JSON traces are read as read-only fixtures.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from reconstruction.transport.kdcan.framing import (
    body_length as ds2_body_length,
    build as build_ds2_frame,
    checksum as ds2_checksum,
)

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
from .transport import (
    DiagnosticTransport,
    FixtureTransport,
    TransportError,
    TransportTimeoutError,
)


# ============================================================================
# Response Validation Engine (Fail-Closed)
# ============================================================================


class ResponseValidator:
    """Fail-closed validator enforcing DS2 framing, addressing, SID, and length."""

    @staticmethod
    def extract_raw_frame(data: Any) -> Optional[bytes]:
        """Extract full DS2 frame if available in raw form."""
        if isinstance(data, TraceFixture):
            return data.raw_rx
        if isinstance(data, dict):
            for k in ("raw_rx", "rx", "raw"):
                if k in data and isinstance(data[k], (bytes, bytearray)):
                    return bytes(data[k])
                if k in data and isinstance(data[k], str):
                    try:
                        return bytes.fromhex(data[k].replace(" ", "").strip())
                    except ValueError:
                        pass
        if isinstance(data, (bytes, bytearray)):
            return bytes(data)
        if isinstance(data, str):
            try:
                return bytes.fromhex(data.replace(" ", "").strip())
            except ValueError:
                pass
        return None

    @classmethod
    def validate_response(
        cls,
        job_def: SgbdJobDefinition,
        response_input: Any,
        target_address: int = 0x18,
        tester_address: int = 0xF1,
    ) -> Tuple[bool, bytes, str, List[str]]:
        """Validate response input against job definition constraints.

        Returns:
            (is_valid, payload_bytes, status_code, error_messages)
        """
        raw_frame = cls.extract_raw_frame(response_input)
        payload = b""

        # 1. Full DS2 frame validation if frame is present
        if raw_frame is not None and len(raw_frame) >= 4:
            # Check DS2 header format byte (must have bit 7 set and bit 6 clear)
            if (raw_frame[0] & 0xC0) != 0x80:
                return (
                    False,
                    raw_frame,
                    "ERROR_DS2_FRAMING",
                    [f"Invalid DS2 format byte: 0x{raw_frame[0]:02X}"],
                )

            # Check encoded length vs actual length
            try:
                expected_total = ds2_body_length(raw_frame) + 1
            except ValueError as e:
                return False, raw_frame, "ERROR_DS2_FRAMING", [str(e)]

            if len(raw_frame) != expected_total:
                return (
                    False,
                    raw_frame,
                    "ERROR_DS2_FRAMING",
                    [f"Frame length {len(raw_frame)} != expected {expected_total}"],
                )

            # Check addressing (destination = tester, source = target)
            dst = raw_frame[1]
            src = raw_frame[2]
            if dst != tester_address or src != target_address:
                return (
                    False,
                    raw_frame,
                    "ERROR_DS2_ADDRESSING",
                    [f"Address mismatch: dst=0x{dst:02X} (exp 0x{tester_address:02X}), src=0x{src:02X} (exp 0x{target_address:02X})"],
                )

            # Check checksum
            expected_cs = ds2_checksum(raw_frame[:-1])
            actual_cs = raw_frame[-1]
            if actual_cs != expected_cs:
                return (
                    False,
                    raw_frame,
                    "ERROR_DS2_CHECKSUM",
                    [f"Checksum error: got 0x{actual_cs:02X}, expected 0x{expected_cs:02X}"],
                )

            # Extract payload from verified frame
            short_len = raw_frame[0] & 0x3F
            if short_len != 0:
                payload = raw_frame[3:-1]
            elif raw_frame[3] != 0:
                payload = raw_frame[4:-1]
            else:
                payload = raw_frame[6:-1]
        else:
            try:
                payload = _extract_payload(response_input)
            except Exception as e:
                return False, b"", "ERROR_ECU_INCORRECT_LEN", [str(e)]

        # 2. Basic payload boundary
        if len(payload) == 0:
            return False, payload, "ERROR_ECU_INCORRECT_LEN", ["Empty payload"]

        # 3. Negative response handling
        if payload[0] == 0x7F:
            nrc = payload[2] if len(payload) >= 3 else 0x00
            return (
                False,
                payload,
                f"ERROR_ECU_NEGATIVE_RESPONSE_0x{nrc:02X}",
                [f"Negative response received with NRC 0x{nrc:02X}"],
            )

        # 4. Expected Response SID verification
        if job_def.expected_response_sid is not None:
            if payload[0] != job_def.expected_response_sid:
                # Special isolation for AIF_LESEN vs 1A 86
                if (
                    job_def.job_name == "AIF_LESEN"
                    and payload[0] == 0x5A
                    and len(payload) >= 2
                    and payload[1] == 0x86
                ):
                    return (
                        False,
                        payload,
                        "ERROR_SGBD_USES_SERVICE_0x23_NOT_0x1A86",
                        [
                            "Official SGBD AIF_LESEN requires KWP Service 0x23 (ReadMemoryByAddress). "
                            "The 1A 86 response is classified as AIF_READ_BENCH_ALIAS."
                        ],
                    )
                return (
                    False,
                    payload,
                    "ERROR_ECU_INCORRECT_RESPONSE_ID",
                    [f"Expected SID 0x{job_def.expected_response_sid:02X}, received 0x{payload[0]:02X}"],
                )

        # 5. Expected Subfunction / Common Identifier verification
        if job_def.expected_response_subfunction is not None:
            exp_sub = job_def.expected_response_subfunction
            if exp_sub <= 0xFF:
                # 1-byte subfunction
                if len(payload) < 2 or payload[1] != exp_sub:
                    actual_sub = payload[1] if len(payload) >= 2 else 0
                    return (
                        False,
                        payload,
                        "ERROR_ECU_INCORRECT_SUBID",
                        [f"Expected SubID 0x{exp_sub:02X}, received 0x{actual_sub:02X}"],
                    )
            else:
                # 2-byte common identifier (e.g. 0x2503, 0x2500, 0x2502, 0x2504)
                exp_bytes = exp_sub.to_bytes(2, "big")
                if len(payload) < 3 or payload[1:3] != exp_bytes:
                    actual_sub = (
                        int.from_bytes(payload[1:3], "big") if len(payload) >= 3 else 0
                    )
                    return (
                        False,
                        payload,
                        "ERROR_ECU_INCORRECT_SUBID",
                        [f"Expected CommonIdentifier 0x{exp_sub:04X}, received 0x{actual_sub:04X}"],
                    )

        # 6. Payload length constraints
        if len(payload) < job_def.min_payload_len:
            return (
                False,
                payload,
                "ERROR_ECU_INCORRECT_LEN",
                [f"Payload length {len(payload)} < minimum {job_def.min_payload_len}"],
            )

        if job_def.exact_payload_len is not None and len(payload) != job_def.exact_payload_len:
            return (
                False,
                payload,
                "ERROR_ECU_INCORRECT_LEN",
                [f"Payload length {len(payload)} != exact required {job_def.exact_payload_len}"],
            )

        return True, payload, "OKAY", []


# ============================================================================
# Canonical Catalog of GKE195 Read-Only Job Definitions
# ============================================================================


def _create_canonical_definitions() -> Dict[str, SgbdJobDefinition]:
    """Create all canonical job definitions based on Milestone 5.8.1 audit."""
    defs: Dict[str, SgbdJobDefinition] = {}

    # 1. IDENT (1A 80)
    defs["IDENT"] = SgbdJobDefinition(
        job_name="IDENT",
        ipo_procedure="Ident",
        sgbd_routine="IDENT",
        service=0x1A,
        subfunction=0x80,
        request_payload=b"\x1A\x80",
        expected_response_sid=0x5A,
        expected_response_subfunction=0x80,
        min_payload_len=31,
        exact_payload_len=None,
        expected_response_shape="5A 80 <60B Table>",
        parser=decode_10flash_ident,
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

    # 2. PHYSIKALISCHE_HW_NR_LESEN (1A 87)
    defs["PHYSIKALISCHE_HW_NR_LESEN"] = SgbdJobDefinition(
        job_name="PHYSIKALISCHE_HW_NR_LESEN",
        ipo_procedure="PhysHwNrLesen",
        sgbd_routine="PHYSIKALISCHE_HW_NR_LESEN",
        service=0x1A,
        subfunction=0x87,
        request_payload=b"\x1A\x87",
        fallback_service=0x1A,
        fallback_subfunction=0x80,
        fallback_payload=b"\x1A\x80",
        expected_response_sid=0x5A,
        expected_response_subfunction=0x87,
        min_payload_len=20,
        exact_payload_len=20,
        expected_response_shape="5A 87 <6B PECUHN x 3>",
        parser=decode_10flash_phys_hw_nr,
        result_fields=("PHYSIKALISCHE_HW_NR",),
        evidence_class="DIRECTLY_RESOLVED",
        sgbd_supported=True,
        factory_trace_observed=True,
        physical_trace_exists=True,
        directly_resolved=True,
        description="Read physical hardware number from unprogrammed controller board.",
    )

    # 3. SERIENNUMMER_LESEN (1A 89)
    defs["SERIENNUMMER_LESEN"] = SgbdJobDefinition(
        job_name="SERIENNUMMER_LESEN",
        ipo_procedure="SgSerienNr",
        sgbd_routine="SERIENNUMMER_LESEN",
        service=0x1A,
        subfunction=0x89,
        request_payload=b"\x1A\x89",
        fallback_service=0x1A,
        fallback_subfunction=0x80,
        fallback_payload=b"\x1A\x80",
        expected_response_sid=0x5A,
        expected_response_subfunction=0x89,
        min_payload_len=2,
        expected_response_shape="5A 89 <Serial ASCII>",
        parser=decode_10flash_seriennummer,
        result_fields=("SERIENNUMMER",),
        evidence_class="DIRECT_SGBD_MAPPING[10FLASH] + OBSERVED_JOB_MAPPING[target=10FLASH] + UNKNOWN[target=0479S90T641Z]",
        sgbd_supported=True,
        factory_trace_observed=True,
        physical_trace_exists=False,
        directly_resolved=False,
        description="ECU serial number string from KWP2000 service 0x1A local ID 0x89.",
    )

    # 4. AIF_LESEN (official SGBD job: KWP2000 0x23)
    defs["AIF_LESEN"] = SgbdJobDefinition(
        job_name="AIF_LESEN",
        ipo_procedure="AifLesen",
        sgbd_routine="AIF_LESEN",
        service=0x23,
        subfunction=None,
        request_payload=b"\x23\x00\x00\x00\x07\x12",
        expected_response_sid=0x63,
        expected_response_subfunction=None,
        min_payload_len=19,
        expected_response_shape="63 <AIF Data>",
        parser=decode_10flash_aif_s23,
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

    # 5. AIF_READ_BENCH_ALIAS (reconstruction tool probe: KWP2000 0x1A 0x86)
    defs["AIF_READ_BENCH_ALIAS"] = SgbdJobDefinition(
        job_name="AIF_READ_BENCH_ALIAS",
        ipo_procedure=None,
        sgbd_routine=None,
        service=0x1A,
        subfunction=0x86,
        request_payload=b"\x1A\x86",
        expected_response_sid=0x5A,
        expected_response_subfunction=0x86,
        min_payload_len=20,
        expected_response_shape="5A 86 40 <66B Payload / 71B Total>",
        parser=decode_aif_bench_alias,
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

    # 6. ZIF_LESEN ($22 $2503)
    defs["ZIF_LESEN"] = SgbdJobDefinition(
        job_name="ZIF_LESEN",
        ipo_procedure="ZifLesen",
        sgbd_routine="ZIF_LESEN",
        service=0x22,
        subfunction=0x2503,
        request_payload=b"\x22\x25\x03",
        fallback_service=0x1A,
        fallback_subfunction=0x91,
        fallback_payload=b"\x1A\x91",
        expected_response_sid=0x62,
        expected_response_subfunction=0x2503,
        min_payload_len=3,
        expected_response_shape="62 25 03 <12B PRGREF>",
        parser=decode_10flash_zif,
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

    # 7. ZIF_BACKUP_LESEN ($22 $2500)
    defs["ZIF_BACKUP_LESEN"] = SgbdJobDefinition(
        job_name="ZIF_BACKUP_LESEN",
        ipo_procedure="ZifBackupLesen",
        sgbd_routine="ZIF_BACKUP_LESEN",
        service=0x22,
        subfunction=0x2500,
        request_payload=b"\x22\x25\x00",
        fallback_service=0x1A,
        fallback_subfunction=0x80,
        fallback_payload=b"\x1A\x80",
        expected_response_sid=0x62,
        expected_response_subfunction=0x2500,
        min_payload_len=3,
        expected_response_shape="62 25 00 <12B PRGREFB>",
        parser=decode_10flash_zif_backup,
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

    # 8. HARDWARE_REFERENZ_LESEN ($22 $2502)
    defs["HARDWARE_REFERENZ_LESEN"] = SgbdJobDefinition(
        job_name="HARDWARE_REFERENZ_LESEN",
        ipo_procedure="HwReferenzLesen",
        sgbd_routine="HARDWARE_REFERENZ_LESEN",
        service=0x22,
        subfunction=0x2502,
        request_payload=b"\x22\x25\x02",
        fallback_service=0x1A,
        fallback_subfunction=0x80,
        fallback_payload=b"\x1A\x80",
        expected_response_sid=0x62,
        expected_response_subfunction=0x2502,
        min_payload_len=3,
        expected_response_shape="62 25 02 <7B HWREF>",
        parser=decode_10flash_hw_referenz,
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

    # 9. DATEN_REFERENZ_LESEN ($22 $2504)
    defs["DATEN_REFERENZ_LESEN"] = SgbdJobDefinition(
        job_name="DATEN_REFERENZ_LESEN",
        ipo_procedure="DatenReferenzLesen",
        sgbd_routine="DATEN_REFERENZ_LESEN",
        service=0x22,
        subfunction=0x2504,
        request_payload=b"\x22\x25\x04",
        expected_response_sid=0x62,
        expected_response_subfunction=0x2504,
        min_payload_len=3,
        expected_response_shape="62 25 04 <17B DREF>",
        parser=decode_10flash_daten_referenz,
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

    return defs


# ============================================================================
# Canonical Pipeline Executor
# ============================================================================


class CanonicalPipeline:
    """Deterministic, unified pipeline for executing read-only SGBD jobs offline."""

    def __init__(self, catalog: Optional[Dict[str, SgbdJobDefinition]] = None):
        self.catalog = catalog or _create_canonical_definitions()
        self.validator = ResponseValidator()

    def get_job(self, job_name: str) -> SgbdJobDefinition:
        """Lookup canonical job definition by name."""
        key = job_name.strip().upper()
        if key not in self.catalog:
            raise NotImplementedError(
                f"Job '{job_name}' unknown or unsupported for GKE195 offline execution. "
                f"Available: {sorted(list(self.catalog.keys()))}"
            )
        return self.catalog[key]

    def build_request(
        self,
        job_name: str,
        target_address: int = 0x18,
        tester_address: int = 0xF1,
        use_fallback: bool = False,
        custom_params: Optional[bytes] = None,
        destination_address: Optional[int] = None,
        source_address: Optional[int] = None,
    ) -> bytes:
        """Stage 1: Build the exact DS2 wire request frame for a job."""
        job_def = self.get_job(job_name)
        return job_def.build_request(
            target_address=target_address,
            tester_address=tester_address,
            use_fallback=use_fallback,
            custom_params=custom_params,
            destination_address=destination_address,
            source_address=source_address,
        )

    def execute_transport(
        self,
        job_name: str,
        transport: DiagnosticTransport,
        target_address: int = 0x18,
        tester_address: int = 0xF1,
        destination_address: Optional[int] = None,
        source_address: Optional[int] = None,
        timeout: float = 1.0,
        custom_params: Optional[bytes] = None,
        use_fallback: bool = False,
    ) -> SgbdJobResult:
        """Execute canonical pipeline stage 1->4 using an abstract DiagnosticTransport.

        Pipeline Stages:
            1. Job Definition: Resolves metadata and canonical constraints.
            2. Request Builder: Builds canonical physical DS2 wire request frame.
            3. Transport Transceive: Sends wire frame and receives raw wire response.
            4. Response Validator: Fail-closed DS2 framing, addressing, SID, length.
            5. Semantic Parser: Decodes validated payload into typed result.
        """
        dst = destination_address if destination_address is not None else target_address
        src = source_address if source_address is not None else tester_address
        job_def = self.get_job(job_name)
        trace_source = getattr(transport, "source_name", None)

        # Stage 2: Request Builder
        wire_request = self.build_request(
            job_name=job_name,
            target_address=target_address,
            tester_address=tester_address,
            destination_address=destination_address,
            source_address=source_address,
            use_fallback=use_fallback,
            custom_params=custom_params,
        )

        # Stage 3: Transport Transceive
        try:
            wire_response = transport.transceive_ds2(wire_request, timeout=timeout)
        except TransportTimeoutError as exc:
            return SgbdJobResult(
                job_name=job_def.job_name,
                status="ERROR_TIMEOUT",
                fields={},
                raw_payload=b"",
                evidence_class=job_def.evidence_class,
                trace_source=trace_source,
                errors=[str(exc)],
                sgbd_supported=job_def.sgbd_supported,
                factory_trace_observed=job_def.factory_trace_observed,
                physical_trace_exists=job_def.physical_trace_exists,
                directly_resolved=job_def.directly_resolved,
            )
        except TransportError as exc:
            return SgbdJobResult(
                job_name=job_def.job_name,
                status="ERROR_TRANSPORT",
                fields={},
                raw_payload=b"",
                evidence_class=job_def.evidence_class,
                trace_source=trace_source,
                errors=[str(exc)],
                sgbd_supported=job_def.sgbd_supported,
                factory_trace_observed=job_def.factory_trace_observed,
                physical_trace_exists=job_def.physical_trace_exists,
                directly_resolved=job_def.directly_resolved,
            )

        # Stage 4: Response Validation
        is_valid, payload, status, error_msgs = self.validator.validate_response(
            job_def=job_def,
            response_input=wire_response,
            target_address=dst,
            tester_address=src,
        )

        if not is_valid:
            return SgbdJobResult(
                job_name=job_def.job_name,
                status=status,
                fields={},
                raw_payload=payload,
                evidence_class=job_def.evidence_class,
                trace_source=trace_source,
                errors=error_msgs,
                sgbd_supported=job_def.sgbd_supported,
                factory_trace_observed=job_def.factory_trace_observed,
                physical_trace_exists=job_def.physical_trace_exists,
                directly_resolved=job_def.directly_resolved,
            )

        # Stage 5: Semantic Parsing
        decoded = job_def.parser(payload)
        parsed_status = decoded.get("JOB_STATUS", "OKAY")
        errors: List[str] = []
        if parsed_status != "OKAY":
            errors.append(parsed_status)
            if "JOB_MESSAGE" in decoded and decoded["JOB_MESSAGE"] != parsed_status:
                errors.append(decoded["JOB_MESSAGE"])

        fields = {k: v for k, v in decoded.items() if k not in ("JOB_STATUS", "JOB_MESSAGE")}

        return SgbdJobResult(
            job_name=job_def.job_name,
            status=parsed_status,
            fields=fields,
            raw_payload=payload,
            evidence_class=job_def.evidence_class,
            trace_source=trace_source,
            errors=errors,
            sgbd_supported=job_def.sgbd_supported,
            factory_trace_observed=job_def.factory_trace_observed,
            physical_trace_exists=job_def.physical_trace_exists,
            directly_resolved=job_def.directly_resolved,
        )

    def execute(
        self,
        job_name: str,
        fixture_or_data: Union[DiagnosticTransport, TraceFixture, bytes, bytearray, dict, str, Path],
        target_address: int = 0x18,
        tester_address: int = 0xF1,
        destination_address: Optional[int] = None,
        source_address: Optional[int] = None,
    ) -> SgbdJobResult:
        """Execute the canonical 4-stage pipeline against offline fixture data or transport.

        Pipeline Stages:
            1. Job Definition: Resolves metadata and canonical constraints.
            2. Request Builder: Exposes request payload and fallback parameters.
            3. Response Validator: Fail-closed DS2 framing, addressing, SID, length.
            4. Semantic Parser: Decodes validated payload into typed result.
        """
        if hasattr(fixture_or_data, "transceive_ds2"):
            return self.execute_transport(
                job_name=job_name,
                transport=fixture_or_data,  # type: ignore[arg-type]
                target_address=target_address,
                tester_address=tester_address,
                destination_address=destination_address,
                source_address=source_address,
            )

        dst = destination_address if destination_address is not None else target_address
        src = source_address if source_address is not None else tester_address
        trace_source: Optional[str] = None

        # Resolve file path to TraceFixture if passed as Path/str ending in .json
        if isinstance(fixture_or_data, (str, Path)):
            p = Path(fixture_or_data)
            if p.suffix.lower() == ".json":
                fixture_or_data = load_trace_fixture(p)
                trace_source = p.name

        if isinstance(fixture_or_data, TraceFixture):
            trace_source = fixture_or_data.path.name

        job_def = self.get_job(job_name)

        # Stage 3: Response Validation
        is_valid, payload, status, error_msgs = self.validator.validate_response(
            job_def=job_def,
            response_input=fixture_or_data,
            target_address=dst,
            tester_address=src,
        )

        # If validation fails closed before semantic parsing:
        if not is_valid:
            return SgbdJobResult(
                job_name=job_def.job_name,
                status=status,
                fields={},
                raw_payload=payload,
                evidence_class=job_def.evidence_class,
                trace_source=trace_source,
                errors=error_msgs,
                sgbd_supported=job_def.sgbd_supported,
                factory_trace_observed=job_def.factory_trace_observed,
                physical_trace_exists=job_def.physical_trace_exists,
                directly_resolved=job_def.directly_resolved,
            )

        # Stage 4: Semantic Parsing
        decoded = job_def.parser(payload)
        parsed_status = decoded.get("JOB_STATUS", "OKAY")
        errors: List[str] = []
        if parsed_status != "OKAY":
            errors.append(parsed_status)
            if "JOB_MESSAGE" in decoded and decoded["JOB_MESSAGE"] != parsed_status:
                errors.append(decoded["JOB_MESSAGE"])

        fields = {k: v for k, v in decoded.items() if k not in ("JOB_STATUS", "JOB_MESSAGE")}

        return SgbdJobResult(
            job_name=job_def.job_name,
            status=parsed_status,
            fields=fields,
            raw_payload=payload,
            evidence_class=job_def.evidence_class,
            trace_source=trace_source,
            errors=errors,
            sgbd_supported=job_def.sgbd_supported,
            factory_trace_observed=job_def.factory_trace_observed,
            physical_trace_exists=job_def.physical_trace_exists,
            directly_resolved=job_def.directly_resolved,
        )


# Global canonical singleton pipeline instance
default_pipeline = CanonicalPipeline()
