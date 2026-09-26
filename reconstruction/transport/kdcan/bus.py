"""Direct K+DCAN bus adapter satisfying FlashRunner bus contract.

Contract:
- job(device: str, name: str, args: str = "") -> bool
- job_bin(device: str, name: str, data: bytes) -> bool
- read_text(name: str, default: str = "") -> str
- read_binary(name: str) -> bytes

CANONICAL TARGET-SCOPED EVIDENCE POLICY:
- OBSERVED_WIRE: Wire exchanges physically captured and confirmed on hardware.
  Direct wire operations (wire_read_aif, wire_tester_present) execute these directly.
- OBSERVED_JOB_MAPPING[target=X]: Verified correspondence between high-level EDIABAS job
  names and wire requests via direct SGBD bytecode execution or correlated factory traces for target X.
  (Absent for bench target 0479S90T641Z / EGS 0x18).
- INFERRED_JOB_MAPPING[target=X]: Jobs where wire service is observed, but SGBD job mapping
  lacks direct execution evidence for this ECU (e.g. AIF_LESEN on EGS).
- RECONSTRUCTION_ALIAS: Convenient names introduced by clean-room reconstruction
  (IDENT_LESEN, TESTER_PRESENT, SG_PHYS_HWNR_LESEN). Must not be represented as original OEM jobs.
- UNKNOWN[target=X]: Unevidenced job names (e.g. SG_STATUS_LESEN -> 0x3E 0x00 assumption is rejected).
  These FAIL CLOSED always.
- FORBIDDEN: Flash modification, erase, and write operations. Hard safety block.
- VIRTUAL: Internal orchestration / GUI / callback operation without wire representation.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from .base import KdcanError, KdcanTransport
from .serial import SerialKdcanTransport
from .trace import SessionTracer, TracedKdcanTransport

# Default ECU addressing
DEV_ADDRESS_MAP = {
    "DLE08": 0x18,   # ZF 6HP EGS transmission controller
    "GS19": 0x18,    # EGS
    "13_ASK": 0x13,  # ASK audio module
    "DME": 0x12,     # Engine ECU
}


class DirectKdcanBus:
    """FlashRunner bus adapter communicating directly over physical K+DCAN."""

    IS_REAL_HW = True

    def __init__(
        self,
        transport: Optional[KdcanTransport] = None,
        port: Optional[str] = None,
        default_dst: int = 0x18,
        trace: bool = True,
        log_path: Optional[str] = None,
        allow_inferred: bool = False,
    ) -> None:
        self.default_dst = default_dst
        self.allow_inferred = allow_inferred
        self.tracer: Optional[SessionTracer] = None

        if transport is not None:
            self.transport = transport
        else:
            base = SerialKdcanTransport(port=port)
            if trace:
                self.tracer = SessionTracer(log_path=log_path)
                self.transport = TracedKdcanTransport(base, self.tracer)
            else:
                self.transport = base

        self._text_results: Dict[str, str] = {}
        self._binary_results: Dict[str, bytes] = {}
        self._last_job_status: str = ""

    def open(self) -> None:
        self.transport.open()

    def close(self) -> None:
        self.transport.close()

    def __enter__(self) -> "DirectKdcanBus":
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _resolve_dst(self, device: str) -> int:
        return DEV_ADDRESS_MAP.get(device.upper(), self.default_dst)

    def wire_read_aif(self, dst: Optional[int] = None) -> bool:
        """Execute physical KWP2000 ReadECUIdentification (0x1A 0x86). [OBSERVED_WIRE]"""
        target = dst if dst is not None else self.default_dst
        return self._execute_aif_lesen(target)

    def wire_tester_present(self, dst: Optional[int] = None) -> bool:
        """Execute physical KWP2000 TesterPresent (0x3E 0x00). [OBSERVED_WIRE]"""
        target = dst if dst is not None else self.default_dst
        return self._execute_tester_present(target)

    def job(self, device: str, name: str, args: str = "") -> bool:
        """Execute a text-based diagnostic job against the ECU."""
        # 1. Flash writing prohibition (Hard Safety Gate - FORBIDDEN)
        if name in ("FLASH_SCHREIBEN", "SEND_SEGMENT", "FLASH_SCHREIBEN_XXL", "NG_SIGNATUR_PRUEFEN"):
            self._last_job_status = "ERROR_FLASH_WRITE_PROHIBITED"
            self._text_results["JOB_STATUS"] = self._last_job_status
            raise KdcanError(f"Job {name} is prohibited on physical DirectKdcanBus (read-only validation)")

        dst = self._resolve_dst(device)

        # 2. Re-audited UNKNOWN jobs:
        # SG_STATUS_LESEN was previously speculatively mapped to 0x3E 0x00 without direct evidence.
        # Direct evidence does not exist for this mapping on this ECU; fail closed always.
        if name == "SG_STATUS_LESEN":
            self._last_job_status = "ERROR_JOB_UNKNOWN_FAIL_CLOSED"
            self._text_results["JOB_STATUS"] = self._last_job_status
            raise NotImplementedError(
                f"Job 'SG_STATUS_LESEN' on device '{device}' is UNKNOWN (mapping to 0x3E 0x00 is unevidenced); "
                f"fail-closed per repository evidence policy."
            )

        # 3. High-level WinKFP/EDIABAS jobs classified as INFERRED_JOB_MAPPING or RECONSTRUCTION_ALIAS:
        # Physical wire telegrams (0x1A 0x86 and 0x3E 0x00) are OBSERVED_WIRE on this ECU,
        # but their mapping to high-level EDIABAS job names on this ECU (0479S90T641Z)
        # lacks direct SGBD bytecode execution evidence (AIF_LESEN is INFERRED_JOB_MAPPING[target=0479S90T641Z];
        # IDENT_LESEN, SG_PHYS_HWNR_LESEN, TESTER_PRESENT are RECONSTRUCTION_ALIAS).
        # Fail-closed unless allow_inferred=True.
        if name in ("AIF_LESEN", "IDENT_LESEN", "SG_PHYS_HWNR_LESEN", "TESTER_PRESENT"):
            if not self.allow_inferred:
                self._last_job_status = "ERROR_JOB_INFERRED_FAIL_CLOSED"
                self._text_results["JOB_STATUS"] = self._last_job_status
                raise NotImplementedError(
                    f"Job '{name}' on device '{device}' is INFERRED_JOB_MAPPING / RECONSTRUCTION_ALIAS "
                    f"(physical wire request is observed, but high-level job mapping lacks direct SGBD execution "
                    f"evidence for this ECU); fail-closed per repository evidence policy. Pass allow_inferred=True to execute."
                )
            if name in ("AIF_LESEN", "IDENT_LESEN", "SG_PHYS_HWNR_LESEN"):
                return self._execute_aif_lesen(dst)
            if name == "TESTER_PRESENT":
                return self._execute_tester_present(dst)

        # 4. Fail-closed: unmapped jobs must NOT be guessed or faked
        self._last_job_status = "ERROR_JOB_UNMAPPED_ON_DIRECT_BUS"
        self._text_results["JOB_STATUS"] = self._last_job_status
        raise NotImplementedError(
            f"Job '{name}' on device '{device}' is UNKNOWN / unmapped on physical wire (fail-closed)"
        )

    def job_bin(self, device: str, name: str, data: bytes) -> bool:
        """Execute a binary diagnostic job against the ECU."""
        # Flash writing is strictly prohibited
        self._last_job_status = "ERROR_FLASH_WRITE_PROHIBITED"
        self._text_results["JOB_STATUS"] = self._last_job_status
        raise KdcanError(
            f"Binary job '{name}' on device '{device}' ({len(data)} bytes) is prohibited on physical DirectKdcanBus"
        )

    def read_text(self, name: str, default: str = "") -> str:
        """Retrieve text result parameter from previous job."""
        return self._text_results.get(name, default)

    def read_binary(self, name: str) -> bytes:
        """Retrieve binary result parameter from previous job."""
        return self._binary_results.get(name, b"")

    def _execute_aif_lesen(self, dst: int) -> bool:
        """Execute KWP2000 AIF identification (0x1A 0x86). [OBSERVED ON WIRE]"""
        try:
            # Query KWP2000 AIF
            resp = self.transport.send_job(dst, bytes([0x1A, 0x86]), timeout=1.0)
            if not resp or resp[0] == 0x7F:
                self._last_job_status = f"ERROR_NRC_0x{resp[2]:02X}" if resp and len(resp) >= 3 else "NO_RESPONSE"
                self._text_results["JOB_STATUS"] = self._last_job_status
                return False

            self._last_job_status = "OKAY"
            self._text_results["JOB_STATUS"] = "OKAY"
            self._binary_results["RAW_IDENT"] = resp

            # Parse standard AIF fields if length allows
            ascii_text = resp.decode("ascii", "ignore")
            # Extract Short VIN
            if len(resp) >= 10:
                short_raw = resp[3:10].decode("ascii", "ignore").strip()
                if re.match(r"^[A-HJ-NPR-Z0-9]{7}$", short_raw, re.IGNORECASE):
                    self._text_results["SHORT_VIN"] = short_raw
                    self._text_results["VIN"] = short_raw

            # Extract ZB number
            if len(resp) >= 20:
                zb_bytes = resp[16:20]
                zb = f"{zb_bytes[0]:02X}{zb_bytes[1]:02X}{zb_bytes[2]:02X}{zb_bytes[3]:02X}".lstrip("0")
                if zb:
                    self._text_results["ZB_NUMMER"] = zb
                    self._text_results["SG_PHYS_HWNR"] = zb
                    self._text_results["HWNR"] = zb

            # Extract SW number
            if len(resp) >= 26:
                sw_bytes = resp[22:26]
                sw = f"{sw_bytes[0]:02X}{sw_bytes[1]:02X}{sw_bytes[2]:02X}{sw_bytes[3]:02X}".lstrip("0")
                if sw:
                    self._text_results["SW_NUMMER"] = sw

            # Extract SGBD identifier
            sgbd_match = re.search(r"(\d{4}[A-Z0-9]{8})", ascii_text)
            if sgbd_match:
                self._text_results["SGBD"] = sgbd_match.group(1)

            return True
        except KdcanError as e:
            self._last_job_status = f"ERROR_TRANSPORT: {e}"
            self._text_results["JOB_STATUS"] = self._last_job_status
            return False

    _execute_ident_lesen = _execute_aif_lesen

    def _execute_tester_present(self, dst: int) -> bool:
        """Execute TesterPresent (0x3E 0x00). [OBSERVED ON WIRE]"""
        try:
            resp = self.transport.send_job(dst, bytes([0x3E, 0x00]), timeout=0.5)
            # Both positive response (0x7E) and negative response (0x7F 0x3E ...) prove ECU presence
            if resp:
                self._last_job_status = "OKAY"
                self._text_results["JOB_STATUS"] = "OKAY"
                return True
            self._last_job_status = "NO_RESPONSE"
            self._text_results["JOB_STATUS"] = "NO_RESPONSE"
            return False
        except KdcanError as e:
            self._last_job_status = f"ERROR_TRANSPORT: {e}"
            self._text_results["JOB_STATUS"] = self._last_job_status
            return False
