"""SGBD 10FLASH.prg clean-room parser and offline execution engine.

Reconstructed from official BMW EDIABAS SGBD (10FLASH.prg) and SP-Daten
configuration (KFCONF10.DA2, GKE195.DAT, HWNR.DA2, 03GKE195.ipo).

Target: ZF 6HP EGS mechatronic controller at diagnostic address 0x18,
assembly ZB 7592132, calibration reference 0479S90T641Z (SG-TYP: GKE195).
"""

from __future__ import annotations

import json
from pathlib import Path
from reconstruction.transport.kdcan.framing import parse as parse_ds2_frame


def _extract_payload(data: Any) -> bytes:
    """Normalize input into response payload bytes."""
    if hasattr(data, "rx_payload"):
        return bytes(getattr(data, "rx_payload"))

    if isinstance(data, dict):
        if "rx_payload" in data:
            data = data["rx_payload"]
        elif "raw_rx" in data:
            data = data["raw_rx"]
        elif "rx" in data:
            data = data["rx"]
        else:
            raise ValueError(f"Trace dict missing payload fields: {data.keys()}")

    if isinstance(data, str):
        data = bytes.fromhex(data.replace(" ", "").strip())

    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"Unsupported payload type: {type(data)}")

    data_bytes = bytes(data)
    if len(data_bytes) >= 5:
        # If short header with inline length: 0x81..0xBF (3 header bytes + payload + 1 CS)
        if (data_bytes[0] & 0xC0 == 0x80) and (data_bytes[0] & 0x3F != 0):
            short_len = data_bytes[0] & 0x3F
            if len(data_bytes) == short_len + 4:
                return data_bytes[3:-1]
        # If extended header with 1-byte length: 0x80, dst, src, len (4 header bytes + payload + 1 CS)
        elif data_bytes[0] == 0x80 and len(data_bytes) >= 5:
            ext_len = data_bytes[3]
            if len(data_bytes) == ext_len + 5:
                return data_bytes[4:-1]

    return data_bytes


def _bcd_to_str(bcd_bytes: bytes, strip_leading_zeros: bool = True) -> str:
    """Convert BCD byte sequence into decimal string."""
    s = "".join(f"{b:02x}" for b in bcd_bytes)
    if strip_leading_zeros:
        s = s.lstrip("0")
        if not s:
            s = "0"
    return s


def decode_10flash_phys_hw_nr(response: Union[bytes, str, dict]) -> dict[str, Any]:
    """Decode KWP2000 1A 87 response per 10FLASH.prg PHYSIKALISCHE_HW_NR_LESEN.

    Telegram contract in 10FLASH.prg:
        Request:  82 <ADDR> F1 1A 87 <CS>
        Response: <FMT> F1 <ADDR> 5A 87 <PECUHN x 3> <CS>
        Payload:  5A 87 + 3 blocks of 6 bytes BCD

    SGBD logic:
        1. Verifies SID == 0x5A, SubID == 0x87.
        2. Validates payload length == 20 bytes (2 header + 3 * 6 bytes).
        3. Compares block1 == block2 == block3. If mismatch -> ERROR_CHECK_PECUHN.
        4. Strips leading zeros from 6-byte BCD block -> PHYSIKALISCHE_HW_NR.
    """
    payload = _extract_payload(response)
    results: dict[str, Any] = {}

    if len(payload) < 2:
        results["JOB_STATUS"] = "ERROR_ECU_INCORRECT_LEN"
        results["PHYSIKALISCHE_HW_NR"] = None
        return results

    sid = payload[0]
    subid = payload[1]

    if sid != 0x5A:
        if sid == 0x7F:
            results["JOB_STATUS"] = f"ERROR_ECU_NEGATIVE_RESPONSE_0x{payload[2]:02X}" if len(payload) >= 3 else "ERROR_ECU_NEGATIVE_RESPONSE"
        else:
            results["JOB_STATUS"] = "ERROR_ECU_INCORRECT_RESPONSE_ID"
        results["PHYSIKALISCHE_HW_NR"] = None
        return results

    if subid != 0x87:
        results["JOB_STATUS"] = "ERROR_ECU_INCORRECT_RESPONSE_ID"
        results["PHYSIKALISCHE_HW_NR"] = None
        return results

    # 10FLASH expects 3 blocks of 6 bytes = 18 bytes after 5A 87
    expected_len = 2 + 18
    if len(payload) != expected_len:
        results["JOB_STATUS"] = "ERROR_ECU_INCORRECT_LEN"
        results["JOB_MESSAGE"] = f"Invalid Len {len(payload)} != {expected_len}"
        results["PHYSIKALISCHE_HW_NR"] = None
        return results

    block1 = payload[2:8]
    block2 = payload[8:14]
    block3 = payload[14:20]

    if not (block1 == block2 == block3):
        results["JOB_STATUS"] = "ERROR_CHECK_PECUHN"
        results["JOB_MESSAGE"] = "Block comparison failed (block1 != block2 != block3)"
        results["PHYSIKALISCHE_HW_NR"] = None
        results["_BLOCK_MATCH"] = False
        return results

    hw_nr_str = _bcd_to_str(block1, strip_leading_zeros=True)

    results["JOB_STATUS"] = "OKAY"
    results["PHYSIKALISCHE_HW_NR"] = hw_nr_str
    results["_BLOCK_COUNT"] = 3
    results["_BLOCK_MATCH"] = True
    results["_RAW_BLOCK_HEX"] = block1.hex().upper()
    return results


def decode_10flash_ident(response: Union[bytes, str, dict]) -> dict[str, Any]:
    """Decode KWP2000 1A 80 response per 10FLASH.prg IDENT.

    Telegram contract in 10FLASH.prg:
        Request:  82 <ADDR> F1 1A 80 <CS>
        Response: <FMT> F1 <ADDR> 5A 80 <Ident-Table> <CS>

    Field mapping extracted directly from 10FLASH.prg bytecode:
        offset +2..8:   ID_BMW_NR        (6 bytes BCD, stripped leading zeros)
        offset +8:      ID_HW_NR         (1 byte decimal string, e.g. "10")
        offset +9:      ID_COD_INDEX     (1 byte int)
        offset +10..12: ID_DIAG_INDEX    (2 bytes big-endian int)
        offset +12..15: ID_LIEF_TEXT     (3 bytes ASCII, e.g. "SL ")
        offset +15:     ID_DATUM_JAHR    (1 byte BCD + 2000, e.g. 2008)
        offset +16:     ID_DATUM_MONAT   (1 byte BCD, e.g. 10)
        offset +17:     ID_DATUM_TAG     (1 byte BCD, e.g. 30)
        formatted:      ID_DATUM         (string "TT.MM.JJJJ", e.g. "30.10.2008")
        offset +18:     ID_LIEF_NR       (1 byte int, e.g. 8)
        offset +19..22: ID_SW_NR_MCV     (3 bytes int "A.B.C", e.g. "0.29.69")
        offset +22..25: ID_SW_NR_FSV     (3 bytes int "A.B.C", e.g. "195.64.1")
        offset +25..28: ID_SW_NR_OSV     (3 bytes int "A.B.C", e.g. "2.3.10")
        offset +28..31: ID_SW_NR_RES     (3 bytes int "A.B.C", e.g. "0.0.0")
        offset +31..37: _PECUHN_FALLBACK (6 bytes BCD, stripped leading zeros)
    """
    payload = _extract_payload(response)
    results: dict[str, Any] = {}

    if len(payload) < 2:
        results["JOB_STATUS"] = "ERROR_ECU_INCORRECT_LEN"
        return results

    sid = payload[0]
    subid = payload[1]

    if sid != 0x5A:
        if sid == 0x7F:
            results["JOB_STATUS"] = f"ERROR_ECU_NEGATIVE_RESPONSE_0x{payload[2]:02X}" if len(payload) >= 3 else "ERROR_ECU_NEGATIVE_RESPONSE"
        else:
            results["JOB_STATUS"] = "ERROR_ECU_INCORRECT_RESPONSE_ID"
        return results

    if subid != 0x80:
        results["JOB_STATUS"] = "ERROR_ECU_INCORRECT_RESPONSE_ID"
        return results

    if len(payload) < 31:
        results["JOB_STATUS"] = "ERROR_ECU_INCORRECT_LEN"
        results["JOB_MESSAGE"] = f"Payload too short for IDENT: {len(payload)} < 31"
        return results

    # Field extractions
    bmw_nr = _bcd_to_str(payload[2:8], strip_leading_zeros=True)
    hw_nr = f"{payload[8]:02x}"
    cod_index = int(payload[9])
    diag_index = int.from_bytes(payload[10:12], "big")

    lief_text = payload[12:15].decode("latin1", "ignore")

    jahr_bcd = int(f"{payload[15]:02x}")
    jahr = 2000 + jahr_bcd if jahr_bcd < 100 else jahr_bcd
    monat = int(f"{payload[16]:02x}")
    tag = int(f"{payload[17]:02x}")
    datum = f"{tag:02d}.{monat:02d}.{jahr:04d}"

    lief_nr = int(payload[18])

    mcv = f"{payload[19]}.{payload[20]}.{payload[21]}"
    fsv = f"{payload[22]}.{payload[23]}.{payload[24]}"
    osv = f"{payload[25]}.{payload[26]}.{payload[27]}"
    res = f"{payload[28]}.{payload[29]}.{payload[30]}"

    results["JOB_STATUS"] = "OKAY"
    results["ID_BMW_NR"] = bmw_nr
    results["ID_HW_NR"] = hw_nr
    results["ID_COD_INDEX"] = cod_index
    results["ID_DIAG_INDEX"] = diag_index
    results["ID_DATUM_JAHR"] = jahr
    results["ID_DATUM_MONAT"] = monat
    results["ID_DATUM_TAG"] = tag
    results["ID_DATUM"] = datum
    results["ID_LIEF_NR"] = lief_nr
    results["ID_LIEF_TEXT"] = lief_text
    results["ID_SW_NR_MCV"] = mcv
    results["ID_SW_NR_FSV"] = fsv
    results["ID_SW_NR_OSV"] = osv
    results["ID_SW_NR_RES"] = res

    # Fallback PECUHN extracted at offset 31..37 if payload is long enough
    if len(payload) >= 37:
        pecuhn_fallback = _bcd_to_str(payload[31:37], strip_leading_zeros=True)
        results["_PECUHN_FALLBACK"] = pecuhn_fallback

    # Calibration referenz string in trailing bytes
    if len(payload) >= 60:
        results["_CALIBRATION_REFERENZ_TAIL"] = payload[55:60].decode("latin1", "ignore")
        results["_CALIBRATION_PROJECT"] = payload[41:48].decode("latin1", "ignore")

    return results


def decode_10flash_seriennummer(response: Union[bytes, str, dict]) -> dict[str, Any]:
    """Decode KWP2000 1A 89 response per 10FLASH.prg SERIENNUMMER_LESEN.

    Telegram contract in 10FLASH.prg:
        Request:  82 <ADDR> F1 1A 89 <CS>
        Response: <FMT> F1 <ADDR> 5A 89 <Serial ASCII> <CS>
    """
    payload = _extract_payload(response)
    results: dict[str, Any] = {}

    if len(payload) < 2:
        results["JOB_STATUS"] = "ERROR_ECU_INCORRECT_LEN"
        results["SERIENNUMMER"] = None
        return results

    sid = payload[0]
    subid = payload[1]

    if sid != 0x5A:
        if sid == 0x7F:
            results["JOB_STATUS"] = f"ERROR_ECU_NEGATIVE_RESPONSE_0x{payload[2]:02X}" if len(payload) >= 3 else "ERROR_ECU_NEGATIVE_RESPONSE"
        else:
            results["JOB_STATUS"] = "ERROR_ECU_INCORRECT_RESPONSE_ID"
        results["SERIENNUMMER"] = None
        return results

    if subid != 0x89:
        results["JOB_STATUS"] = "ERROR_ECU_INCORRECT_RESPONSE_ID"
        results["SERIENNUMMER"] = None
        return results

    serial_bytes = payload[2:]
    serial_str = serial_bytes.decode("latin1", "ignore").strip("\x00 ").strip()

    results["JOB_STATUS"] = "OKAY"
    results["SERIENNUMMER"] = serial_str
    results["_RAW_SERIAL_HEX"] = serial_bytes.hex().upper()
    return results


def decode_10flash_aif_s23(response: Any) -> dict[str, Any]:
    """Decode KWP2000 ReadMemoryByAddress ($23) response per official 10FLASH.prg AIF_LESEN.

    Telegram contract in 10FLASH.prg:
        Request:  86 <ADDR> F1 23 <MemAddress(3B)> <MemLen(1B)> <CS>
        Response: <FMT> F1 <ADDR> 63 <AIF Data> <CS>

    Distinction:
        The official SGBD job AIF_LESEN uses service 0x23 (ReadMemoryByAddress),
        NOT service 0x1A 0x86 (which is AIF_READ_BENCH_ALIAS).
    """
    payload = _extract_payload(response)
    results: dict[str, Any] = {}

    if len(payload) < 1:
        results["JOB_STATUS"] = "ERROR_ECU_INCORRECT_LEN"
        return results

    sid = payload[0]

    if sid != 0x63:
        if sid == 0x7F:
            results["JOB_STATUS"] = (
                f"ERROR_ECU_NEGATIVE_RESPONSE_0x{payload[2]:02X}"
                if len(payload) >= 3
                else "ERROR_ECU_NEGATIVE_RESPONSE"
            )
        elif sid == 0x5A and len(payload) >= 2 and payload[1] == 0x86:
            results["JOB_STATUS"] = "ERROR_SGBD_USES_SERVICE_0x23_NOT_0x1A86"
            results["JOB_MESSAGE"] = (
                "Official SGBD AIF_LESEN requires KWP Service 0x23 (ReadMemoryByAddress). "
                "The 1A 86 response is classified as AIF_READ_BENCH_ALIAS."
            )
        else:
            results["JOB_STATUS"] = "ERROR_ECU_INCORRECT_RESPONSE_ID"
        return results

    aif_bytes = payload[1:]
    if len(aif_bytes) < 18:
        results["JOB_STATUS"] = "ERROR_ECU_INCORRECT_LEN"
        results["JOB_MESSAGE"] = f"AIF payload length too short: {len(aif_bytes)} < 18"
        return results

    if len(aif_bytes) < 32:
        # Factory trace 18-byte memory block (e.g. factory line 11956: 63 12 FF FF FF FF FF FF FF 20 08 10 07 00 00 09 16 56 72)
        mem = aif_bytes
        results["JOB_STATUS"] = "OKAY"
        results["AIF_FG_NR"] = mem[1:8].decode("latin1", "ignore").replace("\xff", "").strip()
        results["AIF_FG_NR_LANG"] = ""
        # Date: 20 08 10 07 -> 07.10.2008
        if len(mem) >= 12:
            results["AIF_DATUM"] = f"{mem[11]:02x}.{mem[10]:02x}.{mem[8]:02x}{mem[9]:02x}"
        else:
            results["AIF_DATUM"] = ""
        results["AIF_ZB_NR"] = _bcd_to_str(mem[12:18], strip_leading_zeros=True) if len(mem) >= 18 else ""
        results["AIF_SW_NR"] = ""
        results["AIF_BEHOERDEN_NR"] = "0"
        results["AIF_HAENDLER_NR"] = 0
        results["AIF_SERIEN_NR"] = ""
        results["AIF_KM"] = 0
        results["AIF_PROG_NR"] = 1
        results["AIF_GROESSE"] = mem[0] if len(mem) >= 1 else len(mem)
        return results

    results["JOB_STATUS"] = "OKAY"
    results["AIF_FG_NR"] = aif_bytes[0:7].decode("latin1", "ignore").strip()
    results["AIF_FG_NR_LANG"] = (
        aif_bytes[0:17].decode("latin1", "ignore").strip() if len(aif_bytes) >= 17 else ""
    )
    results["AIF_DATUM"] = (
        f"{aif_bytes[17]:02x}.{aif_bytes[18]:02x}.20{aif_bytes[19]:02x}"
        if len(aif_bytes) >= 20
        else ""
    )
    results["AIF_ZB_NR"] = _bcd_to_str(aif_bytes[20:24]) if len(aif_bytes) >= 24 else ""
    results["AIF_SW_NR"] = _bcd_to_str(aif_bytes[24:28]) if len(aif_bytes) >= 28 else ""
    results["AIF_BEHOERDEN_NR"] = _bcd_to_str(aif_bytes[28:32]) if len(aif_bytes) >= 32 else "0"
    results["AIF_HAENDLER_NR"] = 0
    results["AIF_SERIEN_NR"] = ""
    results["AIF_KM"] = 0
    results["AIF_PROG_NR"] = 1
    results["AIF_GROESSE"] = len(aif_bytes)
    return results


def decode_aif_bench_alias(response: Any) -> dict[str, Any]:
    """Decode KWP2000 1A 86 response for bench reconstruction alias AIF_READ_BENCH_ALIAS.

    Classification: OBSERVED_WIRE / RECONSTRUCTION_ALIAS.
    This is NOT the official SGBD AIF_LESEN job (which uses service 0x23).
    """
    import re

    payload = _extract_payload(response)
    results: dict[str, Any] = {}

    if len(payload) < 2:
        results["JOB_STATUS"] = "ERROR_ECU_INCORRECT_LEN"
        return results

    sid = payload[0]
    subid = payload[1]

    if sid != 0x5A:
        if sid == 0x7F:
            results["JOB_STATUS"] = (
                f"ERROR_ECU_NEGATIVE_RESPONSE_0x{payload[2]:02X}"
                if len(payload) >= 3
                else "ERROR_ECU_NEGATIVE_RESPONSE"
            )
        else:
            results["JOB_STATUS"] = "ERROR_ECU_INCORRECT_RESPONSE_ID"
        return results

    if subid != 0x86:
        results["JOB_STATUS"] = "ERROR_ECU_INCORRECT_RESPONSE_ID"
        return results

    if len(payload) < 20:
        results["JOB_STATUS"] = "ERROR_ECU_INCORRECT_LEN"
        return results

    results["JOB_STATUS"] = "OKAY"

    # Short VIN (7 ASCII chars at offset 3:10)
    short_raw = payload[3:10].decode("ascii", "ignore").strip()
    if re.match(r"^[A-HJ-NPR-Z0-9]{7}$", short_raw, re.IGNORECASE):
        results["short_vin"] = short_raw

    # Programming Date (BCD: YYYY.MM.DD at offset 10:14)
    if len(payload) >= 14:
        results["flash_date"] = (
            f"{payload[10]:02X}{payload[11]:02X}.{payload[12]:02X}.{payload[13]:02X}"
        )

    # ZB Number (4 bytes at offset 16:20)
    if len(payload) >= 20:
        zb_bytes = payload[16:20]
        zb_str = (
            f"{zb_bytes[0]:02X}{zb_bytes[1]:02X}{zb_bytes[2]:02X}{zb_bytes[3]:02X}".lstrip(
                "0"
            )
        )
        results["zb_number"] = zb_str or "0"

    # Software Number (4 bytes at offset 22:26)
    if len(payload) >= 26:
        sw_bytes = payload[22:26]
        sw_str = (
            f"{sw_bytes[0]:02X}{sw_bytes[1]:02X}{sw_bytes[2]:02X}{sw_bytes[3]:02X}".lstrip(
                "0"
            )
        )
        results["sw_number"] = sw_str or "0"

    # Full ASCII extraction for SGBD and Tool stamp
    ascii_text = payload.decode("ascii", "ignore")
    sgbd_match = re.search(r"(\d{4}[A-Z0-9]{8})", ascii_text)
    if sgbd_match:
        results["sgbd"] = sgbd_match.group(1)

    tool_match = re.search(r"(NFS\d{2}|BMW\w{2})", ascii_text)
    if tool_match:
        results["tool_marker"] = tool_match.group(1)

    # Chassis VIN prefix (10 ASCII chars at offset 53:63, e.g. WBANX71040)
    if len(payload) >= 63:
        chassis_prefix = payload[53:63].decode("ascii", "ignore").strip()
        if re.match(r"^[A-HJ-NPR-Z0-9]{10}$", chassis_prefix):
            results["chassis_prefix"] = chassis_prefix

    return results


def decode_10flash_zif(response: Any) -> dict[str, Any]:
    """Decode KWP2000 22 25 03 response per 10FLASH.prg ZIF_LESEN."""
    payload = _extract_payload(response)
    results: dict[str, Any] = {}
    if len(payload) < 3:
        results["JOB_STATUS"] = "ERROR_ECU_INCORRECT_LEN"
        return results
    if payload[0] == 0x7F:
        results["JOB_STATUS"] = (
            f"ERROR_ECU_NEGATIVE_RESPONSE_0x{payload[2]:02X}"
            if len(payload) >= 3
            else "ERROR_ECU_NEGATIVE_RESPONSE"
        )
        return results
    if payload[0] != 0x62 or payload[1:3] != b"\x25\x03":
        results["JOB_STATUS"] = "ERROR_ECU_INCORRECT_RESPONSE_ID"
        return results
    data = payload[3:]
    results["JOB_STATUS"] = "OKAY"
    results["ZIF_PROGRAMM_REFERENZ"] = data[:12].decode("latin1", "ignore").strip()
    results["ZIF_SG_KENNUNG"] = data[:3].decode("latin1", "ignore").strip() if len(data) >= 3 else ""
    results["ZIF_PROJEKT"] = data[3:6].decode("latin1", "ignore").strip() if len(data) >= 6 else ""
    results["ZIF_PROGRAMM_STAND"] = (
        data[6:10].decode("latin1", "ignore").strip() if len(data) >= 10 else ""
    )
    results["ZIF_STATUS"] = "0"
    results["ZIF_BMW_HW"] = ""
    return results


def decode_10flash_zif_backup(response: Any) -> dict[str, Any]:
    """Decode KWP2000 22 25 00 response per 10FLASH.prg ZIF_BACKUP_LESEN."""
    payload = _extract_payload(response)
    results: dict[str, Any] = {}
    if len(payload) < 3:
        results["JOB_STATUS"] = "ERROR_ECU_INCORRECT_LEN"
        return results
    if payload[0] == 0x7F:
        results["JOB_STATUS"] = (
            f"ERROR_ECU_NEGATIVE_RESPONSE_0x{payload[2]:02X}"
            if len(payload) >= 3
            else "ERROR_ECU_NEGATIVE_RESPONSE"
        )
        return results
    if payload[0] != 0x62 or payload[1:3] != b"\x25\x00":
        results["JOB_STATUS"] = "ERROR_ECU_INCORRECT_RESPONSE_ID"
        return results
    data = payload[3:]
    results["JOB_STATUS"] = "OKAY"
    results["ZIF_BACKUP_PROGRAMM_REFERENZ"] = data[:12].decode("latin1", "ignore").strip()
    results["ZIF_BACKUP_SG_KENNUNG"] = (
        data[:3].decode("latin1", "ignore").strip() if len(data) >= 3 else ""
    )
    results["ZIF_BACKUP_PROJEKT"] = (
        data[3:6].decode("latin1", "ignore").strip() if len(data) >= 6 else ""
    )
    results["ZIF_BACKUP_PROGRAMM_STAND"] = (
        data[6:10].decode("latin1", "ignore").strip() if len(data) >= 10 else ""
    )
    results["ZIF_BACKUP_STATUS"] = "0"
    results["ZIF_BACKUP_BMW_HW"] = ""
    return results


def decode_10flash_hw_referenz(response: Any) -> dict[str, Any]:
    """Decode KWP2000 22 25 02 response per 10FLASH.prg HARDWARE_REFERENZ_LESEN."""
    payload = _extract_payload(response)
    results: dict[str, Any] = {}
    if len(payload) < 3:
        results["JOB_STATUS"] = "ERROR_ECU_INCORRECT_LEN"
        return results
    if payload[0] == 0x7F:
        results["JOB_STATUS"] = (
            f"ERROR_ECU_NEGATIVE_RESPONSE_0x{payload[2]:02X}"
            if len(payload) >= 3
            else "ERROR_ECU_NEGATIVE_RESPONSE"
        )
        return results
    if payload[0] != 0x62 or payload[1:3] != b"\x25\x02":
        results["JOB_STATUS"] = "ERROR_ECU_INCORRECT_RESPONSE_ID"
        return results
    data = payload[3:]
    results["JOB_STATUS"] = "OKAY"
    results["HARDWARE_REFERENZ"] = data[:7].decode("latin1", "ignore").strip()
    results["HW_REF_SG_KENNUNG"] = data[:3].decode("latin1", "ignore").strip() if len(data) >= 3 else ""
    results["HW_REF_PROJEKT"] = data[3:6].decode("latin1", "ignore").strip() if len(data) >= 6 else ""
    results["HW_REF_STATUS"] = "0"
    return results


def decode_10flash_daten_referenz(response: Any) -> dict[str, Any]:
    """Decode KWP2000 22 25 04 response per 10FLASH.prg DATEN_REFERENZ_LESEN."""
    payload = _extract_payload(response)
    results: dict[str, Any] = {}
    if len(payload) < 3:
        results["JOB_STATUS"] = "ERROR_ECU_INCORRECT_LEN"
        return results
    if payload[0] == 0x7F:
        results["JOB_STATUS"] = (
            f"ERROR_ECU_NEGATIVE_RESPONSE_0x{payload[2]:02X}"
            if len(payload) >= 3
            else "ERROR_ECU_NEGATIVE_RESPONSE"
        )
        return results
    if payload[0] != 0x62 or payload[1:3] != b"\x25\x04":
        results["JOB_STATUS"] = "ERROR_ECU_INCORRECT_RESPONSE_ID"
        return results
    data = payload[3:]
    results["JOB_STATUS"] = "OKAY"
    results["DATEN_REFERENZ"] = data[:17].decode("latin1", "ignore").strip()
    results["DATEN_REF_SG_KENNUNG"] = (
        data[:3].decode("latin1", "ignore").strip() if len(data) >= 3 else ""
    )
    results["DATEN_REF_PROJEKT"] = (
        data[3:6].decode("latin1", "ignore").strip() if len(data) >= 6 else ""
    )
    results["DATEN_REF_PROGRAMM_STAND"] = (
        data[6:10].decode("latin1", "ignore").strip() if len(data) >= 10 else ""
    )
    results["DATEN_REF_DATENSATZ"] = (
        data[10:17].decode("latin1", "ignore").strip() if len(data) >= 17 else ""
    )
    results["DATEN_REF_STATUS"] = "0"
    return results


class Sgbd10FlashOffline:
    """Offline interpreter for 10FLASH.prg diagnostic jobs.

    Simulates the EDIABAS execution layer reading SGBD 10FLASH.prg against
    recorded wire traces without physical bus access.
    """

    SUPPORTED_JOBS = (
        "PHYSIKALISCHE_HW_NR_LESEN",
        "IDENT",
        "SERIENNUMMER_LESEN",
        "AIF_LESEN",
        "AIF_READ_BENCH_ALIAS",
        "ZIF_LESEN",
        "ZIF_BACKUP_LESEN",
        "HARDWARE_REFERENZ_LESEN",
        "DATEN_REFERENZ_LESEN",
    )

    def __init__(self, target_address: int = 0x18, sg_family: str = "GKE195"):
        self.target_address = target_address
        self.sg_family = sg_family
        self.last_results: dict[str, Any] = {}

    def execute_job(self, job_name: str, response_data: Union[bytes, str, dict, Any]) -> dict[str, Any]:
        """Execute SGBD job parsing on the provided response data."""
        job_norm = job_name.strip().upper()
        if job_norm == "PHYSIKALISCHE_HW_NR_LESEN":
            self.last_results = decode_10flash_phys_hw_nr(response_data)
        elif job_norm == "IDENT":
            self.last_results = decode_10flash_ident(response_data)
        elif job_norm == "SERIENNUMMER_LESEN":
            self.last_results = decode_10flash_seriennummer(response_data)
        elif job_norm == "AIF_LESEN":
            self.last_results = decode_10flash_aif_s23(response_data)
        elif job_norm in ("AIF_READ_BENCH_ALIAS", "AIF_LESEN_BENCH_ALIAS", "AIF_BENCH_ALIAS"):
            self.last_results = decode_aif_bench_alias(response_data)
        elif job_norm == "ZIF_LESEN":
            self.last_results = decode_10flash_zif(response_data)
        elif job_norm == "ZIF_BACKUP_LESEN":
            self.last_results = decode_10flash_zif_backup(response_data)
        elif job_norm == "HARDWARE_REFERENZ_LESEN":
            self.last_results = decode_10flash_hw_referenz(response_data)
        elif job_norm == "DATEN_REFERENZ_LESEN":
            self.last_results = decode_10flash_daten_referenz(response_data)
        else:
            raise NotImplementedError(
                f"Job '{job_name}' not implemented in Sgbd10FlashOffline. "
                f"Supported: {self.SUPPORTED_JOBS}"
            )
        return self.last_results

    def read_result(self, var_name: str) -> Any:
        """Read a specific named result field from the last job execution."""
        if var_name not in self.last_results:
            raise KeyError(f"Result variable '{var_name}' not found. Available: {list(self.last_results.keys())}")
        return self.last_results[var_name]
