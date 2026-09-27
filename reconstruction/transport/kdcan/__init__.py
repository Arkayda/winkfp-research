"""K+DCAN native transport package for winkfp-research.

Adapted from open6hp (https://github.com/Arkayda/open6hp) transport implementation.
Copyright (c) open6hp contributors. Licensed under the MIT License.
"""

from .adapter import KdcanDiagnosticAdapter, ScriptedKdcanBackend
from .base import KdcanError, KdcanTransport
from .bus import DirectKdcanBus
from .framing import (
    NRC_BUSY_REPEAT_REQUEST,
    NRC_CONDITIONS_NOT_CORRECT,
    NRC_GENERAL_REJECT,
    NRC_INVALID_KEY,
    NRC_REQUEST_OUT_OF_RANGE,
    NRC_REQUEST_SEQUENCE_ERROR,
    NRC_SECURITY_ACCESS_DENIED,
    NRC_SERVICE_NOT_SUPPORTED,
    NRC_SUBFUNCTION_NOT_SUPPORTED,
    SID_ECU_RESET,
    SID_READ_DATA_BY_COMMON_IDENTIFIER,
    SID_READ_DATA_BY_LOCAL_IDENTIFIER,
    SID_READ_ECU_IDENTIFICATION,
    SID_READ_STATUS_OF_DTC,
    SID_SECURITY_ACCESS,
    SID_START_DIAGNOSTIC_SESSION,
    SID_TESTER_PRESENT,
    TESTER_ADDRESS,
    Telegram,
    body_length,
    build,
    checksum,
    parse,
)
from .serial import SerialKdcanTransport
from .trace import SessionTracer, TracedKdcanTransport

__all__ = [
    "DirectKdcanBus",
    "KdcanDiagnosticAdapter",
    "KdcanError",
    "KdcanTransport",
    "ScriptedKdcanBackend",
    "SerialKdcanTransport",
    "SessionTracer",
    "TracedKdcanTransport",
    "Telegram",
    "build",
    "parse",
    "checksum",
    "body_length",
    "TESTER_ADDRESS",
    "SID_START_DIAGNOSTIC_SESSION",
    "SID_ECU_RESET",
    "SID_READ_STATUS_OF_DTC",
    "SID_READ_ECU_IDENTIFICATION",
    "SID_READ_DATA_BY_LOCAL_IDENTIFIER",
    "SID_READ_DATA_BY_COMMON_IDENTIFIER",
    "SID_SECURITY_ACCESS",
    "SID_TESTER_PRESENT",
    "NRC_GENERAL_REJECT",
    "NRC_SERVICE_NOT_SUPPORTED",
    "NRC_SUBFUNCTION_NOT_SUPPORTED",
    "NRC_BUSY_REPEAT_REQUEST",
    "NRC_CONDITIONS_NOT_CORRECT",
    "NRC_REQUEST_SEQUENCE_ERROR",
    "NRC_REQUEST_OUT_OF_RANGE",
    "NRC_SECURITY_ACCESS_DENIED",
    "NRC_INVALID_KEY",
]
