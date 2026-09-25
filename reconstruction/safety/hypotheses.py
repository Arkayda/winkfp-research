"""Safety interlock — hypothesis structure only.

The binaries prove the CHECKLIST SHAPE (nfs.exe "ID_CHECK", "CASCADE
ZB-Nr Check", "Batterie und Z(ündung)", override flag "Ignorieren der
Bedingung"; ebas32 "ifhSetProgramVoltage"; winkfpt
"KONF_PROGRAMMIERSPANNUNG_ANZEIGEN") [O].

The LIMITS themselves are NOT in these binaries — and (rev 15) NOT in
NFS's ID_CHECK.DAT either: the real CFGDAT/ID_CHECK.DAT is the list of
mandatory ECU addresses / erratic-AIF addresses per chassis, parsed by
safety/id_check.py. The battery/ignition interlock numbers therefore
come from an operator-curated LIMITS FILE — a digest-bound operator
POLICY, not BMW-validated per-ECU data — whose strict format is parsed
here, so the recorded sha256 provably covers the NUMBERS, not just the
fact that some file existed:

    # BMW flash bench limits v1
    BAT 11.5 14.8
    IGNITION ON
    PROGVOLTAGE ON
    ZB ON

BAT is mandatory; unknown lines are rejected. Sanity checks reject
degenerate ranges at construction time.
"""

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Tuple

# Module-private factory token (rev 12): only Limits.from_limits_file
# (production) and Limits.for_testing (explicitly labelled test data)
# can mint it onto an instance. A bare Limits(...) carries no token,
# so check_preconditions() refuses it — untraced limits can no longer
# pass the safety gate through the direct constructor.
_FACTORY_TOKEN = object()

_BAT_RE = re.compile(r"^BAT\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)$")
_FLAG_RE = re.compile(r"^(IGNITION|PROGVOLTAGE|ZB)\s+(ON|OFF)$")


@dataclass(frozen=True)
class Limits:
    """Where every number came from matters. Build via
    Limits.from_limits_file (production) or Limits.for_testing (tests);
    a bare Limits(...) stays provenance-invalid and can NOT pass the
    gate (provenance_ok False → check_preconditions refuses it)."""
    battery_v_range: Tuple[float, float]
    ignition_on: bool
    programming_voltage_enabled: bool
    zb_number_must_match: bool
    ecu_family: str = "UNKNOWN"
    ecu_part_number: str = "UNKNOWN"
    source_digest: str = "UNPROVENANCED"      # sha256 of the limits file

    def __post_init__(self):
        lo, hi = self.battery_v_range
        if not (0 < lo < hi < 100):
            raise ValueError(f"implausible battery range "
                             f"{self.battery_v_range} V — limits must be "
                             f"parsed from the operator's limits policy "
                             f"file (Limits.from_limits_file)")

    @property
    def provenance_ok(self) -> bool:
        """True only for instances minted by a factory of this module:
        from_limits_file (digest-bound production data) or for_testing
        (explicitly labelled TEST-ONLY). Rev 12: a bare Limits(...) is
        never gate-accepted, whatever its fields say."""
        return (getattr(self, "_provenance_mint", None) is _FACTORY_TOKEN
                and self.source_digest != "UNPROVENANCED")

    def _mint(self) -> "Limits":
        object.__setattr__(self, "_provenance_mint", _FACTORY_TOKEN)
        return self

    @classmethod
    def from_limits_file(cls, limits_path: Path, ecu_family: str,
                         ecu_part_number: str) -> "Limits":
        """Parse the strict limits file so the digest provably covers
        the NUMBERS (rev 15): BAT <lo> <hi> mandatory, IGNITION /
        PROGVOLTAGE / ZB with ON|OFF optional (default ON), comments
        with '#', anything else is a hard error — a mistyped file can
        no longer degrade into silently-defaulted limits."""
        path = Path(limits_path)
        lo = hi = None
        ignition = prog = zb = True
        for lineno, raw in enumerate(
                path.read_text(encoding="ascii").splitlines(), 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            m = _BAT_RE.match(line)
            if m:
                lo, hi = float(m.group(1)), float(m.group(2))
                continue
            m = _FLAG_RE.match(line)
            if m:
                val = m.group(2) == "ON"
                if m.group(1) == "IGNITION":
                    ignition = val
                elif m.group(1) == "PROGVOLTAGE":
                    prog = val
                else:
                    zb = val
                continue
            raise ValueError(
                f"{path.name}:{lineno}: unparsable limits line "
                f"{raw.strip()!r} — expected 'BAT <lo> <hi>' or "
                f"'IGNITION|PROGVOLTAGE|ZB ON|OFF'")
        if lo is None:
            raise ValueError(
                f"{path.name}: no 'BAT <lo> <hi>' line — refusing to "
                f"construct limits without a parsed battery range")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return cls(battery_v_range=(lo, hi),
                   ignition_on=ignition,
                   programming_voltage_enabled=prog,
                   zb_number_must_match=zb,
                   ecu_family=ecu_family,
                   ecu_part_number=ecu_part_number,
                   source_digest=digest)._mint()

    @classmethod
    def for_testing(cls, battery_v_range: Tuple[float, float],
                    ignition_on: bool = True,
                    programming_voltage_enabled: bool = True,
                    zb_number_must_match: bool = True,
                    ecu_family: str = "SELFTEST",
                    ecu_part_number: str = "SELFTEST") -> "Limits":
        """Test-only limits: structurally valid and gate-accepted, but
        the provenance is explicitly labelled TEST-ONLY and can never
        be mistaken for file-derived production data."""
        return cls(battery_v_range=battery_v_range,
                   ignition_on=ignition_on,
                   programming_voltage_enabled=programming_voltage_enabled,
                   zb_number_must_match=zb_number_must_match,
                   ecu_family=ecu_family,
                   ecu_part_number=ecu_part_number,
                   source_digest=f"TEST-ONLY:{ecu_family}")._mint()


def check_preconditions(read_state: Callable[[str], object],
                        limits: Limits) -> Tuple[bool, List]:
    """Evaluate the interlock against explicit, provenance-carrying limits."""
    if not isinstance(limits, Limits) and getattr(limits, "__class__", None).__name__ != "Limits":
        raise TypeError("limits must be a Limits instance (ideally via "
                        "Limits.from_limits_file) — no defaults exist "
                        "by design")
    if not limits.provenance_ok:
        raise ValueError(
            "limits have untraced provenance — build them via "
            "Limits.from_limits_file(...) (production, digest-bound) or "
            "Limits.for_testing(...) (explicitly labelled tests). A bare "
            "Limits(...) cannot pass the safety gate (rev 12)")
    failures = []
    v = float(read_state("battery_v"))
    lo, hi = limits.battery_v_range
    if not lo <= v <= hi:
        failures.append(f"battery {v}V outside the parsed operator-policy "
                        f"range {lo}-{hi}V "
                        f"(ecu {limits.ecu_family}/{limits.ecu_part_number}, "
                        f"source {limits.source_digest[:12]})")
    if bool(read_state("ignition_on")) != limits.ignition_on:
        failures.append("ignition state wrong")
    if bool(read_state("programming_voltage_enabled")) != \
            limits.programming_voltage_enabled:
        failures.append("ifhSetProgramVoltage not applied")
    if bool(read_state("zb_number_matches")) != limits.zb_number_must_match:
        failures.append("ZB number mismatch (CASCADE ZB-Check)")
    return (len(failures) == 0, failures)
