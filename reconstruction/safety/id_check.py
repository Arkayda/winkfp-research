#!/usr/bin/env python3
"""Parser for the REAL NFS CFGDAT/ID_CHECK.DAT (rev 15).

The file [O, shipping distribution, cp1252 INI-style] is — despite the
name our earlier revisions assumed — NOT a battery-limits file. Its own
header says:

    "Liste der zwingend verbauten Steuergeräteadressen und der
     Steuergeräteadressen bei denen der AIF-Eintrag systematisch
     fehlerhaft ist"

per-line format (documented in the file itself):
    1. Integrationsstufe  EXXX-XX-XX-XXX (14 chars) or XX.XXXX (4-7,
       legacy); wildcard '?' allowed
    2. SG-Adresse         2 hex digits
    3. Typschlüssel       T#### (wildcard '?', negation '!' allowed,
       several AND-combined)
    4. Sonderausstattung  S### (same rules)
    5. Existiert          ECU is mandatorily installed
    6. AifEingriff        ECU has a systematically wrong AIF entry

Sections are chassis names ([MUSTER], [E65], [E60], ...). This module
parses that real format; the battery/ignition interlock numbers live
in the separate limits file (safety.hypotheses.Limits.from_limits_file).
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

_SECTION = re.compile(r"^\[([A-Za-z0-9_]+)\]$")
_ADDR = re.compile(r"^([0-9A-Fa-f]{2})$")
_TOKEN = re.compile(r"^([TS])(!)?([0-9A-Za-z?]+)$")

LEGAL_FLAGS = ("Existiert", "AifEingriff")


@dataclass(frozen=True)
class Rule:
    """One ID_CHECK line: when (integration level, address, type keys,
    optional equipment) matches the vehicle, `exists` says the ECU is
    mandatorily installed and `aif_erratic` says its AIF entry cannot
    be trusted (nfs must not gate on it)."""
    integration: str            # raw pattern, '?' wildcards
    address: int                # SG-Adresse (hex byte)
    type_keys: tuple = ()       # (letter, negate, pattern)
    options: tuple = ()
    exists: bool = False
    aif_erratic: bool = False
    section: str = ""


def _tokenize(word):
    m = _TOKEN.match(word)
    if not m:
        return None
    letter, neg, pattern = m.groups()
    return (letter.upper(), neg == "!", pattern.upper())


def parse_id_check(path) -> dict:
    """Parse ID_CHECK.DAT → {section: [Rule, ...]}. Raises ValueError
    on lines that fit neither the documented rule format nor a
    comment/blank — silent skipping would fake provenance."""
    section = ""
    rules: dict = {}
    for lineno, raw in enumerate(
            Path(path).read_bytes().decode("cp1252").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        m = _SECTION.match(line)
        if m:
            section = m.group(1)
            rules.setdefault(section, [])
            continue
        words = line.split()
        integ = words[0]
        addr_hex = words[1] if len(words) > 1 else ""
        if not _ADDR.match(addr_hex):
            raise ValueError(
                f"{Path(path).name}:{lineno}: expected "
                f"'<integration> <SG-addr hex> ...', got {line!r}")
        types, options, flags = [], [], set()
        for w in words[2:]:
            if w in LEGAL_FLAGS:
                flags.add(w)
                continue
            tok = _tokenize(w)
            if tok is None:
                raise ValueError(
                    f"{Path(path).name}:{lineno}: unparsable token "
                    f"{w!r} (expected T####/S###/Existiert/AifEingriff)")
            (types if tok[0] == "T" else options).append(tok)
        rules.setdefault(section, []).append(Rule(
            integration=integ.upper(),
            address=int(addr_hex, 16),
            type_keys=tuple(types),
            options=tuple(options),
            exists="Existiert" in flags,
            aif_erratic="AifEingriff" in flags,
            section=section))
    return rules


def _pattern_match(pattern: str, actual: str) -> bool:
    """'?' matches any single char; other chars must match literally
    (format doc: 'Wildcard ? erlaubt')."""
    if len(pattern) != len(actual):
        return False
    return all(p == "?" or p == a for p, a in zip(pattern, actual.upper()))


def rules_for_address(rules: dict, address: int, section: str = None):
    """All rules concerning one SG address, optionally per chassis
    section. Bench use: show which ID_CHECK rules touch the ECU about
    to be programmed (an AifEingriff rule means nfs could not gate on
    its AIF entry)."""
    out = []
    for sect, rs in rules.items():
        if section is not None and sect.upper() != section.upper():
            continue
        out += [r for r in rs if r.address == address]
    return out


# ---------------------------------------------------------------------------
def _selftest():
    from pathlib import Path

    passed, failed = 0, []
    def check(name, cond):
        nonlocal passed
        if cond:
            passed += 1
            print(f"IDCHK OK   {name}")
        else:
            failed.append(name)
            print(f"IDCHK FAIL {name}")

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        # strict parser: the documented MUSTER example line round-trips
        p = Path(td) / "ID_CHECK.DAT"
        p.write_bytes(
            "; comment\r\n[MUSTER]\r\n"
            "????-??-??-???      0F     TAB?? T!AB44  S2?? S!201 S400 "
            "Existiert AifEingriff\r\n"
            "????-??-??-???      02     T????\r\n".encode("cp1252"))
        rules = parse_id_check(p)
        r0 = rules["MUSTER"][0]
        check("MUSTER rule 1 parses (wildcards, AND-tokens, both flags)",
              r0.address == 0x0F and r0.exists and r0.aif_erratic
              and r0.type_keys == (("T", False, "AB??"),
                                   ("T", True, "AB44"))
              and r0.options[2] == ("S", False, "400"))
        check("MUSTER rule 2: always-installed address 02",
              rules["MUSTER"][1].address == 0x02
              and rules["MUSTER"][1].type_keys == (("T", False, "????"),))
        check("pattern matcher honours '?' and literals",
              _pattern_match("AB??", "AB99")
              and not _pattern_match("AB??", "AB9")
              and not _pattern_match("AB??", "AC99"))
        try:
            p2 = Path(td) / "bad.DAT"
            p2.write_bytes("[X]\ngarbage line here\r\n".encode("cp1252"))
            parse_id_check(p2)
            check("garbage line rejected loudly", False)
        except ValueError:
            check("garbage line rejected loudly", True)

    # the REAL shipping ID_CHECK.DAT [O]
    real = (Path.home() / "Downloads/BMW/extracted/standard_tools/"
            "code$GetNFSInstallDir/CFGDAT/ID_CHECK.DAT")
    if real.exists():
        rules = parse_id_check(real)
        check("real ID_CHECK.DAT: chassis sections parse",
              {"MUSTER", "E65", "E60", "RR1", "E89X"} <= set(rules))
        check("real ID_CHECK.DAT: MUSTER carries the documented "
              "examples (0F erratic-AIF + mandatory, 02 always)",
              any(r.address == 0x0F and r.aif_erratic and r.exists
                  for r in rules["MUSTER"])
              and any(r.address == 0x02 for r in rules["MUSTER"]))
        check("real ID_CHECK.DAT: production sections empty in this "
              "release (documented — rules ship per SP-Daten)",
              not rules.get("E60"))
        check("rules_for_address finds by hex address",
              len(rules_for_address(rules, 0x0F)) == 1
              and rules_for_address(rules, 0x55) == [])
    else:
        print("IDCHK SKIP real ID_CHECK.DAT not found")

    print(f"\n{passed} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_selftest())
