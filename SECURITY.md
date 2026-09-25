# Security & Safety Policy

## Automotive Safety & Flashing Risks

This repository contains reverse-engineering research and clean-room protocol implementations for legacy automotive diagnostic and flashing toolchains.

> [!CAUTION]
> **ECU PROGRAMMING CARRIES SUBSTANTIAL RISK OF IRREVERSIBLE DAMAGE ("BRICKING").**
> Writing to ECU flash memory alters low-level firmware, bootloaders, and calibration tables. A power interruption, protocol mismatch, checksum failure, or aborted transfer can render an ECU completely unresponsive and non-recoverable via OBD.

### Essential Hardware Preconditions

1. **Power Supply Stability**: Flashing requires a dedicated, clean automotive power supply unit (PSU) capable of sustaining a steady voltage between 13.0V and 14.2V with at least 30A–50A capacity. Standard battery chargers or running engines are unsafe.
2. **Bench Testing First**: All physical experimentation must be conducted on isolated test benches (bench ECUs) before any consideration of vehicle installation.
3. **Hardware Recovery Capability**: Ensure that background bootloader recovery tools (e.g., BDM, JTAG, boot-pin programmers) and full EEPROM/flash backup dumps are available before initiating experimental reprogramming.
4. **Precondition Validation**: The safety interlock framework (`reconstruction/safety/id_check.py`) enforces strict pre-flash checks:
   - Verification of ECU hardware and software part numbers against target data.
   - Verification of battery voltage limits (`Limits.from_limits_file()`).
   - Confirmation of ignition and terminal status.

---

## Defensive Scope & Exclusions

* This research is strictly defensive, aimed at understanding legacy protocols, achieving protocol interoperability, and verifying data integrity.
* This repository does **NOT** provide instructions, exploits, or tooling for bypassing immobilizer systems (EWS/CAS), manipulating anti-theft mechanisms, altering odometers, or circumventing vehicle emissions compliance.

---

## Reporting Vulnerabilities

If you identify a security flaw in the reconstructed code or believe an unintended proprietary artifact or sensitive secret has been committed to this repository:

1. **Do not open a public issue.**
2. Report the vulnerability privately to the project maintainers via email or security advisory.
3. Include specific commit hashes, file paths, and technical rationale.
