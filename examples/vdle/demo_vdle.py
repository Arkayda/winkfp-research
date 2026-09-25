#!/usr/bin/env python3
"""Demonstration of VDLE flash orchestration using synthetic image data.

This script executes:
1. Segment table parsing.
2. OPPS hardware configuration sequence generation.
3. Construction of 21-byte header FLASH_SCHREIBEN blocks.
4. Flashing execution using MockBus and SafetyContext.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from reconstruction.vdle.core import build_flash_block, opps_setup_jobs, load_table
from reconstruction.runner import FlashRunner, SafetyContext
from reconstruction.ediabas import MockBus
from reconstruction.safety import Limits


def main():
    print("=== WinKFP Research: VDLE Flash Engine Demo ===\n")

    # 1. OPPS Setup Sequence
    jobs = opps_setup_jobs(blocksize=256)
    print("[1] OPPS Configuration Job Sequence (256-byte blocks):")
    for idx, (dev, name, arg) in enumerate(jobs, 1):
        print(f"    {idx}. {dev}:{name}({arg!r})")
    print()

    # 2. Block Framing Construction
    addr = 0x00080000
    chunk = b"\xAA" * 128
    block = build_flash_block(addr, chunk)
    print(f"[2] Flash Block Header Construction:")
    print(f"    Target Address: {addr:#010x}")
    print(f"    Payload Length: {len(chunk)} bytes")
    print(f"    Total Block Size (Header + Data + Suffix): {len(block)} bytes")
    print(f"    Header Bytes (First 21 bytes): {block[:21].hex()}\n")

    # 3. Execution on MockBus with Safety Interlock
    fixtures_dir = ROOT / "tests" / "fixtures" / "synthetic"
    image = (fixtures_dir / "synthetic_image.bin").read_bytes()
    limits_path = fixtures_dir / "synthetic_limits.txt"
    limits = Limits.from_limits_file(str(limits_path), ecu_family="GKE19", ecu_part_number="7592144")

    state = {
        "battery_v": 13.5,
        "ignition_on": True,
        "programming_voltage_enabled": True,
        "zb_number_matches": True,
    }
    safety = SafetyContext(limits=limits, read_state=lambda k: state[k])
    bus = MockBus(sig_seq=["OKAY"])

    print("[3] Simulating Flash Execution on MockBus:")
    runner = FlashRunner(bus, image, blocksize=16, safety=safety)
    rep = runner.flash()
    print(f"    Flash Result: {'SUCCESS' if rep.ok else 'FAILED'}")
    print(f"    Blocks Written: {rep.blocks_written}")
    print(f"    Bytes Written: {rep.bytes_written}")
    print(f"    Phases Executed: {', '.join(p.name for p in rep.phases)}\n")

    print("Demo completed successfully.")


if __name__ == "__main__":
    main()
