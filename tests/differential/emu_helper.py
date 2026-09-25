"""Helper utilities for differential testing via Unicorn x86 emulation.

This module provides PE loading and x86 execution primitives to compare
reconstructed Python algorithms directly against original binary code.

Differential tests are conditionally executed: if Unicorn, pefile, or
the original binary files are not available in the environment, tests
gracefully skip with informative messages.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Optional, Tuple

HAVE_DEPS = False
try:
    import pefile
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_INVALID
    from unicorn.x86_const import (
        UC_X86_REG_EAX,
        UC_X86_REG_ECX,
        UC_X86_REG_EDX,
        UC_X86_REG_EIP,
        UC_X86_REG_ESP,
    )
    HAVE_DEPS = True
except ImportError:
    pass

IMG_BASE = 0x400000
STACK_ADDR = 0x7F000000
STACK_SZ = 0x100000
SCRATCH_ADDR = 0x60000000
STOP_ADDR = 0x50000000


def get_winkfpt_path() -> Optional[Path]:
    """Locate winkfpt.exe from environment or well-known research paths."""
    env = os.environ.get("WINKFPT_EXE")
    if env and Path(env).is_file():
        return Path(env)
    bin_dir = os.environ.get("BMW_BINARIES_DIR")
    if bin_dir and (Path(bin_dir) / "winkfpt.exe").is_file():
        return Path(bin_dir) / "winkfpt.exe"

    candidates = [
        Path.home() / "Downloads/BMW_Flashing_Binaries/winkfpt.exe",
        Path.home() / "bmw_flash_re/winkfpt.exe",
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None


def get_obd32_path() -> Optional[Path]:
    """Locate OBD32.dll from environment or well-known research paths."""
    env = os.environ.get("OBD32_DLL")
    if env and Path(env).is_file():
        return Path(env)
    candidates = [
        Path.home() / "bmw_flash_re/EDIABAS_6.4.7/Bin/OBD32.dll",
        Path.home() / "Downloads/BMW_Flashing_Binaries/OBD32.dll",
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None


def can_run_winkfp_diff() -> Tuple[bool, str]:
    """Check if environment can run winkfpt.exe differential tests."""
    if not HAVE_DEPS:
        return False, "Missing unicorn or pefile python package"
    p = get_winkfpt_path()
    if p is None:
        return False, "winkfpt.exe not found (set WINKFPT_EXE environment variable)"
    return True, ""


def can_run_obd32_diff() -> Tuple[bool, str]:
    """Check if environment can run OBD32.dll differential tests."""
    if not HAVE_DEPS:
        return False, "Missing unicorn or pefile python package"
    p = get_obd32_path()
    if p is None:
        return False, "OBD32.dll not found (set OBD32_DLL environment variable)"
    return True, ""


def _align(val: int, align: int) -> int:
    return (val + align - 1) & ~(align - 1)


class WinEmu:
    """Minimal 32-bit x86 Windows emulator for running reverse-engineered functions."""

    def __init__(self, binary_path: Path, base_addr: int = IMG_BASE):
        if not HAVE_DEPS:
            raise RuntimeError("Unicorn or pefile is not available")

        pe = pefile.PE(str(binary_path))
        max_va = max(
            _align(s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData), 0x1000)
            for s in pe.sections
        )

        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        self.uc.mem_map(base_addr, _align(max_va, 0x1000))
        self.uc.mem_write(base_addr, pe.__data__[: pe.OPTIONAL_HEADER.SizeOfHeaders])
        for s in pe.sections:
            if s.SizeOfRawData:
                self.uc.mem_write(base_addr + s.VirtualAddress, s.get_data())

        self.uc.mem_map(STACK_ADDR, STACK_SZ)
        self.uc.mem_map(SCRATCH_ADDR, 0x10000)
        self.uc.mem_map(STOP_ADDR, 0x1000)
        # Map low memory to satisfy zero-page references
        self.uc.mem_map(0x0, 0x4000)
        self.scratch_ptr = SCRATCH_ADDR + 0x100

        # Fake CRT per-thread data
        self.ptd = self._raw_alloc(0x200)

        def _ptd_hook(uc, address, size, user_data):
            esp = uc.reg_read(UC_X86_REG_ESP)
            ret = struct.unpack("<I", bytes(uc.mem_read(esp, 4)))[0]
            uc.reg_write(UC_X86_REG_ESP, esp + 4)
            uc.reg_write(UC_X86_REG_EAX, self.ptd)
            uc.reg_write(UC_X86_REG_EIP, ret)

        for f in (0x5D1465, 0x5D14DE):
            try:
                self.uc.hook_add(UC_HOOK_CODE, _ptd_hook, begin=f, end=f)
            except Exception:
                pass

        self.uc.hook_add(UC_HOOK_MEM_INVALID, self._on_fault)

    def _on_fault(self, uc, access, address, size, value, user_data):
        return False

    def _raw_alloc(self, n: int) -> int:
        p = self.scratch_ptr
        self.scratch_ptr += _align(n, 16)
        self.uc.mem_write(p, b"\x00" * n)
        return p

    def alloc(self, data: bytes) -> int:
        p = self.scratch_ptr
        self.uc.mem_write(p, data)
        self.scratch_ptr += _align(len(data) + 16, 16)
        return p

    def read(self, addr: int, n: int) -> bytes:
        return bytes(self.uc.mem_read(addr, n))

    def call(self, func: int, args: list[int], ecx: int = 0, edx: int = 0, max_ops: int = 100_000_000) -> int:
        uc = self.uc
        esp = STACK_ADDR + STACK_SZ - 0x1000
        for a in reversed(args):
            esp -= 4
            uc.mem_write(esp, struct.pack("<I", a))
        esp -= 4
        uc.mem_write(esp, struct.pack("<I", STOP_ADDR))
        uc.reg_write(UC_X86_REG_ESP, esp)
        uc.reg_write(UC_X86_REG_ECX, ecx)
        uc.reg_write(UC_X86_REG_EDX, edx)
        uc.emu_start(func, STOP_ADDR, count=max_ops)
        return uc.reg_read(UC_X86_REG_EAX)
