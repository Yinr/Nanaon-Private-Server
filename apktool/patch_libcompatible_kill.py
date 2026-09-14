#!/usr/bin/env python3
"""Patch AppGuard's arm64 libcompatible kill syscall stubs.

Nanaon 2.4.0's ``libcompatible.so`` exposes two adjacent arm64 syscall stubs
for Linux ``kill(2)``.  Runtime ftrace showed the remaining AppGuard blocker is
an in-package SIGKILL chain after the Java attach/onCreate native calls are
NOPed and the Unity bridge is stubbed.  This diagnostic patch changes only the
two observed ``kill`` syscall entries to ``return 0``.

The patch is intentionally tiny and arm64-specific.  It preserves the rest of
``libcompatible.so`` so Unity/AppGuard bootstrap code can still run.
"""
from __future__ import annotations

import sys
import zipfile
from pathlib import Path


SIGNATURE_PREFIX = "META-INF/"
SIGNATURE_SUFFIXES = ("MANIFEST.MF", ".SF", ".RSA", ".DSA", ".EC")


def is_signature_entry(name: str) -> bool:
    """Drop only JAR signature records; preserve dependency metadata."""
    return (name.upper().startswith(SIGNATURE_PREFIX)
            and name.upper().endswith(SIGNATURE_SUFFIXES))
LIB_ARM64 = "lib/arm64-v8a/libcompatible.so"

PATCHES = {
    0x103C78: (
        bytes.fromhex("281080d2010000d4"),
        bytes.fromhex("000080d2c0035fd6"),  # mov x0,#0 ; ret
    ),
    0x103C88: (
        bytes.fromhex("281080d2010000d4"),
        bytes.fromhex("000080d2c0035fd6"),  # mov x0,#0 ; ret
    ),
}


def copy_zip_info(item: zipfile.ZipInfo) -> zipfile.ZipInfo:
    clone = zipfile.ZipInfo(item.filename, date_time=item.date_time)
    clone.compress_type = item.compress_type
    clone.external_attr = item.external_attr
    clone.comment = item.comment
    clone.extra = item.extra
    clone.internal_attr = item.internal_attr
    clone.create_system = item.create_system
    clone.create_version = item.create_version
    clone.extract_version = item.extract_version
    clone.flag_bits = item.flag_bits
    return clone


def patch_lib(raw: bytes) -> bytes:
    data = bytearray(raw)
    for offset, (expected, replacement) in PATCHES.items():
        actual = bytes(data[offset:offset + len(expected)])
        if actual != expected:
            raise ValueError(
                f"{LIB_ARM64} offset 0x{offset:x}: expected "
                f"{expected.hex()}, found {actual.hex()}"
            )
        data[offset:offset + len(replacement)] = replacement
        print(
            f"patched {LIB_ARM64} kill stub at 0x{offset:x}: "
            f"{expected.hex()} -> {replacement.hex()}"
        )
    return bytes(data)


def patch_apk(src: Path, dst: Path) -> None:
    with zipfile.ZipFile(src, "r") as zin, zipfile.ZipFile(dst, "w") as zout:
        seen: set[str] = set()
        patched = False
        for item in zin.infolist():
            if item.filename in seen:
                raise ValueError(f"duplicate source ZIP entry: {item.filename}")
            seen.add(item.filename)
            if is_signature_entry(item.filename):
                continue
            payload = zin.read(item.filename)
            if item.filename == LIB_ARM64:
                payload = patch_lib(payload)
                patched = True
            zout.writestr(copy_zip_info(item), payload)
        if not patched:
            raise ValueError(f"{LIB_ARM64} not found in {src}")


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} INPUT.apk OUTPUT.unsigned.apk")
    src, dst = map(Path, sys.argv[1:])
    patch_apk(src, dst)
    print(f"patched libcompatible kill syscall stubs: {src} -> {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
