#!/usr/bin/env python3
"""Replace encrypted watchdog kill dispatch calls with ``return 0``.

The three calls were identified in the v29 runtime decode of the official
2.4.0 arm64 ``libcompatible.so``.  A pure NOP leaves the PID in ``x0`` and
caused a later Unity/GPU crash in v33.  ``mov w0, #0`` occupies one ARM64
instruction, skips the dynamic ``kill(2)`` dispatch, and preserves the
success return value expected by the surrounding cleanup loop.
"""
from __future__ import annotations

import sys
import zipfile
from pathlib import Path


LIB_ARM64 = "lib/arm64-v8a/libcompatible.so"
XOR_KEY = bytes.fromhex("08c183b9c907009029213d91a80700b0")
RETURN_ZERO = bytes.fromhex("00008052")  # mov w0, #0

# File offsets, not virtual addresses; confirmed against v29 runtime code.
PATCHES = {
    0x2A0B0: bytes.fromhex("83b9ff97"),
    0x2A0CC: bytes.fromhex("7cb9ff97"),
    0x2A0E8: bytes.fromhex("75b9ff97"),
}

SIGNATURE_PREFIX = "META-INF/"
SIGNATURE_SUFFIXES = ("MANIFEST.MF", ".SF", ".RSA", ".DSA", ".EC")


def is_signature_entry(name: str) -> bool:
    return (name.upper().startswith(SIGNATURE_PREFIX)
            and name.upper().endswith(SIGNATURE_SUFFIXES))


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


def xor_at(data: bytes, offset: int) -> bytes:
    return bytes(value ^ XOR_KEY[(offset + index) % len(XOR_KEY)]
                 for index, value in enumerate(data))


def patch_lib(raw: bytes) -> bytes:
    data = bytearray(raw)
    for offset, expected_decoded in PATCHES.items():
        if offset + len(expected_decoded) > len(data):
            raise ValueError(f"{LIB_ARM64} offset 0x{offset:x} is outside the file")
        decoded = xor_at(bytes(data[offset:offset + len(expected_decoded)]), offset)
        if decoded != expected_decoded:
            raise ValueError(
                f"{LIB_ARM64} offset 0x{offset:x}: expected decoded "
                f"{expected_decoded.hex()}, found {decoded.hex()}"
            )
        encoded = xor_at(RETURN_ZERO, offset)
        data[offset:offset + len(RETURN_ZERO)] = encoded
        print(
            f"patched {LIB_ARM64} watchdog BL at 0x{offset:x}: "
            f"{decoded.hex()} -> {RETURN_ZERO.hex()} (encoded {encoded.hex()})"
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
    print(f"patched encrypted watchdog return-zero calls: {src} -> {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
