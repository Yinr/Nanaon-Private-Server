#!/usr/bin/env python3
"""Return from the encrypted watchdog cleanup function before its body runs.

The three inner ``kill(2)`` call-site patches changed the cleanup function's
control flow and led to a Unity/GPU crash. Runtime decoding shows the whole
PID-cleanup routine starts at file offset ``0x2a020``. Replacing only that
entry with ``mov w0,#0; ret`` skips the routine as a unit and leaves the shared
dynamic kill wrapper untouched.
"""
from __future__ import annotations

import sys
import zipfile
from pathlib import Path


LIB_ARM64 = "lib/arm64-v8a/libcompatible.so"
XOR_KEY = bytes.fromhex("08c183b9c907009029213d91a80700b0")
PATCH_OFFSET = 0x2A020
EXPECTED_DECODED = bytes.fromhex("ecb20394ffc302d1")
RETURN_ZERO = bytes.fromhex("00008052c0035fd6")
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
    end = PATCH_OFFSET + len(EXPECTED_DECODED)
    if end > len(data):
        raise ValueError(f"{LIB_ARM64} offset 0x{PATCH_OFFSET:x} is outside the file")
    decoded = xor_at(bytes(data[PATCH_OFFSET:end]), PATCH_OFFSET)
    if decoded != EXPECTED_DECODED:
        raise ValueError(
            f"{LIB_ARM64} offset 0x{PATCH_OFFSET:x}: expected decoded "
            f"{EXPECTED_DECODED.hex()}, found {decoded.hex()}"
        )
    data[PATCH_OFFSET:end] = xor_at(RETURN_ZERO, PATCH_OFFSET)
    print(
        f"patched {LIB_ARM64} watchdog entry at 0x{PATCH_OFFSET:x}: "
        f"{decoded.hex()} -> {RETURN_ZERO.hex()}"
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
    print(f"patched encrypted watchdog entry return-zero: {src} -> {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
