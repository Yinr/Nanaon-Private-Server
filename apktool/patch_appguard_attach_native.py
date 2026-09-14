#!/usr/bin/env python3
"""Skip AppGuardProxyApplication.attachBaseContext's native loader call.

This is a narrow diagnostic patch for Nanaon 2.4.0.  It replaces only the
``invoke-static`` call from ``AppGuardProxyApplication.attachBaseContext`` to
``iIiIiIiIii.iIiIIiIiiI(Context,Object)`` with three DEX NOP instructions.

The patch intentionally does not change Unity/AppGuard bridge references or
the onCreate native call.  If the app advances and later misses a dynamically
loaded AppGuard class, that becomes the next explicit variable to solve.
"""
from __future__ import annotations

import hashlib
import struct
import sys
import zipfile
import zlib
from pathlib import Path


APP_CLASS = "Lcom/inca/security/Proxy/AppGuardProxyApplication;"
ATTACH_NAME = "attachBaseContext"
LOADER_CLASS = "Lcom/inca/security/Proxy/iIiIiIiIii;"
LOADER_METHOD = "iIiIIiIiiI"
INVOKE_STATIC = 0x71
NOP3 = bytes.fromhex("00 00 00 00 00 00")
SIGNATURE_PREFIX = "META-INF/"


def u16(data: bytes | bytearray, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes | bytearray, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def read_uleb(data: bytes | bytearray, off: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        byte = data[off]
        off += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, off
        shift += 7


def read_string(data: bytes | bytearray, string_idx: int) -> str:
    string_ids_off = u32(data, 0x3C)
    string_data_off = u32(data, string_ids_off + string_idx * 4)
    _, pos = read_uleb(data, string_data_off)
    end = data.index(0, pos)
    return bytes(data[pos:end]).decode("utf-8", errors="replace")


def type_descriptor(data: bytes | bytearray, type_idx: int) -> str:
    type_ids_off = u32(data, 0x44)
    return read_string(data, u32(data, type_ids_off + type_idx * 4))


def find_type_idx(data: bytes | bytearray, descriptor: str) -> int:
    type_ids_size = u32(data, 0x40)
    for idx in range(type_ids_size):
        if type_descriptor(data, idx) == descriptor:
            return idx
    raise ValueError(f"type not found: {descriptor}")


def find_string_idx(data: bytes | bytearray, value: str) -> int:
    string_ids_size = u32(data, 0x38)
    for idx in range(string_ids_size):
        if read_string(data, idx) == value:
            return idx
    raise ValueError(f"string not found: {value}")


def find_method_idx(data: bytes | bytearray, class_desc: str, name: str) -> int:
    class_idx = find_type_idx(data, class_desc)
    name_idx = find_string_idx(data, name)
    method_ids_size = u32(data, 0x58)
    method_ids_off = u32(data, 0x5C)
    matches = [
        idx
        for idx in range(method_ids_size)
        if u16(data, method_ids_off + idx * 8) == class_idx
        and u32(data, method_ids_off + idx * 8 + 4) == name_idx
    ]
    if len(matches) != 1:
        raise ValueError(f"expected one method {class_desc}->{name}, found {matches}")
    return matches[0]


def class_methods(data: bytes | bytearray, class_data_off: int) -> list[tuple[int, int]]:
    pos = class_data_off
    counts = []
    for _ in range(4):
        value, pos = read_uleb(data, pos)
        counts.append(value)
    methods: list[tuple[int, int]] = []
    for index, count in enumerate(counts):
        method_idx = 0
        for _ in range(count):
            diff, pos = read_uleb(data, pos)
            _, pos = read_uleb(data, pos)
            code_off, pos = read_uleb(data, pos)
            method_idx += diff
            if index >= 2:
                methods.append((method_idx, code_off))
    return methods


def locate_method_code(data: bytes | bytearray, class_desc: str, name: str) -> int:
    class_type_idx = find_type_idx(data, class_desc)
    method_idx = find_method_idx(data, class_desc, name)
    class_defs_size = u32(data, 0x60)
    class_defs_off = u32(data, 0x64)
    for class_idx in range(class_defs_size):
        class_off = class_defs_off + class_idx * 32
        if u32(data, class_off) != class_type_idx:
            continue
        class_data_off = u32(data, class_off + 24)
        for current_method_idx, code_off in class_methods(data, class_data_off):
            if current_method_idx == method_idx:
                if not code_off:
                    raise ValueError(f"{class_desc}->{name} has no code item")
                return code_off
    raise ValueError(f"code item not found: {class_desc}->{name}")


def refresh_dex_header(data: bytearray) -> None:
    data[12:32] = hashlib.sha1(data[32:]).digest()
    data[8:12] = struct.pack("<I", zlib.adler32(data[12:]) & 0xFFFFFFFF)


def patch_dex(raw: bytes) -> bytes:
    data = bytearray(raw)
    attach_code_off = locate_method_code(data, APP_CLASS, ATTACH_NAME)
    loader_method_idx = find_method_idx(data, LOADER_CLASS, LOADER_METHOD)
    insns_size = u32(data, attach_code_off + 12)
    insns_off = attach_code_off + 16
    insns = data[insns_off : insns_off + insns_size * 2]
    hits: list[int] = []
    for offset in range(0, len(insns) - 6 + 1, 2):
        absolute = insns_off + offset
        if data[absolute] != INVOKE_STATIC:
            continue
        if u16(data, absolute + 2) == loader_method_idx:
            hits.append(offset)
    if len(hits) != 1:
        raise ValueError(
            f"expected one attach native invoke to method@{loader_method_idx:04x}, "
            f"found {len(hits)}"
        )
    call_offset = hits[0]
    absolute = insns_off + call_offset
    original = bytes(data[absolute:absolute + 6])
    data[absolute:absolute + 6] = NOP3
    refresh_dex_header(data)
    print(
        f"patched {APP_CLASS}->{ATTACH_NAME}: method@{loader_method_idx:04x}, "
        f"code_off=0x{attach_code_off:x}, insns_offset=0x{call_offset:x}, "
        f"original={original.hex()}"
    )
    return bytes(data)


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


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} INPUT.apk OUTPUT.unsigned.apk")
    src, dst = map(Path, sys.argv[1:])
    with zipfile.ZipFile(src, "r") as zin, zipfile.ZipFile(dst, "w") as zout:
        seen: set[str] = set()
        for item in zin.infolist():
            if item.filename in seen:
                raise ValueError(f"duplicate source ZIP entry: {item.filename}")
            seen.add(item.filename)
            if item.filename.upper().startswith(SIGNATURE_PREFIX):
                continue
            payload = zin.read(item.filename)
            if item.filename == "classes.dex":
                payload = patch_dex(payload)
            zout.writestr(copy_zip_info(item), payload)
    print(f"patched attach native call: {src} -> {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
