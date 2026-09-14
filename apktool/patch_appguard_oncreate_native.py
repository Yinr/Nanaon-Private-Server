#!/usr/bin/env python3
"""Skip only AppGuardProxyApplication's final native onCreate call.

This is a version-specific diagnostic patch for Nanaon 2.4.0.  It keeps the
normal Application lifecycle and attachBaseContext path intact, but replaces
the private native AppGuard initialization call at the end of onCreate with
three no-op DEX instructions.  The caller's return and exception table are
left in place so the resulting classes.dex remains structurally valid.
"""
from __future__ import annotations

import hashlib
import struct
import sys
import zipfile
import zlib
from pathlib import Path


CLASS_DESC = "Lcom/inca/security/Proxy/AppGuardProxyApplication;"
METHOD_NAME = "onCreate"
TARGET_METHOD_ID = 0x79D2  # IiIiiIiIiI(Context) in the stock 2.4.0 DEX
INVOKE_NATIVE = bytes.fromhex("70 20 d2 79 44 00")
NOP3 = bytes.fromhex("00 00 00 00 00 00")


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def read_uleb(data: bytes, off: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        byte = data[off]
        off += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, off
        shift += 7


def read_string(data: bytes, string_idx: int) -> str:
    string_ids_off = u32(data, 0x3C)
    string_data_off = u32(data, string_ids_off + string_idx * 4)
    _, pos = read_uleb(data, string_data_off)
    end = data.index(0, pos)
    return data[pos:end].decode("utf-8", errors="replace")


def type_descriptor(data: bytes, type_idx: int) -> str:
    type_ids_off = u32(data, 0x44)
    return read_string(data, u32(data, type_ids_off + type_idx * 4))


def class_methods(data: bytes, class_data_off: int) -> list[tuple[int, int]]:
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


def locate_oncreate(data: bytes) -> int:
    type_ids_size = u32(data, 0x40)
    type_ids_off = u32(data, 0x44)
    string_ids_size = u32(data, 0x38)
    method_ids_size = u32(data, 0x58)
    method_ids_off = u32(data, 0x5C)
    class_defs_size = u32(data, 0x60)
    class_defs_off = u32(data, 0x64)

    target_type_idx = next(
        (idx for idx in range(type_ids_size) if type_descriptor(data, idx) == CLASS_DESC),
        None,
    )
    if target_type_idx is None:
        raise ValueError(f"class not found: {CLASS_DESC}")

    oncreate_name = next(
        (idx for idx in range(string_ids_size) if read_string(data, idx) == METHOD_NAME),
        None,
    )
    if oncreate_name is None:
        raise ValueError("onCreate string not found")

    target_method_idx = next(
        (
            idx
            for idx in range(method_ids_size)
            if u16(data, method_ids_off + idx * 8) == target_type_idx
            and u32(data, method_ids_off + idx * 8 + 4) == oncreate_name
        ),
        None,
    )
    if target_method_idx is None:
        raise ValueError("AppGuardProxyApplication.onCreate method not found")

    for class_idx in range(class_defs_size):
        class_off = class_defs_off + class_idx * 32
        if u32(data, class_off) != target_type_idx:
            continue
        class_data_off = u32(data, class_off + 24)
        for method_idx, code_off in class_methods(data, class_data_off):
            if method_idx == target_method_idx:
                if not code_off:
                    raise ValueError("onCreate has no code item")
                return code_off
    raise ValueError("onCreate code item not found")


def patch_dex(raw: bytes) -> bytes:
    data = bytearray(raw)
    code_off = locate_oncreate(data)
    registers_size, ins_size, _, _ = struct.unpack_from("<HHHH", data, code_off)
    insns_size = u32(data, code_off + 12)
    if registers_size < 1 or ins_size != 1 or insns_size < 3:
        raise ValueError("unexpected onCreate code item shape")

    insns_off = code_off + 16
    insns = bytes(data[insns_off : insns_off + insns_size * 2])
    hits = [
        offset
        for offset in range(0, len(insns) - len(INVOKE_NATIVE) + 1, 2)
        if insns[offset : offset + len(INVOKE_NATIVE)] == INVOKE_NATIVE
    ]
    if len(hits) != 1:
        raise ValueError(f"expected one native AppGuard call, found {len(hits)}")
    call_offset = hits[0]
    data[insns_off + call_offset : insns_off + call_offset + len(NOP3)] = NOP3

    data[12:32] = hashlib.sha1(data[32:]).digest()
    data[8:12] = struct.pack("<I", zlib.adler32(data[12:]) & 0xFFFFFFFF)
    print(
        f"patched {CLASS_DESC}->{METHOD_NAME}: native method@{TARGET_METHOD_ID:04x} "
        f"at code_off=0x{code_off:x}, insns_offset=0x{call_offset:x}"
    )
    return bytes(data)


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} INPUT.apk OUTPUT.apk")
    src, dst = map(Path, sys.argv[1:])
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w") as zout:
        for item in zin.infolist():
            payload = zin.read(item.filename)
            if item.filename == "classes.dex":
                payload = patch_dex(payload)
            clone = zipfile.ZipInfo(item.filename, date_time=item.date_time)
            clone.compress_type = item.compress_type
            clone.external_attr = item.external_attr
            clone.comment = item.comment
            zout.writestr(clone, payload)
    print(f"patched onCreate native call: {src} -> {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
