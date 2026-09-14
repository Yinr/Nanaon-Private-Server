#!/usr/bin/env python3
"""Skip selected AppGuard ``System.loadLibrary`` calls.

This is a narrow Nanaon 2.4.0 diagnostic patch.  It removes the Java-side
``System.loadLibrary(...)`` invocations from AppGuard bootstrap class
initializers, while leaving the rest of the class initializer bytecode intact.

Use this after the attach/onCreate native-call NOP candidate to test whether
``libcompatible.so``'s early ``JNI_OnLoad`` / native bootstrap is responsible
for the later watchdog-style SIGKILL chain.
"""
from __future__ import annotations

import hashlib
import struct
import sys
import zipfile
import zlib
from pathlib import Path


TARGET_METHODS = (
    ("Lcom/inca/security/Proxy/AppGuardProxyApplication;", "<clinit>"),
    ("Lcom/inca/security/Proxy/AppGuardProxyAssistantApp;", "<clinit>"),
    ("Lcom/inca/security/Proxy/iIiIiIiIii;", "Load"),
)
SYSTEM_CLASS = "Ljava/lang/System;"
LOAD_LIBRARY_NAME = "loadLibrary"
INVOKE_STATIC = 0x71
INVOKE_STATIC_RANGE = 0x77
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


def find_method_idxs(data: bytes | bytearray, class_desc: str, name: str) -> list[int]:
    class_idx = find_type_idx(data, class_desc)
    name_idx = find_string_idx(data, name)
    method_ids_size = u32(data, 0x58)
    method_ids_off = u32(data, 0x5C)
    return [
        idx
        for idx in range(method_ids_size)
        if u16(data, method_ids_off + idx * 8) == class_idx
        and u32(data, method_ids_off + idx * 8 + 4) == name_idx
    ]


def find_single_method_idx(data: bytes | bytearray, class_desc: str, name: str) -> int:
    matches = find_method_idxs(data, class_desc, name)
    if len(matches) != 1:
        raise ValueError(f"expected one method {class_desc}->{name}, found {matches}")
    return matches[0]


def skip_encoded_fields(data: bytes | bytearray, pos: int, count: int) -> int:
    for _ in range(count):
        _, pos = read_uleb(data, pos)  # field_idx_diff
        _, pos = read_uleb(data, pos)  # access_flags
    return pos


def read_encoded_methods(
    data: bytes | bytearray,
    pos: int,
    count: int,
) -> tuple[int, list[tuple[int, int]]]:
    methods: list[tuple[int, int]] = []
    method_idx = 0
    for _ in range(count):
        diff, pos = read_uleb(data, pos)
        _, pos = read_uleb(data, pos)  # access_flags
        code_off, pos = read_uleb(data, pos)
        method_idx += diff
        methods.append((method_idx, code_off))
    return pos, methods


def class_methods(data: bytes | bytearray, class_data_off: int) -> list[tuple[int, int]]:
    pos = class_data_off
    static_fields_size, pos = read_uleb(data, pos)
    instance_fields_size, pos = read_uleb(data, pos)
    direct_methods_size, pos = read_uleb(data, pos)
    virtual_methods_size, pos = read_uleb(data, pos)

    pos = skip_encoded_fields(data, pos, static_fields_size)
    pos = skip_encoded_fields(data, pos, instance_fields_size)
    pos, direct_methods = read_encoded_methods(data, pos, direct_methods_size)
    _, virtual_methods = read_encoded_methods(data, pos, virtual_methods_size)
    return direct_methods + virtual_methods


def locate_method_code(data: bytes | bytearray, class_desc: str, name: str) -> int:
    class_type_idx = find_type_idx(data, class_desc)
    method_idx = find_single_method_idx(data, class_desc, name)
    class_defs_size = u32(data, 0x60)
    class_defs_off = u32(data, 0x64)
    for class_idx in range(class_defs_size):
        class_off = class_defs_off + class_idx * 32
        if u32(data, class_off) != class_type_idx:
            continue
        class_data_off = u32(data, class_off + 24)
        if not class_data_off:
            raise ValueError(f"class has no class_data: {class_desc}")
        for current_method_idx, code_off in class_methods(data, class_data_off):
            if current_method_idx == method_idx:
                if not code_off:
                    raise ValueError(f"{class_desc}->{name} has no code item")
                return code_off
    raise ValueError(f"code item not found: {class_desc}->{name}")


def refresh_dex_header(data: bytearray) -> None:
    data[12:32] = hashlib.sha1(data[32:]).digest()
    data[8:12] = struct.pack("<I", zlib.adler32(data[12:]) & 0xFFFFFFFF)


def patch_method_loadlibrary(
    data: bytearray,
    class_desc: str,
    method_name: str,
    load_library_method_idx: int,
) -> int:
    code_off = locate_method_code(data, class_desc, method_name)
    insns_size = u32(data, code_off + 12)
    insns_off = code_off + 16
    insns_len = insns_size * 2
    hits: list[int] = []
    for offset in range(0, insns_len - len(NOP3) + 1, 2):
        absolute = insns_off + offset
        opcode = data[absolute]
        if opcode not in (INVOKE_STATIC, INVOKE_STATIC_RANGE):
            continue
        if u16(data, absolute + 2) == load_library_method_idx:
            hits.append(offset)

    for offset in hits:
        absolute = insns_off + offset
        original = bytes(data[absolute:absolute + len(NOP3)])
        data[absolute:absolute + len(NOP3)] = NOP3
        print(
            f"patched {class_desc}->{method_name}: "
            f"code_off=0x{code_off:x}, insns_offset=0x{offset:x}, "
            f"original={original.hex()}"
        )
    return len(hits)


def patch_dex(raw: bytes) -> bytes:
    data = bytearray(raw)
    load_library_matches = find_method_idxs(data, SYSTEM_CLASS, LOAD_LIBRARY_NAME)
    if not load_library_matches:
        raise ValueError("java.lang.System.loadLibrary method id not found")

    total = 0
    errors: list[str] = []
    for load_library_method_idx in load_library_matches:
        for class_desc, method_name in TARGET_METHODS:
            try:
                total += patch_method_loadlibrary(
                    data, class_desc, method_name, load_library_method_idx,
                )
            except ValueError as exc:
                errors.append(f"{class_desc}->{method_name}: {exc}")

    if total == 0:
        details = "\n".join(errors)
        raise ValueError(f"no target System.loadLibrary invocation patched\n{details}")

    refresh_dex_header(data)
    print(f"patched System.loadLibrary invocations: {total}")
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
    print(f"patched AppGuard loadLibrary calls: {src} -> {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
