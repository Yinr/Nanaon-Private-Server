#!/usr/bin/env python3
"""Analyze direct AArch64 branch xrefs inside Nanaon's libcompatible.so.

The AppGuard library has deliberately unhelpful section headers, so ordinary
objdump can fail.  This script uses only ELF program headers plus Capstone to
disassemble executable LOAD ranges and report direct BL/B calls to selected
dynamic-symbol wrapper functions.  The library's section metadata is damaged,
so imported functions are resolved from ``DT_JMPREL`` and the generated PLT
stubs instead of relying on objdump's section view.
"""
from __future__ import annotations

import argparse
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_IMM, ARM64_REG_X16, ARM64_REG_X17


WATCH_SYMBOLS = {
    "asm_kill",
    "asm_waitpid",
    "asm_getpid",
    "asm_ptrace",
    "asm_prctl",
    "asm_inotify_init",
    "asm_inotify_add_watch",
    "vfork",
    "execve",
    "execl",
    "sleep",
    "nanosleep",
    "pthread_create",
    "abort",
    "exit",
}


@dataclass(frozen=True)
class LoadSegment:
    offset: int
    vaddr: int
    filesz: int
    memsz: int
    flags: int

    @property
    def executable(self) -> bool:
        return bool(self.flags & 1)

    def contains_va(self, va: int) -> bool:
        return self.vaddr <= va < self.vaddr + self.filesz

    def file_offset(self, va: int) -> int:
        if not self.contains_va(va):
            raise ValueError(f"VA 0x{va:x} outside segment")
        return self.offset + va - self.vaddr


def va_to_file(segments: list[LoadSegment], va: int) -> int:
    """Translate a load-segment virtual address to a file offset."""
    for segment in segments:
        if segment.contains_va(va):
            return segment.file_offset(va)
    raise ValueError(f"VA 0x{va:x} is outside file-backed LOAD segments")


def parse_load_segments(data: bytes) -> list[LoadSegment]:
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError("expected ELF64 little-endian file")
    phoff = struct.unpack_from("<Q", data, 0x20)[0]
    phentsize = struct.unpack_from("<H", data, 0x36)[0]
    phnum = struct.unpack_from("<H", data, 0x38)[0]
    loads: list[LoadSegment] = []
    for index in range(phnum):
        off = phoff + index * phentsize
        p_type, p_flags = struct.unpack_from("<II", data, off)
        if p_type != 1:  # PT_LOAD
            continue
        p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from(
            "<QQQQQQ", data, off + 8,
        )
        loads.append(LoadSegment(p_offset, p_vaddr, p_filesz, p_memsz, p_flags))
    return loads


def parse_dynamic(data: bytes, segments: list[LoadSegment]) -> dict[int, int]:
    """Read the PT_DYNAMIC tag/value pairs without section-header support."""
    phoff = struct.unpack_from("<Q", data, 0x20)[0]
    phentsize = struct.unpack_from("<H", data, 0x36)[0]
    phnum = struct.unpack_from("<H", data, 0x38)[0]
    for index in range(phnum):
        off = phoff + index * phentsize
        p_type = struct.unpack_from("<I", data, off)[0]
        if p_type != 2:  # PT_DYNAMIC
            continue
        _, vaddr, _, filesz, _, _ = struct.unpack_from("<QQQQQQ", data, off + 8)
        file_off = va_to_file(segments, vaddr)
        tags: dict[int, int] = {}
        for pos in range(file_off, file_off + filesz, 16):
            tag, value = struct.unpack_from("<QQ", data, pos)
            if tag == 0:  # DT_NULL
                break
            tags[tag] = value
        return tags
    raise ValueError("PT_DYNAMIC not found")


def read_dynamic_symbol_names(
    data: bytes, segments: list[LoadSegment], dynamic: dict[int, int],
) -> dict[int, str]:
    """Return dynsym index -> name using DT_HASH's symbol count."""
    symtab_va = dynamic.get(6)  # DT_SYMTAB
    strtab_va = dynamic.get(5)  # DT_STRTAB
    hash_va = dynamic.get(4)  # DT_HASH
    if not symtab_va or not strtab_va or not hash_va:
        raise ValueError("missing DT_SYMTAB/DT_STRTAB/DT_HASH")
    hash_off = va_to_file(segments, hash_va)
    _, symbol_count = struct.unpack_from("<II", data, hash_off)
    symtab = va_to_file(segments, symtab_va)
    strtab = va_to_file(segments, strtab_va)
    names: dict[int, str] = {}
    for index in range(symbol_count):
        off = symtab + index * 0x18
        st_name = struct.unpack_from("<I", data, off)[0]
        if not st_name:
            continue
        end = data.find(b"\0", strtab + st_name)
        if end < 0:
            continue
        names[index] = data[strtab + st_name:end].decode("utf-8", "replace")
    return names


def find_plt_stubs(
    data: bytes, segments: list[LoadSegment],
) -> dict[tuple[int, int], int]:
    """Find standard AArch64 ``adrp/ldr/add/br`` PLT stubs.

    The key is (GOT page, page-relative offset), matching a JUMP_SLOT
    relocation.  Scanning only executable LOAD bytes keeps this independent of
    the library's malformed section table.
    """
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    stubs: dict[tuple[int, int], int] = {}
    for segment in segments:
        if not segment.executable:
            continue
        start = (segment.vaddr + 3) & ~3
        stop = segment.vaddr + segment.filesz - 16
        for address in range(start, stop, 4):
            file_off = segment.file_offset(address)
            word = struct.unpack_from("<I", data, file_off)[0]
            # ADRP X16 has op/rd bits matching 0x90000010.
            if word & 0x9F00001F != 0x90000010:
                continue
            insns = list(md.disasm(data[file_off:file_off + 16], address))
            if len(insns) != 4:
                continue
            first, second, third, fourth = insns
            if (
                first.mnemonic != "adrp"
                or first.operands[0].reg != ARM64_REG_X16
                or second.mnemonic != "ldr"
                or second.operands[0].reg != ARM64_REG_X17
                or third.mnemonic != "add"
                or third.operands[0].reg != ARM64_REG_X16
                or fourth.mnemonic != "br"
                or fourth.operands[0].reg != ARM64_REG_X17
            ):
                continue
            page = int(first.operands[1].imm)
            add_offset = int(third.operands[2].imm)
            stubs[(page, add_offset)] = address
    return stubs


def read_import_targets(
    data: bytes, segments: list[LoadSegment], dynamic: dict[int, int],
    names: dict[int, str],
) -> dict[str, int]:
    """Resolve imported WATCH_SYMBOLS to their PLT entry addresses."""
    jmprel_va = dynamic.get(23)  # DT_JMPREL
    pltrelsz = dynamic.get(2)  # DT_PLTRELSZ
    if not jmprel_va or not pltrelsz:
        return {}
    stubs = find_plt_stubs(data, segments)
    jmprel = va_to_file(segments, jmprel_va)
    targets: dict[str, int] = {}
    for pos in range(jmprel, jmprel + pltrelsz, 0x18):
        got, info, _ = struct.unpack_from("<QQq", data, pos)
        name = names.get(info >> 32)
        if name not in WATCH_SYMBOLS:
            continue
        page = got & ~0xFFF
        address = stubs.get((page, got - page))
        if address is not None:
            targets[name] = address
    return targets


def read_symbols_with_readelf(readelf: str, so_path: Path) -> dict[str, int]:
    proc = subprocess.run(
        [readelf, "-Ws", str(so_path)],
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    symbols: dict[str, int] = {}
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) < 8 or not parts[0].rstrip(":").isdigit():
            continue
        name = parts[-1].split("@", 1)[0]
        if name not in WATCH_SYMBOLS:
            continue
        try:
            value = int(parts[1], 16)
        except ValueError:
            continue
        if value:
            symbols[name] = value
    return symbols


def disassemble_xrefs(
    data: bytes,
    segments: list[LoadSegment],
    targets: dict[str, int],
    context: int,
) -> None:
    target_to_name = {value: name for name, value in targets.items()}
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    callsites: list[tuple[int, str, str]] = []
    for segment in segments:
        if not segment.executable:
            continue
        # Decode B/BL directly.  This remains reliable when opaque data or
        # intentionally invalid instructions interrupt a linear disassembly.
        for address in range(segment.vaddr, segment.vaddr + segment.filesz, 4):
            file_off = segment.file_offset(address)
            word = struct.unpack_from("<I", data, file_off)[0]
            opcode = word & 0xFC000000
            if opcode not in (0x14000000, 0x94000000):
                continue
            immediate = word & 0x03FFFFFF
            if immediate & 0x02000000:
                immediate -= 0x04000000
            target = address + (immediate << 2)
            name = target_to_name.get(target)
            if name:
                mnemonic = "bl" if opcode == 0x94000000 else "b"
                callsites.append((address, name, f"{mnemonic} #0x{target:x}"))

    for addr, name, text in callsites:
        print(f"xref 0x{addr:x} -> {name}: {text}")
        if context <= 0:
            continue
        seg = next(s for s in segments if s.contains_va(addr))
        start = max(seg.vaddr, addr - context)
        stop = min(seg.vaddr + seg.filesz, addr + context + 4)
        blob = data[seg.file_offset(start):seg.file_offset(stop)]
        for insn in md.disasm(blob, start):
            marker = "=>" if insn.address == addr else "  "
            print(f"  {marker} 0x{insn.address:x}: {insn.mnemonic:<8} {insn.op_str}")

    print(f"total_direct_xrefs={len(callsites)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("so", type=Path)
    parser.add_argument("--readelf", default="readelf.exe")
    parser.add_argument("--context", type=lambda text: int(text, 0), default=0x30)
    args = parser.parse_args()

    data = args.so.read_bytes()
    segments = parse_load_segments(data)
    targets = read_symbols_with_readelf(args.readelf, args.so)
    dynamic = parse_dynamic(data, segments)
    dynsym_names = read_dynamic_symbol_names(data, segments, dynamic)
    import_targets = read_import_targets(data, segments, dynamic, dynsym_names)
    targets.update(import_targets)
    print("targets:")
    for name, value in sorted(targets.items(), key=lambda item: item[1]):
        source = "import-plt" if name in import_targets else "export"
        print(f"  {name}=0x{value:x} ({source})")
    disassemble_xrefs(data, segments, targets, args.context)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
