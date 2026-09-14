#!/usr/bin/env python3
"""Build a static, no-LSPatch Nanaon private-server APK candidate.

The input is the official Nanaon 2.4.0 APK.  Depending on ``--patch-mode``
the builder applies no code patch or the single version-specific
AppGuardProxyApplication.onCreate native-call patch.  A narrow Network
Security Config can then be applied so that only the two private gateway
hostnames accept the Android user CA store.

This command never publishes to ``www`` and never touches a device.  It is a
local test/release-candidate builder; the signing password must be supplied
through ``--ks-pass`` or ``NANAON_KS_PASS`` and is not stored in this file.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
NSC_WRITER = ROOT / "build_patched_apk.py"
DEX_PATCHER = ROOT / "patch_appguard_oncreate_native.py"
ATTACH_PATCHER = ROOT / "patch_appguard_attach_native.py"
LOADLIB_PATCHER = ROOT / "patch_appguard_loadlibrary.py"
LIBCOMPATIBLE_PATCHER = ROOT / "patch_libcompatible_kill.py"
WATCHDOG_PATCHER = ROOT / "patch_libcompatible_watchdog_nop.py"
WATCHDOG_RETURN0_PATCHER = ROOT / "patch_libcompatible_watchdog_return0.py"
WATCHDOG_ENTRY_RETURN0_PATCHER = ROOT / "patch_libcompatible_watchdog_entry_return0.py"
FIXED_DOMAINS = ("227.hand.co.jp", "prd-asset.227.hand.co.jp")
NSC_ENTRY = "res/xml/network_security_config.xml"
INVOKE_NATIVE = bytes.fromhex("70 20 d2 79 44 00")


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load helper: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(command: list[Path | str], *, capture: bool = False) -> str:
    printable = ["<redacted>" if str(item).startswith("pass:") else str(item)
                 for item in command]
    print("+", " ".join(printable))
    result = subprocess.run(
        [str(item) for item in command],
        check=False,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=capture,
    )
    if result.returncode:
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        raise RuntimeError(f"command failed ({result.returncode}): {command[0]}")
    return result.stdout if capture else ""


def find_tool(build_tools: Path, name: str) -> Path:
    for suffix in (".exe", ".bat", ""):
        candidate = build_tools / f"{name}{suffix}"
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(build_tools / name)


def patch_code_only(
    src: Path,
    dst: Path,
    patchers,
    *,
    require_oncreate_patch: bool,
    require_code_change: bool,
) -> tuple[str, str]:
    """Apply one or more version-specific DEX patches.

    Patches are deliberately composed in a fixed order so the resulting
    classes.dex is reproducible.  Each patcher exposes ``patch_dex(bytes)``;
    no runtime module or broad process/termination hook is involved.
    """
    with zipfile.ZipFile(src, "r") as archive:
        original_dex = archive.read("classes.dex")
    patched_dex = original_dex
    for patcher in patchers:
        patched_dex = patcher.patch_dex(patched_dex)
    if require_code_change and patched_dex == original_dex:
        raise ValueError("AppGuard DEX patch did not change classes.dex")
    if not require_code_change and patched_dex != original_dex:
        raise ValueError("no-patch mode unexpectedly changed classes.dex")
    if require_oncreate_patch and INVOKE_NATIVE in patched_dex:
        raise ValueError("target native invoke remains in patched classes.dex")

    with zipfile.ZipFile(src, "r") as zin, zipfile.ZipFile(dst, "w") as zout:
        seen: set[str] = set()
        for item in zin.infolist():
            if item.filename in seen:
                raise ValueError(f"duplicate source ZIP entry: {item.filename}")
            seen.add(item.filename)
            data = patched_dex if item.filename == "classes.dex" else zin.read(item)
            clone = zipfile.ZipInfo(item.filename, date_time=item.date_time)
            clone.compress_type = item.compress_type
            clone.comment = item.comment
            clone.extra = item.extra
            clone.internal_attr = item.internal_attr
            clone.external_attr = item.external_attr
            clone.create_system = item.create_system
            clone.create_version = item.create_version
            clone.extract_version = item.extract_version
            clone.flag_bits = item.flag_bits
            zout.writestr(clone, data)
    return sha256_bytes(original_dex), sha256_bytes(patched_dex)


def verify_static_contents(path: Path, stock: Path, *, nsc: bool,
                           require_oncreate_patch: bool,
                           require_code_change: bool,
                           extra_changed_entries: tuple[str, ...] = ()) -> None:
    with zipfile.ZipFile(path, "r") as archive, zipfile.ZipFile(stock, "r") as source:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("output contains duplicate ZIP entries")
        bad = [name for name in names if name.startswith("assets/lspatch/")
               or name in {"loader.dex", "lspatch.dex"}]
        if bad:
            raise ValueError("static APK contains LSPatch entries: " + ", ".join(bad))
        if "classes.dex" not in names or "AndroidManifest.xml" not in names:
            raise ValueError("output is missing classes.dex or AndroidManifest.xml")
        if nsc and NSC_ENTRY not in names:
            raise ValueError(f"output is missing {NSC_ENTRY}")
        if not nsc and archive.read(NSC_ENTRY) != source.read(NSC_ENTRY):
            raise ValueError("no-NSC output unexpectedly changed NSC")
        if archive.testzip() is not None:
            raise ValueError("output ZIP has a corrupt entry")
        dex = archive.read("classes.dex")
        if require_oncreate_patch and INVOKE_NATIVE in dex:
            raise ValueError("target native invoke remains after packaging")
        source_dex = source.read("classes.dex")
        if require_code_change and dex == source_dex:
            raise ValueError("expected classes.dex to change")
        if not require_code_change and dex != source_dex:
            raise ValueError("no-patch mode changed classes.dex")
        source_names = source.namelist()
        changed = {"classes.dex", *extra_changed_entries}
        if nsc:
            changed.add(NSC_ENTRY)
            signature_suffixes = ("MANIFEST.MF", ".SF", ".RSA", ".DSA", ".EC")
            def is_signature_entry(name: str) -> bool:
                return (name.startswith("META-INF/")
                        and name.upper().endswith(signature_suffixes))

            normalized_names = [name for name in names if not is_signature_entry(name)]
            normalized_source_names = [
                name for name in source_names if not is_signature_entry(name)
            ]
            if normalized_names != normalized_source_names:
                raise ValueError("static APK changed the non-signature ZIP entries")
            for name in names:
                if name in changed or is_signature_entry(name):
                    continue
                if archive.read(name) != source.read(name):
                    raise ValueError(f"unexpected static APK entry change: {name}")


def verify_manifest(aapt2: Path, path: Path, *, expected_package: str) -> None:
    text = run([aapt2, "dump", "badging", path], capture=True)
    required = (
        f"package: name='{expected_package}'",
        "versionCode='5465'",
        "versionName='2.4.0'",
        "application-label:",
    )
    missing = [marker for marker in required if marker not in text]
    if missing:
        raise ValueError("unexpected APK metadata: " + ", ".join(missing))
    manifest = run([aapt2, "dump", "xmltree", path, "--file", "AndroidManifest.xml"],
                   capture=True)
    if "com.inca.security.Proxy.AppGuardProxyApplication" not in manifest:
        raise ValueError("static APK changed the AppGuard Application class")


def verify_nsc(aapt2: Path, path: Path, private_domains=None) -> None:
    text = run([aapt2, "dump", "xmltree", path, "--file", NSC_ENTRY], capture=True)
    domains = tuple(private_domains or FIXED_DOMAINS)
    for marker in (*domains, "system", "user"):
        if marker not in text:
            raise ValueError(f"NSC verification missing {marker!r}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock-apk", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--build-tools", type=Path, required=True)
    parser.add_argument("--keystore", type=Path, required=True)
    parser.add_argument("--ks-alias", required=True)
    parser.add_argument("--ks-pass", default=None)
    parser.add_argument(
        "--expected-package",
        default="com.aniplex.nananiji",
        help="expected package name in the built APK",
    )
    parser.add_argument(
        "--patch-mode",
        choices=(
            "none",
            "oncreate-native",
            "attach-native",
            "loadlibrary",
            "libcompatible-kill",
            "attach-native+oncreate-native",
            "oncreate-native+libcompatible-kill",
            "attach-native+libcompatible-kill",
            "attach-native+oncreate-native+libcompatible-kill",
            "attach-native+oncreate-native+loadlibrary",
            "libcompatible-watchdog-nop",
            "attach-native+oncreate-native+libcompatible-watchdog-nop",
            "libcompatible-watchdog-return0",
            "attach-native+oncreate-native+libcompatible-watchdog-return0",
            "libcompatible-watchdog-entry-return0",
            "attach-native+oncreate-native+libcompatible-watchdog-entry-return0",
        ),
        default="oncreate-native",
        help=("version-specific AppGuard call-site patch; use none for an "
              "NSC-only control; libcompatible-kill only patches the two "
              "observed kill syscall stubs; oncreate-native+libcompatible-kill "
              "applies both; default removes only the onCreate native call"),
    )
    parser.add_argument("--no-nsc", action="store_true",
                        help="keep the stock NSC for a lifecycle-only control")
    parser.add_argument(
        "--private-domain", dest="private_domains", action="append",
        help="HTTPS host allowed to use the Android user CA (repeatable)",
    )
    parser.add_argument(
        "--cleartext-domain", dest="cleartext_domains", action="append",
        help="legacy cleartext host preserved in the NSC (repeatable)",
    )
    parser.add_argument("--force", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    stock = args.stock_apk.resolve()
    output = args.out.resolve()
    build_tools = args.build_tools.resolve()
    keystore = args.keystore.resolve()
    if not stock.is_file():
        raise SystemExit(f"stock APK missing: {stock}")
    if not keystore.is_file():
        raise SystemExit(f"keystore missing: {keystore}")
    patch_modes = {
        "none": {"dex": (), "apk": (), "extra_changed": ()},
        "oncreate-native": {
            "dex": (DEX_PATCHER,),
            "apk": (),
            "extra_changed": (),
        },
        "attach-native": {
            "dex": (ATTACH_PATCHER,),
            "apk": (),
            "extra_changed": (),
        },
        "loadlibrary": {
            "dex": (LOADLIB_PATCHER,),
            "apk": (),
            "extra_changed": (),
        },
        "libcompatible-kill": {
            "dex": (),
            "apk": (LIBCOMPATIBLE_PATCHER,),
            "extra_changed": ("lib/arm64-v8a/libcompatible.so",),
        },
        "attach-native+oncreate-native": {
            "dex": (ATTACH_PATCHER, DEX_PATCHER),
            "apk": (),
            "extra_changed": (),
        },
        "oncreate-native+libcompatible-kill": {
            "dex": (DEX_PATCHER,),
            "apk": (LIBCOMPATIBLE_PATCHER,),
            "extra_changed": ("lib/arm64-v8a/libcompatible.so",),
        },
        "attach-native+libcompatible-kill": {
            "dex": (ATTACH_PATCHER,),
            "apk": (LIBCOMPATIBLE_PATCHER,),
            "extra_changed": ("lib/arm64-v8a/libcompatible.so",),
        },
        "attach-native+oncreate-native+libcompatible-kill": {
            "dex": (ATTACH_PATCHER, DEX_PATCHER),
            "apk": (LIBCOMPATIBLE_PATCHER,),
            "extra_changed": ("lib/arm64-v8a/libcompatible.so",),
        },
        "attach-native+oncreate-native+loadlibrary": {
            "dex": (ATTACH_PATCHER, DEX_PATCHER, LOADLIB_PATCHER),
            "apk": (),
            "extra_changed": (),
        },
        "libcompatible-watchdog-nop": {
            "dex": (),
            "apk": (WATCHDOG_PATCHER,),
            "extra_changed": ("lib/arm64-v8a/libcompatible.so",),
        },
        "attach-native+oncreate-native+libcompatible-watchdog-nop": {
            "dex": (ATTACH_PATCHER, DEX_PATCHER),
            "apk": (WATCHDOG_PATCHER,),
            "extra_changed": ("lib/arm64-v8a/libcompatible.so",),
        },
        "libcompatible-watchdog-return0": {
            "dex": (),
            "apk": (WATCHDOG_RETURN0_PATCHER,),
            "extra_changed": ("lib/arm64-v8a/libcompatible.so",),
        },
        "attach-native+oncreate-native+libcompatible-watchdog-return0": {
            "dex": (ATTACH_PATCHER, DEX_PATCHER),
            "apk": (WATCHDOG_RETURN0_PATCHER,),
            "extra_changed": ("lib/arm64-v8a/libcompatible.so",),
        },
        "libcompatible-watchdog-entry-return0": {
            "dex": (),
            "apk": (WATCHDOG_ENTRY_RETURN0_PATCHER,),
            "extra_changed": ("lib/arm64-v8a/libcompatible.so",),
        },
        "attach-native+oncreate-native+libcompatible-watchdog-entry-return0": {
            "dex": (ATTACH_PATCHER, DEX_PATCHER),
            "apk": (WATCHDOG_ENTRY_RETURN0_PATCHER,),
            "extra_changed": ("lib/arm64-v8a/libcompatible.so",),
        },
    }
    patch_plan = patch_modes[args.patch_mode]
    if not NSC_WRITER.is_file() or any(
        not path.is_file()
        for path in (*patch_plan["dex"], *patch_plan["apk"])
    ):
        raise SystemExit("static build helpers are missing")
    if output == stock or output in {
        NSC_WRITER,
        DEX_PATCHER,
        ATTACH_PATCHER,
        LOADLIB_PATCHER,
        LIBCOMPATIBLE_PATCHER,
        WATCHDOG_PATCHER,
        WATCHDOG_RETURN0_PATCHER,
        WATCHDOG_ENTRY_RETURN0_PATCHER,
    }:
        raise SystemExit("output must be distinct from every input/helper")
    if output.exists() and not args.force:
        raise SystemExit(f"output exists (use --force): {output}")
    password = args.ks_pass or os.environ.get("NANAON_KS_PASS")
    if not password:
        raise SystemExit("provide --ks-pass or NANAON_KS_PASS")

    require_oncreate_patch = DEX_PATCHER in patch_plan["dex"]
    require_code_change = bool(patch_plan["dex"])
    patchers = [
        load_module(path, f"nanaon_static_dex_patcher_{index}")
        for index, path in enumerate(patch_plan["dex"])
    ]
    apk_patchers = [
        load_module(path, f"nanaon_static_apk_patcher_{index}")
        for index, path in enumerate(patch_plan["apk"])
    ]
    nsc_writer = load_module(NSC_WRITER, "nanaon_static_nsc_writer")
    zipalign = find_tool(build_tools, "zipalign")
    apksigner = find_tool(build_tools, "apksigner")
    aapt2 = find_tool(build_tools, "aapt2")
    output.parent.mkdir(parents=True, exist_ok=True)
    temp_root = Path(tempfile.mkdtemp(prefix="nanaon-static-apk-", dir=output.parent))
    try:
        code_patched = temp_root / "code-patched.apk"
        nsc_patched = temp_root / "nsc-patched.apk"
        raw_aligned = temp_root / "aligned.apk"
        signed = temp_root / "signed.apk"
        before_hash, after_hash = patch_code_only(
            stock, code_patched, patchers,
            require_oncreate_patch=require_oncreate_patch,
            require_code_change=require_code_change,
        )
        source_for_align = code_patched
        if args.no_nsc:
            shutil.copyfile(code_patched, nsc_patched)
        else:
            private_domains = (
                tuple(args.private_domains)
                if args.private_domains is not None
                else nsc_writer.PRIVATE_DOMAINS
            )
            cleartext_domains = (
                tuple(args.cleartext_domains)
                if args.cleartext_domains is not None
                else nsc_writer.CLEARTEXT_DOMAINS
            )
            nsc_writer.patch_apk(
                code_patched,
                nsc_patched,
                nsc_writer.build_nsc(
                    private_domains,
                    cleartext_domains,
                ),
            )
        source_for_align = nsc_patched
        for index, patcher in enumerate(apk_patchers):
            next_stage = temp_root / f"apk-patched-{index}.apk"
            patcher.patch_apk(source_for_align, next_stage)
            source_for_align = next_stage
        verify_static_contents(
            source_for_align, stock, nsc=not args.no_nsc,
            require_oncreate_patch=require_oncreate_patch,
            require_code_change=require_code_change,
            extra_changed_entries=patch_plan["extra_changed"],
        )
        verify_manifest(aapt2, source_for_align, expected_package=args.expected_package)
        if not args.no_nsc:
            verify_nsc(aapt2, source_for_align, private_domains)
        run([zipalign, "-f", "-P", "16", "4", source_for_align, raw_aligned])
        run([
            apksigner, "sign", "--v1-signing-enabled", "true",
            "--v2-signing-enabled", "true", "--v3-signing-enabled", "true",
            "--v4-signing-enabled", "false", "--ks", keystore,
            "--ks-key-alias", args.ks_alias, "--ks-pass", f"pass:{password}",
            "--key-pass", f"pass:{password}", "--out", signed, raw_aligned,
        ])
        run([zipalign, "-c", "-P", "16", "-v", "4", signed])
        verify_static_contents(
            signed, stock, nsc=not args.no_nsc,
            require_oncreate_patch=require_oncreate_patch,
            require_code_change=require_code_change,
            extra_changed_entries=patch_plan["extra_changed"],
        )
        verify_manifest(aapt2, signed, expected_package=args.expected_package)
        if not args.no_nsc:
            verify_nsc(aapt2, signed, private_domains)
        run([apksigner, "verify", "--verbose", "--print-certs", signed])
        if output.exists():
            output.unlink()
        shutil.copyfile(signed, output)
        print(f"stock-sha256={sha256_file(stock)}")
        print(f"classes-dex-before={before_hash}")
        print(f"classes-dex-after={after_hash}")
        print(f"patch-mode={args.patch_mode}")
        print(f"classes-dex-changed={str(require_code_change).lower()}")
        print(f"nsc={'stock' if args.no_nsc else 'narrow-private-hosts'}")
        print(f"output-sha256={sha256_file(output)}")
        print(f"output-bytes={output.stat().st_size}")
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
