#!/usr/bin/env python3
"""Build clean Nanaon package-name baseline APKs for device comparison.

This script intentionally does not patch AppGuard, endpoints, or Network
Security Config.  It produces:

* an official-copy APK with the original package name and official signature;
* an equal-length package-name rewrite signed with a local test key;
* a longer package-name rewrite rebuilt through Apktool and signed locally.

Outputs are test baselines, not final private-server APKs.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import struct
import subprocess
import tempfile
import zipfile
import zlib
from xml.sax.saxutils import escape
from pathlib import Path


OLD_PACKAGE = "com.aniplex.nananiji"
EQUAL_PACKAGE = "com.aniplex.nananips"
TARGET_PACKAGE = "com.aniplex.nananiji.ps"
EXPECTED_APK_SHA256 = (
    "692247de9daec19fcc7bb28559215069b5093197326170f75cc5a3dc6a199c89"
)
SIGNATURE_PREFIX = "META-INF/"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def find_tool(build_tools: Path, name: str) -> Path:
    candidates = [build_tools / name]
    if os.name == "nt":
        candidates.extend([build_tools / f"{name}.exe", build_tools / f"{name}.bat"])
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(build_tools / name)


def run(command: list[str | Path], *, env: dict[str, str] | None = None,
        capture: bool = False) -> str:
    printable = ["<redacted>" if str(item).startswith("pass:") else str(item)
                 for item in command]
    print("+", " ".join(map(str, printable)))
    result = subprocess.run(
        [str(item) for item in command],
        check=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
        env=env,
    )
    return result.stdout or ""


def copy_zip_info(item: zipfile.ZipInfo) -> zipfile.ZipInfo:
    copy = zipfile.ZipInfo(item.filename, date_time=item.date_time)
    copy.compress_type = item.compress_type
    copy.external_attr = item.external_attr
    copy.comment = item.comment
    copy.extra = item.extra
    copy.internal_attr = item.internal_attr
    copy.create_system = item.create_system
    copy.create_version = item.create_version
    copy.extract_version = item.extract_version
    copy.flag_bits = item.flag_bits
    return copy


def refresh_dex_header(raw: bytes) -> bytes:
    """Recompute a DEX header after byte-level equal-length edits."""
    if len(raw) < 0x70 or not raw.startswith(b"dex\n"):
        return raw
    data = bytearray(raw)
    file_size = struct.unpack_from("<I", data, 0x20)[0]
    if file_size != len(data):
        raise ValueError(
            f"unexpected DEX size: header={file_size} actual={len(data)}"
        )
    data[12:32] = hashlib.sha1(data[32:]).digest()
    data[8:12] = struct.pack("<I", zlib.adler32(data[12:]) & 0xFFFFFFFF)
    return bytes(data)


def verify_dex_headers(path: Path) -> None:
    with zipfile.ZipFile(path, "r") as archive:
        for name in archive.namelist():
            if not name.endswith(".dex"):
                continue
            data = archive.read(name)
            if len(data) < 0x70 or not data.startswith(b"dex\n"):
                raise ValueError(f"invalid DEX magic: {name}")
            expected_sha1 = hashlib.sha1(data[32:]).digest()
            expected_adler = zlib.adler32(data[12:]) & 0xFFFFFFFF
            actual_adler = struct.unpack_from("<I", data, 8)[0]
            if data[12:32] != expected_sha1 or actual_adler != expected_adler:
                raise ValueError(f"stale DEX header checksum/signature: {name}")


def rewrite_equal_length_package(src: Path, dst: Path, old: str,
                                 new: str) -> dict[str, tuple[int, int]]:
    old_utf8 = old.encode("utf-8")
    new_utf8 = new.encode("utf-8")
    old_utf16 = old.encode("utf-16le")
    new_utf16 = new.encode("utf-16le")
    if len(old_utf8) != len(new_utf8) or len(old_utf16) != len(new_utf16):
        raise ValueError("equal-length rewrite requires equal encoded lengths")

    counts: dict[str, tuple[int, int]] = {}
    seen_old = 0
    with zipfile.ZipFile(src, "r") as zin, zipfile.ZipFile(dst, "w") as zout:
        for item in zin.infolist():
            if item.filename.upper().startswith(SIGNATURE_PREFIX):
                continue
            payload = zin.read(item.filename)
            utf8_count = payload.count(old_utf8)
            utf16_count = payload.count(old_utf16)
            if utf8_count or utf16_count:
                counts[item.filename] = (utf8_count, utf16_count)
                seen_old += utf8_count + utf16_count
                payload = payload.replace(old_utf8, new_utf8)
                payload = payload.replace(old_utf16, new_utf16)
                if item.filename.endswith(".dex"):
                    payload = refresh_dex_header(payload)
                if old_utf8 in payload or old_utf16 in payload:
                    raise ValueError(f"old package remains in {item.filename}")
            zout.writestr(copy_zip_info(item), payload)
    if seen_old == 0:
        raise ValueError("old package was not found in the APK")
    return counts


def strip_existing_meta_inf(src: Path) -> None:
    """Remove pre-existing META-INF entries before local signing."""
    stripped = src.with_suffix(".stripped.apk")
    with zipfile.ZipFile(src, "r") as zin, zipfile.ZipFile(stripped, "w") as zout:
        for item in zin.infolist():
            if item.filename.upper().startswith(SIGNATURE_PREFIX):
                continue
            zout.writestr(copy_zip_info(item), zin.read(item.filename))
    stripped.replace(src)


def text_replace_package(root: Path, old: str, new: str) -> dict[str, int]:
    suffixes = {".xml", ".yml", ".yaml", ".smali"}
    counts: dict[str, int] = {}
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in suffixes:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        count = text.count(old)
        if not count:
            continue
        path.write_text(text.replace(old, new), encoding="utf-8", newline="")
        counts[str(path.relative_to(root))] = count
    if not counts:
        raise ValueError("apktool decode did not expose package text")
    return counts


def replace_app_name(root: Path, app_name: str) -> int:
    """Replace the decoded app_name string in the default values resource."""
    if not app_name:
        return 0
    path = root / "res" / "values" / "strings.xml"
    if not path.is_file():
        raise ValueError(f"decoded APK has no default strings resource: {path}")
    text = path.read_text(encoding="utf-8")
    import re
    pattern = re.compile(r"(<string\s+name=\"app_name\"[^>]*>)(.*?)(</string>)")
    updated, count = pattern.subn(
        lambda match: match.group(1) + escape(app_name) + match.group(3), text,
        count=1,
    )
    if count != 1:
        raise ValueError("decoded APK has no unique default app_name string")
    path.write_text(updated, encoding="utf-8", newline="")
    return count


def build_apktool_package(src: Path, dst: Path, package_name: str,
                          apktool_jar: Path, build_tools: Path,
                          work_root: Path, app_name: str | None = None) -> dict[str, int]:
    decoded = work_root / "decoded-target-package"
    frame_path = work_root / "apktool-framework"
    java_tmp = work_root / "java-tmp"
    decoded.mkdir(parents=True, exist_ok=True)
    frame_path.mkdir(parents=True, exist_ok=True)
    java_tmp.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["TMP"] = str(java_tmp)
    env["TEMP"] = str(java_tmp)
    env["PATH"] = str(build_tools) + os.pathsep + env.get("PATH", "")
    java = [
        "java",
        f"-Djava.io.tmpdir={java_tmp}",
        "-jar",
        apktool_jar,
    ]
    run(java + ["d", "-f", "-p", frame_path, "-o", decoded, src], env=env)
    counts = text_replace_package(decoded, OLD_PACKAGE, package_name)
    if app_name:
        counts["res/values/strings.xml:app_name"] = replace_app_name(decoded, app_name)
    run(java + ["b", "-f", "-p", frame_path, "-o", dst, decoded], env=env)
    return counts


def align_sign_verify(src: Path, dst: Path, build_tools: Path, keystore: Path,
                      alias: str, password: str) -> None:
    zipalign = find_tool(build_tools, "zipalign")
    apksigner = find_tool(build_tools, "apksigner")
    aligned = dst.with_suffix(".aligned.apk")
    run([zipalign, "-f", "-P", "16", "4", src, aligned])
    run([
        apksigner, "sign",
        "--ks", keystore,
        "--ks-key-alias", alias,
        "--ks-pass", f"pass:{password}",
        "--key-pass", f"pass:{password}",
        "--out", dst,
        aligned,
    ])
    run([zipalign, "-c", "-P", "16", "4", dst])
    run([apksigner, "verify", "--print-certs", dst])
    verify_dex_headers(dst)
    aligned.unlink(missing_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stock-apk", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--build-tools", type=Path, required=True)
    parser.add_argument("--keystore", type=Path, required=True)
    parser.add_argument("--ks-alias", default="test")
    parser.add_argument("--ks-pass", default=os.environ.get("NANAON_KS_PASS"))
    parser.add_argument("--apktool-jar", type=Path, required=True)
    parser.add_argument(
        "--equal-package", default=EQUAL_PACKAGE,
        help=f"equal-length comparison package (default: {EQUAL_PACKAGE})",
    )
    parser.add_argument(
        "--target-package", default=TARGET_PACKAGE,
        help=f"target package for the Apktool rebuild (default: {TARGET_PACKAGE})",
    )
    parser.add_argument(
        "--app-name", default=None,
        help="optional default app_name label; omitted keeps the stock label",
    )
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    stock_apk = args.stock_apk.resolve()
    out_dir = args.out_dir.resolve()
    build_tools = args.build_tools.resolve()
    keystore = args.keystore.resolve()
    apktool_jar = args.apktool_jar.resolve()
    if sha256_file(stock_apk).lower() != EXPECTED_APK_SHA256:
        raise SystemExit(f"unexpected stock APK hash: {stock_apk}")
    if not args.ks_pass:
        raise SystemExit("provide --ks-pass or NANAON_KS_PASS")
    if out_dir.exists() and any(out_dir.iterdir()) and not args.force:
        raise SystemExit(f"output directory is not empty: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)

    official = out_dir / "nanaon-2.4.0-official-com.aniplex.nananiji.apk"
    equal_unsigned = out_dir / "nanaon-2.4.0-com.aniplex.nananips.unsigned.apk"
    equal_signed = out_dir / f"nanaon-2.4.0-{args.equal_package}.signed.apk"
    target_unsigned = out_dir / f"nanaon-2.4.0-{args.target_package}.unsigned.apk"
    target_signed = out_dir / f"nanaon-2.4.0-{args.target_package}.signed.apk"

    shutil.copyfile(stock_apk, official)
    print(f"official={official}")
    print(f"official-sha256={sha256_file(official)}")

    equal_counts = rewrite_equal_length_package(
        stock_apk, equal_unsigned, OLD_PACKAGE, args.equal_package,
    )
    print(f"equal-rewrite-counts={equal_counts}")
    align_sign_verify(
        equal_unsigned, equal_signed, build_tools, keystore,
        args.ks_alias, args.ks_pass,
    )
    equal_unsigned.unlink(missing_ok=True)

    with tempfile.TemporaryDirectory(
        prefix="nanaon-apktool-", dir=str(out_dir)
    ) as temp_dir:
        target_counts = build_apktool_package(
            stock_apk, target_unsigned, args.target_package,
            apktool_jar, build_tools, Path(temp_dir), args.app_name,
        )
    print(f"target-rewrite-counts={target_counts}")
    strip_existing_meta_inf(target_unsigned)
    align_sign_verify(
        target_unsigned, target_signed, build_tools, keystore,
        args.ks_alias, args.ks_pass,
    )
    target_unsigned.unlink(missing_ok=True)

    for package, apk in [
        (OLD_PACKAGE, official),
        (args.equal_package, equal_signed),
        (args.target_package, target_signed),
    ]:
        print(f"package={package}")
        print(f"apk={apk}")
        print(f"sha256={sha256_file(apk)}")
        print(f"bytes={apk.stat().st_size}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
