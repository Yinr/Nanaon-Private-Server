#!/usr/bin/env python3
"""Package one APK and one OBB into an XAPK archive.

The input APK and OBB are copied byte-for-byte.  The tool only creates a new
ZIP container; it never signs, installs, or changes a device.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, NoReturn


PACKAGE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")
PACKAGE_LINE_RE = re.compile(
    r"package: name='([^']+)' versionCode='([^']+)' versionName='([^']*)'"
)
APP_LINE_RE = re.compile(r"application: label='([^']*)'")
MIN_SDK_RE = re.compile(r"minSdkVersion:'([^']+)'")
TARGET_SDK_RE = re.compile(r"targetSdkVersion:'([^']+)'")
PERMISSION_RE = re.compile(
    r"uses-permission(?:-sdk-\d+)?: name='([^']+)'"
)
COPY_BUFFER = 1024 * 1024


@dataclass(frozen=True)
class ApkMetadata:
    package_name: str
    version_code: str
    version_name: str
    app_name: str | None
    min_sdk: str | None
    target_sdk: str | None
    permissions: tuple[str, ...]


@dataclass(frozen=True)
class DataSource:
    path: Path
    entry_name: str | None
    size: int

    def open(self) -> BinaryIO:
        if self.entry_name is None:
            return self.path.open("rb")
        archive = zipfile.ZipFile(self.path, "r")
        stream = archive.open(self.entry_name, "r")
        return _ArchiveEntryStream(archive, stream)


class _ArchiveEntryStream:
    """Close both an entry stream and its owning archive."""

    def __init__(self, archive: zipfile.ZipFile, stream: BinaryIO) -> None:
        self._archive = archive
        self._stream = stream

    def __enter__(self) -> "_ArchiveEntryStream":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)

    def close(self) -> None:
        try:
            self._stream.close()
        finally:
            self._archive.close()


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"error: {message}")


def resolve_file(value: str | Path, label: str) -> Path:
    path = Path(value).expanduser().resolve()
    if not path.is_file():
        fail(f"{label} does not exist or is not a file: {path}")
    return path


def validate_leaf_name(value: str, label: str) -> str:
    if not value or value in {".", ".."} or "/" in value or "\\" in value:
        fail(f"{label} must be a single archive file name: {value!r}")
    if value.startswith("."):
        fail(f"{label} must not start with '.': {value!r}")
    return value


def validate_package(value: str) -> str:
    if not PACKAGE_RE.fullmatch(value):
        fail(f"invalid Android package name: {value!r}")
    return value


def find_aapt2(explicit: Path | None) -> Path | None:
    if explicit is not None:
        path = explicit.expanduser().resolve()
        if not path.is_file():
            fail(f"aapt2 does not exist: {path}")
        return path

    env_value = os.environ.get("NANAON_AAPT2")
    if env_value:
        path = Path(env_value).expanduser().resolve()
        if path.is_file():
            return path

    on_path = shutil.which("aapt2")
    if on_path:
        return Path(on_path).resolve()

    for sdk_var in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        sdk = os.environ.get(sdk_var)
        if not sdk:
            continue
        build_tools = Path(sdk) / "build-tools"
        if not build_tools.is_dir():
            continue
        candidates = sorted(
            (item / ("aapt2.exe" if os.name == "nt" else "aapt2"))
            for item in build_tools.iterdir()
            if item.is_dir()
        )
        for candidate in reversed(candidates):
            if candidate.is_file():
                return candidate.resolve()
    return None


def inspect_apk(apk: Path, aapt2: Path | None) -> ApkMetadata | None:
    try:
        with zipfile.ZipFile(apk, "r") as archive:
            if "AndroidManifest.xml" not in archive.namelist():
                fail(f"APK is missing AndroidManifest.xml: {apk}")
            if "classes.dex" not in archive.namelist():
                fail(f"APK is missing classes.dex: {apk}")
            if archive.testzip() is not None:
                fail(f"APK ZIP integrity check failed: {apk}")
    except zipfile.BadZipFile as exc:
        fail(f"invalid APK ZIP {apk}: {exc}")

    if aapt2 is None:
        return None

    result = subprocess.run(
        [str(aapt2), "dump", "badging", str(apk)],
        check=False,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
    )
    if result.returncode:
        fail(f"aapt2 dump badging failed for {apk}: {result.stderr.strip()}")

    package_match = PACKAGE_LINE_RE.search(result.stdout)
    if package_match is None:
        fail(f"aapt2 output has no package metadata: {apk}")
    app_match = APP_LINE_RE.search(result.stdout)
    min_match = MIN_SDK_RE.search(result.stdout)
    target_match = TARGET_SDK_RE.search(result.stdout)
    permissions = tuple(dict.fromkeys(PERMISSION_RE.findall(result.stdout)))
    return ApkMetadata(
        package_name=package_match.group(1),
        version_code=package_match.group(2),
        version_name=package_match.group(3),
        app_name=app_match.group(1) if app_match else None,
        min_sdk=min_match.group(1) if min_match else None,
        target_sdk=target_match.group(1) if target_match else None,
        permissions=permissions,
    )


def locate_obb_source(path: Path, entry_name: str | None) -> DataSource:
    if path.suffix.lower() != ".xapk" and entry_name is None:
        return DataSource(path=path, entry_name=None, size=path.stat().st_size)

    try:
        with zipfile.ZipFile(path, "r") as archive:
            if entry_name is None:
                candidates = [
                    item.filename
                    for item in archive.infolist()
                    if item.filename.lower().endswith(".obb")
                    and item.filename.lower().startswith("android/obb/")
                ]
                if len(candidates) != 1:
                    fail(
                        f"expected exactly one Android/obb entry in {path}; "
                        f"found {len(candidates)} (use --obb-entry)"
                    )
                entry_name = candidates[0]
            try:
                info = archive.getinfo(entry_name)
            except KeyError:
                fail(f"OBB ZIP entry not found in {path}: {entry_name}")
            if info.is_dir() or not entry_name.lower().endswith(".obb"):
                fail(f"OBB entry must be a file ending in .obb: {entry_name}")
            return DataSource(path=path, entry_name=entry_name, size=info.file_size)
    except zipfile.BadZipFile as exc:
        fail(f"invalid OBB/XAPK ZIP {path}: {exc}")
    raise AssertionError("unreachable")


def locate_icon_source(path: Path, entry_name: str) -> DataSource | None:
    """Read an icon entry from an XAPK without extracting it to disk."""
    try:
        with zipfile.ZipFile(path, "r") as archive:
            try:
                info = archive.getinfo(entry_name)
            except KeyError:
                return None
            if info.is_dir():
                fail(f"icon entry must be a file: {entry_name}")
            return DataSource(path=path, entry_name=entry_name, size=info.file_size)
    except zipfile.BadZipFile as exc:
        fail(f"invalid XAPK ZIP {path}: {exc}")
    raise AssertionError("unreachable")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(COPY_BUFFER), b""):
            digest.update(block)
    return digest.hexdigest()


def copy_stream(source: BinaryIO, target: BinaryIO) -> None:
    shutil.copyfileobj(source, target, length=COPY_BUFFER)


def fixed_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 0
    info.external_attr = 0o644 << 16
    return info


def build_manifest(
    *,
    package_name: str,
    apk_name: str,
    app_name: str,
    version_code: str,
    version_name: str,
    min_sdk: str | None,
    target_sdk: str | None,
    permissions: tuple[str, ...],
    apk_size: int,
    obb_path: str,
    obb_size: int,
    icon_name: str | None,
) -> dict[str, object]:
    manifest: dict[str, object] = {
        "xapk_version": 2,
        "package_name": package_name,
        "name": app_name,
        "version_code": version_code,
        "version_name": version_name,
        "permissions": list(permissions),
        "total_size": apk_size + obb_size,
        "expansions": [
            {
                "file": obb_path,
                "install_location": "EXTERNAL_STORAGE",
                "install_path": obb_path,
            }
        ],
        "split_apks": [{"file": apk_name, "id": "base"}],
    }
    if min_sdk is not None:
        manifest["min_sdk_version"] = min_sdk
    if target_sdk is not None:
        manifest["target_sdk_version"] = target_sdk
    if icon_name is not None:
        manifest["icon"] = icon_name
    return manifest


def verify_output(
    output: Path,
    manifest: dict[str, object],
    apk_size: int,
    obb_size: int,
) -> None:
    apk_name = str(manifest["split_apks"][0]["file"])
    obb_name = str(manifest["expansions"][0]["file"])
    expected = {"manifest.json", apk_name, obb_name}
    if "icon" in manifest:
        expected.add(str(manifest["icon"]))
    try:
        with zipfile.ZipFile(output, "r") as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                fail("output XAPK contains duplicate ZIP entries")
            if set(names) != expected:
                fail(f"output XAPK entries differ from manifest: {names}")
            if archive.testzip() is not None:
                fail("output XAPK ZIP integrity check failed")
            if archive.getinfo(apk_name).file_size != apk_size:
                fail("output APK entry size differs from input")
            if archive.getinfo(obb_name).file_size != obb_size:
                fail("output OBB entry size differs from input")
            parsed = json.loads(archive.read("manifest.json"))
            if parsed != manifest:
                fail("manifest.json changed while writing output")
    except zipfile.BadZipFile as exc:
        fail(f"invalid output XAPK ZIP: {exc}")


def write_xapk(
    *,
    output: Path,
    apk: Path,
    obb: DataSource,
    icon: DataSource | None,
    manifest: dict[str, object],
    force: bool,
) -> None:
    if output.exists() and not force:
        fail(f"output exists (use --force): {output}")
    input_paths = {apk.resolve(), obb.path.resolve()}
    if icon is not None:
        input_paths.add(icon.path.resolve())
    if output.resolve() in input_paths:
        fail("output must be different from every input file")
    output.parent.mkdir(parents=True, exist_ok=True)
    temp_fd, temp_path = tempfile.mkstemp(
        prefix=f".{output.name}.tmp-", dir=str(output.parent)
    )
    os.close(temp_fd)
    temp_name = Path(temp_path)

    manifest_bytes = (
        json.dumps(manifest, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    try:
        with zipfile.ZipFile(temp_name, "w", compression=zipfile.ZIP_STORED) as archive:
            apk_info = fixed_info(str(manifest["split_apks"][0]["file"]))
            with apk.open("rb") as source, archive.open(apk_info, "w") as target:
                copy_stream(source, target)

            if icon is not None:
                icon_info = fixed_info(str(manifest["icon"]))
                with icon.open() as source, archive.open(icon_info, "w") as target:
                    copy_stream(source, target)

            obb_info = fixed_info(str(manifest["expansions"][0]["file"]))
            with obb.open() as source, archive.open(obb_info, "w") as target:
                copy_stream(source, target)

            archive.writestr(fixed_info("manifest.json"), manifest_bytes)
        verify_output(output=temp_name, manifest=manifest,
                      apk_size=apk.stat().st_size, obb_size=obb.size)
        os.replace(temp_name, output)
    finally:
        if temp_name.exists():
            temp_name.unlink()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, required=True, help="input APK")
    parser.add_argument(
        "--obb", type=Path, required=True,
        help="input OBB, or an XAPK containing one OBB entry",
    )
    parser.add_argument(
        "--obb-entry",
        help="OBB entry inside --obb when --obb is a ZIP/XAPK with multiple entries",
    )
    parser.add_argument("--output", type=Path, help="output XAPK (default: <apk>.xapk)")
    parser.add_argument("--aapt2", type=Path, help="aapt2 used to inspect APK metadata")
    parser.add_argument("--package-name", help="expected package name")
    parser.add_argument("--app-name", help="XAPK display name; does not modify APK label")
    parser.add_argument("--version-code", help="override XAPK metadata version code")
    parser.add_argument("--version-name", help="override XAPK metadata version name")
    parser.add_argument("--min-sdk", help="override XAPK metadata min SDK")
    parser.add_argument("--target-sdk", help="override XAPK metadata target SDK")
    parser.add_argument(
        "--icon", type=Path,
        help="optional icon file to store as icon.png (does not extract APK resources)",
    )
    parser.add_argument(
        "--icon-entry", default="icon.png",
        help="icon entry to copy from an XAPK passed via --obb (default: icon.png)",
    )
    parser.add_argument(
        "--no-icon", action="store_true",
        help="disable automatic icon copy from an XAPK passed via --obb",
    )
    parser.add_argument("--icon-name", default="icon.png", help="archive name for --icon")
    parser.add_argument("--apk-name", help="APK archive name (default: <package>.apk)")
    parser.add_argument(
        "--obb-name",
        help="OBB archive file name (default: main.<versionCode>.<package>.obb)",
    )
    parser.add_argument("--force", action="store_true", help="overwrite output if it exists")
    parser.add_argument("--dry-run", action="store_true", help="validate and print layout only")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    apk = resolve_file(args.apk, "APK")
    obb_path = resolve_file(args.obb, "OBB source")
    if args.icon is not None and args.no_icon:
        fail("--icon and --no-icon cannot be used together")
    if args.icon is not None and args.icon_entry != "icon.png":
        fail("--icon-entry is only valid for automatic XAPK icon copy")
    icon_path = resolve_file(args.icon, "icon") if args.icon is not None else None
    if icon_path is not None:
        validate_leaf_name(args.icon_name, "icon name")

    aapt2 = find_aapt2(args.aapt2)
    detected = inspect_apk(apk, aapt2)
    if detected is None:
        print(
            "warning: aapt2 was not found; APK package/version metadata is "
            "not verified. Provide --aapt2 for consistency checks.",
            file=sys.stderr,
        )
    package_name = args.package_name or (detected.package_name if detected else None)
    if package_name is None:
        fail("provide --package-name when aapt2 is unavailable")
    validate_package(package_name)
    if detected is not None and detected.package_name != package_name:
        fail(
            f"--package-name {package_name!r} does not match APK package "
            f"{detected.package_name!r}"
        )

    version_code = args.version_code or (detected.version_code if detected else None)
    version_name = args.version_name or (detected.version_name if detected else None)
    if not version_code or not version_code.isdigit():
        fail("provide a numeric --version-code when aapt2 metadata is unavailable")
    if version_name is None:
        fail("provide --version-name when aapt2 metadata is unavailable")

    app_name = args.app_name or (detected.app_name if detected and detected.app_name else package_name)
    min_sdk = args.min_sdk or (detected.min_sdk if detected else None)
    target_sdk = args.target_sdk or (detected.target_sdk if detected else None)
    permissions = detected.permissions if detected else ()

    apk_name = validate_leaf_name(args.apk_name or f"{package_name}.apk", "APK name")
    obb_name = validate_leaf_name(
        args.obb_name or f"main.{version_code}.{package_name}.obb", "OBB name"
    )
    if not obb_name.lower().endswith(".obb"):
        fail(f"OBB name must end in .obb: {obb_name!r}")
    obb = locate_obb_source(obb_path, args.obb_entry)
    icon: DataSource | None = None
    if icon_path is not None:
        icon = DataSource(path=icon_path, entry_name=None, size=icon_path.stat().st_size)
    elif not args.no_icon and obb_path.suffix.lower() == ".xapk":
        icon = locate_icon_source(obb_path, args.icon_entry)
        if icon is None:
            print(
                f"warning: icon entry not found in XAPK; omitting {args.icon_entry!r}",
                file=sys.stderr,
            )
    obb_archive_path = f"Android/obb/{package_name}/{obb_name}"
    icon_name = args.icon_name if icon is not None else None
    archive_names = {"manifest.json", apk_name, obb_archive_path}
    if icon_name is not None:
        archive_names.add(icon_name)
    if len(archive_names) != (4 if icon_name is not None else 3):
        fail("APK, OBB, icon, and manifest archive names must be distinct")
    manifest = build_manifest(
        package_name=package_name,
        apk_name=apk_name,
        app_name=app_name,
        version_code=version_code,
        version_name=version_name,
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        permissions=permissions,
        apk_size=apk.stat().st_size,
        obb_path=obb_archive_path,
        obb_size=obb.size,
        icon_name=icon_name,
    )
    output = (
        args.output.expanduser().resolve()
        if args.output is not None
        else apk.with_suffix(".xapk").resolve()
    )

    print(f"apk={apk}")
    print(f"obb-source={obb.path}" + (f"!{obb.entry_name}" if obb.entry_name else ""))
    print(f"output={output}")
    print(f"package={package_name}")
    print(f"version={version_name} ({version_code})")
    print(f"apk-entry={apk_name} size={apk.stat().st_size}")
    print(f"obb-entry={obb_archive_path} size={obb.size}")
    print("manifest=" + json.dumps(manifest, ensure_ascii=False, separators=(",", ":")))

    if args.dry_run:
        if output.exists() and not args.force:
            print("dry-run=ok (output exists; use --force to replace it)")
        else:
            print("dry-run=ok")
        return 0

    write_xapk(
        output=output,
        apk=apk,
        obb=obb,
        icon=icon,
        manifest=manifest,
        force=args.force,
    )
    print(f"sha256={sha256_file(output)}")
    print(f"bytes={output.stat().st_size}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
