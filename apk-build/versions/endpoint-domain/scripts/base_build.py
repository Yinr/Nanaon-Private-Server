#!/usr/bin/env python3
"""Rebuild the validated dns-user-ca Nanaon private-server APK.

The default invocation builds the v44 dns-user-ca payload.  This wrapper keeps
all version-specific patch helpers in the repository ``apktool`` directory while making the normal
release knobs explicit: target package, app label, private HTTPS hosts and
local signing material.  It never installs an APK or changes a device.
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
from pathlib import Path

import toolchain


VERSION_ROOT = Path(__file__).resolve().parents[1]
BUILD_ROOT = VERSION_ROOT.parents[1]
PROJECT_ROOT = BUILD_ROOT.parents[2]
SERVER_ROOT = BUILD_ROOT.parent
APKTOOL_ROOT = SERVER_ROOT / "apktool"
BASELINE = APKTOOL_ROOT / "build_baseline_packages.py"
STATIC = APKTOOL_ROOT / "build_static_apk.py"
BRIDGE = APKTOOL_ROOT / "build_bridge_stub_candidate.py"
DEFAULT_STOCK = PROJECT_ROOT / "tools" / "apk-mod" / "work" / "original.apk"
DEFAULT_OUTPUT = PROJECT_ROOT / "tools" / "apk-mod" / "out" / (
    "nanaon-2.4.0-com.aniplex.nananiji.ps.v44-dns-user-ca.final.signed.apk"
)
DEFAULT_KEYSTORE = PROJECT_ROOT / "tools" / "apk-mod" / "keys" / "test.keystore"
DEFAULT_TMP = PROJECT_ROOT / "tools" / "_tmp"
DEFAULT_TARGET = "com.aniplex.nananiji.ps"
DEFAULT_EQUAL = "com.aniplex.nananips"
DEFAULT_DOMAINS = ("227.hand.co.jp", "prd-asset.227.hand.co.jp")
NSC_ENTRY = "res/xml/network_security_config.xml"
PACKAGE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")


def load_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if value[:1] in {"'", '"'} and value[-1:] == value[:1]:
            value = value[1:-1]
        values[key] = value
    return values


def env_value(dotenv: dict[str, str], key: str) -> str | None:
    return os.environ.get(key) or dotenv.get(key)


def resolve_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (VERSION_ROOT / path).resolve()


def resolve_argument_path(cli_value: Path | None, env_value_text: str | None,
                          default: Path) -> Path:
    """CLI paths are relative to cwd; .env paths are relative to this dir."""
    if cli_value is not None:
        return cli_value.resolve()
    if env_value_text:
        return resolve_path(env_value_text)
    return default.resolve()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def find_tool(build_tools: Path, name: str) -> Path:
    for suffix in (".bat", ".cmd", ".exe", ""):
        candidate = build_tools / f"{name}{suffix}"
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"{name} not found under {build_tools}")


def run(command: list[str | Path], *, env: dict[str, str]) -> None:
    shown = ["pass:<redacted>" if str(item).startswith("pass:") else str(item)
             for item in command]
    print("+", " ".join(shown))
    subprocess.run([str(item) for item in command], check=True, env=env)


def verify_output(path: Path, build_tools: Path, target: str,
                  app_name: str | None, private_domains: list[str]) -> dict[str, object]:
    with zipfile.ZipFile(path, "r") as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise RuntimeError("final APK contains duplicate ZIP entries")
        if archive.testzip() is not None:
            raise RuntimeError("final APK ZIP integrity check failed")
        if "classes2.dex" not in names:
            raise RuntimeError("final APK is missing the basic bridge classes2.dex")
        if any(name.startswith("assets/lspatch/") for name in names):
            raise RuntimeError("final APK unexpectedly contains LSPatch assets")
    aapt2 = find_tool(build_tools, "aapt2")
    result = subprocess.run(
        [str(aapt2), "dump", "badging", str(path)], check=True,
        text=True, encoding="utf-8", errors="replace", capture_output=True,
    ).stdout
    if f"package: name='{target}'" not in result:
        raise RuntimeError(f"final APK package name is not {target}")
    if "versionCode='5465'" not in result or "versionName='2.4.0'" not in result:
        raise RuntimeError("final APK version metadata changed unexpectedly")
    if app_name is not None and f"application-label:'{app_name}'" not in result:
        raise RuntimeError(f"final APK application label is not {app_name!r}")

    nsc = subprocess.run(
        [str(aapt2), "dump", "xmltree", "--file", NSC_ENTRY, str(path)],
        check=True, text=True, encoding="utf-8", errors="replace",
        capture_output=True,
    ).stdout
    for domain in private_domains:
        if f"'{domain}'" not in nsc:
            raise RuntimeError(f"NSC is missing private domain {domain!r}")
    if 'A: src="system"' not in nsc or 'A: src="user"' not in nsc:
        raise RuntimeError("NSC does not contain both system and user trust anchors")

    zipalign = find_tool(build_tools, "zipalign")
    aligned = subprocess.run(
        [str(zipalign), "-c", "-P", "16", "4", str(path)],
        text=True, encoding="utf-8", errors="replace", capture_output=True,
    )
    if aligned.returncode:
        raise RuntimeError(f"zipalign verification failed: {aligned.stderr or aligned.stdout}")

    apksigner = find_tool(build_tools, "apksigner")
    signed = subprocess.run(
        [str(apksigner), "verify", "--verbose", "--print-certs", str(path)],
        text=True, encoding="utf-8", errors="replace", capture_output=True,
    )
    if signed.returncode:
        raise RuntimeError(f"APK signature verification failed: {signed.stderr or signed.stdout}")
    return {
        "path": str(path), "bytes": path.stat().st_size,
        "sha256": sha256_file(path), "package": target,
        "app_name": app_name,
        "patch_mode": "attach-native+oncreate-native+libcompatible-watchdog-entry-return0",
        "bridge_variant": "basic", "nsc": "narrow-private-hosts",
        "static_checks": ["zip", "zipalign", "aapt2", "nsc", "apksigner"],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock-apk", type=Path)
    parser.add_argument("--output-apk", type=Path)
    parser.add_argument("--target-package")
    parser.add_argument("--equal-package")
    parser.add_argument("--app-name")
    parser.add_argument("--private-domain", action="append", dest="private_domains")
    parser.add_argument("--cleartext-domain", action="append", dest="cleartext_domains")
    parser.add_argument("--keystore", type=Path)
    parser.add_argument("--ks-alias")
    parser.add_argument("--ks-pass", help="discouraged; prefer NANAON_KS_PASS")
    parser.add_argument("--build-tools", type=Path)
    parser.add_argument("--apktool-jar", type=Path)
    parser.add_argument("--tmp-root", type=Path)
    parser.add_argument("--keep-work", action="store_true")
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    dotenv = load_dotenv(VERSION_ROOT / ".env")
    stock = resolve_argument_path(args.stock_apk, env_value(dotenv, "NANAON_STOCK_APK"), DEFAULT_STOCK)
    output = resolve_argument_path(args.output_apk, env_value(dotenv, "NANAON_OUTPUT_APK"), DEFAULT_OUTPUT)
    target = args.target_package or env_value(dotenv, "NANAON_TARGET_PACKAGE") or DEFAULT_TARGET
    equal = args.equal_package or env_value(dotenv, "NANAON_EQUAL_PACKAGE") or DEFAULT_EQUAL
    app_name = args.app_name if args.app_name is not None else env_value(dotenv, "NANAON_APP_NAME")
    private_domains = args.private_domains
    if private_domains is None:
        private_domains = [item.strip() for item in
                           (env_value(dotenv, "NANAON_PRIVATE_DOMAINS") or
                            ",".join(DEFAULT_DOMAINS)).split(",") if item.strip()]
    cleartext = args.cleartext_domains
    if cleartext is None:
        raw = env_value(dotenv, "NANAON_CLEARTEXT_DOMAINS")
        cleartext = [item.strip() for item in raw.split(",") if item.strip()] if raw else None
    keystore = resolve_argument_path(args.keystore, env_value(dotenv, "NANAON_KEYSTORE"), DEFAULT_KEYSTORE)
    alias = args.ks_alias or env_value(dotenv, "NANAON_KS_ALIAS") or "test"
    password = args.ks_pass or os.environ.get("NANAON_KS_PASS") or dotenv.get("NANAON_KS_PASS")
    build_tools = toolchain.resolve_build_tools(
        resolve_argument_path(args.build_tools, env_value(dotenv, "NANAON_BUILD_TOOLS"), None)
    )
    apktool_jar = toolchain.resolve_apktool_jar(
        resolve_argument_path(args.apktool_jar, env_value(dotenv, "NANAON_APKTOOL_JAR"), None)
    )
    tmp_root = resolve_argument_path(
        args.tmp_root, env_value(dotenv, "NANAON_TMP_ROOT"), DEFAULT_TMP,
    )

    for name, value in (("target package", target), ("equal package", equal)):
        if not PACKAGE_RE.fullmatch(value):
            raise SystemExit(f"invalid {name}: {value!r}")
    if not stock.is_file():
        raise SystemExit(f"stock APK missing: {stock}")
    if not keystore.is_file():
        raise SystemExit(f"keystore missing: {keystore}")
    if not password:
        raise SystemExit("provide NANAON_KS_PASS or --ks-pass")
    if output == stock:
        raise SystemExit("output APK must be different from the stock input")
    if output.exists() and not args.force:
        raise SystemExit(f"output exists (use --force): {output}")
    if sha256_file(stock).lower() != "692247de9daec19fcc7bb28559215069b5093197326170f75cc5a3dc6a199c89":
        raise SystemExit("stock APK hash does not match the recorded Nanaon 2.4.0 input")

    tmp_root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="apk-build-", dir=str(tmp_root)))
    baseline_dir = work / "baseline"
    static_apk = work / "static.signed.apk"
    bridge_dir = work / "bridge"
    child_env = os.environ.copy()
    child_env["NANAON_KS_PASS"] = password
    try:
        baseline_cmd = [sys.executable, BASELINE, "--stock-apk", stock,
                        "--out-dir", baseline_dir, "--build-tools", build_tools,
                        "--keystore", keystore, "--ks-alias", alias,
                        "--apktool-jar", apktool_jar, "--equal-package", equal,
                        "--target-package", target, "--force"]
        if app_name is not None:
            baseline_cmd += ["--app-name", app_name]
        run(baseline_cmd, env=child_env)
        target_baseline = baseline_dir / f"nanaon-2.4.0-{target}.signed.apk"
        static_cmd = [sys.executable, STATIC, "--stock-apk", target_baseline,
                      "--out", static_apk, "--build-tools", build_tools,
                      "--keystore", keystore, "--ks-alias", alias,
                      "--expected-package", target,
                      "--patch-mode", "attach-native+oncreate-native+libcompatible-watchdog-entry-return0",
                      "--force"]
        for domain in private_domains:
            static_cmd += ["--private-domain", domain]
        if cleartext:
            for domain in cleartext:
                static_cmd += ["--cleartext-domain", domain]
        run(static_cmd, env=child_env)
        output.parent.mkdir(parents=True, exist_ok=True)
        bridge_cmd = [sys.executable, BRIDGE, "--source-apk", static_apk,
                      "--output-apk", output, "--build-tools", build_tools,
                      "--keystore", keystore, "--ks-alias", alias,
                      "--work-dir", bridge_dir, "--variant", "basic", "--force"]
        run(bridge_cmd, env=child_env)
        manifest = verify_output(output, build_tools, target, app_name, private_domains)
        manifest["private_domains"] = private_domains
        print("final-manifest=" + json.dumps(manifest, ensure_ascii=False))
        if args.keep_work:
            print(f"work-dir={work}")
    finally:
        if not args.keep_work:
            shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
