#!/usr/bin/env python3
"""One-shot build of the private-server APK.

Patches the stock v2.4.0 APK (networkSecurityConfig trusts user CAs),
zipaligns, signs with apktool/release.keystore, verifies, and copies the
resulting APK plus the CA certificate into www/ for the /downloads page.

Usage:
    python build_apk.py <stock.apk>

Requires the Android build-tools (aapt/zipalign/apksigner) and a JDK.
ANDROID_HOME must point at the SDK, or pass --build-tools.
"""
from __future__ import annotations

import argparse
import datetime
import os
import shutil
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
KEYSTORE = BASE / "release.keystore"
KS_PASS = "nanaon"
WWW = BASE.parent / "www"
SDK_BUILD_TOOLS = [
    Path(os.environ.get("ANDROID_HOME", "")) / "build-tools" / "37.0.0",
    Path(os.environ.get("ANDROID_HOME", "")) / "build-tools" / "34.0.0",
]


def tool(name: str, override: Path | None) -> Path:
    candidates = ([override] if override else []) + SDK_BUILD_TOOLS
    for base in candidates:
        exe = base / name
        if exe.is_file():
            return exe
        win = base / f"{name}.exe"
        if win.is_file():
            return win
        bat = base / f"{name}.bat"
        if bat.is_file():
            return bat
    raise SystemExit(f"build tool not found: {name} (set ANDROID_HOME or --build-tools)")


def run(cmd: list[str]) -> None:
    print("+", " ".join(str(c) for c in cmd))
    result = subprocess.run([str(c) for c in cmd])
    if result.returncode != 0:
        raise SystemExit(f"command failed with exit code {result.returncode}: {cmd[0]}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stock_apk", type=Path)
    parser.add_argument("--build-tools", type=Path, default=None)
    parser.add_argument("--out", type=Path, default=None, help="final signed APK path")
    args = parser.parse_args()

    if not args.stock_apk.is_file():
        raise SystemExit(f"stock APK missing: {args.stock_apk}")

    work = BASE / "work"
    work.mkdir(exist_ok=True)
    stamp = datetime.date.today().isoformat()
    patched = work / "patched.apk"
    aligned = work / "aligned.apk"
    final = args.out or (work / f"nanaon-2.4.0-ps-{stamp}.apk")

    run([sys.executable, BASE / "build_patched_apk.py", args.stock_apk, patched])
    run([tool("zipalign", args.build_tools), "-f", "4", patched, aligned])

    apksigner = tool("apksigner", args.build_tools)
    run([
        apksigner, "sign",
        "--ks", KEYSTORE,
        "--ks-key-alias", "nanaon-ps",
        "--ks-pass", f"pass:{KS_PASS}",
        "--key-pass", f"pass:{KS_PASS}",
        "--out", final,
        aligned,
    ])
    run([apksigner, "verify", final])

    # Publish APK + CA certificate to the downloads page directory.
    cert_src = BASE.parent / "var" / "certs" / "gateway_trust_cert.pem"
    if WWW.exists() or cert_src.is_file():
        WWW.mkdir(parents=True, exist_ok=True)
        shutil.copy2(final, WWW / final.name)
        if cert_src.is_file():
            shutil.copy2(cert_src, WWW / "nanaon-ps-ca.crt")
        print(f"published to {WWW}: {final.name}, nanaon-ps-ca.crt")

    patched.unlink(missing_ok=True)
    aligned.unlink(missing_ok=True)
    print(f"done: {final}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
