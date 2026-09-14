#!/usr/bin/env python3
"""Build an APK candidate with a synthetic AppGuard Unity bridge class.

This is a diagnostic builder for Nanaon 2.4.0.  It does not attempt to emulate
AppGuard.  Instead it adds a tiny ``classesN.dex`` containing
``com.inca.security.AppGuard.AppGuardClientUnityBridge`` so the next runtime
failure can reveal the exact Unity/JNI method name and signature expected by
the IL2CPP side.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path


SIGNATURE_PREFIX = "META-INF/"


EMPTY_BRIDGE_SOURCE = """\
package com.inca.security.AppGuard;

public final class AppGuardClientUnityBridge {
    public AppGuardClientUnityBridge() {
    }
}
"""

BASIC_BRIDGE_SOURCE = """\
package com.inca.security.AppGuard;

import java.util.HashMap;
import java.util.Map;

public final class AppGuardClientUnityBridge {
    private static final AppGuardClientUnityBridge INSTANCE =
            new AppGuardClientUnityBridge();

    private final Map<String, String> values = new HashMap<String, String>();

    public AppGuardClientUnityBridge() {
    }

    public static Object get() {
        return INSTANCE;
    }

    public static Object create() {
        return INSTANCE;
    }

    public static Object getInstance() {
        return INSTANCE;
    }

    public static Object getClient() {
        return INSTANCE;
    }

    public static Object getAppGuardClient() {
        return INSTANCE;
    }

    public static Object getAppGuardClientUnityBridge() {
        return INSTANCE;
    }

    public static Object getBridge() {
        return INSTANCE;
    }

    public void setUserId(String value) {
        values.put("userId", value);
    }

    public void setUserID(String value) {
        setUserId(value);
    }

    public void setUuid(String value) {
        values.put("uuid", value);
    }

    public void setUUID(String value) {
        setUuid(value);
    }

    public void setToken(String value) {
        values.put("token", value);
    }

    public void setDeviceId(String value) {
        values.put("deviceId", value);
    }

    public void setAppVersion(String value) {
        values.put("appVersion", value);
    }

    public void setServerUrl(String value) {
        values.put("serverUrl", value);
    }

    public void set(String key, String value) {
        values.put(key, value);
    }

    public String getUserId() {
        return values.get("userId");
    }

    public String getUuid() {
        return values.get("uuid");
    }

    public String getToken() {
        return values.get("token");
    }

    public boolean isRooting() {
        return false;
    }

    public boolean isRooted() {
        return false;
    }

    public boolean isEmulator() {
        return false;
    }

    public boolean isCheatDetected() {
        return false;
    }

    public int getStatus() {
        return 0;
    }

    public void start() {
    }

    public void stop() {
    }

    public void pause() {
    }

    public void resume() {
    }
}
"""

# Endpoint-rewrite keeps this bridge separate so the validated dns-user-ca
# build does not attempt to load an optional native resolver library.
ENDPOINT_DNS_BRIDGE_SOURCE = """\
package com.inca.security.AppGuard;

import java.util.HashMap;
import java.util.Map;

public final class AppGuardClientUnityBridge {
    private static final AppGuardClientUnityBridge INSTANCE =
            new AppGuardClientUnityBridge();

    static {
        System.loadLibrary("nanaon_endpoint");
    }

    private final Map<String, String> values = new HashMap<String, String>();

    public AppGuardClientUnityBridge() { }
    public static Object get() { return INSTANCE; }
    public static Object create() { return INSTANCE; }
    public static Object getInstance() { return INSTANCE; }
    public static Object getClient() { return INSTANCE; }
    public static Object getAppGuardClient() { return INSTANCE; }
    public static Object getAppGuardClientUnityBridge() { return INSTANCE; }
    public static Object getBridge() { return INSTANCE; }
    public void setUserId(String value) { values.put("userId", value); }
    public void setUserID(String value) { setUserId(value); }
    public void setUuid(String value) { values.put("uuid", value); }
    public void setUUID(String value) { setUuid(value); }
    public void setToken(String value) { values.put("token", value); }
    public void setDeviceId(String value) { values.put("deviceId", value); }
    public void setAppVersion(String value) { values.put("appVersion", value); }
    public void setServerUrl(String value) { values.put("serverUrl", value); }
    public void set(String key, String value) { values.put(key, value); }
    public String getUserId() { return values.get("userId"); }
    public String getUuid() { return values.get("uuid"); }
    public String getToken() { return values.get("token"); }
    public boolean isRooting() { return false; }
    public boolean isRooted() { return false; }
    public boolean isEmulator() { return false; }
    public boolean isCheatDetected() { return false; }
    public int getStatus() { return 0; }
    public void start() { }
    public void stop() { }
    public void pause() { }
    public void resume() { }
}
"""

# The v2 endpoint experiment adds a manifest ContentProvider. Android creates
# providers after Application.attachBaseContext but before Application.onCreate,
# which is early enough to test whether a resolver loaded before Unity can see
# the first bootstrap lookup. Keep this class separate from the validated
# ``basic`` bridge so existing v43/v44 payloads remain byte-for-byte unchanged.
ENDPOINT_DNS_EARLY_PROVIDER_SOURCE = """\
package com.inca.security.AppGuard;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.CancellationSignal;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import java.io.FileNotFoundException;

public final class NanaonEndpointProvider extends ContentProvider {
    private static final String TAG = "NanaonEndpoint";

    @Override
    public boolean onCreate() {
        try {
            System.loadLibrary("nanaon_endpoint");
            Log.i(TAG, "early provider loaded resolver");
        } catch (Throwable error) {
            // Keep provider installation from aborting the process; the log
            // makes a linker/class-loader failure explicit in the experiment.
            Log.e(TAG, "early provider failed to load resolver", error);
        }
        return true;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {
        return null;
    }

    @Override
    public String getType(Uri uri) {
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection,
                      String[] selectionArgs) {
        return 0;
    }
}
"""

BRIDGE_SOURCES = {
    "empty": EMPTY_BRIDGE_SOURCE,
    "basic": BASIC_BRIDGE_SOURCE,
    "endpoint-dns": ENDPOINT_DNS_BRIDGE_SOURCE,
    "endpoint-dns-early": ENDPOINT_DNS_BRIDGE_SOURCE,
}


def run(argv: list[Path | str], *, cwd: Path | None = None) -> None:
    printable: list[str] = []
    for arg in argv:
        text = str(arg)
        if text.startswith("pass:"):
            text = "pass:<redacted>"
        printable.append(text)
    print("+ " + " ".join(printable))
    subprocess.run([str(arg) for arg in argv], cwd=cwd, check=True)


def find_tool(build_tools: Path, name: str) -> Path:
    suffixes = (".bat", ".cmd", ".exe", "")
    for suffix in suffixes:
        candidate = build_tools / f"{name}{suffix}"
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"{name} not found under {build_tools}")


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


def next_dex_name(entries: set[str]) -> str:
    index = 2
    while f"classes{index}.dex" in entries:
        index += 1
    return f"classes{index}.dex"


def build_stub_dex(build_tools: Path, javac: Path, work_dir: Path,
                   variant: str, android_jar: Path | None = None) -> Path:
    src_dir = work_dir / "src" / "com" / "inca" / "security" / "AppGuard"
    classes_dir = work_dir / "classes"
    dex_dir = work_dir / "dex"
    src_dir.mkdir(parents=True, exist_ok=True)
    classes_dir.mkdir(parents=True, exist_ok=True)
    dex_dir.mkdir(parents=True, exist_ok=True)

    java_file = src_dir / "AppGuardClientUnityBridge.java"
    java_file.write_text(BRIDGE_SOURCES[variant], encoding="utf-8", newline="\n")
    source_files = [java_file]
    if variant == "endpoint-dns-early":
        provider_file = src_dir / "NanaonEndpointProvider.java"
        provider_file.write_text(
            ENDPOINT_DNS_EARLY_PROVIDER_SOURCE, encoding="utf-8", newline="\n"
        )
        source_files.append(provider_file)

    javac_command = [
        javac, "-source", "8", "-target", "8", "-g:none",
    ]
    if android_jar is not None:
        if not android_jar.is_file():
            raise FileNotFoundError(f"android.jar not found: {android_jar}")
        javac_command += ["-classpath", android_jar]
    javac_command += ["-d", classes_dir, *source_files]
    run(javac_command)

    d8 = find_tool(build_tools, "d8")
    class_files = sorted(classes_dir.rglob("*.class"))
    if not class_files:
        raise RuntimeError("javac did not produce any .class files")
    d8_command = [d8, "--min-api", "21"]
    if android_jar is not None:
        d8_command += ["--lib", android_jar]
    d8_command += ["--output", dex_dir, *class_files]
    run(d8_command)
    dex = dex_dir / "classes.dex"
    if not dex.is_file():
        raise RuntimeError(f"d8 did not produce {dex}")
    return dex


def inject_stub_dex(source_apk: Path, unsigned_apk: Path, stub_dex: Path) -> str:
    with zipfile.ZipFile(source_apk, "r") as zin:
        names = {item.filename for item in zin.infolist()}
        added_name = next_dex_name(names)
        with zipfile.ZipFile(unsigned_apk, "w") as zout:
            seen: set[str] = set()
            for item in zin.infolist():
                if item.filename in seen:
                    raise ValueError(f"duplicate source ZIP entry: {item.filename}")
                seen.add(item.filename)
                if item.filename.upper().startswith(SIGNATURE_PREFIX):
                    continue
                zout.writestr(copy_zip_info(item), zin.read(item.filename))
            dex_info = zipfile.ZipInfo(added_name)
            dex_info.compress_type = zipfile.ZIP_DEFLATED
            zout.writestr(dex_info, stub_dex.read_bytes())
    return added_name


def align_sign_verify(unsigned_apk: Path, output_apk: Path, build_tools: Path,
                      keystore: Path, alias: str, password: str,
                      work_dir: Path) -> None:
    zipalign = find_tool(build_tools, "zipalign")
    apksigner = find_tool(build_tools, "apksigner")
    aligned = work_dir / f"{output_apk.stem}.aligned.apk"
    output_apk.unlink(missing_ok=True)
    run([zipalign, "-f", "-P", "16", "4", unsigned_apk, aligned])
    run([
        apksigner, "sign",
        "--v1-signing-enabled", "true",
        "--v2-signing-enabled", "true",
        "--v3-signing-enabled", "true",
        "--v4-signing-enabled", "false",
        "--ks", keystore,
        "--ks-key-alias", alias,
        "--ks-pass", f"pass:{password}",
        "--key-pass", f"pass:{password}",
        "--out", output_apk,
        aligned,
    ])
    run([zipalign, "-c", "-P", "16", "4", output_apk])
    run([apksigner, "verify", "--verbose", "--print-certs", output_apk])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-apk", type=Path, required=True)
    parser.add_argument("--output-apk", type=Path, required=True)
    parser.add_argument("--build-tools", type=Path, required=True)
    parser.add_argument("--keystore", type=Path, required=True)
    parser.add_argument("--ks-alias", default="test")
    parser.add_argument("--ks-pass", default=os.environ.get("NANAON_KS_PASS"))
    parser.add_argument("--javac", type=Path, default=shutil.which("javac"))
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--variant", choices=sorted(BRIDGE_SOURCES), default="empty")
    parser.add_argument(
        "--android-jar", type=Path,
        help="Android platform android.jar (required for endpoint-dns-early)",
    )
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    if not args.ks_pass:
        raise SystemExit("keystore password missing; pass --ks-pass or set NANAON_KS_PASS")
    if not args.javac:
        raise SystemExit("javac not found")

    source_apk = args.source_apk.resolve()
    output_apk = args.output_apk.resolve()
    build_tools = args.build_tools.resolve()
    keystore = args.keystore.resolve()
    work_dir = args.work_dir.resolve()

    if output_apk.exists() and not args.force:
        raise SystemExit(f"output exists; use --force: {output_apk}")
    if work_dir.exists() and args.force:
        shutil.rmtree(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    output_apk.parent.mkdir(parents=True, exist_ok=True)

    android_jar = args.android_jar.resolve() if args.android_jar else None
    if args.variant == "endpoint-dns-early" and android_jar is None:
        raise SystemExit("--android-jar is required for endpoint-dns-early")
    stub_dex = build_stub_dex(
        build_tools, args.javac.resolve(), work_dir, args.variant, android_jar
    )
    unsigned_apk = work_dir / f"{output_apk.stem}.unsigned.apk"
    added_name = inject_stub_dex(source_apk, unsigned_apk, stub_dex)
    align_sign_verify(
        unsigned_apk, output_apk, build_tools, keystore,
        args.ks_alias, args.ks_pass, work_dir,
    )
    print(f"added {added_name} with {args.variant} AppGuardClientUnityBridge stub")
    print(f"output: {output_apk}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
