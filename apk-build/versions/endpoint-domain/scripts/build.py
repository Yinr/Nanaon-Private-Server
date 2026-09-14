#!/usr/bin/env python3
"""Build the public-domain endpoint Nanaon APK candidate.

The pipeline starts with the reproducible base payload produced by the
vendored ``scripts/base_build.py`` (originally the ``dns-user-ca`` builder; or an
explicit base APK), patches only the Java ``UnityWebRequest`` URL consumer,
adds a small helper DEX, then aligns, signs, and verifies the result.  The
default policy trusts system CAs only; ``--allow-user-ca`` is an explicit
diagnostic override.  It never installs an APK or changes a device/network
setting.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import zipfile
from pathlib import Path

import toolchain


VERSION_ROOT = Path(__file__).resolve().parents[1]
BUILD_ROOT = VERSION_ROOT.parents[1]
PROJECT_ROOT = BUILD_ROOT.parents[2]
SERVER_ROOT = BUILD_ROOT.parent
APKTOOL_ROOT = SERVER_ROOT / "apktool"
DNS_BUILDER = VERSION_ROOT / "scripts" / "base_build.py"
PATCHER = VERSION_ROOT / "scripts" / "patch_unity_web_request.py"
NSC_WRITER = APKTOOL_ROOT / "build_patched_apk.py"
DEFAULT_STOCK = PROJECT_ROOT / "tools" / "apk-mod" / "work" / "original.apk"
DEFAULT_OUTPUT = PROJECT_ROOT / "tools" / "apk-mod" / "out" / (
    "nanaon-2.4.0-com.aniplex.nananiji.ps227.endpoint-domain.signed.apk"
)
DEFAULT_KEYSTORE = PROJECT_ROOT / "tools" / "apk-mod" / "keys" / "test.keystore"
DEFAULT_TMP = PROJECT_ROOT / "tools" / "_tmp"
DEFAULT_TARGET = "com.aniplex.nananiji.ps227"
DEFAULT_APP_NAME = "ナナオン 227"
DEFAULT_API_HOST = "nanaon.0000227.xyz"
DEFAULT_ASSET_HOST = "nanaon.0000227.xyz"
DEFAULT_ORIGINAL_API = "227.hand.co.jp"
DEFAULT_ORIGINAL_ASSET = "prd-asset.227.hand.co.jp"
EXPECTED_STOCK_SHA256 = (
    "692247de9daec19fcc7bb28559215069b5093197326170f75cc5a3dc6a199c89"
)
NSC_ENTRY = "res/xml/network_security_config.xml"
HELPER_ENTRY = "classes3.dex"
HELPER_DESCRIPTOR = b"com/nanaon/endpoint/EndpointRewrite"
CLASS_DESCRIPTOR = b"com/unity3d/player/UnityWebRequest"
PACKAGE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")
HOST_RE = re.compile(
    r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


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
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        values[key] = value
    return values


def env_value(dotenv: dict[str, str], key: str) -> str | None:
    return os.environ.get(key) or dotenv.get(key)


def resolve_version_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (VERSION_ROOT / path).resolve()


def resolve_arg(cli: Path | None, text: str | None, default: Path) -> Path:
    if cli is not None:
        return cli.resolve()
    if text:
        return resolve_version_path(text)
    return default.resolve()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def find_tool(build_tools: Path, name: str) -> Path:
    for suffix in (".exe", ".bat", ".cmd", ""):
        candidate = build_tools / f"{name}{suffix}"
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"{name} not found under {build_tools}")


def run(command: list[str | Path], *, env: dict[str, str] | None = None,
        capture: bool = False) -> str:
    shown = ["pass:<redacted>" if str(item).startswith("pass:") else str(item)
             for item in command]
    print("+", " ".join(shown))
    result = subprocess.run(
        [str(item) for item in command], check=False, env=env,
        text=True, encoding="utf-8", errors="replace", capture_output=capture,
    )
    if result.returncode:
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        raise RuntimeError(f"command failed ({result.returncode}): {command[0]}")
    return result.stdout if capture else ""


def parse_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"invalid boolean value: {value!r}")


def validate_host(value: str, label: str) -> str:
    value = value.strip().rstrip(".")
    if not value or "/" in value or "://" in value or ":" in value:
        raise ValueError(f"{label} must be a host name or IPv4 address: {value!r}")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if not HOST_RE.fullmatch(value):
            raise ValueError(f"invalid {label}: {value!r}")
        return value.lower()


def parse_domains(raw: str | None) -> list[str]:
    values = [item.strip() for item in (raw or "").split(",") if item.strip()]
    result: list[str] = []
    for value in values:
        normalized = validate_host(value, "private domain")
        if normalized not in result:
            result.append(normalized)
    return result


def copy_zip_info(item: zipfile.ZipInfo) -> zipfile.ZipInfo:
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
    return clone


def import_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import helper: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def java_quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def helper_source(api_target: str, asset_target: str,
                  use_original_verifier: bool) -> str:
    # Values are validated before being embedded; JSON quoting also escapes
    # any characters that could terminate a Java string literal.
    return textwrap.dedent(
        f'''\
        package com.nanaon.endpoint;

        import android.util.Log;
        import java.net.URL;
        import java.util.Locale;
        import javax.net.ssl.HostnameVerifier;
        import javax.net.ssl.HttpsURLConnection;
        import javax.net.ssl.SSLSession;

        /** Exact authority rewrite used by the endpoint-domain candidate. */
        public final class EndpointRewrite {{
            private static final String TAG = "NanaonEndpointDomain";
            private static final String API_ORIGINAL = "{DEFAULT_ORIGINAL_API}";
            private static final String ASSET_ORIGINAL = "{DEFAULT_ORIGINAL_ASSET}";
            private static final String API_TARGET = {java_quote(api_target)};
            private static final String ASSET_TARGET = {java_quote(asset_target)};
            private static final boolean USE_ORIGINAL_VERIFIER =
                    {str(use_original_verifier).lower()};

            private EndpointRewrite() {{}}

            public static String originalHost(String url) {{
                if (matches(url, API_ORIGINAL)) return API_ORIGINAL;
                if (matches(url, ASSET_ORIGINAL)) return ASSET_ORIGINAL;
                return null;
            }}

            public static String rewrite(String url) {{
                if (url == null) return null;
                String rewritten = replaceAuthority(url, API_ORIGINAL, API_TARGET);
                if (rewritten.equals(url))
                    rewritten = replaceAuthority(url, ASSET_ORIGINAL, ASSET_TARGET);
                if (!rewritten.equals(url))
                    Log.i(TAG, "rewrote business endpoint authority");
                return rewritten;
            }}

            public static HostnameVerifier hostnameVerifier(String originalHost) {{
                if (!USE_ORIGINAL_VERIFIER || originalHost == null)
                    return HttpsURLConnection.getDefaultHostnameVerifier();
                return new OriginalHostVerifier(originalHost);
            }}

            private static boolean matches(String url, String original) {{
                return authorityHost(url, original) != null;
            }}

            private static String replaceAuthority(String url, String original,
                                                   String target) {{
                int scheme = url.indexOf("://");
                if (scheme < 0) return url;
                int start = scheme + 3;
                int end = url.length();
                for (int i = start; i < url.length(); i++) {{
                    char c = url.charAt(i);
                    if (c == '/' || c == '?' || c == '#') {{ end = i; break; }}
                }}
                String authority = url.substring(start, end);
                int at = authority.lastIndexOf('@');
                String prefix = at >= 0 ? authority.substring(0, at + 1) : "";
                String hostPort = at >= 0 ? authority.substring(at + 1) : authority;
                String host = hostPort;
                String port = "";
                int colon = hostPort.lastIndexOf(':');
                if (colon > 0 && hostPort.substring(colon + 1).matches("[0-9]+")) {{
                    host = hostPort.substring(0, colon);
                    port = hostPort.substring(colon);
                }}
                if (!host.equalsIgnoreCase(original)) return url;
                String replacement = prefix + target + port;
                return url.substring(0, start) + replacement + url.substring(end);
            }}

            private static String authorityHost(String url, String expected) {{
                if (url == null) return null;
                int scheme = url.indexOf("://");
                if (scheme < 0) return null;
                int start = scheme + 3;
                int end = url.length();
                for (int i = start; i < url.length(); i++) {{
                    char c = url.charAt(i);
                    if (c == '/' || c == '?' || c == '#') {{ end = i; break; }}
                }}
                String authority = url.substring(start, end);
                int at = authority.lastIndexOf('@');
                String hostPort = at >= 0 ? authority.substring(at + 1) : authority;
                int colon = hostPort.lastIndexOf(':');
                String host = colon > 0 && hostPort.substring(colon + 1).matches("[0-9]+")
                        ? hostPort.substring(0, colon) : hostPort;
                return host.equalsIgnoreCase(expected) ? host : null;
            }}

            private static final class OriginalHostVerifier implements HostnameVerifier {{
                private final String originalHost;
                OriginalHostVerifier(String originalHost) {{ this.originalHost = originalHost; }}
                @Override public boolean verify(String ignored, SSLSession session) {{
                    return HttpsURLConnection.getDefaultHostnameVerifier()
                            .verify(originalHost, session);
                }}
            }}
        }}
        '''
    )


def compile_helper(source: str, work: Path, build_tools: Path,
                   android_jar: Path, javac: Path | None) -> Path:
    if not android_jar.is_file():
        raise FileNotFoundError(f"android.jar not found: {android_jar}")
    javac_path = javac or (Path(shutil.which("javac")) if shutil.which("javac") else None)
    if javac_path is None or not javac_path.is_file():
        raise FileNotFoundError("javac not found; pass --javac")
    src = work / "helper-src" / "com" / "nanaon" / "endpoint" / "EndpointRewrite.java"
    classes = work / "helper-classes"
    dex_dir = work / "helper-dex"
    src.parent.mkdir(parents=True, exist_ok=True)
    classes.mkdir(parents=True, exist_ok=True)
    dex_dir.mkdir(parents=True, exist_ok=True)
    src.write_text(source, encoding="utf-8", newline="\n")
    run([
        javac_path, "-source", "8", "-target", "8", "-g:none",
        "-classpath", android_jar, "-d", classes, src,
    ])
    d8 = find_tool(build_tools, "d8")
    class_files = sorted(classes.rglob("*.class"))
    if not class_files:
        raise RuntimeError("javac produced no helper class")
    run([d8, "--min-api", "21", "--lib", android_jar,
         "--output", dex_dir, *class_files])
    dex = dex_dir / "classes.dex"
    if not dex.is_file() or not dex.read_bytes().startswith(b"dex\n"):
        raise RuntimeError("d8 did not produce a valid helper DEX")
    return dex


def build_base(stock: Path, output: Path, target: str, app_name: str,
               private_domains: list[str], keystore: Path, alias: str,
               password: str, build_tools: Path, apktool_jar: Path,
               work: Path) -> None:
    if not DNS_BUILDER.is_file():
        raise FileNotFoundError(f"validated base builder missing: {DNS_BUILDER}")
    env = os.environ.copy()
    env["NANAON_KS_PASS"] = password
    command: list[str | Path] = [
        sys.executable, DNS_BUILDER,
        "--stock-apk", stock,
        "--output-apk", output,
        "--target-package", target,
        "--app-name", app_name,
        "--keystore", keystore,
        "--ks-alias", alias,
        "--build-tools", build_tools,
        "--apktool-jar", apktool_jar,
        "--tmp-root", work / "base-tmp",
        "--force",
    ]
    for domain in private_domains:
        command += ["--private-domain", domain]
    run(command, env=env)


def ensure_nsc(source: Path, output: Path, private_domains: list[str],
               allow_user_ca: bool) -> None:
    """Write the scoped trust policy for the embedded endpoint hosts.

    This is also applied when ``--base-apk`` points at an older v44 artifact,
    whose NSC lists a different set of hosts. User trust is opt-in and limited
    to ``private_domains``; the default is system CA only.
    """
    writer = import_module(NSC_WRITER, "nanaon_endpoint_domain_nsc_writer")
    xml = writer.build_nsc(
        tuple(private_domains), tuple(writer.CLEARTEXT_DOMAINS),
        allow_user_ca=allow_user_ca,
    )
    with zipfile.ZipFile(source, "r") as zin, zipfile.ZipFile(output, "w", allowZip64=True) as zout:
        seen: set[str] = set()
        replaced = False
        for item in zin.infolist():
            if item.filename in seen:
                raise ValueError(f"duplicate source ZIP entry: {item.filename}")
            seen.add(item.filename)
            payload = xml if item.filename == NSC_ENTRY else zin.read(item.filename)
            replaced = replaced or item.filename == NSC_ENTRY
            zout.writestr(copy_zip_info(item), payload)
    if not replaced:
        raise RuntimeError(f"base APK has no {NSC_ENTRY} entry")


def decode_patch(base_apk: Path, work: Path, apktool_jar: Path) -> Path:
    decoded = work / "decoded"
    java_tmp = work / "java-tmp"
    java_tmp.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["TMP"] = str(java_tmp)
    env["TEMP"] = str(java_tmp)
    run(["java", f"-Djava.io.tmpdir={java_tmp}", "-jar", apktool_jar,
         "d", "-f", "-r", "--no-assets", "-o", decoded, base_apk], env=env)
    patcher = import_module(PATCHER, "nanaon_endpoint_direct_smali_patcher")
    patcher.patch_decoded(decoded)
    # Preserve the already verified bridge DEX byte-for-byte. Apktool's
    # baksmali/smali round-trip changes classes2.dex metadata even when its
    # semantics are unchanged, so it is deliberately excluded from assembly.
    saved = work / "saved-secondary-smali"
    saved.mkdir(parents=True, exist_ok=True)
    for child in sorted(decoded.iterdir()):
        if re.fullmatch(r"smali_classes[2-9][0-9]*", child.name):
            shutil.move(str(child), saved / child.name)
    run(["java", f"-Djava.io.tmpdir={java_tmp}", "-jar", apktool_jar,
         "b", "-f", "--no-apk", decoded], env=env)
    rebuilt = decoded / "build" / "apk" / "classes.dex"
    if not rebuilt.is_file() or not rebuilt.read_bytes().startswith(b"dex\n"):
        raise RuntimeError(f"Apktool did not produce rebuilt classes.dex: {rebuilt}")
    if CLASS_DESCRIPTOR not in rebuilt.read_bytes():
        raise RuntimeError("rebuilt classes.dex lacks UnityWebRequest descriptor")
    return rebuilt


def next_dex_name(names: set[str]) -> str:
    index = 2
    while f"classes{index}.dex" in names:
        index += 1
    return f"classes{index}.dex"


def inject(base_apk: Path, rebuilt_classes: Path, helper_dex: Path,
           output: Path) -> str:
    with zipfile.ZipFile(base_apk, "r") as zin:
        names = {item.filename for item in zin.infolist()}
        helper_name = next_dex_name(names)
        if helper_name != HELPER_ENTRY:
            # The verifier accepts the actual next slot; this guard only keeps
            # the expected current v44 layout explicit in logs.
            print(f"helper-entry={helper_name}")
        with zipfile.ZipFile(output, "w", allowZip64=True) as zout:
            seen: set[str] = set()
            for item in zin.infolist():
                if item.filename in seen:
                    raise ValueError(f"duplicate source ZIP entry: {item.filename}")
                seen.add(item.filename)
                if item.filename.upper().startswith("META-INF/"):
                    continue
                payload = (rebuilt_classes.read_bytes()
                           if item.filename == "classes.dex"
                           else zin.read(item.filename))
                zout.writestr(copy_zip_info(item), payload)
            dex_info = zipfile.ZipInfo(helper_name)
            dex_info.compress_type = zipfile.ZIP_DEFLATED
            zout.writestr(dex_info, helper_dex.read_bytes())
    return helper_name


def align_sign(unsigned: Path, output: Path, build_tools: Path,
               keystore: Path, alias: str, password: str, work: Path) -> None:
    zipalign = find_tool(build_tools, "zipalign")
    apksigner = find_tool(build_tools, "apksigner")
    aligned = work / "aligned.apk"
    run([zipalign, "-f", "-P", "16", "4", unsigned, aligned])
    run([
        apksigner, "sign", "--v1-signing-enabled", "true",
        "--v2-signing-enabled", "true", "--v3-signing-enabled", "true",
        "--v4-signing-enabled", "false", "--ks", keystore,
        "--ks-key-alias", alias, "--ks-pass", f"pass:{password}",
        "--key-pass", f"pass:{password}", "--out", output, aligned,
    ])
    run([zipalign, "-c", "-P", "16", "4", output])
    run([apksigner, "verify", "--verbose", "--print-certs", output])


def verify_output(path: Path, build_tools: Path, target: str,
                  app_name: str, private_domains: list[str],
                  helper_name: str, allow_user_ca: bool) -> dict[str, object]:
    with zipfile.ZipFile(path, "r") as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise RuntimeError("final APK contains duplicate ZIP entries")
        if archive.testzip() is not None:
            raise RuntimeError("final APK ZIP integrity check failed")
        if helper_name not in names:
            raise RuntimeError(f"missing helper DEX {helper_name}")
        if HELPER_DESCRIPTOR not in archive.read(helper_name):
            raise RuntimeError("helper DEX descriptor is missing")
        if CLASS_DESCRIPTOR not in archive.read("classes.dex"):
            raise RuntimeError("patched classes.dex descriptor is missing")
        signature_entries = [
            name for name in names
            if name.upper().startswith("META-INF/")
            and name.upper().endswith(("MANIFEST.MF", ".SF", ".RSA", ".DSA", ".EC"))
        ]
        if not signature_entries:
            raise RuntimeError("signed APK has no v1 signature entries")
    aapt2 = find_tool(build_tools, "aapt2")
    badging = run([aapt2, "dump", "badging", path], capture=True)
    for marker in (
        f"package: name='{target}'",
        "versionCode='5465'",
        "versionName='2.4.0'",
        f"application-label:'{app_name}'",
    ):
        if marker not in badging:
            raise RuntimeError(f"aapt2 badging missing {marker!r}")
    nsc = run([aapt2, "dump", "xmltree", "--file", NSC_ENTRY, path], capture=True)
    for domain in private_domains:
        if f"'{domain}'" not in nsc:
            raise RuntimeError(f"NSC missing private host {domain!r}")
    if 'A: src="system"' not in nsc:
        raise RuntimeError("NSC does not retain the system trust anchor")
    has_user = 'A: src="user"' in nsc
    if has_user != allow_user_ca:
        mode = "enabled" if allow_user_ca else "disabled"
        raise RuntimeError(f"NSC user-CA state is {has_user}, expected {mode}")
    zipalign = find_tool(build_tools, "zipalign")
    run([zipalign, "-c", "-P", "16", "4", path])
    apksigner = find_tool(build_tools, "apksigner")
    run([apksigner, "verify", "--verbose", "--print-certs", path])
    return {
        "path": str(path),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        "package": target,
        "app_name": app_name,
        "api_target_host": None,
        "asset_target_host": None,
        "helper_dex": helper_name,
        "patch_mode": "v44-base+UnityWebRequest-constructor-authority-rewrite",
        "routing_header": "X-Nanaon-Original-Host",
        "allow_user_ca": allow_user_ca,
        "static_checks": ["zip", "aapt2", "NSC", "zipalign", "apksigner"],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock-apk", type=Path)
    parser.add_argument("--base-apk", type=Path,
                        help="optional already-built v44 payload; default rebuilds it")
    parser.add_argument("--output-apk", type=Path)
    parser.add_argument("--target-package")
    parser.add_argument("--app-name")
    parser.add_argument("--api-host")
    parser.add_argument("--asset-host")
    parser.add_argument("--private-domain", action="append", dest="private_domains")
    parser.add_argument("--use-original-host-verifier", choices=("true", "false"))
    trust_group = parser.add_mutually_exclusive_group()
    trust_group.add_argument("--allow-user-ca", dest="allow_user_ca",
                             action="store_true",
                             help="allow user CA only for embedded endpoint hosts")
    trust_group.add_argument("--system-only", dest="allow_user_ca",
                             action="store_false",
                             help="trust system CA only (default)")
    parser.set_defaults(allow_user_ca=None)
    parser.add_argument("--keystore", type=Path)
    parser.add_argument("--ks-alias")
    parser.add_argument("--ks-pass")
    parser.add_argument("--javac", type=Path)
    parser.add_argument("--build-tools", type=Path)
    parser.add_argument("--apktool-jar", type=Path)
    parser.add_argument("--android-jar", type=Path)
    parser.add_argument("--tmp-root", type=Path)
    parser.add_argument("--keep-work", action="store_true")
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    dotenv = load_dotenv(VERSION_ROOT / ".env")
    stock = resolve_arg(args.stock_apk, env_value(dotenv, "NANAON_STOCK_APK"), DEFAULT_STOCK)
    base_text = env_value(dotenv, "NANAON_BASE_APK")
    base_apk = resolve_arg(args.base_apk, base_text, Path("")) if (args.base_apk or base_text) else None
    output = resolve_arg(args.output_apk, env_value(dotenv, "NANAON_OUTPUT_APK"), DEFAULT_OUTPUT)
    target = args.target_package or env_value(dotenv, "NANAON_TARGET_PACKAGE") or DEFAULT_TARGET
    app_name = args.app_name if args.app_name is not None else (env_value(dotenv, "NANAON_APP_NAME") or DEFAULT_APP_NAME)
    api_host = validate_host(args.api_host or env_value(dotenv, "NANAON_ENDPOINT_API_HOST") or DEFAULT_API_HOST, "API endpoint host")
    asset_host = validate_host(args.asset_host or env_value(dotenv, "NANAON_ENDPOINT_ASSET_HOST") or DEFAULT_ASSET_HOST, "asset endpoint host")
    raw_domains = (
        ",".join(args.private_domains)
        if args.private_domains is not None
        else (env_value(dotenv, "NANAON_PRIVATE_DOMAINS") or
              f"{api_host},{asset_host}")
    )
    private_domains = parse_domains(raw_domains)
    for host in (api_host, asset_host):
        if host not in private_domains:
            private_domains.append(host)
    use_verifier_raw = args.use_original_host_verifier or env_value(dotenv, "NANAON_USE_ORIGINAL_HOST_VERIFIER")
    use_original_verifier = parse_bool(use_verifier_raw, False)
    if args.allow_user_ca is not None:
        allow_user_ca = args.allow_user_ca
    else:
        allow_user_ca = parse_bool(env_value(dotenv, "NANAON_ALLOW_USER_CA"), False)
    keystore = resolve_arg(args.keystore, env_value(dotenv, "NANAON_KEYSTORE"), DEFAULT_KEYSTORE)
    alias = args.ks_alias or env_value(dotenv, "NANAON_KS_ALIAS") or "test"
    password = args.ks_pass or os.environ.get("NANAON_KS_PASS") or dotenv.get("NANAON_KS_PASS")
    build_tools = toolchain.resolve_build_tools(
        resolve_arg(args.build_tools, env_value(dotenv, "NANAON_BUILD_TOOLS"), None)
    )
    apktool_jar = toolchain.resolve_apktool_jar(
        resolve_arg(args.apktool_jar, env_value(dotenv, "NANAON_APKTOOL_JAR"), None)
    )
    android_jar = toolchain.resolve_android_jar(
        resolve_arg(args.android_jar, env_value(dotenv, "NANAON_ANDROID_JAR"), None)
    )
    tmp_root = resolve_arg(args.tmp_root, env_value(dotenv, "NANAON_TMP_ROOT"), DEFAULT_TMP)
    if not PACKAGE_RE.fullmatch(target):
        raise SystemExit(f"invalid target package: {target!r}")
    if not app_name:
        raise SystemExit("application name cannot be empty")
    if not password:
        raise SystemExit("provide NANAON_KS_PASS or --ks-pass")
    if not stock.is_file():
        raise SystemExit(f"stock APK missing: {stock}")
    if sha256_file(stock).lower() != EXPECTED_STOCK_SHA256:
        raise SystemExit("stock APK hash does not match recorded Nanaon 2.4.0 input")
    if base_apk is not None and not base_apk.is_file():
        raise SystemExit(f"base APK missing: {base_apk}")
    if not keystore.is_file():
        raise SystemExit(f"keystore missing: {keystore}")
    if output.exists() and not args.force:
        raise SystemExit(f"output exists (use --force): {output}")
    # Never let an endpoint experiment overwrite a known validated artifact.
    if output.name in {
        "nanaon-2.4.0-com.aniplex.nananiji.ps.v43-repro.signed.apk",
        "nanaon-2.4.0-com.aniplex.nananiji.ps.v44-dns-user-ca.final.signed.apk",
    }:
        raise SystemExit("refusing to overwrite a validated v43/v44 artifact")
    tmp_root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="endpoint-domain-build-", dir=str(tmp_root)))
    output.parent.mkdir(parents=True, exist_ok=True)
    child_env = os.environ.copy()
    child_env["NANAON_KS_PASS"] = password
    try:
        base = work / "base.signed.apk"
        if base_apk is None:
            build_base(stock, base, target, app_name, private_domains, keystore,
                       alias, password, build_tools, apktool_jar, work)
        else:
            shutil.copyfile(base_apk, base)
        base_with_nsc = work / "base-with-nsc.apk"
        ensure_nsc(base, base_with_nsc, private_domains, allow_user_ca)
        rebuilt = decode_patch(base_with_nsc, work / "smali", apktool_jar)
        helper = compile_helper(
            helper_source(api_host, asset_host, use_original_verifier),
            work / "helper", build_tools, android_jar, args.javac.resolve() if args.javac else None,
        )
        unsigned = work / "endpoint-domain.unsigned.apk"
        helper_name = inject(base_with_nsc, rebuilt, helper, unsigned)
        align_sign(unsigned, output, build_tools, keystore, alias, password, work)
        manifest = verify_output(output, build_tools, target, app_name,
                                 private_domains, helper_name, allow_user_ca)
        manifest["api_target_host"] = api_host
        manifest["asset_target_host"] = asset_host
        manifest["use_original_host_verifier"] = use_original_verifier
        manifest["allow_user_ca"] = allow_user_ca
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
