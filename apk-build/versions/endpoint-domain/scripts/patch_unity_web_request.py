#!/usr/bin/env python3
"""Patch UnityWebRequest to use the embedded public-domain endpoint helper.

The patch is intentionally textual and version-guarded.  It adds one private
field to retain the original business host, rewrites the URL at construction
time, optionally installs a verifier for legacy certificate deployments, and
adds a private routing header so API/CDN backends can retain the original
service identity.  No broad string
replacement or global TLS hook is used.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path


CLASS_REL = Path("smali/com/unity3d/player/UnityWebRequest.smali")
CLASS_DESC = "Lcom/unity3d/player/UnityWebRequest;"
HELPER_DESC = "Lcom/nanaon/endpoint/EndpointRewrite;"
MARKER = "# NANAON_ENDPOINT_DOMAIN"
CONSTRUCTOR_HEADER = ".method constructor <init>(JLjava/lang/String;Ljava/util/Map;Ljava/lang/String;ZI)V"
RUNSAFE_HEADER = ".method private runSafe()V"


def _method_slice(text: str, header: str) -> tuple[int, int, str]:
    starts = [m.start() for m in re.finditer(r"(?m)^" + re.escape(header) + r"\s*$", text)]
    if len(starts) != 1:
        raise ValueError(f"expected one {header!r}, found {len(starts)}")
    start = starts[0]
    end_match = re.search(r"(?m)^\.end method\s*$", text[start:])
    if end_match is None:
        raise ValueError(f"unterminated method {header!r}")
    end = start + end_match.end()
    return start, end, text[start:end]


def _replace_once(body: str, old: str, new: str, label: str) -> str:
    count = body.count(old)
    if count != 1:
        raise ValueError(f"{label}: expected one anchor, found {count}")
    return body.replace(old, new, 1)


def patch_decoded(decoded_root: Path) -> dict[str, str]:
    path = decoded_root / CLASS_REL
    if not path.is_file():
        matches = list((decoded_root / "smali").rglob("UnityWebRequest.smali"))
        if len(matches) != 1:
            raise FileNotFoundError(f"cannot locate {CLASS_REL}")
        path = matches[0]
    text = path.read_text(encoding="utf-8")
    original_text = text
    if MARKER in text:
        raise ValueError("UnityWebRequest is already patched")
    if not text.startswith(f".class {CLASS_DESC}\n"):
        raise ValueError("unexpected UnityWebRequest class descriptor")

    field_anchor = ".field private j:Z\n"
    field_replacement = (
        field_anchor
        + "\n# Original URL host retained for gateway routing and certificate checks.\n"
        + ".field private l:Ljava/lang/String;\n"
    )
    text = _replace_once(text, field_anchor, field_replacement, "field anchor")

    c_start, c_end, constructor = _method_slice(text, CONSTRUCTOR_HEADER)
    constructor = _replace_once(
        constructor,
        "    .locals 0\n",
        "    .locals 1\n",
        "constructor locals",
    )
    old_assignment = (
        "    iput-object p5, p0, " + CLASS_DESC + "->b:Ljava/lang/String;\n"
    )
    new_assignment = (
        f"    {MARKER}: retain original host\n"
        f"    invoke-static {{p5}}, {HELPER_DESC}->originalHost(Ljava/lang/String;)Ljava/lang/String;\n"
        "    move-result-object v0\n"
        f"    iput-object v0, p0, {CLASS_DESC}->l:Ljava/lang/String;\n\n"
        f"    invoke-static {{p5}}, {HELPER_DESC}->rewrite(Ljava/lang/String;)Ljava/lang/String;\n"
        "    move-result-object v0\n"
        f"    iput-object v0, p0, {CLASS_DESC}->b:Ljava/lang/String;\n"
    )
    constructor = _replace_once(
        constructor, old_assignment, new_assignment, "constructor URL assignment"
    )
    text = text[:c_start] + constructor + text[c_end:]

    r_start, r_end, run_safe = _method_slice(text, RUNSAFE_HEADER)
    verifier_anchor = (
        "    :goto_0\n"
        "    invoke-static {v5}, Lcom/unity3d/player/b;->a(Lcom/unity3d/player/b$b;)Ljavax/net/ssl/SSLSocketFactory;\n"
    )
    verifier_replacement = (
        "    :goto_0\n\n"
        f"    {MARKER}: optionally validate the rewritten authority\n"
        f"    iget-object v6, v1, {CLASS_DESC}->l:Ljava/lang/String;\n"
        "    if-eqz v6, :cond_nanaon_endpoint_verifier_done\n"
        f"    invoke-static {{v6}}, {HELPER_DESC}->hostnameVerifier(Ljava/lang/String;)Ljavax/net/ssl/HostnameVerifier;\n"
        "    move-result-object v6\n"
        "    invoke-virtual {v0, v6}, Ljavax/net/ssl/HttpsURLConnection;->setHostnameVerifier(Ljavax/net/ssl/HostnameVerifier;)V\n"
        "    :cond_nanaon_endpoint_verifier_done\n"
        "    invoke-static {v5}, Lcom/unity3d/player/b;->a(Lcom/unity3d/player/b$b;)Ljavax/net/ssl/SSLSocketFactory;\n"
    )
    run_safe = _replace_once(
        run_safe, verifier_anchor, verifier_replacement, "verifier anchor"
    )
    header_anchor = (
        "    :cond_4\n"
        "    :goto_2\n"
        f"    iget-object v6, v1, {CLASS_DESC}->d:Ljava/util/Map;\n"
    )
    header_replacement = (
        "    :cond_4\n"
        "    :goto_2\n\n"
        f"    {MARKER}: preserve API/CDN distinction after authority rewrite\n"
        f"    iget-object v6, v1, {CLASS_DESC}->l:Ljava/lang/String;\n"
        "    if-eqz v6, :cond_nanaon_endpoint_header_done\n"
        "    const-string v7, \"X-Nanaon-Original-Host\"\n"
        "    invoke-virtual {v3, v7, v6}, Ljava/net/URLConnection;->addRequestProperty(Ljava/lang/String;Ljava/lang/String;)V\n"
        "    :cond_nanaon_endpoint_header_done\n"
        f"    iget-object v6, v1, {CLASS_DESC}->d:Ljava/util/Map;\n"
    )
    run_safe = _replace_once(
        run_safe, header_anchor, header_replacement, "header anchor"
    )
    text = text[:r_start] + run_safe + text[r_end:]
    path.write_text(text, encoding="utf-8", newline="\n")
    return {
        "path": str(path),
        "before_sha256": hashlib.sha256(original_text.encode("utf-8")).hexdigest(),
        "after_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "marker_count": str(text.count(MARKER)),
    }


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded_root", type=Path)
    args = parser.parse_args()
    result = patch_decoded(args.decoded_root.resolve())
    for key, value in result.items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
