#!/usr/bin/env python3
"""Build a narrowly scoped Network Security Config patch.

The stock APK has one cleartext domain-config for the game's legacy IP
endpoints and otherwise uses Android's default (system) trust store.  The
private gateway uses a locally generated CA, so this patch adds a separate
domain-config for the two DNS-routed HTTPS hosts.  Only those hosts accept a
user-installed CA; every other host remains system-CA-only.

No apktool is required: the replacement resource is a small binary AXML
document generated from scratch.  ``src="user"`` refers to Android's user
certificate store.  The gateway certificate therefore still has to be
installed on the test device (or replaced by a publicly trusted certificate).

Usage:
    python build_patched_apk.py <input.apk> <output.apk>

Optional repeated arguments can override the built-in host lists:

    python build_patched_apk.py input.apk output.apk \
        --private-domain 227.hand.co.jp \
        --private-domain prd-asset.227.hand.co.jp

Then sign:
    zipalign -f 4 <output.apk> <output-aligned.apk>
    apksigner sign --ks keys/test.keystore --ks-key-alias test \
        --ks-pass <local-password> --key-pass <local-password> \
        --out <output-signed.apk> <output-aligned.apk>
"""
import argparse
import re
import struct
import zipfile
from pathlib import Path

U = lambda v: v & 0xFFFFFFFF
NEG1 = U(-1)
TYPE_STRING = 0x03
TYPE_BOOLEAN = 0x12
BOOL_TRUE = 0xFFFFFFFF
BOOL_FALSE = 0

PRIVATE_DOMAINS = (
    "227.hand.co.jp",
    "prd-asset.227.hand.co.jp",
)

# These are the seven entries present in the stock NSC.  They are kept in a
# separate domain-config so they do not inherit the private user CA.
CLEARTEXT_DOMAINS = (
    "172.16.14.1",
    "192.168.234.101",
    "3.114.101.10",
    "10.1.1.225",
    "10.1.1.190",
    "52.199.71.142",
    "54.64.37.126",
)

NSC_ENTRY = "res/xml/network_security_config.xml"
DOMAIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$")


class StrPool:
    def __init__(self):
        self.strings = []
        self.index = {}

    def add(self, s):
        if s not in self.index:
            self.index[s] = len(self.strings)
            self.strings.append(s)
        return self.index[s]

    def build(self):
        data = b""
        offsets = []

        def uleb128(v):
            """Encode a UTF-8 string-pool length as little-endian ULEB128."""
            if v < 0:
                raise ValueError("negative binary AXML string length")
            out = bytearray()
            while True:
                byte = v & 0x7F
                v >>= 7
                if v:
                    byte |= 0x80
                out.append(byte)
                if not v:
                    return bytes(out)

        for s in self.strings:
            b = s.encode("utf-8")
            offsets.append(len(data))
            data += uleb128(len(s)) + uleb128(len(b)) + b + b"\x00"
        while len(data) % 4:
            data += b"\x00"
        hs = 28
        ss = hs + 4 * len(self.strings)
        size = ss + len(data)
        buf = struct.pack("<HHIIIIII", 0x0001, hs, size, len(self.strings), 0, 0x100, ss, 0)
        for o in offsets:
            buf += struct.pack("<I", o)
        return buf + data


def attr(name, raw, tvtype, tvdata):
    return (struct.pack("<III", NEG1, U(name), U(raw))
            + struct.pack("<HBB", 8, 0, tvtype)
            + struct.pack("<I", U(tvdata)))


def start_elem(line, name, attrs_bytes):
    n = len(attrs_bytes) // 20
    out = struct.pack("<HHI", 0x0102, 16, 36 + n * 20)
    out += struct.pack("<ii", line, -1)
    out += struct.pack("<iI", -1, U(name))
    out += struct.pack("<HHHHHH", 20, 20, n, 0, 0, 0)
    return out + attrs_bytes


def end_elem(line, name):
    out = struct.pack("<HHI", 0x0103, 16, 24)
    out += struct.pack("<ii", line, -1)
    return out + struct.pack("<iI", -1, U(name))


def cdata(line, stridx):
    """Text chunk: Android's NSC parser reads <domain> content from here,
    not from an attribute - omitting it fails with "Domain name missing".
    Payload = string idx (4B) + Res_value {u16 size=8, u8 res0, u8 type, u32 data}."""
    return (struct.pack("<HHI", 0x0104, 16, 28)
            + struct.pack("<ii", line, -1)
            + struct.pack("<I", U(stridx))
            + struct.pack("<HBBI", 8, 0, 0, 0))


def _domain_value(value: str) -> str:
    """Validate and normalize a host name accepted by NSC's ``domain``."""
    value = value.strip().rstrip(".").lower()
    if not value or len(value) > 253 or not DOMAIN_RE.fullmatch(value):
        raise ValueError(f"invalid domain: {value!r}")
    labels = value.split(".")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
           for label in labels):
        raise ValueError(f"invalid domain label: {value!r}")
    return value


def _domain_list(values):
    result = tuple(_domain_value(value) for value in values)
    if len(set(result)) != len(result):
        raise ValueError("duplicate domain in NSC host list")
    return result


def _boolean_attr(name, value):
    return attr(name, NEG1, TYPE_BOOLEAN, BOOL_TRUE if value else BOOL_FALSE)


def _trust_anchors(pool, names, attr_src, cert_name, line):
    body = start_elem(line, pool.add("trust-anchors"), b"")
    for source in names:
        source_id = pool.add(source)
        body += start_elem(line + 1, cert_name,
                           attr(attr_src, source_id, TYPE_STRING, source_id))
        body += end_elem(line + 2, cert_name)
    return body + end_elem(line + 3, pool.add("trust-anchors"))


def _domain(pool, name_id, domain_id, include_subdomains, attr_include, line):
    attrs = (_boolean_attr(attr_include, True) if include_subdomains else b"")
    return (start_elem(line, name_id, attrs)
            + cdata(line + 1, domain_id)
            + end_elem(line + 2, name_id))


def build_nsc(private_domains=PRIVATE_DOMAINS,
              cleartext_domains=CLEARTEXT_DOMAINS,
              allow_user_ca=True):
    """Return binary AXML with configurable trust for ``private_domains``.

    The base and legacy-IP configurations explicitly list only ``system``
    certificates.  This is intentional: putting ``src="user"`` in
    ``base-config`` would make every HTTPS endpoint accept arbitrary user CAs.
    ``allow_user_ca=False`` keeps the private domain block system-only, which
    is the default security policy for the public-domain APK candidate.
    """
    private_domains = _domain_list(private_domains)
    cleartext_domains = _domain_list(cleartext_domains)
    if not private_domains:
        raise ValueError("at least one private domain is required")
    overlap = set(private_domains).intersection(cleartext_domains)
    if overlap:
        raise ValueError(
            "a domain cannot be both private-CA and cleartext: "
            + ", ".join(sorted(overlap))
        )

    pool = StrPool()
    S_NETSEC = pool.add("network-security-config")
    S_BASE = pool.add("base-config")
    S_TA = pool.add("trust-anchors")
    S_CERT = pool.add("certificates")
    S_DC = pool.add("domain-config")
    S_DOMAIN = pool.add("domain")
    A_SRC = pool.add("src")
    A_CLEARTEXT = pool.add("cleartextTrafficPermitted")
    A_INCLUDE_SUB = pool.add("includeSubdomains")
    S_PRIVATE = [pool.add(d) for d in private_domains]
    S_CLEARTEXT = [pool.add(d) for d in cleartext_domains]

    body = b""
    body += start_elem(2, S_NETSEC, b"")

    # Android's default is system-only for targetSdk 24+, but making it
    # explicit protects this policy if the target SDK or parser changes.
    body += start_elem(3, S_BASE,
                       _boolean_attr(A_CLEARTEXT, False))
    body += _trust_anchors(pool, ("system",), A_SRC, S_CERT, 4)
    body += end_elem(8, S_BASE)

    # Exact-match private HTTPS hosts.  No includeSubdomains attribute means
    # a sibling host cannot inherit the user CA accidentally.
    body += start_elem(9, S_DC,
                       _boolean_attr(A_CLEARTEXT, False))
    for sid in S_PRIVATE:
        body += _domain(pool, S_DOMAIN, sid, False, A_INCLUDE_SUB, 10)
    private_sources = ("system", "user") if allow_user_ca else ("system",)
    body += _trust_anchors(pool, private_sources, A_SRC, S_CERT, 20)
    body += end_elem(25, S_DC)

    # Preserve the stock HTTP exception list, but keep it system-CA-only.
    if S_CLEARTEXT:
        body += start_elem(26, S_DC,
                           _boolean_attr(A_CLEARTEXT, True))
        for sid in S_CLEARTEXT:
            body += _domain(pool, S_DOMAIN, sid, True, A_INCLUDE_SUB, 27)
        body += _trust_anchors(pool, ("system",), A_SRC, S_CERT, 40)
        body += end_elem(45, S_DC)

    body += end_elem(13, S_NETSEC)

    pb = pool.build()
    return struct.pack("<HHI", 0x0003, 8, 8 + len(pb) + len(body)) + pb + body


def patch_apk(src: Path, dst: Path, xml: bytes) -> None:
    src = src.resolve()
    dst = dst.resolve()
    if src == dst:
        raise ValueError("input and output APK must be different files")
    if not src.is_file():
        raise FileNotFoundError(src)
    seen = set()
    replaced = False
    with zipfile.ZipFile(src, "r") as zin, zipfile.ZipFile(
        dst, "w", allowZip64=True
    ) as zout:
        zout.comment = zin.comment
        for item in zin.infolist():
            if item.filename in seen:
                raise ValueError(f"duplicate ZIP entry: {item.filename}")
            seen.add(item.filename)
            data = zin.read(item)
            if item.filename == NSC_ENTRY:
                data = xml
                replaced = True
            # Preserve the source entry metadata; zipalign is run afterwards.
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
    if not replaced:
        raise ValueError(f"APK has no {NSC_ENTRY} entry")


def _parser_domain(value):
    try:
        return _domain_value(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_apk", type=Path)
    parser.add_argument("output_apk", type=Path)
    parser.add_argument("--private-domain", dest="private_domains",
                        action="append", type=_parser_domain,
                        help="HTTPS host allowed to use user CA (repeatable)")
    parser.add_argument("--cleartext-domain", dest="cleartext_domains",
                        action="append", type=_parser_domain,
                        help="legacy cleartext host (repeatable)")
    trust_group = parser.add_mutually_exclusive_group()
    trust_group.add_argument("--allow-user-ca", dest="allow_user_ca",
                             action="store_true", default=True,
                             help="allow user CA for private domains (default)")
    trust_group.add_argument("--system-only", dest="allow_user_ca",
                             action="store_false",
                             help="use only system CA for private domains")
    args = parser.parse_args(argv)
    private_domains = (tuple(args.private_domains)
                       if args.private_domains is not None else PRIVATE_DOMAINS)
    cleartext_domains = (tuple(args.cleartext_domains)
                         if args.cleartext_domains is not None else CLEARTEXT_DOMAINS)
    xml = build_nsc(private_domains, cleartext_domains, args.allow_user_ca)
    patch_apk(args.input_apk, args.output_apk, xml)
    print(f"patched -> {args.output_apk}")


if __name__ == "__main__":
    main()
