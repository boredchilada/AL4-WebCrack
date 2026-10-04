"""Pure analysis functions. No AssemblyLine or Node imports, so they unit-test anywhere."""

import base64
import binascii
import hashlib
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

MAX_URLS = 50
MAX_WASM_BLOBS = 20

_URL = re.compile(r"""(?:https?://|//)[^\s'"<>{}\[\]|\\^`\x00-\x1f]{4,500}""", re.IGNORECASE)

# (signature id, description). Signature ids are lowercase: AL rejects other keys in score maps.
_OBFUSCATORS = [
    ("obfuscator_io_call", "obfuscator.io style _0x calls", re.compile(r"_0x[0-9a-f]{4,6}\s*\(")),
    ("obfuscator_io_string_array", "obfuscator.io string array", re.compile(r"var\s+_0x[0-9a-f]{4}\s*=\s*\[")),
    (
        "atob_long_string",
        "long base64 string passed to atob()",
        re.compile(r"""atob\s*\(\s*['"]\s*[A-Za-z0-9+/=]{20,}"""),
    ),
]

# WASM magic bytes \0asm encode to AGFzbQ in base64.
_WASM_PATTERNS = [
    ("data URI", re.compile(r"data:application/wasm;base64,([A-Za-z0-9+/=]{20,})", re.IGNORECASE)),
    ("base64 string literal", re.compile(r"""["']([A-Za-z0-9+/]{0,4}AGFzbQ[A-Za-z0-9+/=]{20,})["']""")),
]


@dataclass(frozen=True)
class WasmBlob:
    data: bytes
    encoding: str
    base64_chars: int


def decode_source(raw: bytes) -> str:
    if raw.startswith(b"\xef\xbb\xbf"):
        encoding = "utf-8-sig"
    elif raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        encoding = "utf-16"
    else:
        encoding = "utf-8"
    try:
        return raw.decode(encoding)
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def detect_obfuscators(source: str) -> list[tuple[str, str]]:
    return [(sig, description) for sig, description, pattern in _OBFUSCATORS if pattern.search(source)]


def _normalize(code: str) -> str:
    return re.sub(r"\s+", " ", code).strip()


def code_changed(original: str, transformed: str | None) -> bool:
    return bool(transformed) and _normalize(transformed) != _normalize(original)


def extract_urls(source: str) -> list[str]:
    urls: set[str] = set()
    for match in _URL.finditer(source):
        url = match.group(0).rstrip(".,;)'\"")
        if len(url) > 10 and "." in url:
            urls.add(url)
            if len(urls) >= MAX_URLS:
                break
    return sorted(urls)


def url_host(url: str) -> tuple[str, str] | None:
    """('domain' | 'ip', host) for tagging, or None when the URL has no host."""
    try:
        host = urlsplit(url if not url.startswith("//") else "http:" + url).hostname
    except ValueError:
        return None
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return ("ip", host)
    except ValueError:
        return ("domain", host)


def find_wasm_blobs(source: str) -> list[WasmBlob]:
    blobs: list[WasmBlob] = []
    seen: set[str] = set()
    for encoding, pattern in _WASM_PATTERNS:
        for match in pattern.finditer(source):
            text = match.group(1)
            try:
                data = base64.b64decode(text, validate=True)
            except (binascii.Error, ValueError):
                continue
            digest = hashlib.sha256(data).hexdigest()
            if data[:4] != b"\x00asm" or digest in seen:
                continue
            seen.add(digest)
            blobs.append(WasmBlob(data, encoding, len(text)))
            if len(blobs) >= MAX_WASM_BLOBS:
                return blobs
    return blobs
