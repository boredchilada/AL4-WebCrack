"""Pure analysis functions. No AssemblyLine or Node imports, so they unit-test anywhere."""

import base64
import binascii
import hashlib
import ipaddress
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urlsplit

MAX_URLS = 50
MAX_WASM_BLOBS = 20
MAX_SCRIPTS = 50

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


_MARKUP_TAG = re.compile(r"<\s*(!doctype|html|head|body|script|svg|div|form|iframe)\b", re.IGNORECASE)
_JS_TYPES = {"", "text/javascript", "application/javascript", "application/x-javascript", "text/ecmascript",
             "application/ecmascript", "text/jscript", "module"}
_CDATA = re.compile(r"^\s*(?://\s*)?<!\[CDATA\[(.*?)(?://\s*)?\]\]>\s*$", re.DOTALL)


def looks_like_markup(source: str) -> bool:
    """True for HTML/SVG documents. Decided by content: AL sometimes labels JavaScript as HTML."""
    head = source.lstrip("\ufeff \t\r\n")
    return head.startswith("<") and bool(_MARKUP_TAG.search(head[:65536]))


class _ScriptCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.scripts: list[str] = []
        self._current: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "script":
            values = {name: (value or "") for name, value in attrs}
            script_type = values.get("type", "").split(";")[0].strip().lower()
            self._current = [] if script_type in _JS_TYPES and "src" not in values else None

    def handle_data(self, data: str) -> None:
        if self._current is not None:
            self._current.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._current is not None:
            code = "".join(self._current)
            cdata = _CDATA.match(code)
            code = (cdata.group(1) if cdata else code).strip()
            if code and len(self.scripts) < MAX_SCRIPTS:
                self.scripts.append(code)
            self._current = None


def extract_inline_scripts(markup: str) -> list[str]:
    """Inline JavaScript from <script> blocks; external (src=) and non-JS types are skipped."""
    collector = _ScriptCollector()
    collector.feed(markup)
    collector.close()
    return collector.scripts
