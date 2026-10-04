import base64

from webcrack_.analysis import (
    MAX_URLS,
    MAX_WASM_BLOBS,
    code_changed,
    decode_source,
    detect_obfuscators,
    extract_urls,
    find_wasm_blobs,
    url_host,
)

# Minimal valid module: one exported function "main" returning 42.
WASM = bytes.fromhex(
    "0061736d" "01000000" "0105016000017f" "03020100" "070801046d61696e0000" "0a06010400412a0b"
)
WASM_B64 = base64.b64encode(WASM).decode()


def test_decode_source_handles_boms_and_bad_utf8():
    assert decode_source(b"\xef\xbb\xbfvar a = 1;") == "var a = 1;"
    assert decode_source("var é;".encode("utf-16")) == "var é;"
    assert decode_source(b"var a = '\xff';") == "var a = '\xff';"  # latin-1 fallback, no crash


def test_detects_obfuscator_io_markers():
    source = "var _0x3a1f = ['log']; (function(_0x1b2c){})(_0x3a1f); _0xab12('0x1');"
    ids = [sig for sig, _ in detect_obfuscators(source)]
    assert ids == ["obfuscator_io_call", "obfuscator_io_string_array"]


def test_plain_code_has_no_obfuscator_markers():
    assert detect_obfuscators("function add(a, b) { return a + b; }") == []


def test_code_changed_ignores_whitespace_only_differences():
    assert not code_changed("var a=1;\nvar b=2;", "var a=1;   var b=2;")
    assert code_changed("var a='\\x68';", "var a = 'h';")
    assert not code_changed("var a=1;", None)


def test_extract_urls_trims_trailing_punctuation_and_dedupes():
    source = 'fetch("https://evil.example.com/a.php"); x = "//cdn.example.net/lib.js"; y = "https://evil.example.com/a.php".'
    assert extract_urls(source) == ["//cdn.example.net/lib.js", "https://evil.example.com/a.php"]


def test_extract_urls_ignores_strings_that_are_not_urls():
    assert extract_urls('a = "http://x"; b = "//comment"') == []


def test_extract_urls_caps_hostile_input():
    source = " ".join(f"https://h{i}.example.com/p" for i in range(MAX_URLS + 30))
    assert len(extract_urls(source)) == MAX_URLS


def test_url_host_splits_domains_and_ips():
    assert url_host("https://user@Evil.Example.com:8443/x") == ("domain", "evil.example.com")
    assert url_host("http://203.0.113.7/payload") == ("ip", "203.0.113.7")
    assert url_host("https:///nohost") is None


def test_finds_wasm_in_data_uri_and_string_literal():
    source = f'a = "data:application/wasm;base64,{WASM_B64}"; b = \'{WASM_B64}\';'
    blobs = find_wasm_blobs(source)
    assert [b.encoding for b in blobs] == ["data URI"]  # same bytes twice: extracted once
    assert blobs[0].data == WASM


def test_ignores_base64_that_is_not_wasm():
    not_wasm = base64.b64encode(b"\x00asX" + b"A" * 30).decode()
    assert find_wasm_blobs(f'"{not_wasm}"') == []
    assert find_wasm_blobs('"AGFzbQ!!!!not-base64-at-all!!!!!!!!!!!"') == []


def test_wasm_blob_count_is_capped():
    blobs = [base64.b64encode(WASM + bytes([i])).decode() for i in range(MAX_WASM_BLOBS + 5)]
    source = " ".join(f'"{b}"' for b in blobs)
    assert len(find_wasm_blobs(source)) == MAX_WASM_BLOBS
