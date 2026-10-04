import hashlib
import json
import os
from pathlib import Path

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Heuristic,
    Result,
    ResultTableSection,
    ResultTextSection,
    TableRow,
)

from webcrack_.analysis import (
    MAX_URLS,
    decode_source,
    detect_obfuscators,
    extract_inline_scripts,
    extract_urls,
    find_wasm_blobs,
    looks_like_markup,
    url_host,
)
from webcrack_.runner import WebcrackResult, run_webcrack

WEBCRACK_DIR = Path("/opt/webcrack")
NODE_TIMEOUT = 90  # below the manifest's 120 s service timeout


class WebCrack(ServiceBase):
    def start(self) -> None:
        if not (WEBCRACK_DIR / "dist" / "index.js").is_file():
            raise RuntimeError(f"webcrack not installed under {WEBCRACK_DIR}")
        self.log.info(f"WebCrack started with webcrack {self.get_tool_version()}")

    def get_tool_version(self) -> str:
        # A changed tool version makes AL re-run cached files, so include the exact build commit.
        try:
            version = json.loads((WEBCRACK_DIR / "package.json").read_text())["version"]
            commit = (WEBCRACK_DIR / "BUILD_COMMIT").read_text().strip()[:7]
            return f"{version}+{commit}"
        except (OSError, KeyError, ValueError):
            return "unknown"

    def execute(self, request: ServiceRequest) -> None:
        result = Result()
        with open(request.file_path, "rb") as handle:
            source = decode_source(handle.read())

        # Pages: analyse each inline script. Decided by content, since AL sometimes labels JS as HTML.
        markup = looks_like_markup(source)
        if markup:
            sources = [(f"script {i}", code) for i, code in enumerate(extract_inline_scripts(source), 1)]
        else:
            sources = [("file", source)]
        if not sources:
            request.result = result
            return

        options = {
            "deobfuscate": bool(request.get_param("deobfuscate_code")),
            "unminify": bool(request.get_param("unminify_code")),
            "unpack": bool(request.get_param("unpack_bundles")),
        }
        max_size = int((self.config or {}).get("max_deobfuscated_size", 10 * 1024 * 1024))
        units = run_webcrack(sources, Path(self.working_directory), options, NODE_TIMEOUT, max_size)

        def row(unit: WebcrackResult, **columns: object) -> TableRow:
            return TableRow({"script": unit.label, **columns} if markup else columns)

        self._add_errors(result, units, markup)
        self._add_obfuscators(result, units, row)
        self._add_bundles(result, units, row)
        self._add_deobfuscated(request, result, units, row)
        self._add_urls(result, units, row)
        self._add_wasm(request, result, units, row)
        request.result = result

    @staticmethod
    def _add_errors(result: Result, units: list[WebcrackResult], markup: bool) -> None:
        failed = [u for u in units if u.error]
        if not failed:
            return
        # Analyst visibility only: malformed or unsupported JavaScript is common and not a finding.
        if markup:
            section = ResultTextSection(f"Webcrack could not process {len(failed)} inline script(s)")
            for unit in failed:
                section.add_line(f"{unit.label}: {(unit.error or '')[:200]}")
        else:
            section = ResultTextSection("Webcrack could not fully process this file")
            section.add_line((failed[0].error or "")[:300])
        result.add_section(section)

    @staticmethod
    def _add_obfuscators(result: Result, units: list[WebcrackResult], row) -> None:
        section = ResultTableSection("Known obfuscator detected")
        heuristic = Heuristic(2)
        for unit in units:
            for signature, description in detect_obfuscators(unit.source):
                section.add_row(row(unit, technique=description))
                heuristic.add_signature_id(signature)
        if section.body:
            section.set_heuristic(heuristic)
            result.add_section(section)

    @staticmethod
    def _add_bundles(result: Result, units: list[WebcrackResult], row) -> None:
        section = ResultTableSection("JavaScript bundle detected and unpacked")
        for unit in units:
            if unit.bundle_type:
                section.add_row(row(unit, bundle_type=unit.bundle_type))
        if section.body:
            section.set_heuristic(3)
            result.add_section(section)

    def _add_deobfuscated(self, request: ServiceRequest, result: Result, units: list[WebcrackResult], row) -> None:
        section = ResultTableSection("JavaScript deobfuscated")
        for index, unit in enumerate(units, 1):
            # Extract webcrack's output only when it revealed something: deobfuscation or an unpacked bundle.
            # Unminified libraries are not resubmitted, since AL would re-run every service on them.
            if unit.transformed is None or not (unit.deobfuscated or (unit.bundle_type and unit.changed)):
                continue
            name = "deobfuscated.js" if unit.label == "file" else f"script_{index}_deobfuscated.js"
            path = os.path.join(self.working_directory, name)
            Path(path).write_text(unit.transformed, encoding="utf-8")
            request.add_extracted(path, name, f"webcrack output for {unit.label}")
            if unit.deobfuscated:
                section.add_row(row(unit, original_size=len(unit.source), deobfuscated_size=len(unit.transformed),
                                    extracted=name))
        if section.body:
            section.set_heuristic(1)
            result.add_section(section)

    @staticmethod
    def _add_urls(result: Result, units: list[WebcrackResult], row) -> None:
        # Tags only, no heuristic: a URL in JavaScript is not suspicious by itself.
        section = ResultTableSection("URLs found in JavaScript")
        seen: set[str] = set()
        for unit in units:
            for url in extract_urls(unit.analysis_target):
                if url in seen or len(seen) >= MAX_URLS:
                    continue
                seen.add(url)
                host = url_host(url)
                section.add_row(row(unit, url=url, host=host[1] if host else ""))
                section.add_tag("network.static.uri", url)
                if host:
                    section.add_tag("network.static.domain" if host[0] == "domain" else "network.static.ip", host[1])
        if section.body:
            result.add_section(section)

    def _add_wasm(self, request: ServiceRequest, result: Result, units: list[WebcrackResult], row) -> None:
        section = ResultTableSection("Embedded WebAssembly")
        seen: set[str] = set()
        for unit in units:
            for blob in find_wasm_blobs(unit.analysis_target):
                digest = hashlib.sha256(blob.data).hexdigest()
                if digest in seen:
                    continue
                seen.add(digest)
                name = f"embedded_{len(seen)}.wasm"
                path = os.path.join(self.working_directory, name)
                with open(path, "wb") as handle:
                    handle.write(blob.data)
                request.add_extracted(path, name,
                                      f"Base64-encoded WebAssembly from JavaScript ({len(blob.data)} bytes)")
                section.add_row(row(unit, file=name, size=len(blob.data), encoding=blob.encoding,
                                    base64_chars=blob.base64_chars))
        if section.body:
            section.set_heuristic(4)
            result.add_section(section)
