import json
import os
import subprocess
from pathlib import Path

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Heuristic,
    Result,
    ResultKeyValueSection,
    ResultTableSection,
    ResultTextSection,
    TableRow,
)

from webcrack_.analysis import code_changed, decode_source, detect_obfuscators, extract_urls, find_wasm_blobs, url_host

WEBCRACK_DIR = Path("/opt/webcrack")
RUNNER = Path(__file__).with_name("run_webcrack.mjs")
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

        obfuscators = detect_obfuscators(source)
        transformed, baseline, bundle_type, error = self._run_webcrack(request, source)
        # Against webcrack's own reprint, so pure reformatting (quotes, parentheses, line breaks) does
        # not count as deobfuscation. Falls back to the source if the reprint is unavailable.
        changed = code_changed(baseline if baseline is not None else source, transformed)

        if error:
            # Analyst visibility only: malformed or unsupported JavaScript is common and not a finding.
            section = ResultTextSection("Webcrack could not fully process this file")
            section.add_line(error[:300])
            result.add_section(section)

        if obfuscators:
            section = ResultTableSection("Known obfuscator detected")
            heuristic = Heuristic(2)
            for signature, description in obfuscators:
                section.add_row(TableRow({"technique": description}))
                heuristic.add_signature_id(signature)
            section.set_heuristic(heuristic)
            result.add_section(section)

        if bundle_type:
            section = ResultKeyValueSection(f"{bundle_type.title()} bundle detected and unpacked")
            section.set_item("bundle_type", bundle_type)
            section.set_heuristic(3)
            result.add_section(section)

        if changed and transformed is not None:
            output = os.path.join(self.working_directory, "deobfuscated.js")
            request.add_extracted(output, "deobfuscated.js", "Deobfuscated JavaScript from webcrack")
            section = ResultKeyValueSection("JavaScript deobfuscated")
            section.set_item("original_size", len(source))
            section.set_item("deobfuscated_size", len(transformed))
            if obfuscators:
                section.set_item("obfuscation_removed", ", ".join(d for _, d in obfuscators))
            section.set_heuristic(1)
            result.add_section(section)

        # Indicators come from the deobfuscated code when webcrack changed it.
        target = transformed if changed and transformed is not None else source
        self._add_url_section(result, target, "deobfuscated" if changed else "original")
        self._add_wasm_section(request, result, target)

        request.result = result

    def _run_webcrack(
        self, request: ServiceRequest, source: str
    ) -> tuple[str | None, str | None, str | None, str | None]:
        """Returns (transformed code, reprint baseline, bundle type, error message)."""
        workdir = Path(self.working_directory)
        input_path, output_path = workdir / "input.js", workdir / "deobfuscated.js"
        baseline_path, info_path = workdir / "reprint.js", workdir / "info.json"
        input_path.write_text(source, encoding="utf-8")
        options = {
            "deobfuscate": request.get_param("deobfuscate_code"),
            "unminify": request.get_param("unminify_code"),
            "unpack": request.get_param("unpack_bundles"),
        }
        try:
            proc = subprocess.run(
                ["node", "--max-old-space-size=3072", str(RUNNER), str(input_path), str(output_path),
                 str(baseline_path), str(info_path), json.dumps(options)],
                capture_output=True, text=True, timeout=NODE_TIMEOUT, cwd=workdir,
            )
        except subprocess.TimeoutExpired:
            return None, None, None, f"webcrack timed out after {NODE_TIMEOUT} s"

        error = None
        if proc.returncode != 0:
            raw = proc.stderr.strip() or "unknown error"
            self.log.warning(f"webcrack exited {proc.returncode}: {raw[:500]}")
            try:
                error = json.loads(raw.splitlines()[-1]).get("message", raw)
            except (ValueError, AttributeError):
                error = raw.splitlines()[0]

        transformed = baseline = None
        max_size = int((self.config or {}).get("max_deobfuscated_size", 10 * 1024 * 1024))
        if output_path.is_file() and output_path.stat().st_size <= max_size:
            transformed = output_path.read_text(errors="replace")
            if baseline_path.is_file():
                baseline = baseline_path.read_text(errors="replace")

        bundle_type = None
        if info_path.is_file():
            try:
                bundle_type = json.loads(info_path.read_text()).get("bundleType")
            except ValueError:
                pass
        return transformed, baseline, bundle_type, error

    @staticmethod
    def _add_url_section(result: Result, code: str, origin: str) -> None:
        urls = extract_urls(code)
        if not urls:
            return
        # Tags only, no heuristic: a URL in JavaScript is not suspicious by itself.
        section = ResultTableSection(f"URLs in {origin} code")
        for url in urls:
            host = url_host(url)
            section.add_row(TableRow({"url": url, "host": host[1] if host else ""}))
            section.add_tag("network.static.uri", url)
            if host:
                section.add_tag("network.static.domain" if host[0] == "domain" else "network.static.ip", host[1])
        result.add_section(section)

    def _add_wasm_section(self, request: ServiceRequest, result: Result, code: str) -> None:
        blobs = find_wasm_blobs(code)
        if not blobs:
            return
        section = ResultTableSection("Embedded WebAssembly")
        for index, blob in enumerate(blobs, 1):
            name = f"embedded_{index}.wasm"
            path = os.path.join(self.working_directory, name)
            with open(path, "wb") as handle:
                handle.write(blob.data)
            request.add_extracted(path, name, f"Base64-encoded WebAssembly from JavaScript ({len(blob.data)} bytes)")
            section.add_row(TableRow({"file": name, "size": len(blob.data), "encoding": blob.encoding,
                                      "base64_chars": blob.base64_chars}))
        section.set_heuristic(4)
        result.add_section(section)
