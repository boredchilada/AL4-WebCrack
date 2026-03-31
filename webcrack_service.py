import os
import re
import json
import base64
import subprocess
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import (
    Result, ResultSection, ResultKeyValueSection,
    BODY_FORMAT,
)

# URL pattern for IOC tagging
URL_RE = re.compile(
    r'''(?:https?://|//)[^\s'"<>{}\[\]|\\^`\x00-\x1f]{4,500}''',
    re.IGNORECASE,
)

# Embedded WASM patterns (base64-encoded WASM binaries in JS)
# WASM magic bytes \x00asm = AGFzbQ in base64
WASM_B64_PATTERNS = [
    re.compile(r'data:application/wasm;base64,([A-Za-z0-9+/=]{20,})', re.IGNORECASE),
    re.compile(r'''["']([A-Za-z0-9+/]{0,4}AGFzbQ[A-Za-z0-9+/=]{20,})["']'''),
]

# Known obfuscator signatures
OBFUSCATOR_PATTERNS = [
    (re.compile(r'''_0x[0-9a-f]{4,6}\s*\('''), "obfuscator.io style"),
    (re.compile(r'''var\s+_0x[0-9a-f]{4}\s*=\s*\['''), "obfuscator.io string array"),
    (re.compile(r'''atob\s*\(\s*['"]\s*[A-Za-z0-9+/=]{20,}'''), "base64 encoded strings"),
]


class WebcrackService(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)
        self.webcrack_path = "/opt/al_service/node_modules/webcrack"

    def get_tool_version(self):
        try:
            pkg_json = os.path.join(self.webcrack_path, "package.json")
            if os.path.exists(pkg_json):
                with open(pkg_json) as f:
                    return json.load(f).get("version", "unknown")
        except Exception:
            pass
        return "unknown"

    def start(self):
        self.log.info(f"WebcrackService starting, webcrack version: {self.get_tool_version()}")
        if not os.path.exists(self.webcrack_path):
            raise Exception(f"Webcrack not installed at {self.webcrack_path}")

    def execute(self, request):
        result = Result()

        deobfuscate_code = request.get_param("deobfuscate_code")
        unminify_code = request.get_param("unminify_code")
        unpack_bundles = request.get_param("unpack_bundles")

        file_path = request.file_path

        # Read and decode input
        with open(file_path, "rb") as f:
            raw = f.read()

        if raw.startswith(b"\xef\xbb\xbf"):
            encoding = "utf-8-sig"
        elif raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
            encoding = "utf-16"
        else:
            encoding = "utf-8"

        try:
            js_content = raw.decode(encoding)
        except UnicodeDecodeError:
            js_content = raw.decode("latin-1")

        # Check for obfuscator patterns in original code
        detected_obfuscators = []
        for pattern, name in OBFUSCATOR_PATTERNS:
            if pattern.search(js_content):
                detected_obfuscators.append(name)

        # Run webcrack
        output_path = os.path.join(self.working_directory, "deobfuscated.js")
        input_path = os.path.join(self.working_directory, "input.js")
        script_path = os.path.join(self.working_directory, "run_webcrack.mjs")

        with open(input_path, "w", encoding="utf-8") as f:
            f.write(js_content)

        script_content = f'''
import {{ webcrack }} from '/opt/al_service/node_modules/webcrack/dist/index.js';
import fs from 'fs';

(async () => {{
    try {{
        const input = fs.readFileSync(process.argv[2], 'utf8');
        const result = await webcrack(input, {{
            jsx: true,
            unpack: {str(unpack_bundles).lower()},
            unminify: {str(unminify_code).lower()},
            deobfuscate: {str(deobfuscate_code).lower()},
            mangle: false,
        }});

        fs.writeFileSync(process.argv[3], result.code);

        const info = {{
            hasBundle: result.bundle !== undefined && result.bundle !== null,
            bundleType: result.bundle ? result.bundle.type : null,
        }};
        fs.writeFileSync(process.argv[4], JSON.stringify(info));

    }} catch (error) {{
        console.error(JSON.stringify({{
            message: error.message,
            name: error.name,
        }}));
        process.exit(1);
    }}
}})();
'''
        with open(script_path, "w") as f:
            f.write(script_content)

        info_path = os.path.join(self.working_directory, "info.json")

        proc = subprocess.run(
            ["node", "--max-old-space-size=3072", script_path, input_path, output_path, info_path],
            capture_output=True,
            text=True,
            timeout=90,
            cwd=self.working_directory,
            env={**os.environ, "NODE_PATH": "/opt/al_service/node_modules"},
        )

        # Parse info output
        bundle_info = None
        if os.path.exists(info_path):
            try:
                with open(info_path) as f:
                    bundle_info = json.load(f)
            except Exception:
                pass

        # Handle process failure
        if proc.returncode != 0:
            err_msg = proc.stderr.strip() if proc.stderr else "Unknown error"
            self.log.warning(f"Webcrack exited {proc.returncode}: {err_msg}")
            try:
                err_json = json.loads(err_msg)
                clean_err = err_json.get("message", err_msg)
            except (json.JSONDecodeError, TypeError):
                clean_err = err_msg.split("\n")[0]
            error_section = ResultSection("Webcrack Analysis Error", body_format=BODY_FORMAT.TEXT)
            error_section.add_line(f"Webcrack could not fully process this file: {clean_err[:300]}")
            result.add_section(error_section)

        # Process deobfuscated output
        deobfuscated = None
        if os.path.exists(output_path):
            max_size = self.config.get("max_deobfuscated_size", 10 * 1024 * 1024)
            size = os.path.getsize(output_path)
            if size <= max_size:
                with open(output_path, "r", errors="replace") as f:
                    deobfuscated = f.read()

        def _normalize(s):
            return re.sub(r'\s+', ' ', s).strip()

        code_changed = deobfuscated and _normalize(deobfuscated) != _normalize(js_content)

        # Known obfuscator detection
        if detected_obfuscators:
            obf_section = ResultSection("Known Obfuscator Detected", body_format=BODY_FORMAT.TEXT)
            obf_section.set_heuristic(2)
            obf_section.add_line("The following obfuscation techniques were identified in the source code:")
            for name in detected_obfuscators:
                obf_section.add_line(f"  - {name}")
                obf_section.heuristic.add_signature_id(name)
            result.add_section(obf_section)

        # Bundle detection
        if bundle_info and bundle_info.get("hasBundle") and bundle_info.get("bundleType"):
            bundle_type = bundle_info["bundleType"]
            bundle_section = ResultKeyValueSection(f"{bundle_type.title()} Bundle Detected and Unpacked")
            bundle_section.set_item("Bundle Type", bundle_type)
            bundle_section.set_item("Status", "Unpacked by webcrack")
            bundle_section.set_heuristic(3)
            result.add_section(bundle_section)

        # Deobfuscated code extraction
        if code_changed:
            request.add_extracted(
                output_path, "deobfuscated.js",
                "Deobfuscated JavaScript code from webcrack",
            )
            size_delta = len(deobfuscated) - len(js_content)
            direction = "larger" if size_delta > 0 else "smaller"
            deobf_section = ResultSection("JavaScript Successfully Deobfuscated", body_format=BODY_FORMAT.TEXT)
            deobf_section.set_heuristic(1)
            deobf_section.add_line(
                f"Webcrack transformed the code from {len(js_content):,} bytes "
                f"to {len(deobfuscated):,} bytes ({abs(size_delta):,} bytes {direction})"
            )
            if detected_obfuscators:
                deobf_section.add_line(
                    f"Obfuscation removed: {', '.join(detected_obfuscators)}"
                )
            deobf_section.add_line("Deobfuscated output extracted for further analysis")
            result.add_section(deobf_section)

        # IOC tagging on deobfuscated code (or original if no change)
        # No heuristic — just feeds tags into AL correlation engine
        analysis_target = deobfuscated if code_changed else js_content

        urls = set()
        for match in URL_RE.finditer(analysis_target):
            url = match.group(0).rstrip(".,;)'\"")
            if len(url) > 10 and "." in url:
                urls.add(url)

        if urls:
            source = "deobfuscated" if code_changed else "original"
            url_section = ResultSection(
                f"URLs Extracted from {source.title()} Code ({len(urls)} found)",
                body_format=BODY_FORMAT.TEXT,
            )
            for url in sorted(urls)[:50]:
                url_section.add_line(url)
                url_section.add_tag("network.static.uri", url)
                domain_match = re.search(r'//([^/:?#\s]+)', url)
                if domain_match:
                    domain = domain_match.group(1)
                    if not re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
                        url_section.add_tag("network.static.domain", domain)
                    else:
                        url_section.add_tag("network.static.ip", domain)
            result.add_section(url_section)

        # Embedded WASM detection and extraction
        wasm_extractions = []
        for pattern in WASM_B64_PATTERNS:
            for match in pattern.finditer(analysis_target):
                b64_data = match.group(1)
                try:
                    wasm_bytes = base64.b64decode(b64_data)
                    if wasm_bytes[:4] == b"\x00asm":
                        idx = len(wasm_extractions) + 1
                        wasm_path = os.path.join(
                            self.working_directory, f"embedded_{idx}.wasm"
                        )
                        with open(wasm_path, "wb") as f:
                            f.write(wasm_bytes)
                        request.add_extracted(
                            wasm_path,
                            f"embedded_{idx}.wasm",
                            f"Base64-encoded WebAssembly binary extracted from JavaScript ({len(wasm_bytes)} bytes)",
                        )
                        full_match = match.group(0)
                        if "data:application/wasm;base64," in full_match.lower():
                            encoding_method = "data: URI (data:application/wasm;base64,...)"
                        else:
                            encoding_method = "base64 string literal"
                        wasm_extractions.append({
                            "size": len(wasm_bytes),
                            "b64_size": len(b64_data),
                            "encoding": encoding_method,
                        })
                except Exception:
                    pass

        if wasm_extractions:
            wasm_section = ResultSection("Embedded WebAssembly Detected", body_format=BODY_FORMAT.TEXT)
            wasm_section.set_heuristic(4)
            wasm_section.add_line(
                f"Found {len(wasm_extractions)} base64-encoded WebAssembly "
                f"{'binary' if len(wasm_extractions) == 1 else 'binaries'} "
                f"embedded in JavaScript code:"
            )
            for i, info in enumerate(wasm_extractions, 1):
                wasm_section.add_line(
                    f"  #{i}: {info['size']:,} bytes decoded from "
                    f"{info['b64_size']:,} chars base64 via {info['encoding']}"
                )
            result.add_section(wasm_section)

        request.result = result
