"""Runs webcrack (Node) over one or more JavaScript sources and reads back what it produced."""

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from webcrack_.analysis import code_changed

RUNNER = Path(__file__).with_name("run_webcrack.mjs")


@dataclass
class WebcrackResult:
    label: str  # "file" for a JavaScript file, "script N" for an inline script
    source: str
    transformed: str | None = None
    reprint: str | None = None
    deobfuscate_only: str | None = None
    bundle_type: str | None = None
    error: str | None = None

    @property
    def changed(self) -> bool:
        """webcrack changed the code beyond reformatting (deobfuscation, unminifying or unpacking)."""
        return code_changed(self.reprint if self.reprint is not None else self.source, self.transformed)

    @property
    def deobfuscated(self) -> bool:
        """The deobfuscate step alone changed the code: something was hidden. Unminifying does not count."""
        baseline = self.reprint if self.reprint is not None else self.source
        return code_changed(baseline, self.deobfuscate_only)

    @property
    def analysis_target(self) -> str:
        """Code to search for indicators: webcrack's output when it changed anything, else the source."""
        return self.transformed if self.changed and self.transformed is not None else self.source


def run_webcrack(
    sources: list[tuple[str, str]], workdir: Path, options: dict[str, bool], timeout: int, max_size: int
) -> list[WebcrackResult]:
    results = [WebcrackResult(label, source) for label, source in sources]
    jobs = []
    for index, result in enumerate(results):
        stem = workdir / f"unit_{index}"
        Path(f"{stem}.in.js").write_text(result.source, encoding="utf-8")
        jobs.append({kind: f"{stem}.{kind}.js" for kind in ("output", "reprint", "deobfuscated")}
                    | {"input": f"{stem}.in.js", "info": f"{stem}.info.json"})
    jobs_path = workdir / "jobs.json"
    jobs_path.write_text(json.dumps(jobs))

    try:
        proc = subprocess.run(
            ["node", "--max-old-space-size=3072", str(RUNNER), str(jobs_path), json.dumps(options)],
            capture_output=True, text=True, timeout=timeout, cwd=workdir,
        )
    except subprocess.TimeoutExpired:
        for result in results:
            result.error = result.error or f"webcrack timed out after {timeout} s"
        return results
    if proc.returncode != 0:
        message = (proc.stderr.strip().splitlines() or ["unknown error"])[-1]
        for result in results:
            result.error = f"webcrack failed: {message[:300]}"
        return results

    for result, job in zip(results, jobs, strict=True):
        info_path = Path(job["info"])
        if not info_path.is_file():
            result.error = "webcrack did not finish this input"
            continue
        info = json.loads(info_path.read_text())
        if not info.get("ok"):
            result.error = info.get("error", {}).get("message", "unknown error")
            continue
        result.bundle_type = info.get("bundleType")
        result.transformed = _read(Path(job["output"]), max_size)
        if result.transformed is not None:
            result.reprint = _read(Path(job["reprint"]), max_size)
            result.deobfuscate_only = _read(Path(job["deobfuscated"]), max_size)
    return results


def _read(path: Path, max_size: int) -> str | None:
    if path.is_file() and path.stat().st_size <= max_size:
        return path.read_text(errors="replace")
    return None
