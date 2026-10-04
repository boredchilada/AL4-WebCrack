"""Regenerate expected results for every folder in tests/results/ (CCCS gentests pattern).

To add a sample: put <sha256>.cart in tests/samples/, create the empty folder
tests/results/<sha256>/, run this script inside the service image, then read the result.json
it writes before committing it.
"""

import os
from pathlib import Path

ROOT = Path.cwd()
os.environ["SERVICE_MANIFEST_PATH"] = str(ROOT / "service_manifest.yml")

from assemblyline.common.importing import load_module_by_path  # noqa: E402
from assemblyline_service_utilities.testing.helper import TestHelper  # noqa: E402

service_path = next(
    line.split("=", 1)[1].strip()
    for line in (ROOT / "Dockerfile").read_text().splitlines()
    if line.startswith("ENV SERVICE_PATH=")
)
th = TestHelper(
    load_module_by_path(service_path, str(ROOT)),
    str(ROOT / "tests" / "results"),
    str(ROOT / "tests" / "samples"),
)
th.regenerate_results(save_files=False)
