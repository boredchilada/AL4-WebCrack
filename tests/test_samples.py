"""Sample regression tests (CCCS TestHelper pattern).

Samples are CaRT files named <sha256>.cart in tests/samples/. Expected results live in
tests/results/<sha256>/ and are regenerated with scripts/gentests.py.
"""

import os
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
os.environ["SERVICE_MANIFEST_PATH"] = str(HERE.parent / "service_manifest.yml")

from assemblyline.common.importing import load_module_by_path  # noqa: E402
from assemblyline_service_utilities.testing.helper import TestHelper  # noqa: E402

SERVICE_PATH = next(
    line.split("=", 1)[1].strip()
    for line in (HERE.parent / "Dockerfile").read_text().splitlines()
    if line.startswith("ENV SERVICE_PATH=")
)
th = TestHelper(load_module_by_path(SERVICE_PATH, str(HERE.parent)), str(HERE / "results"), str(HERE / "samples"))


@pytest.mark.parametrize("sample", th.result_list())
def test_sample(sample):
    # test_extra=True also compares section bodies, which TestHelper skips by default.
    th.run_test_comparison(sample, test_extra=True)
