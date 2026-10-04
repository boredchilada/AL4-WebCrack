"""Checks that otherwise only fail when AssemblyLine registers the service."""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = yaml.safe_load((ROOT / "service_manifest.yml").read_text())


def test_version_is_stamped_at_build():
    assert MANIFEST["version"] == "$SERVICE_TAG"
    assert MANIFEST["docker_config"]["image"].endswith(":$SERVICE_TAG")


def test_image_uses_registry_variable_or_ghcr():
    image = MANIFEST["docker_config"]["image"]
    assert image.startswith("${PRIVATE_REGISTRY}") or image.startswith("ghcr.io/boredchilada/")


def test_heuristic_ids_are_unique_positive_ints():
    ids = [h["heur_id"] for h in MANIFEST.get("heuristics", [])]
    assert all(isinstance(i, int) and i > 0 for i in ids)
    assert len(ids) == len(set(ids))


def test_heuristic_fields_and_scores():
    for heur in MANIFEST.get("heuristics", []):
        for field in ("heur_id", "name", "score", "filetype", "description"):
            assert field in heur, f"heuristic {heur.get('heur_id')} missing {field}"
        assert 0 <= heur["score"] <= 1000
        if "attack_id" in heur:
            # A scalar string crashes the Rust service_server at registration.
            assert isinstance(heur["attack_id"], list)


def test_service_path_points_at_manifest_class():
    dockerfile = (ROOT / "Dockerfile").read_text()
    found = re.search(r"^ENV SERVICE_PATH=(\S+)$", dockerfile, re.M)
    assert found, "Dockerfile must set ENV SERVICE_PATH"
    module, cls = found.group(1).rsplit(".", 1)
    assert cls == MANIFEST["name"]
    assert (ROOT / (module.replace(".", "/") + ".py")).is_file()
