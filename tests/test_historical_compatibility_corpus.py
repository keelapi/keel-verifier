from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.check_historical_compatibility_corpus import (
    DEFAULT_MANIFEST,
    REQUIRED_CATEGORIES,
    validate_manifest,
)


def test_historical_compatibility_manifest_is_complete_and_pinned() -> None:
    nodeids = validate_manifest()
    manifest = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))

    assert nodeids
    assert {case["category"] for case in manifest["cases"]} == REQUIRED_CATEGORIES


def test_historical_compatibility_manifest_fails_loudly_when_artifact_is_absent(
    tmp_path: Path,
) -> None:
    manifest = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))
    manifest["cases"][0]["artifacts"][0]["path"] = "missing-required-artifact.json"
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="required artifact is missing"):
        validate_manifest(path)
