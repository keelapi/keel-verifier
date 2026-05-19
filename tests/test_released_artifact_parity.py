from __future__ import annotations

import os
from pathlib import Path

import pytest

from keel_verifier.semantics import RELEASED_ARTIFACT_PATHS


REPO_ROOT = Path(__file__).resolve().parents[1]
PRODUCT_ROOT = REPO_ROOT.parent
SOURCE_PERMIT = PRODUCT_ROOT / "keel-permit"
BUNDLED_DATA = REPO_ROOT / "keel_verifier" / "data"


@pytest.mark.parametrize(
    ("artifact_id", "relative_path"),
    sorted(RELEASED_ARTIFACT_PATHS.items()),
)
def test_released_artifact_matches_keel_permit_source_bytes(
    artifact_id: str,
    relative_path: str,
) -> None:
    source_artifact = SOURCE_PERMIT / relative_path
    if not source_artifact.exists():
        message = (
            "keel-permit released artifact is not checked out next to "
            f"keel-verifier: {source_artifact}"
        )
        if os.getenv("KEEL_REQUIRE_GOLDEN_CORPUS"):
            raise FileNotFoundError(message)
        pytest.skip(message)

    bundled_artifact = BUNDLED_DATA / relative_path

    assert bundled_artifact.exists(), (
        f"{artifact_id} is not bundled at keel_verifier/data/{relative_path}"
    )
    assert bundled_artifact.read_bytes() == source_artifact.read_bytes()
