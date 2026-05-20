from __future__ import annotations

import os
import json
from pathlib import Path

import pytest

from keel_verifier.semantics import (
    EXPORT_SCOPE_FAITHFULNESS_ID,
    RELEASED_ARTIFACT_PATHS,
    SCOPE_STATE_MERKLE_ID,
    SCOPE_STATE_SIDECAR_FORMAT_ID,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PRODUCT_ROOT = REPO_ROOT.parent
SOURCE_PERMIT = PRODUCT_ROOT / "keel-permit"
BUNDLED_DATA = REPO_ROOT / "keel_verifier" / "data"
CANONICAL_SOURCE_ARTIFACTS = {
    EXPORT_SCOPE_FAITHFULNESS_ID,
    SCOPE_STATE_MERKLE_ID,
    SCOPE_STATE_SIDECAR_FORMAT_ID,
}


def _expected_source_bytes(artifact_id: str, source_artifact: Path) -> bytes:
    raw = source_artifact.read_bytes()
    if artifact_id not in CANONICAL_SOURCE_ARTIFACTS:
        return raw
    return json.dumps(
        json.loads(raw.decode("utf-8")),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


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
    assert bundled_artifact.read_bytes() == _expected_source_bytes(
        artifact_id,
        source_artifact,
    )
