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
SOURCE_API = PRODUCT_ROOT / "keel-api"
BUNDLED_DATA = REPO_ROOT / "keel_verifier" / "data"
CANONICAL_SOURCE_ARTIFACTS = {
    EXPORT_SCOPE_FAITHFULNESS_ID,
    SCOPE_STATE_MERKLE_ID,
    SCOPE_STATE_SIDECAR_FORMAT_ID,
}
STEP2_CLOSING_ARTIFACTS = {
    "keel.verifier_claim_registry.v0",
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


def test_released_artifact_paths_cover_step2_closing_artifacts() -> None:
    missing = STEP2_CLOSING_ARTIFACTS - set(RELEASED_ARTIFACT_PATHS)
    assert not missing


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


@pytest.mark.parametrize(
    ("artifact_id", "relative_path"),
    [
        (artifact_id, RELEASED_ARTIFACT_PATHS[artifact_id])
        for artifact_id in sorted(STEP2_CLOSING_ARTIFACTS)
    ],
)
def test_keel_api_verifier_additive_artifact_matches_keel_permit_source_bytes(
    artifact_id: str,
    relative_path: str,
) -> None:
    api_root = SOURCE_API / "app" / "verifier_additive_artifacts"
    if not api_root.exists():
        message = (
            "keel-api verifier_additive_artifacts is not checked out next to "
            f"keel-verifier: {api_root}"
        )
        if os.getenv("KEEL_REQUIRE_GOLDEN_CORPUS"):
            raise FileNotFoundError(message)
        pytest.skip(message)

    source_artifact = SOURCE_PERMIT / relative_path
    if not source_artifact.exists():
        message = (
            "keel-permit released artifact is not checked out next to "
            f"keel-verifier: {source_artifact}"
        )
        if os.getenv("KEEL_REQUIRE_GOLDEN_CORPUS"):
            raise FileNotFoundError(message)
        pytest.skip(message)

    api_artifact = api_root / relative_path
    assert api_artifact.exists(), (
        f"{artifact_id} is not mirrored at "
        f"keel-api/app/verifier_additive_artifacts/{relative_path}"
    )
    assert api_artifact.read_bytes() == source_artifact.read_bytes()
