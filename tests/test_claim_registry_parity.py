from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from keel_verifier.semantics import (
    CLAIM_REGISTRY_HASH,
    CLAIM_REGISTRY_ID,
    LEGACY_PROFILE_ID,
    RELEASED_ARTIFACT_HASHES,
    RELEASED_ARTIFACT_PATHS,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
BUNDLED_DATA = REPO_ROOT / "keel_verifier" / "data"

BUNDLED_ARTIFACT_COPIES = [
    pytest.param(
        BUNDLED_DATA / "claim_registry_v0.json",
        CLAIM_REGISTRY_ID,
        CLAIM_REGISTRY_HASH,
        id="claim-registry-v0-legacy-path",
    ),
    *[
        pytest.param(
            BUNDLED_DATA / relative_path,
            artifact_id,
            RELEASED_ARTIFACT_HASHES[artifact_id],
            id=(
                "pre-pinning-default-profile-v0"
                if artifact_id == LEGACY_PROFILE_ID
                else Path(relative_path).stem
            ),
        )
        for artifact_id, relative_path in sorted(RELEASED_ARTIFACT_PATHS.items())
    ],
]


def _sha256(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


@pytest.mark.parametrize(
    ("bundled_artifact", "artifact_id", "expected_hash"),
    BUNDLED_ARTIFACT_COPIES,
)
def test_bundled_artifact_matches_declared_hash(
    bundled_artifact: Path,
    artifact_id: str,
    expected_hash: str,
) -> None:
    assert bundled_artifact.exists(), (
        f"{artifact_id} is not bundled at {bundled_artifact}"
    )
    assert _sha256(bundled_artifact.read_bytes()) == expected_hash
