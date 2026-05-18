from __future__ import annotations

import os
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
PRODUCT_ROOT = REPO_ROOT.parent
BUNDLED_REGISTRY = REPO_ROOT / "keel_verifier" / "data" / "claim_registry_v0.json"
SOURCE_REGISTRY = PRODUCT_ROOT / "keel-permit" / "claim_registry" / "v0.json"
BUNDLED_PROFILE = (
    REPO_ROOT
    / "keel_verifier"
    / "data"
    / "semantics"
    / "profiles"
    / "pre_pinning_default_v0.json"
)
SOURCE_PROFILE = (
    PRODUCT_ROOT
    / "keel-permit"
    / "semantics"
    / "profiles"
    / "pre_pinning_default_v0.json"
)

BUNDLED_ARTIFACT_COPIES = [
    pytest.param(
        BUNDLED_REGISTRY,
        SOURCE_REGISTRY,
        "keel-permit claim registry",
        id="claim-registry-v0",
    ),
    pytest.param(
        BUNDLED_PROFILE,
        SOURCE_PROFILE,
        "keel-permit pre-pinning semantics profile",
        id="pre-pinning-default-profile-v0",
    ),
]


@pytest.mark.parametrize(
    ("bundled_artifact", "source_artifact", "description"),
    BUNDLED_ARTIFACT_COPIES,
)
def test_bundled_artifact_matches_keel_permit_source_bytes(
    bundled_artifact: Path,
    source_artifact: Path,
    description: str,
):
    if not source_artifact.exists():
        message = (
            f"{description} is not checked out next to "
            f"keel-verifier: {source_artifact}"
        )
        if os.getenv("KEEL_REQUIRE_GOLDEN_CORPUS"):
            raise FileNotFoundError(message)
        pytest.skip(message)

    assert bundled_artifact.read_bytes() == source_artifact.read_bytes()
