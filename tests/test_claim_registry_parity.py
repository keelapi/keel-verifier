from __future__ import annotations

import os
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
PRODUCT_ROOT = REPO_ROOT.parent
BUNDLED_REGISTRY = REPO_ROOT / "keel_verifier" / "data" / "claim_registry_v0.json"
SOURCE_REGISTRY = PRODUCT_ROOT / "keel-permit" / "claim_registry" / "v0.json"


def test_bundled_claim_registry_matches_keel_permit_source_bytes():
    if not SOURCE_REGISTRY.exists():
        message = (
            "keel-permit claim registry is not checked out next to "
            f"keel-verifier: {SOURCE_REGISTRY}"
        )
        if os.getenv("KEEL_REQUIRE_GOLDEN_CORPUS"):
            raise FileNotFoundError(message)
        pytest.skip(message)

    assert BUNDLED_REGISTRY.read_bytes() == SOURCE_REGISTRY.read_bytes()
