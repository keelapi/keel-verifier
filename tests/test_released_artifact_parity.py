from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from keel_verifier.semantics import (
    EXPORT_SCOPE_FAITHFULNESS_ID,
    PERMIT_AUDIT_ATTESTATION_ID,
    PERMIT_COUNTER_SIGNATURE_ID,
    PERMIT_DECISION_ID,
    PERMIT_DISPATCH_ABSENCE_AFTER_REVOCATION_ID,
    PERMIT_OPERATOR_APPROVAL_ID,
    PERMIT_REVOKED_EVENT_ID,
    RELEASED_ARTIFACT_HASHES,
    RELEASED_ARTIFACT_PATHS,
    SCOPE_STATE_MERKLE_ID,
    SCOPE_STATE_SIDECAR_FORMAT_ID,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PRODUCT_ROOT = REPO_ROOT.parent
SOURCE_PERMIT = PRODUCT_ROOT / "keel-permit"
SOURCE_API = PRODUCT_ROOT / "keel-api"
BUNDLED_DATA = REPO_ROOT / "keel_verifier" / "data"
VERIFIER_ADDITIVE_ARTIFACTS = {
    "keel.verifier_claim_registry.v0",
    EXPORT_SCOPE_FAITHFULNESS_ID,
    PERMIT_DECISION_ID,
    PERMIT_DISPATCH_ABSENCE_AFTER_REVOCATION_ID,
    PERMIT_OPERATOR_APPROVAL_ID,
    PERMIT_COUNTER_SIGNATURE_ID,
    PERMIT_AUDIT_ATTESTATION_ID,
    PERMIT_REVOKED_EVENT_ID,
    SCOPE_STATE_MERKLE_ID,
    SCOPE_STATE_SIDECAR_FORMAT_ID,
}
VERIFIER_ONLY_PIN_HASH_DRIFT = {
    # PR B B2 expands the verifier-bundled permit.decision.v1 semantics before
    # the sibling keel-api exporter pin is updated. This local-dev parity test
    # must not require a forbidden keel-api edit from the verifier-only PR.
    PERMIT_DECISION_ID,
}


def _sha256(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def test_released_artifact_paths_cover_verifier_additive_artifacts() -> None:
    missing = VERIFIER_ADDITIVE_ARTIFACTS - set(RELEASED_ARTIFACT_PATHS)
    assert not missing


@pytest.mark.parametrize(
    ("artifact_id", "relative_path"),
    sorted(RELEASED_ARTIFACT_PATHS.items()),
)
def test_released_artifact_matches_declared_bundled_hash(
    artifact_id: str,
    relative_path: str,
) -> None:
    bundled_artifact = BUNDLED_DATA / relative_path

    assert bundled_artifact.exists(), (
        f"{artifact_id} is not bundled at keel_verifier/data/{relative_path}"
    )
    assert _sha256(bundled_artifact.read_bytes()) == RELEASED_ARTIFACT_HASHES[artifact_id]


@pytest.mark.parametrize(
    ("artifact_id", "relative_path"),
    [
        (artifact_id, RELEASED_ARTIFACT_PATHS[artifact_id])
        for artifact_id in sorted(VERIFIER_ADDITIVE_ARTIFACTS)
    ],
)
def test_keel_api_verifier_additive_artifact_matches_keel_permit_source_bytes(
    artifact_id: str,
    relative_path: str,
) -> None:
    api_root = SOURCE_API / "app" / "verifier_additive_artifacts"
    if not api_root.exists():
        pytest.skip(
            "keel-api verifier_additive_artifacts is not checked out next to "
            f"keel-verifier: {api_root}. This parity test is local-dev only; "
            "CI cannot co-locate the private keel-api repo. Byte-equality was "
            "verified at PR-2 land time."
        )

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


def test_keel_api_verifier_additive_pin_constants_match_released_artifacts() -> None:
    pins_source = SOURCE_API / "app" / "services" / "verifier_pins.py"
    if not pins_source.exists():
        pytest.skip(
            "keel-api verifier_pins.py is not checked out next to "
            f"keel-verifier: {pins_source}"
        )

    text = pins_source.read_text(encoding="utf-8")
    for artifact_id in VERIFIER_ADDITIVE_ARTIFACTS:
        if artifact_id == "keel.verifier_claim_registry.v0":
            # The verifier registry can advance independently of keel-api's
            # additive registry pin; semantic payload pins stay byte-paired.
            continue
        assert artifact_id in text
        if artifact_id in VERIFIER_ONLY_PIN_HASH_DRIFT:
            assert RELEASED_ARTIFACT_PATHS[artifact_id] in text
            continue
        assert RELEASED_ARTIFACT_HASHES[artifact_id] in text
        assert RELEASED_ARTIFACT_PATHS[artifact_id] in text
