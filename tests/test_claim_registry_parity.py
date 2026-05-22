from __future__ import annotations

import os
import json
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
BUNDLED_GOVERNANCE_EVENT_INTEGRITY = (
    REPO_ROOT
    / "keel_verifier"
    / "data"
    / "semantics"
    / "governance_event"
    / "integrity_digest_v1.json"
)
SOURCE_GOVERNANCE_EVENT_INTEGRITY = (
    PRODUCT_ROOT
    / "keel-permit"
    / "semantics"
    / "governance_event"
    / "integrity_digest_v1.json"
)
BUNDLED_SCOPE_STATE_MERKLE = (
    REPO_ROOT
    / "keel_verifier"
    / "data"
    / "semantics"
    / "scope_state"
    / "merkle_v1.json"
)
SOURCE_SCOPE_STATE_MERKLE = (
    PRODUCT_ROOT
    / "keel-permit"
    / "semantics"
    / "scope_state"
    / "merkle_v1.json"
)
BUNDLED_SCOPE_STATE_SIDECAR_FORMAT = (
    REPO_ROOT
    / "keel_verifier"
    / "data"
    / "semantics"
    / "scope_state"
    / "sidecar_format_v1.json"
)
SOURCE_SCOPE_STATE_SIDECAR_FORMAT = (
    PRODUCT_ROOT
    / "keel-permit"
    / "semantics"
    / "scope_state"
    / "sidecar_format_v1.json"
)
BUNDLED_EXPORT_SCOPE_FAITHFULNESS = (
    REPO_ROOT
    / "keel_verifier"
    / "data"
    / "semantics"
    / "export"
    / "scope_faithfulness_v1.json"
)
BUNDLED_PERMIT_DECISION = (
    REPO_ROOT
    / "keel_verifier"
    / "data"
    / "semantics"
    / "permit"
    / "decision_v1.json"
)
SOURCE_PERMIT_DECISION = (
    PRODUCT_ROOT
    / "keel-permit"
    / "semantics"
    / "permit"
    / "decision_v1.json"
)
BUNDLED_PERMIT_REVOKED_EVENT = (
    REPO_ROOT
    / "keel_verifier"
    / "data"
    / "semantics"
    / "permit"
    / "revoked_event_v1.json"
)
SOURCE_PERMIT_REVOKED_EVENT = (
    PRODUCT_ROOT
    / "keel-permit"
    / "semantics"
    / "permit"
    / "revoked_event_v1.json"
)
BUNDLED_PERMIT_DISPATCH_ABSENCE = (
    REPO_ROOT
    / "keel_verifier"
    / "data"
    / "semantics"
    / "permit"
    / "dispatch_absence_after_revocation_v1.json"
)
SOURCE_PERMIT_DISPATCH_ABSENCE = (
    PRODUCT_ROOT
    / "keel-permit"
    / "semantics"
    / "permit"
    / "dispatch_absence_after_revocation_v1.json"
)
BUNDLED_PERMIT_REVOKED_SCHEMA = (
    REPO_ROOT
    / "keel_verifier"
    / "data"
    / "schemas"
    / "permit-revoked-event.schema.json"
)
SOURCE_PERMIT_REVOKED_SCHEMA = (
    PRODUCT_ROOT
    / "keel-permit"
    / "schemas"
    / "permit-revoked-event.schema.json"
)
SOURCE_EXPORT_SCOPE_FAITHFULNESS = (
    PRODUCT_ROOT
    / "keel-permit"
    / "semantics"
    / "export"
    / "scope_faithfulness_v1.json"
)


def _canonical_json_bytes(path: Path) -> bytes:
    return json.dumps(
        json.loads(path.read_text(encoding="utf-8")),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

BUNDLED_ARTIFACT_COPIES = [
    pytest.param(
        BUNDLED_REGISTRY,
        SOURCE_REGISTRY,
        "keel-permit claim registry",
        False,
        id="claim-registry-v0",
    ),
    pytest.param(
        BUNDLED_PROFILE,
        SOURCE_PROFILE,
        "keel-permit pre-pinning semantics profile",
        False,
        id="pre-pinning-default-profile-v0",
    ),
    pytest.param(
        BUNDLED_GOVERNANCE_EVENT_INTEGRITY,
        SOURCE_GOVERNANCE_EVENT_INTEGRITY,
        "keel-permit governance-event integrity digest semantics",
        False,
        id="governance-event-integrity-digest-v1",
    ),
    pytest.param(
        BUNDLED_SCOPE_STATE_MERKLE,
        SOURCE_SCOPE_STATE_MERKLE,
        "keel-permit scope-state Merkle semantics",
        True,
        id="scope-state-merkle-v1",
    ),
    pytest.param(
        BUNDLED_SCOPE_STATE_SIDECAR_FORMAT,
        SOURCE_SCOPE_STATE_SIDECAR_FORMAT,
        "keel-permit scope-state sidecar format semantics",
        True,
        id="scope-state-sidecar-format-v1",
    ),
    pytest.param(
        BUNDLED_EXPORT_SCOPE_FAITHFULNESS,
        SOURCE_EXPORT_SCOPE_FAITHFULNESS,
        "keel-permit export scope-faithfulness semantics",
        True,
        id="export-scope-faithfulness-v1",
    ),
    pytest.param(
        BUNDLED_PERMIT_DECISION,
        SOURCE_PERMIT_DECISION,
        "keel-permit permit decision semantics",
        False,
        id="permit-decision-v1",
    ),
    pytest.param(
        BUNDLED_PERMIT_REVOKED_EVENT,
        SOURCE_PERMIT_REVOKED_EVENT,
        "keel-permit permit revoked-event semantics",
        False,
        id="permit-revoked-event-v1",
    ),
    pytest.param(
        BUNDLED_PERMIT_DISPATCH_ABSENCE,
        SOURCE_PERMIT_DISPATCH_ABSENCE,
        "keel-permit permit dispatch absence semantics",
        False,
        id="permit-dispatch-absence-after-revocation-v1",
    ),
    pytest.param(
        BUNDLED_PERMIT_REVOKED_SCHEMA,
        SOURCE_PERMIT_REVOKED_SCHEMA,
        "keel-permit permit revoked-event schema",
        False,
        id="permit-revoked-event-schema",
    ),
]


@pytest.mark.parametrize(
    ("bundled_artifact", "source_artifact", "description", "canonical_source"),
    BUNDLED_ARTIFACT_COPIES,
)
def test_bundled_artifact_matches_keel_permit_source_bytes(
    bundled_artifact: Path,
    source_artifact: Path,
    description: str,
    canonical_source: bool,
):
    if not source_artifact.exists():
        message = (
            f"{description} is not checked out next to "
            f"keel-verifier: {source_artifact}"
        )
        if os.getenv("KEEL_REQUIRE_GOLDEN_CORPUS"):
            raise FileNotFoundError(message)
        pytest.skip(message)

    expected = (
        _canonical_json_bytes(source_artifact)
        if canonical_source
        else source_artifact.read_bytes()
    )
    assert bundled_artifact.read_bytes() == expected
