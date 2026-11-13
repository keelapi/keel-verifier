"""Deterministic standing-approval permit vectors (earned-autonomy spec v4, piece V).

Shared by ``test_standing_approval_v8.py`` and by the generator that writes
``fixtures/permit_decision_binding_v8_standing_approval_vectors.json``. The
signing key is a fixed test seed, never a production key.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from keel_verifier.canonical import permit_binding
from keel_verifier.standing_approval import STANDING_APPROVAL_COVERED_REASON
from keel_verifier.verifier import _binding_key_id_from_public_key

TEST_SEED = b"standing-approval-v8-test-seed!!"
assert len(TEST_SEED) == 32

STANDING_APPROVAL_ID = "5a000000-0000-4000-8000-000000000001"
STANDING_APPROVAL_VERSION_ID = "5a000000-0000-4000-8000-0000000000a3"
TERMS_DIGEST = "sha256:" + hashlib.sha256(b"standing approval terms v3").hexdigest()

RESOURCE_ATTRIBUTES: dict[str, Any] = {
    "operation": "identity.group_access.grant",
    "connector_identity": "okta",
}

BASE_FIELDS: dict[str, Any] = {
    "permit_id": "10000000-0000-4000-8000-0000000005a8",
    "project_id": "00000000-0000-0000-0000-000000000041",
    "parent_permit_id": None,
    "decision": "allow",
    "reason": STANDING_APPROVAL_COVERED_REASON,
    "provider": "mcp",
    "model": "okta",
    "operation": "identity.group_access.grant",
    "action_name": "identity.group_access.grant",
    "request_fingerprint": "sha256:" + "1" * 64,
    "constraints": None,
    "routing": None,
    "policy_id": "policy_okta_grants",
    "policy_version": "2026-11-13",
    "policy_snapshot_hash": "sha256:" + "2" * 64,
    "issued_at": "2026-11-13T10:00:00+00:00",
    "expires_at": "2026-11-13T10:05:00+00:00",
    "is_dry_run": False,
    "final_request_hash": "sha256:" + "3" * 64,
}
V2_FIELDS: dict[str, Any] = {
    "binding_session_id": None,
    "binding_session_event_hash": None,
    "binding_project_anchor_hash": None,
    "permit_chain_role": "session_root",
    "inherits_from": None,
    "authority_delta": None,
}
V7_FIELDS: dict[str, Any] = {
    "authority_chain_digest": None,
    "quota_reservation_id": None,
    "subject_id": "40000000-0000-4000-8000-000000000007",
    "subject_type": "agent",
    "account_id": "50000000-0000-4000-8000-000000000001",
    "org_id": None,
}
V8_FIELDS: dict[str, Any] = {
    "standing_approval_version_id": STANDING_APPROVAL_VERSION_ID,
    "terms_digest": TERMS_DIGEST,
}


def signing_key() -> tuple[Ed25519PrivateKey, str]:
    private_key = Ed25519PrivateKey.from_private_bytes(TEST_SEED)
    public = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private_key, "ed25519:" + base64.b64encode(public).decode("ascii")


def builder_fields(binding_version: str, **overrides: Any) -> dict[str, Any]:
    _private, public_key = signing_key()
    fields = dict(BASE_FIELDS)
    fields["binding_key_id"] = _binding_key_id_from_public_key(public_key)
    number = int(binding_version.removeprefix("v"))
    if number >= 2:
        fields.update(V2_FIELDS)
    if number >= 3:
        fields["spend_scope_hash"] = None
    if number >= 4:
        fields["delegation_policy_hash"] = None
    if number >= 6:
        fields["resource_attributes_canonical_hash"] = (
            permit_binding.canonical_resource_attributes_payload(RESOURCE_ATTRIBUTES)
        )
    if number >= 7:
        fields.update(V7_FIELDS)
    if number >= 8:
        fields.update(V8_FIELDS)
    fields.update(overrides)
    return fields


def sign_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Return permit decision evidence for an already-canonical payload."""

    private_key, _public = signing_key()
    canonical_hash = permit_binding.compute_canonical_binding_hash(payload)
    signature = base64.b64encode(private_key.sign(canonical_hash.encode("utf-8"))).decode(
        "ascii"
    )
    evidence: dict[str, Any] = {
        "artifact_type": "permit_decision_binding",
        "artifact_version": "permit.decision.v1",
        "canonical_payload": payload,
        "binding_canonical_hash": canonical_hash,
        "binding_signature": "ed25519:" + signature,
        "binding_issued_at": payload["issued_at"],
    }
    if payload["binding_version"] in {"v6", "v7", "v8"}:
        evidence["resource_attributes_json"] = copy.deepcopy(RESOURCE_ATTRIBUTES)
    return evidence


def decision_evidence(binding_version: str, **overrides: Any) -> dict[str, Any]:
    payload = permit_binding.canonical_binding_payload(
        binding_version=binding_version,
        **builder_fields(binding_version, **overrides),
    )
    return sign_payload(payload)


def receipt_block(**overrides: Any) -> dict[str, Any]:
    block: dict[str, Any] = {
        "admin_review": "satisfied_by_standing_approval",
        "per_action_review": False,
        "facts_trust": "gateway_asserted_keel_authenticated",
        "id": STANDING_APPROVAL_ID,
        "approval_version": 3,
        "standing_approval_version_id": STANDING_APPROVAL_VERSION_ID,
        "terms_digest": TERMS_DIGEST,
        "authorized_by": {"kind": "user", "id": "user_owner_01"},
        "co_approved_by": None,
        "authorized_at": "2026-11-01T09:00:00+00:00",
        "expires_at": "2026-12-01T09:00:00+00:00",
        "origin": "manual",
        "assurance_level": "A2",
        "usage": {"window": "rolling_24h", "used": 4, "cap": 10},
    }
    block.update(overrides)
    return block


def document(
    evidence: dict[str, Any],
    *,
    block: dict[str, Any] | None = None,
    include_receipt: bool = True,
) -> dict[str, Any]:
    doc: dict[str, Any] = {"permit_decision": evidence}
    if include_receipt:
        receipt: dict[str, Any] = {
            "receipt_type": "permit_receipt",
            "decision": {"decision": "allow", "reason": evidence["canonical_payload"]["reason"]},
        }
        if block is not None:
            receipt["standing_approval"] = block
        doc["permit_receipt"] = receipt
    return doc


def golden_vectors() -> dict[str, Any]:
    _private, public_key = signing_key()
    vectors = []
    for name, version in (
        ("v8_standing_approval_covered", "v8"),
        ("v7_standing_approval_covered", "v7"),
    ):
        fields = builder_fields(version)
        evidence = decision_evidence(version)
        payload = evidence["canonical_payload"]
        canonical_bytes = permit_binding.canonical_binding_bytes(version, payload)
        vectors.append(
            {
                "name": name,
                "binding_version": version,
                "builder_inputs": fields,
                "canonical_payload": payload,
                "canonical_key_order": list(json.loads(canonical_bytes).keys()),
                "canonical_bytes_utf8": canonical_bytes.decode("utf-8"),
                "binding_canonical_hash": evidence["binding_canonical_hash"],
                "binding_signature": evidence["binding_signature"],
                "resource_attributes_json": RESOURCE_ATTRIBUTES,
                "permit_receipt_standing_approval": receipt_block(),
            }
        )
    return {
        "description": (
            "Standing-approval covered permit vectors (earned-autonomy spec v4, "
            "piece V). Canonical bytes are RFC 8785 for v5+; key order is the JCS "
            "lexicographic order. Signature is Ed25519 over the UTF-8 bytes of "
            "binding_canonical_hash. Test key only."
        ),
        "binding_public_key": public_key,
        "binding_key_id": _binding_key_id_from_public_key(public_key),
        "covered_reason": STANDING_APPROVAL_COVERED_REASON,
        "vectors": vectors,
    }
