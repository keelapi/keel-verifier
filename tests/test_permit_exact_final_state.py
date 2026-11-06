"""Final authorization is Permit-authority evidence, not export-producer input."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path

import pytest

from keel_verifier import verifier
from keel_verifier.canonical.permit_binding import compute_canonical_binding_hash
from test_bundle_outer_signer_pinning import (
    _args, _keypair, _manifest, _new_bundle, _sign, _write,
)
from test_permit_exact_v2 import _body


def _case(tmp_path, *, version=2, initial="allow", final="allow",
          transition=False, event_changes=None, bad_signature=False,
          declared=None, body_changes=None):
    body = _body()
    body.update(profile=f"keel.permit_exact/v{version}", profile_version=version)
    body["declared_claims"] = declared or [
        "permit.decision.v1", "permit.type.v1",
        "permit.exact_target.v1", "permit.material_request.v1",
    ]
    binding_private, binding_public, _ = _keypair()
    binding_id = verifier._binding_key_id_from_public_key("ed25519:" + binding_public)
    fixture = Path(__file__).parent / "fixtures/production_bundles/ai-ptrm-a66f7f81.json"
    payload = json.loads(fixture.read_text())["body"]["permit_decision"]["canonical_payload"]
    payload.update(body["permit_decision"]["canonical_payload"])
    payload.update(decision=initial, binding_key_id=binding_id)
    digest = compute_canonical_binding_hash(payload)
    body["permit_decision"].update(
        artifact_type="permit_decision_binding", artifact_version="permit.decision.v1",
        canonical_payload=payload, binding_canonical_hash=digest,
        binding_issued_at=payload["issued_at"],
        binding_signature="ed25519:" + base64.b64encode(
            binding_private.sign(digest.encode())
        ).decode(),
    )
    body["decision_state"] = {"decision": final, "status": "attested"}
    if transition:
        event = {
            "event_type": "permit.review.approved", "permit_id": body["permit_id"],
            "project_id": body["project_id"], "decision_at": "2026-07-30T12:05:00Z",
            "actor_id": "reviewer", "actor_kind": "user",
            "from_decision": initial, "from_status": "pending_review",
            "to_decision": final, "to_status": "attested",
        }
        event.update(event_changes or {})
        event_hash = hashlib.sha256(json.dumps(
            event, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode()).hexdigest()
        signature = binding_private.sign(event_hash.encode())
        if bad_signature:
            signature = b"x" * 64
        body["review_transition"] = {
            "status": "present", "canonical_hash": event_hash,
            "signed_event": {**event, "signature": "ed25519:" + base64.b64encode(signature).decode()},
        }
    body.update(body_changes or {})
    export_private, export_public, export_id = _keypair()
    trust = _manifest(tmp_path,
        ("permit_binding_signing", binding_id, binding_public),
        ("export_signing", export_id, export_public),
    )
    bundle = _new_bundle(body, artifact_type="permit_exact", artifact_id="final-state")
    path = _write(tmp_path, "exact.json", _sign(bundle, export_private, export_public, export_id))
    return verifier.verify_export_structured(_args(path, key_manifest=trust))


@pytest.mark.parametrize("version", [2, 3, 4])
@pytest.mark.parametrize("initial", ["deny", "challenge"])
@pytest.mark.parametrize("declared", [None, ["permit.decision.v1"], ["permit.type.v1"]])
def test_signed_non_allow_cannot_be_presented_as_allow(tmp_path, version, initial, declared):
    report = _case(tmp_path, version=version, initial=initial, declared=declared)
    assert not report.ok
    assert "permit" not in report.artifact
    claims = {c.name: c for c in report.claims}
    assert claims["permit.decision.v1"].aggregate_verdict == "supported"
    assert claims["permit.type.v1"].reason_code == "PERMIT_EXACT_FINAL_STATE_MISMATCH"


@pytest.mark.parametrize("version", [2, 3, 4])
@pytest.mark.parametrize("initial,final,transition", [
    ("allow", "allow", False), ("deny", "deny", False),
    ("challenge", "challenge", False), ("challenge", "allow", True),
])
def test_authentic_final_state_preserves_pre_dispatch_evidence(
    tmp_path, version, initial, final, transition,
):
    report = _case(tmp_path, version=version, initial=initial, final=final, transition=transition)
    assert report.ok, report.error
    assert report.artifact["permit"]["decision"] == final
    assert report.artifact["permit"]["status"] == ("attested" if transition else None)


def test_unsigned_lifecycle_status_is_not_projected_as_verified(tmp_path):
    report = _case(tmp_path, body_changes={
        "decision_state": {"decision": "allow", "status": "revoked"},
    })
    assert report.ok, report.error
    assert report.artifact["permit"]["decision"] == "allow"
    assert report.artifact["permit"]["status"] is None


@pytest.mark.parametrize("changes", [
    {"permit_id": "other-permit"}, {"project_id": "other-project"},
    {"from_decision": "deny"}, {"to_decision": "deny"}, {"to_status": "other-status"},
])
def test_valid_signature_on_unlinked_transition_fails(tmp_path, changes):
    report = _case(tmp_path, initial="challenge", transition=True, event_changes=changes)
    assert not report.ok
    assert "permit" not in report.artifact
    claims = {c.name: c for c in report.claims}
    assert claims["permit.review_transition.v1"].aggregate_verdict == "supported"
    assert claims["permit.type.v1"].reason_code == "PERMIT_EXACT_REVIEW_TRANSITION_UNSUPPORTED"


def test_invalid_review_signature_cannot_authorize(tmp_path):
    report = _case(tmp_path, initial="challenge", transition=True, bad_signature=True)
    assert not report.ok
    assert "permit" not in report.artifact


@pytest.mark.parametrize("changes", [
    {"permit_id": "other-permit"}, {"project_id": "other-project"},
    {"review_transition": {"status": "unknown"}},
    {"review_transition": {"status": ["not_present"]}},
])
def test_alternate_unsigned_identity_or_transition_state_fails(tmp_path, changes):
    report = _case(tmp_path, body_changes=copy.deepcopy(changes))
    assert not report.ok
    assert "permit" not in report.artifact
