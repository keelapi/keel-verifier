"""Signed non-approval review outcomes verify as deny, never as authority.

A challenged Permit's review ends in one signed transition. Only the released
approval (``permit.challenge_approved``, challenge/awaiting_attestation to
allow/attested) can authorize. Rejection, expiry, a refused reservation and a
lapsed authority each close the review as deny. An authentic, linked denial
must still let the exact pre-dispatch claims verify, with the verified final
state reported as deny; a forged, unsigned, mismatched or out-of-order one must
not verify at all.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from keel_verifier import verifier
from keel_verifier.permit_exact_v2 import adjudicate_permit_exact_v2_body
from test_bundle_outer_signer_pinning import _args
from test_permit_exact_final_state import _case
from test_permit_exact_v2 import _v3_work_body

EXACT = ("permit.type.v1", "permit.exact_target.v1", "permit.material_request.v1")
DENIALS = [
    ("permit.challenge_rejected", "evaluated"),
    ("permit.challenge_expired", "expired"),
    ("permit.challenge_approval_reservation_denied", "evaluated"),
    ("permit.challenge_approval_authority_lapsed", "evaluated"),
]
FIXTURES = Path(__file__).parent / "fixtures" / "permit_exact_review_outcomes"


def _claims(report):
    return {claim.name: claim for claim in report.claims}


def _denial(tmp_path, event_type, status, **kwargs):
    kwargs.setdefault("version", 2)
    return _case(
        tmp_path, initial="challenge", final="deny", final_status=status,
        transition=True, event_type=event_type, **kwargs,
    )


def _assert_refused(report):
    assert not report.ok
    assert "permit" not in report.artifact
    claims = _claims(report)
    for name in EXACT:
        assert claims[name].aggregate_verdict != "supported", name


@pytest.mark.parametrize("version", [2, 3, 4])
@pytest.mark.parametrize("event_type,status", DENIALS)
def test_authentic_review_denial_verifies_as_deny(tmp_path, version, event_type, status):
    report = _denial(tmp_path, event_type, status, version=version)

    assert report.ok, report.error
    assert report.artifact["permit"]["decision"] == "deny"
    assert report.artifact["permit"]["status"] == status
    claims = _claims(report)
    assert claims["permit.decision.v1"].aggregate_verdict == "supported"
    assert claims["permit.review_transition.v1"].aggregate_verdict == "supported"
    for name in EXACT:
        assert claims[name].aggregate_verdict == "supported", name


@pytest.mark.parametrize("event_type,_status", DENIALS)
def test_review_denial_cannot_reach_an_authorizing_state(tmp_path, event_type, _status):
    # Correctly signed and fully linked, but a denial outcome naming allow.
    report = _case(
        tmp_path, initial="challenge", final="allow", final_status="attested",
        transition=True, event_type=event_type,
    )
    _assert_refused(report)
    assert _claims(report)["permit.type.v1"].reason_code == (
        "PERMIT_EXACT_REVIEW_TRANSITION_UNSUPPORTED"
    )


def test_approval_event_cannot_carry_a_denial_target(tmp_path):
    report = _case(
        tmp_path, initial="challenge", final="deny", final_status="evaluated",
        transition=True, event_type="permit.challenge_approved",
    )
    _assert_refused(report)


@pytest.mark.parametrize("event_type,status", DENIALS)
@pytest.mark.parametrize("changes", [
    {"permit_id": "other-permit"},
    {"project_id": "other-project"},
    {"from_decision": "deny"},
    {"from_status": "pending_review"},
    {"to_status": "revoked"},
])
def test_signed_but_mismatched_review_denial_fails(tmp_path, event_type, status, changes):
    report = _denial(tmp_path, event_type, status, event_changes=changes)
    _assert_refused(report)
    claims = _claims(report)
    # The signature itself is authentic; the linkage is what fails.
    assert claims["permit.review_transition.v1"].aggregate_verdict == "supported"
    assert claims["permit.type.v1"].reason_code == "PERMIT_EXACT_REVIEW_TRANSITION_UNSUPPORTED"


@pytest.mark.parametrize("event_type,wrong_status", [
    ("permit.challenge_rejected", "expired"),
    ("permit.challenge_expired", "evaluated"),
    ("permit.challenge_approval_reservation_denied", "expired"),
    ("permit.challenge_approval_authority_lapsed", "attested"),
])
def test_review_denial_target_status_is_fixed_by_event_type(tmp_path, event_type, wrong_status):
    report = _denial(tmp_path, event_type, wrong_status)
    _assert_refused(report)


@pytest.mark.parametrize("event_type", [
    "permit.challenge_cancelled", "permit.review.rejected", "permit.challenge_rejected.v2",
])
def test_unreleased_review_outcome_fails(tmp_path, event_type):
    report = _denial(tmp_path, event_type, "evaluated")
    _assert_refused(report)


@pytest.mark.parametrize("initial", ["allow", "deny"])
def test_review_denial_requires_a_challenged_permit(tmp_path, initial):
    report = _case(
        tmp_path, initial=initial, final="deny", final_status="evaluated",
        transition=True, event_type="permit.challenge_rejected",
    )
    _assert_refused(report)


@pytest.mark.parametrize("event_type,status", DENIALS)
def test_review_denial_must_match_recorded_state(tmp_path, event_type, status):
    other = "expired" if status == "evaluated" else "evaluated"
    report = _denial(tmp_path, event_type, status, body_changes={
        "decision_state": {"decision": "deny", "status": other},
    })
    _assert_refused(report)


@pytest.mark.parametrize("forgery", [
    {"bad_signature": True},
    {"forge_key": True},
    {"post_sign_changes": {"actor_id": "someone-else"}},
    {"post_sign_changes": {"actor_id": "someone-else"}, "rehash_after_changes": True},
])
@pytest.mark.parametrize("event_type,status", DENIALS[:2])
def test_forged_review_denial_fails(tmp_path, event_type, status, forgery):
    report = _denial(tmp_path, event_type, status, **forgery)
    _assert_refused(report)
    assert _claims(report)["permit.review_transition.v1"].aggregate_verdict != "supported"


@pytest.mark.parametrize("rehash", [False, True])
@pytest.mark.parametrize("event_type,status", DENIALS)
def test_signed_denial_rewritten_as_approval_fails(tmp_path, event_type, status, rehash):
    report = _denial(
        tmp_path, event_type, status,
        post_sign_changes={
            "event_type": "permit.challenge_approved",
            "to_decision": "allow", "to_status": "attested",
        },
        rehash_after_changes=rehash,
        body_changes={"decision_state": {"decision": "allow", "status": "attested"}},
    )
    _assert_refused(report)
    assert _claims(report)["permit.review_transition.v1"].aggregate_verdict == "disproved"


@pytest.mark.parametrize("event_type,status", DENIALS[:2])
@pytest.mark.parametrize("unsigned", [
    {"drop_signature": True},
    {"post_sign_changes": {"signature": ""}},
    {"post_sign_changes": {"signature": None}},
])
def test_unsigned_review_denial_fails(tmp_path, event_type, status, unsigned):
    report = _denial(tmp_path, event_type, status, **unsigned)
    _assert_refused(report)
    assert _claims(report)["permit.review_transition.v1"].aggregate_verdict != "supported"


@pytest.mark.parametrize("event_type,status", DENIALS)
def test_review_denial_before_issuance_fails(tmp_path, event_type, status):
    # Within the binding key's validity window, one second before issuance.
    report = _denial(
        tmp_path, event_type, status, event_changes={"decision_at": "2026-07-30T11:59:59Z"},
    )
    _assert_refused(report)
    assert _claims(report)["permit.type.v1"].reason_code == (
        "PERMIT_EXACT_REVIEW_TRANSITION_TIME_INVALID"
    )


@pytest.mark.parametrize("decision_at", ["not-a-time", ""])
def test_review_denial_without_a_signed_time_fails(tmp_path, decision_at):
    report = _denial(
        tmp_path, "permit.challenge_rejected", "evaluated",
        event_changes={"decision_at": decision_at},
    )
    _assert_refused(report)


@pytest.mark.parametrize("changes", [
    {"status": "revoked"}, {"status": "compromised"},
    {"valid_from": "2026-07-30T12:05:01Z"},
])
@pytest.mark.parametrize("event_type,status", DENIALS[:2])
def test_review_denial_key_must_be_active_at_decision(tmp_path, event_type, status, changes):
    report = _denial(tmp_path, event_type, status, binding_changes=changes)
    _assert_refused(report)


@pytest.mark.parametrize("event_type,status", DENIALS)
def test_review_denial_never_reads_as_dispatch_authority(event_type, status):
    body = _v3_work_body()
    body["declared_claims"] = list(dict.fromkeys([
        *body["declared_claims"],
        "permit.enforced_at_certified_boundary.v1", "permit.valid_at_dispatch.v1",
    ]))
    body["permit_decision"]["canonical_payload"]["decision"] = "challenge"
    body["decision_state"] = {"decision": "deny", "status": status}
    body["review_transition"] = {"status": "present", "signed_event": {
        "event_type": event_type, "permit_id": body["permit_id"],
        "project_id": body["project_id"], "decision_at": "2026-07-30T12:05:00Z",
        "from_decision": "challenge", "from_status": "awaiting_attestation",
        "to_decision": "deny", "to_status": status,
    }}
    result = adjudicate_permit_exact_v2_body(
        body, decision_verdict="supported", review_transition_verdict="supported",
        signed_artifact_verifier=lambda *_: (True, None),
    )
    claims = {c.name: c for c in result.claims}
    assert result.decision == "deny"
    assert result.status == status
    assert claims["permit.valid_at_dispatch.v1"].verdict == "disproved"
    assert claims["permit.valid_at_dispatch.v1"].reason_code == "PERMIT_REVIEW_DENIED_DISPATCH"
    assert claims["permit.enforced_at_certified_boundary.v1"].verdict != "supported"


def _verify_fixture(name: str):
    path = FIXTURES / f"{name}.v4.json"
    trust = FIXTURES / "trust_keys.json"
    report = verifier.verify_export_structured(_args(path, key_manifest=trust))
    body = json.loads(path.read_text())["body"]
    decision_claim = next(c for c in report.claims if c.name == "permit.decision.v1")
    _, summary = verifier._adjudicate_permit_exact_v2(
        body=body, decision_claim=decision_claim, key_manifest_source=str(trust),
    )
    return body, report, summary


@pytest.mark.parametrize("name,event_type,status", [
    ("rejected", "permit.challenge_rejected", "evaluated"),
    ("expired", "permit.challenge_expired", "expired"),
    ("reservation_denied", "permit.challenge_approval_reservation_denied", "evaluated"),
    ("authority_lapsed", "permit.challenge_approval_authority_lapsed", "evaluated"),
])
def test_api_produced_review_denial_pack_verifies_as_deny(name, event_type, status):
    """Regression: keel-api's own packs for each denial outcome.

    The fixtures are unmodified ``/v1/permits/{id}/bundle?profile=permit-exact.v4``
    responses from a local keel-api test run (synthetic project, deterministic
    test signing keys). 3.30.0 before this fix disproved every exact claim in
    them with PERMIT_EXACT_REVIEW_TRANSITION_UNSUPPORTED.
    """
    body, report, summary = _verify_fixture(name)
    assert body["review_transition"]["signed_event"]["event_type"] == event_type
    claims = _claims(report)
    assert claims["evidence_bundle.self_attesting.v1"].aggregate_verdict == "supported"
    assert claims["permit.decision.v1"].aggregate_verdict == "supported"
    assert claims["permit.review_transition.v1"].aggregate_verdict == "supported"
    for claim_name in EXACT:
        assert claims[claim_name].aggregate_verdict == "supported", claim_name
    assert claims["permit.valid_at_dispatch.v1"].aggregate_verdict != "supported"
    assert summary["decision"] == "deny"
    assert summary["status"] == status
    # The pack also declares dispatch and provider claims it has no evidence
    # for, so the report as a whole is not a success.
    assert not report.ok


def test_api_produced_approval_pack_is_unchanged():
    body, report, summary = _verify_fixture("approved")
    assert body["review_transition"]["signed_event"]["event_type"] == "permit.challenge_approved"
    claims = _claims(report)
    for claim_name in (*EXACT, "permit.decision.v1", "permit.review_transition.v1"):
        assert claims[claim_name].aggregate_verdict == "supported", claim_name
    assert summary["decision"] == "allow"
    assert summary["status"] == "attested"
