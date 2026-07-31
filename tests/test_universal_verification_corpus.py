from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

import keel_verifier.permit_exact_v2 as exact_v2
from keel_verifier.permit_exact_v2 import adjudicate_permit_exact_v2_body
from test_permit_exact_v2 import _body, _signed_shape


CORPUS = (
    Path(__file__).resolve().parents[1]
    / "keel_verifier/data/permit_to_x/test_vectors/universal_verification/v1/corpus.json"
)


def _claim(result, name: str):
    return next(claim for claim in result.claims if claim.name == name)


def _signed_artifact_verifier(_artifact, _purpose, _signed_at_field):
    return True, None


def _evidenced_body(
    *,
    maximum_uses: int = 1,
    provider_state: str = "accepted",
    provider_source: str = "provider_response",
) -> dict:
    body = _body()
    body["permit_decision"]["canonical_payload"]["constraints"] = {
        "usage_limits": {"max_calls": maximum_uses}
    }
    certification = _signed_shape(
        {
            "version": "keel.adapter_certification.v1",
            "certification_id": "cert_test",
            "adapter_id": "keel.test.payment",
            "adapter_version": "1.0.0",
            "semantic_ids": ["keel.action.payment_execute.v1"],
            "governed_surfaces": ["payment_rail"],
            "conformance_vector_set_digest": "sha256:" + "1" * 64,
            "negative_test_results_digest": "sha256:" + "2" * 64,
            "anti_bypass_requirements": ["all effects cross the final gate"],
            "issued_at": "2026-07-30T11:00:00Z",
            "expires_at": "2026-08-30T11:00:00Z",
            "revoked_at": None,
            "revocation_event_digest": None,
            "signature_profile": "keel.ed25519.sha256_rfc8785.v1",
            "issuer_key_id": "cert_key",
        }
    )
    deployment = _signed_shape(
        {
            "version": "keel.deployment_assurance.v1",
            "assurance_id": "assurance_test",
            "project_id": "project_test",
            "deployment_id": "deployment_test",
            "deployment_revision": "revision_test",
            "adapter_certification_id": "cert_test",
            "adapter_certification_digest": certification["canonical_hash"],
            "adapter_id": "keel.test.payment",
            "adapter_version": "1.0.0",
            "governed_surface": "payment_rail",
            "semantic_ids": ["keel.action.payment_execute.v1"],
            "anti_bypass_evidence_digest": "sha256:" + "3" * 64,
            "verified_at": "2026-07-30T11:05:00Z",
            "expires_at": "2026-08-15T11:05:00Z",
            "revoked_at": None,
            "revocation_event_digest": None,
            "signature_profile": "keel.ed25519.sha256_rfc8785.v1",
            "issuer_key_id": "deployment_key",
        }
    )
    runtime = _signed_shape(
        {
            "version": "keel.runtime_enforcement_proof.v1",
            "proof_id": "proof_test",
            "permit_id": "permit_test",
            "project_id": "project_test",
            "dispatch_id": "dispatch_test",
            "semantic_id": "keel.action.payment_execute.v1",
            "exact_request_digest": "sha256:" + "6" * 64,
            "adapter_certification_id": "cert_test",
            "adapter_certification_digest": certification["canonical_hash"],
            "deployment_assurance_id": "assurance_test",
            "deployment_assurance_digest": deployment["canonical_hash"],
            "gate_id": "final_dispatch_gate",
            "gate_revision": "revision_test",
            "gate_result": "allow",
            "pre_effect": True,
            "evaluated_at": "2026-07-30T12:10:00Z",
            "signature_profile": "keel.ed25519.sha256_rfc8785.v1",
            "issuer_key_id": "runtime_key",
        }
    )
    transition = _transition(
        sequence=1,
        maximum_uses=maximum_uses,
        consumed_before=0,
        consumed_after=1,
        dispatch_id="dispatch_test",
        commitment_digest="sha256:" + "8" * 64,
    )
    body["enforcement_evidence"] = {
        "adapter_certification": certification,
        "deployment_assurance": deployment,
        "runtime_enforcement_proof": runtime,
    }
    body["bounded_use_transitions"] = [transition]
    body["provider_receipts"] = [
        {
            "version": "keel.provider_receipt.v1",
            "receipt_id": "receipt_test",
            "permit_id": "permit_test",
            "project_id": "project_test",
            "dispatch_id": "dispatch_test",
            "receipt_sequence": 1,
            "provider": "stripe",
            "operation": "payment.execute",
            "semantic_id": "keel.action.payment_execute.v1",
            "state": provider_state,
            "observed_at": "2026-07-30T12:10:01Z",
            "source_class": provider_source,
            "provider_reference_commitment": {
                "method": "keel.randomized_sha256_jcs.v1",
                "digest": "sha256:" + "a" * 64,
            },
            "provider_http_status": 200,
            "exact_request_digest": "sha256:" + "6" * 64,
            "previous_receipt_digest": None,
            "evidence_digest": "sha256:" + "b" * 64,
            "reason_code": None,
            "does_not_establish": [
                "provider completion",
                "external real-world outcome",
            ],
        }
    ]
    return body


def _transition(
    *,
    sequence: int,
    maximum_uses: int,
    consumed_before: int,
    consumed_after: int,
    dispatch_id: str,
    commitment_digest: str,
) -> dict:
    return _signed_shape(
        {
            "version": "keel.permit_bounded_use.v1",
            "counter_id": "counter_test",
            "permit_id": "permit_test",
            "project_id": "project_test",
            "counter_sequence": sequence,
            "previous_transition_digest": None,
            "dispatch_id": dispatch_id,
            "maximum_uses": maximum_uses,
            "consumed_before": consumed_before,
            "consumed_after": consumed_after,
            "exact_request_digest": "sha256:" + "6" * 64,
            "idempotency_key_commitment": {
                "method": "keel.hmac_sha256_jcs.v1",
                "digest": commitment_digest,
            },
            "occurred_at": "2026-07-30T12:10:00Z",
            "signature_profile": "keel.ed25519.sha256_rfc8785.v1",
            "issuer_key_id": "bounded_key",
        }
    )


def _adjudicate(body: dict, **kwargs):
    return adjudicate_permit_exact_v2_body(
        body,
        decision_verdict="supported",
        signed_artifact_verifier=_signed_artifact_verifier,
        **kwargs,
    )


def test_universal_corpus_claims_and_reason_codes_are_executable() -> None:
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    source = Path(exact_v2.__file__).read_text(encoding="utf-8")
    declared = set(exact_v2.UNIVERSAL_CLAIMS)

    assert corpus["required_claims"] == list(exact_v2.UNIVERSAL_CLAIMS)
    for vector in corpus["vectors"]:
        assert vector["claim"] in declared
        assert vector["expected"]["reason"] in source


def test_ambiguous_semantic_selector_is_not_resolved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = exact_v2._decode_pin

    def duplicate_selector(pin, *, label, bundled_path, artifact_id):
        payload, digest = original(
            pin,
            label=label,
            bundled_path=bundled_path,
            artifact_id=artifact_id,
        )
        if label == "semantic selector registry":
            payload = copy.deepcopy(payload)
            duplicate = copy.deepcopy(
                next(
                    entry
                    for entry in payload["entries"]
                    if entry["semantic_id"] == "keel.action.payment_execute.v1"
                )
            )
            duplicate["semantic_id"] = "keel.action.ambiguous_test.v1"
            payload["entries"].append(duplicate)
        return payload, digest

    monkeypatch.setattr(exact_v2, "_decode_pin", duplicate_selector)
    result = _adjudicate(_body())

    assert _claim(result, "permit.type.v1").verdict == "insufficient_evidence"
    assert _claim(result, "permit.type.v1").reason_code == "PERMIT_TYPE_UNRESOLVED"


def test_material_request_divergence_is_disproved() -> None:
    body = _evidenced_body()
    runtime = body["enforcement_evidence"]["runtime_enforcement_proof"]
    unsigned = {
        **{
            key: value
            for key, value in runtime.items()
            if key not in {"canonical_hash", "signature"}
        },
        "exact_request_digest": "sha256:" + "f" * 64,
    }
    body["enforcement_evidence"]["runtime_enforcement_proof"] = _signed_shape(
        unsigned
    )

    result = _adjudicate(body)
    assert _claim(result, "permit.material_request.v1").reason_code == (
        "PERMIT_MATERIAL_REQUEST_MISMATCH"
    )


def test_revoked_at_dispatch_is_disproved() -> None:
    body = _evidenced_body()
    result = _adjudicate(
        body,
        revocation_scope_faithful=True,
        effective_revocation_at=exact_v2._parse_time("2026-07-30T12:09:59Z"),
    )

    assert _claim(result, "permit.revocation_at_dispatch.v1").reason_code == (
        "PERMIT_REVOKED_AT_DISPATCH"
    )


def test_certification_digest_substitution_is_disproved() -> None:
    body = _evidenced_body()
    deployment = body["enforcement_evidence"]["deployment_assurance"]
    unsigned = {
        key: value
        for key, value in deployment.items()
        if key not in {"canonical_hash", "signature"}
    }
    unsigned["adapter_certification_digest"] = "sha256:" + "f" * 64
    body["enforcement_evidence"]["deployment_assurance"] = _signed_shape(unsigned)

    result = _adjudicate(body)
    assert _claim(
        result, "permit.enforced_at_certified_boundary.v1"
    ).reason_code == "CERTIFICATION_BINDING_MISMATCH"


def test_expired_certification_is_disproved() -> None:
    body = _evidenced_body()
    certification = body["enforcement_evidence"]["adapter_certification"]
    unsigned = {
        key: value
        for key, value in certification.items()
        if key not in {"canonical_hash", "signature"}
    }
    unsigned["expires_at"] = "2026-07-30T12:09:59Z"
    replacement = _signed_shape(unsigned)
    body["enforcement_evidence"]["adapter_certification"] = replacement
    deployment = body["enforcement_evidence"]["deployment_assurance"]
    deployment_unsigned = {
        key: value
        for key, value in deployment.items()
        if key not in {"canonical_hash", "signature"}
    }
    deployment_unsigned["adapter_certification_digest"] = replacement[
        "canonical_hash"
    ]
    replacement_deployment = _signed_shape(deployment_unsigned)
    body["enforcement_evidence"]["deployment_assurance"] = replacement_deployment
    runtime = body["enforcement_evidence"]["runtime_enforcement_proof"]
    runtime_unsigned = {
        key: value
        for key, value in runtime.items()
        if key not in {"canonical_hash", "signature"}
    }
    runtime_unsigned["adapter_certification_digest"] = replacement[
        "canonical_hash"
    ]
    runtime_unsigned["deployment_assurance_digest"] = replacement_deployment[
        "canonical_hash"
    ]
    body["enforcement_evidence"]["runtime_enforcement_proof"] = _signed_shape(
        runtime_unsigned
    )

    result = _adjudicate(body)
    assert _claim(
        result, "permit.enforced_at_certified_boundary.v1"
    ).reason_code == "CERTIFICATION_NOT_ACTIVE_AT_DISPATCH"


def test_bounded_use_overflow_single_use_and_replay_fail_closed() -> None:
    body = _evidenced_body()
    first = body["bounded_use_transitions"][0]
    second = _transition(
        sequence=2,
        maximum_uses=1,
        consumed_before=1,
        consumed_after=2,
        dispatch_id="dispatch_replay",
        commitment_digest="sha256:" + "9" * 64,
    )
    second_unsigned = {
        key: value
        for key, value in second.items()
        if key not in {"canonical_hash", "signature"}
    }
    second_unsigned["previous_transition_digest"] = first["canonical_hash"]
    body["bounded_use_transitions"].append(_signed_shape(second_unsigned))

    result = _adjudicate(
        body,
        bounded_use_scope_faithful=True,
        matching_accepted_dispatches=2,
    )
    assert _claim(result, "permit.bounded_use.v1").reason_code == (
        "BOUNDED_USE_LIMIT_EXCEEDED"
    )
    assert _claim(result, "permit.single_use.v1").reason_code == (
        "SINGLE_USE_POPULATION_MISMATCH"
    )
    assert _claim(result, "permit.replay_prevented.v1").reason_code == (
        "PERMIT_REPLAY_DETECTED"
    )


def test_idempotency_commitment_cannot_be_rebound() -> None:
    body = _evidenced_body(maximum_uses=2)
    first = body["bounded_use_transitions"][0]
    second = _transition(
        sequence=2,
        maximum_uses=2,
        consumed_before=1,
        consumed_after=2,
        dispatch_id="dispatch_other",
        commitment_digest=first["idempotency_key_commitment"]["digest"],
    )
    second_unsigned = {
        key: value
        for key, value in second.items()
        if key not in {"canonical_hash", "signature"}
    }
    second_unsigned["previous_transition_digest"] = first["canonical_hash"]
    body["bounded_use_transitions"].append(_signed_shape(second_unsigned))

    result = _adjudicate(body)
    assert _claim(result, "permit.idempotency_bound.v1").reason_code == (
        "PERMIT_IDEMPOTENCY_BINDING_MISMATCH"
    )


@pytest.mark.parametrize(
    ("state", "source", "claim_name", "reason_code", "verdict"),
    [
        (
            "rejected",
            "provider_response",
            "provider.rejected.v1",
            "PROVIDER_REJECTION_VERIFIED",
            "supported",
        ),
        (
            "accepted",
            "keel_transport_observation",
            "provider.accepted.v1",
            "PROVIDER_RECEIPT_SOURCE_CEILING",
            "disproved",
        ),
        (
            "completed",
            "provider_response",
            "provider.completed.v1",
            "PROVIDER_COMPLETION_REPORTED",
            "supported",
        ),
    ],
)
def test_provider_state_evidence_ceiling(
    state: str,
    source: str,
    claim_name: str,
    reason_code: str,
    verdict: str,
) -> None:
    result = _adjudicate(
        _evidenced_body(provider_state=state, provider_source=source)
    )
    claim = _claim(result, claim_name)

    assert claim.verdict == verdict
    assert claim.reason_code == reason_code
    assert claim.does_not_establish
    if claim_name == "provider.completed.v1":
        assert "independent truth of a provider assertion" in (
            claim.does_not_establish
        )


def test_low_entropy_plain_hash_contract_is_rejected() -> None:
    fact_registry = json.loads(
        (
            Path(exact_v2.__file__).resolve().parent
            / "data/permit_to_x/fact_profiles/v2.json"
        ).read_text(encoding="utf-8")
    )
    profile = copy.deepcopy(fact_registry["profiles"][0])
    profile["fields"][1]["commitment_method"] = "keel.sha256_jcs.v1"

    with pytest.raises(exact_v2._AdjudicationError) as exc:
        exact_v2._verify_privacy_profile(
            fact_registry=fact_registry,
            fact_profile=profile,
            facts=_body()["authorization_facts"],
        )

    assert exc.value.reason_code == "DISCLOSURE_LOW_ENTROPY_PLAIN_HASH_FORBIDDEN"


def test_declared_claim_is_never_silently_omitted() -> None:
    body = _body()
    body["declared_claims"] = [
        "permit.decision.v1",
        "provider.receipt_state.v1",
    ]
    result = _adjudicate(body)

    claim = _claim(result, "provider.receipt_state.v1")
    assert claim.verdict == "insufficient_evidence"
    assert claim.reason_code == "PROVIDER_STATE_EVIDENCE_MISSING"
