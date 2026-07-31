from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keel_verifier.canonical.permit_binding import (
    canonical_resource_attributes_payload,
)
from keel_verifier.permit_exact_v2 import (
    UNIVERSAL_CLAIMS,
    adjudicate_permit_exact_v2_body,
)
from keel_verifier.verifier import (
    _adjudicate_permit_exact_v2,
    _permit_claim,
    _verify_permit_exact_v2_signed_artifact,
)


ROOT = Path(__file__).resolve().parents[1] / "keel_verifier" / "data"
PTX = ROOT / "permit_to_x"


def _digest_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _digest_object(value: dict) -> str:
    return _digest_bytes(rfc8785.dumps(value))


def _pin(
    path: Path,
    *,
    artifact_id: str,
    version: str | None = None,
) -> dict:
    raw = path.read_bytes()
    payload = json.loads(raw)
    return {
        "artifact_id": artifact_id,
        "version": str(version or payload.get("version") or "draft-2020-12"),
        "sha256": _digest_bytes(raw),
        "media_type": "application/json",
        "content_base64": base64.b64encode(raw).decode("ascii"),
    }


def _signed_shape(fields: dict) -> dict:
    canonical_hash = _digest_object(fields)
    return {
        **fields,
        "canonical_hash": canonical_hash,
        "signature": "ed25519:"
        + base64.b64encode(b"s" * 64).decode("ascii"),
    }


def _real_signed_shape(fields: dict, private_key: Ed25519PrivateKey) -> dict:
    canonical_hash = _digest_object(fields)
    signature = private_key.sign(canonical_hash.encode("utf-8"))
    return {
        **fields,
        "canonical_hash": canonical_hash,
        "signature": "ed25519:" + base64.b64encode(signature).decode("ascii"),
    }


def _body() -> dict:
    selector_path = PTX / "semantic_registry/v3.json"
    selector_registry = json.loads(selector_path.read_text(encoding="utf-8"))
    selector_entry = next(
        entry
        for entry in selector_registry["entries"]
        if entry["semantic_id"] == "keel.action.payment_execute.v1"
    )
    fact_path = PTX / "fact_profiles/v2.json"
    fact_registry = json.loads(fact_path.read_text(encoding="utf-8"))
    fact_profile = fact_registry["profiles"][0]
    facts_schema_path = PTX / "schemas/payment-exact-facts-v1.schema.json"
    classification_corpus = json.loads(
        (
            PTX / "test_vectors/action_classification_derivation/v1/corpus.json"
        ).read_text(encoding="utf-8")
    )
    facts = {
        "version": "keel.payment_exact_facts.v1",
        "fact_profile_id": "keel.facts.payment_exact.v1",
        "action": "payment.execute",
        "amount_minor": 5000,
        "currency": "USD",
        "recipient_reference_commitment": {
            "method": "keel.salted_sha256_jcs.v1",
            "digest": "sha256:" + "a" * 64,
        },
        "payment_rail": "stripe.payment_intent",
        "request_digest": "sha256:" + "6" * 64,
    }
    claim_path = ROOT / "claim_registry/v2.json"
    universal_path = ROOT / "semantics/permit/universal_verification_v1.json"
    provider_semantics_path = ROOT / "semantics/permit/provider_receipt_state_v1.json"
    binding = {
        "version": "keel.permit_semantic_binding.v2",
        "semantic_id": "keel.action.payment_execute.v1",
        "selector_registry_version": selector_registry["version"],
        "selector_registry_digest": _digest_bytes(selector_path.read_bytes()),
        "selector_entry_digest": _digest_object(selector_entry),
        "trusted_source_kind": "action_verb_execute",
        "chain_role": "action_child",
        "action_name": "payment.execute",
        "operation": "payment.execute",
        "governed_surface": "payment_rail",
        "non_authorizing_presentation_profile_id": "permit_to_pay.r1",
        "claim_registry_version": "verifier-claims.v2",
        "claim_registry_digest": _digest_bytes(claim_path.read_bytes()),
        "universal_semantics_id": "keel.permit.universal_verification.v1",
        "universal_semantics_digest": _digest_bytes(universal_path.read_bytes()),
        "fact_profile_id": "keel.facts.payment_exact.v1",
        "fact_profile_registry_version": fact_registry["version"],
        "fact_profile_registry_digest": _digest_bytes(fact_path.read_bytes()),
        "fact_profile_entry_digest": _digest_object(fact_profile),
        "authorization_facts_schema_digest": _digest_bytes(
            facts_schema_path.read_bytes()
        ),
        "authorization_facts_digest": _digest_object(facts),
        "authorization_facts_canonicalization": "rfc8785",
        "derived_at": "2026-07-30T12:00:00Z",
    }
    attributes = {
        "permit_semantic_binding_v2": binding,
        "permit_authorization_facts_v1": facts,
        "payment_classification_v1": classification_corpus["vectors"][0]["facts"],
    }
    permit_id = "permit_test"
    project_id = "project_test"
    return {
        "profile": "keel.permit_exact/v2",
        "profile_version": 2,
        "generated_at": "2026-07-30T12:20:00Z",
        "permit_id": permit_id,
        "project_id": project_id,
        "declared_claims": ["permit.decision.v1", *UNIVERSAL_CLAIMS],
        "semantic_binding": binding,
        "authorization_facts": facts,
        "contract_pins": {
            "claim_registry": _pin(
                claim_path,
                artifact_id="keel.verifier_claim_registry.v2",
            ),
            "semantic_selector_registry": _pin(
                selector_path,
                artifact_id="keel.permit.semantic_selector_registry",
            ),
            "semantic_selector_entry_digest": _digest_object(selector_entry),
            "fact_profile_registry": _pin(
                fact_path,
                artifact_id="keel.permit.fact_profile_registry",
            ),
            "fact_profile_entry_digest": _digest_object(fact_profile),
            "authorization_facts_schema": _pin(
                facts_schema_path,
                artifact_id="keel.permit.payment_exact_facts.v1.schema",
            ),
            "universal_semantics": _pin(
                universal_path,
                artifact_id="keel.permit.universal_verification.v1",
            ),
            "provider_receipt_semantics": _pin(
                provider_semantics_path,
                artifact_id="keel.provider.receipt_state.v1",
            ),
        },
        "permit_decision": {
            "canonical_payload": {
                "permit_id": permit_id,
                "project_id": project_id,
                "decision": "allow",
                "issued_at": "2026-07-30T12:00:00Z",
                "expires_at": "2026-07-30T13:00:00Z",
                "constraints": {},
                "resource_attributes_canonical_hash": (
                    canonical_resource_attributes_payload(attributes)
                ),
            },
            "resource_attributes_json": copy.deepcopy(attributes),
        },
        "permit_receipt": {
            "action": {"resource_attributes_json": copy.deepcopy(attributes)}
        },
        "decision_state": {"decision": "allow", "status": "active"},
        "review_transition": {"status": "not_present"},
        "bounded_use_transitions": [],
        "provider_receipts": [],
        "selective_disclosures": [],
        "scope_evidence": [],
        "does_not_establish": ["external real-world outcome"],
    }


def _claim_map(result) -> dict[str, object]:
    return {claim.name: claim for claim in result.claims}


def test_v2_emits_every_declared_claim_once() -> None:
    result = adjudicate_permit_exact_v2_body(
        _body(),
        decision_verdict="supported",
    )
    claims = _claim_map(result)

    assert len(result.claims) == len(UNIVERSAL_CLAIMS)
    assert set(claims) == set(UNIVERSAL_CLAIMS)
    assert claims["permit.type.v1"].verdict == "supported"
    assert claims["permit.exact_target.v1"].verdict == "supported"
    assert claims["permit.material_request.v1"].verdict == "supported"
    assert claims["permit.valid_at_dispatch.v1"].verdict == "insufficient_evidence"
    assert claims["permit.revocation_at_dispatch.v1"].verdict == "unverifiable_scope"
    assert claims["provider.completed.v1"].reason_code == (
        "PROVIDER_STATE_EVIDENCE_MISSING"
    )


def test_v2_receipt_projection_divergence_disproves_exact_target() -> None:
    body = _body()
    body["permit_receipt"]["action"]["resource_attributes_json"][
        "permit_authorization_facts_v1"
    ]["recipient_reference_commitment"]["digest"] = "sha256:" + "f" * 64

    claims = _claim_map(
        adjudicate_permit_exact_v2_body(body, decision_verdict="supported")
    )

    assert claims["permit.type.v1"].verdict == "supported"
    assert claims["permit.exact_target.v1"].verdict == "disproved"
    assert claims["permit.exact_target.v1"].reason_code == (
        "PERMIT_EXACT_TARGET_MISMATCH"
    )


def test_v2_contract_pin_digest_mismatch_never_silently_drops_claims() -> None:
    body = _body()
    body["contract_pins"]["fact_profile_registry"]["sha256"] = "sha256:" + "0" * 64

    result = adjudicate_permit_exact_v2_body(
        body,
        decision_verdict="supported",
    )

    assert len(result.claims) == len(UNIVERSAL_CLAIMS)
    assert all(claim.verdict == "disproved" for claim in result.claims)
    assert all(
        claim.reason_code == "PERMIT_CONTRACT_PIN_DIGEST_MISMATCH"
        for claim in result.claims
    )


def test_v2_supports_validity_certified_boundary_bounded_use_and_provider_state() -> None:
    body = _body()
    body["permit_decision"]["canonical_payload"]["constraints"] = {
        "usage_limits": {"max_calls": 1}
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
    transition = _signed_shape(
        {
            "version": "keel.permit_bounded_use.v1",
            "counter_id": "counter_test",
            "permit_id": "permit_test",
            "project_id": "project_test",
            "counter_sequence": 1,
            "previous_transition_digest": None,
            "dispatch_id": "dispatch_test",
            "maximum_uses": 1,
            "consumed_before": 0,
            "consumed_after": 1,
            "exact_request_digest": "sha256:" + "6" * 64,
            "idempotency_key_commitment": {
                "method": "keel.hmac_sha256_jcs.v1",
                "digest": "sha256:" + "8" * 64,
            },
            "occurred_at": "2026-07-30T12:10:00Z",
            "signature_profile": "keel.ed25519.sha256_rfc8785.v1",
            "issuer_key_id": "bounded_key",
        }
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
            "state": "accepted",
            "observed_at": "2026-07-30T12:10:01Z",
            "source_class": "provider_response",
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

    result = adjudicate_permit_exact_v2_body(
        body,
        decision_verdict="supported",
        signed_artifact_verifier=lambda _artifact, _purpose, _time: (True, None),
        revocation_scope_faithful=True,
        effective_revocation_at=None,
        bounded_use_scope_faithful=True,
        matching_accepted_dispatches=1,
    )
    claims = _claim_map(result)

    for name in (
        "permit.valid_at_dispatch.v1",
        "permit.revocation_at_dispatch.v1",
        "permit.enforced_at_certified_boundary.v1",
        "permit.bounded_use.v1",
        "permit.single_use.v1",
        "permit.replay_prevented.v1",
        "permit.idempotency_bound.v1",
        "provider.receipt_state.v1",
        "provider.accepted.v1",
    ):
        assert claims[name].verdict == "supported", name
    assert claims["provider.completed.v1"].verdict == "insufficient_evidence"
    assert "provider completion" in claims[
        "provider.accepted.v1"
    ].does_not_establish


def test_v2_expiry_boundary_is_exclusive() -> None:
    body = _body()
    body["permit_decision"]["canonical_payload"]["expires_at"] = (
        "2026-07-30T12:10:00Z"
    )
    transition = _signed_shape(
        {
            "version": "keel.permit_bounded_use.v1",
            "counter_id": "counter_test",
            "permit_id": "permit_test",
            "project_id": "project_test",
            "counter_sequence": 1,
            "previous_transition_digest": None,
            "dispatch_id": "dispatch_test",
            "maximum_uses": 1,
            "consumed_before": 0,
            "consumed_after": 1,
            "exact_request_digest": "sha256:" + "6" * 64,
            "idempotency_key_commitment": {
                "method": "keel.hmac_sha256_jcs.v1",
                "digest": "sha256:" + "8" * 64,
            },
            "occurred_at": "2026-07-30T12:10:00Z",
            "signature_profile": "keel.ed25519.sha256_rfc8785.v1",
            "issuer_key_id": "bounded_key",
        }
    )
    body["permit_decision"]["canonical_payload"]["constraints"] = {
        "usage_limits": {"max_calls": 1}
    }
    body["bounded_use_transitions"] = [transition]

    claims = _claim_map(
        adjudicate_permit_exact_v2_body(
            body,
            decision_verdict="supported",
            signed_artifact_verifier=lambda _artifact, _purpose, _time: (True, None),
        )
    )

    assert claims["permit.valid_at_dispatch.v1"].verdict == "disproved"
    assert claims["permit.valid_at_dispatch.v1"].reason_code == (
        "PERMIT_EXPIRED_AT_DISPATCH"
    )


def test_v2_verifier_adapter_emits_structured_claims() -> None:
    decision_claim = _permit_claim(
        "permit.decision.v1",
        subject_type="permit",
        subject_id="permit_test",
        verdict="supported",
        reason_code="PERMIT_DECISION_SUPPORTED",
        message="signed Permit decision verified",
    )

    claims, summary = _adjudicate_permit_exact_v2(
        body=_body(),
        decision_claim=decision_claim,
        key_manifest_source=None,
    )
    by_name = {claim.name: claim for claim in claims}

    assert set(by_name) == set(UNIVERSAL_CLAIMS)
    assert by_name["permit.type.v1"].aggregate_verdict == "supported"
    assert by_name["permit.valid_at_dispatch.v1"].aggregate_verdict == (
        "insufficient_evidence"
    )
    assert summary["semantic_id"] == "keel.action.payment_execute.v1"
    assert summary["fact_profile_id"] == "keel.facts.payment_exact.v1"


def test_bounded_use_child_uses_pinned_permit_binding_authority(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(b"\x42" * 32)
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    key_id = "permit-binding-test-key"
    manifest = tmp_path / "trust-root.json"
    manifest.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "key_id": key_id,
                        "algorithm": "ed25519",
                        "public_key": (
                            "ed25519:" + base64.b64encode(public_key).decode("ascii")
                        ),
                        "purpose": "permit_binding_signing",
                        "status": "active",
                        "valid_from": "2026-01-01T00:00:00Z",
                        "valid_to": None,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    transition = _real_signed_shape(
        {
            "version": "keel.permit_bounded_use.v1",
            "occurred_at": "2026-07-30T12:10:00Z",
            "issuer_key_id": key_id,
            "signature_profile": "keel.ed25519.sha256_rfc8785.v1",
        },
        private_key,
    )

    verified, error = _verify_permit_exact_v2_signed_artifact(
        transition,
        "permit_bounded_use_signing",
        "occurred_at",
        key_manifest_source=str(manifest),
    )

    assert verified is True
    assert error is None

    unrelated_verified, unrelated_error = _verify_permit_exact_v2_signed_artifact(
        transition,
        "runtime_enforcement_signing",
        "occurred_at",
        key_manifest_source=str(manifest),
    )
    assert unrelated_verified is False
    assert "runtime_enforcement_signing" in str(unrelated_error)
