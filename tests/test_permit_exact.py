from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import rfc8785

from keel_verifier.permit_exact import verify_permit_exact_body
from keel_verifier.verifier import (
    _adjudicate_permit_review_transition_v1,
    _binding_key_id_from_public_key,
)


ROOT = Path(__file__).resolve().parents[1] / "keel_verifier" / "data" / "permit_to_x"


def _digest_bytes(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _digest_object(value: dict) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def _body() -> dict:
    selector_registry = json.loads(
        (ROOT / "semantic_registry/v3.json").read_text(encoding="utf-8")
    )
    selector_entry = next(
        entry
        for entry in selector_registry["entries"]
        if entry["semantic_id"] == "keel.action.payment_execute.v1"
    )
    fact_registry = json.loads(
        (ROOT / "fact_profiles/v1.json").read_text(encoding="utf-8")
    )
    fact_profile = fact_registry["profiles"][0]
    classification_corpus = json.loads(
        (
            ROOT
            / "test_vectors/action_classification_derivation/v1/corpus.json"
        ).read_text(encoding="utf-8")
    )
    classification = classification_corpus["vectors"][0]["facts"]
    facts = {
        "version": "keel.payment_exact_facts.v1",
        "fact_profile_id": "keel.facts.payment_exact.v1",
        "action": "payment.execute",
        "amount_minor": 5000,
        "currency": "USD",
        "recipient_reference_commitment": {
            "method": "keel.salted_sha256_jcs.v1",
            "digest": _digest_object(
                {
                    "profile": "keel.salted_sha256_jcs.v1",
                    "salt": "test-salt",
                    "value": "Irene",
                }
            ),
        },
        "payment_rail": "stripe.payment_intent",
        "request_digest": "sha256:" + "b" * 64,
    }
    binding = {
        "semantic_id": "keel.action.payment_execute.v1",
        "selector_registry_version": selector_registry["version"],
        "selector_registry_digest": _digest_bytes(
            ROOT / "semantic_registry/v3.json"
        ),
        "selector_entry_digest": _digest_object(selector_entry),
        "fact_profile_id": "keel.facts.payment_exact.v1",
        "fact_profile_registry_version": fact_registry["version"],
        "fact_profile_registry_digest": _digest_bytes(
            ROOT / "fact_profiles/v1.json"
        ),
        "fact_profile_entry_digest": _digest_object(fact_profile),
        "authorization_facts_schema_digest": _digest_bytes(
            ROOT / "schemas/payment-exact-facts-v1.schema.json"
        ),
        "authorization_facts_digest": _digest_object(facts),
        "authorization_facts_canonicalization": "rfc8785",
    }
    attrs = {
        "permit_semantic_binding_v1": binding,
        "permit_authorization_facts_v1": facts,
        "payment_classification_v1": classification,
    }
    permit_id = "permit-test"
    project_id = "project-test"
    transition_unsigned = {
        "event_type": "permit.challenge_approved",
        "permit_id": permit_id,
        "project_id": project_id,
        "decision_at": "2026-07-26T20:00:00+00:00",
        "actor_id": "actor-test",
        "actor_kind": "user",
        "from_decision": "challenge",
        "from_status": "awaiting_attestation",
        "to_decision": "allow",
        "to_status": "attested",
    }
    transition_hash = hashlib.sha256(
        json.dumps(
            transition_unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    return {
        "profile": "keel.permit_exact/v1",
        "profile_version": 1,
        "permit_id": permit_id,
        "project_id": project_id,
        "semantic_binding": binding,
        "authorization_facts": facts,
        "fact_contract": {
            "registry_version": fact_registry["version"],
            "profile": fact_profile,
            "facts_schema": json.loads(
                (
                    ROOT / "schemas/payment-exact-facts-v1.schema.json"
                ).read_text(encoding="utf-8")
            ),
        },
        "semantic_contract": {
            "registry_version": selector_registry["version"],
            "entry": selector_entry,
        },
        "recipient_opening": {
            "status": "disclosed",
            "opening": {"value": "Irene", "salt": "test-salt"},
        },
        "permit_receipt": {
            "action": {"resource_attributes_json": attrs},
        },
        "permit_decision": {
            "canonical_payload": {
                "permit_id": permit_id,
                "project_id": project_id,
                "decision": "challenge",
            }
        },
        "review_transition": {
            "status": "present",
            "canonical_hash": transition_hash,
            "signed_event": {**transition_unsigned, "signature": "test-signature"},
        },
        "decision_state": {"decision": "allow", "status": "attested"},
    }


def test_exact_payment_facts_and_recipient_opening_verify() -> None:
    result = verify_permit_exact_body(_body())
    assert result["title"] == "AI Permit-to-Pay"
    assert result["amount_minor"] == 5000
    assert result["currency"] == "USD"
    assert result["recipient"] == "Irene"


def test_tampered_amount_is_rejected() -> None:
    body = _body()
    body["authorization_facts"]["amount_minor"] = 1
    try:
        verify_permit_exact_body(body)
    except ValueError as exc:
        assert "authorization_facts_digest mismatch" in str(exc)
    else:
        raise AssertionError("tampered amount must fail verification")


def test_tampered_recipient_opening_is_rejected() -> None:
    body = _body()
    body["recipient_opening"]["opening"]["value"] = "Mallory"
    try:
        verify_permit_exact_body(body)
    except ValueError as exc:
        assert "recipient opening commitment mismatch" in str(exc)
    else:
        raise AssertionError("tampered opening must fail verification")


def test_signed_human_review_transition_is_independently_adjudicated(
    tmp_path: Path,
) -> None:
    body = _body()
    transition = body["review_transition"]
    signed_event = transition["signed_event"]
    private_key = Ed25519PrivateKey.generate()
    public_key = "ed25519:" + base64.b64encode(
        private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")
    key_id = _binding_key_id_from_public_key(public_key)
    signed_event["signature"] = base64.b64encode(
        private_key.sign(transition["canonical_hash"].encode("utf-8"))
    ).decode("ascii")
    body["permit_decision"]["canonical_payload"]["binding_key_id"] = key_id
    manifest = tmp_path / "trust.json"
    manifest.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "key_id": key_id,
                        "purpose": "permit_binding_signing",
                        "public_key": public_key,
                        "status": "active",
                        "valid_from": "2020-01-01T00:00:00Z",
                        "valid_to": None,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    supported = _adjudicate_permit_review_transition_v1(
        export_document=body,
        key_manifest_source=str(manifest),
    )
    assert supported.aggregate_verdict == "supported"

    signed_event["signature"] = base64.b64encode(b"x" * 64).decode("ascii")
    disproved = _adjudicate_permit_review_transition_v1(
        export_document=body,
        key_manifest_source=str(manifest),
    )
    assert disproved.aggregate_verdict == "disproved"
    assert disproved.reason_code == "PERMIT_REVIEW_TRANSITION_SIGNATURE_INVALID"
