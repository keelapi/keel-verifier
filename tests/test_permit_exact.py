from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import rfc8785

from keel_verifier import verifier
from keel_verifier.permit_exact import verify_permit_exact_body
from keel_verifier.canonical.permit_binding import (
    canonical_binding_payload_v6,
    canonical_resource_attributes_payload,
    compute_canonical_binding_hash,
)
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
            "action": {"resource_attributes_json": copy.deepcopy(attrs)},
        },
        "permit_decision": {
            "canonical_payload": {
                "permit_id": permit_id,
                "project_id": project_id,
                "decision": "challenge",
                "resource_attributes_canonical_hash": (
                    canonical_resource_attributes_payload(attrs)
                ),
            },
            "resource_attributes_json": copy.deepcopy(attrs),
        },
        "review_transition": {
            "status": "present",
            "canonical_hash": transition_hash,
            "signed_event": {**transition_unsigned, "signature": "test-signature"},
        },
        "decision_state": {"decision": "allow", "status": "attested"},
    }


def _signed_exact_bundle_case(
    tmp_path: Path,
    *,
    divergent_receipt: bool,
    profile: str | None = None,
) -> tuple[Path, Path]:
    body = _body()
    if profile is not None:
        body["profile"] = profile
        body["profile_version"] = int(profile.rsplit("v", 1)[1])
    attrs = body["permit_decision"]["resource_attributes_json"]
    binding_private = Ed25519PrivateKey.generate()
    binding_public = "ed25519:" + base64.b64encode(
        binding_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")
    binding_key_id = _binding_key_id_from_public_key(binding_public)
    payload = canonical_binding_payload_v6(
        permit_id="10000000-0000-4000-8000-000000000001",
        project_id="20000000-0000-4000-8000-000000000002",
        parent_permit_id=None,
        decision="allow",
        reason="policy.allow",
        provider="stripe",
        model="payment-intent",
        operation="payment.execute",
        action_name="payment.execute",
        request_fingerprint="sha256:" + "1" * 64,
        constraints={},
        routing={},
        policy_id="policy-exact",
        policy_version="2026-07-31",
        policy_snapshot_hash="sha256:" + "2" * 64,
        issued_at="2026-07-31T05:00:00Z",
        expires_at="2026-07-31T06:00:00Z",
        is_dry_run=False,
        binding_key_id=binding_key_id,
        final_request_hash="sha256:" + "3" * 64,
        binding_session_id=None,
        binding_session_event_hash=None,
        binding_project_anchor_hash=None,
        permit_chain_role="session_root",
        inherits_from=None,
        authority_delta={},
        spend_scope_hash=None,
        delegation_policy_hash=None,
        resource_attributes_canonical_hash=canonical_resource_attributes_payload(
            attrs
        ),
    )
    canonical_hash = compute_canonical_binding_hash(payload)
    body["permit_id"] = payload["permit_id"]
    body["project_id"] = payload["project_id"]
    body["permit_decision"] = {
        "artifact_type": "permit_decision_binding",
        "artifact_version": "permit.decision.v1",
        "canonical_payload": payload,
        "resource_attributes_json": copy.deepcopy(attrs),
        "binding_canonical_hash": canonical_hash,
        "binding_signature": "ed25519:"
        + base64.b64encode(
            binding_private.sign(canonical_hash.encode("utf-8"))
        ).decode("ascii"),
        "binding_issued_at": payload["issued_at"],
    }
    body["permit_receipt"]["action"]["resource_attributes_json"] = copy.deepcopy(
        attrs
    )
    body["review_transition"] = {"status": "not_present"}
    body["decision_state"] = {"decision": "allow", "status": "issued"}
    if divergent_receipt:
        body["permit_receipt"]["action"]["resource_attributes_json"][
            "permit_authorization_facts_v1"
        ]["amount_minor"] = 1

    artifact_id = "exact-divergence" if divergent_receipt else "exact-supported"
    artifact_material = copy.deepcopy(body)
    body["artifact_ref"] = {
        "schema_version": "artifact_ref.v1",
        "type": "permit_exact",
        "id": artifact_id,
        "urn": f"urn:x-keel:artifact:permit_exact:{artifact_id}",
        "region": "us-west-1",
        "path": f"/v1/test/{artifact_id}",
        "canonical_url": f"https://api.keelapi.com/v1/test/{artifact_id}",
        "digest": verifier._artifact_ref_digest_for_body(artifact_material),
    }

    export_private = Ed25519PrivateKey.generate()
    export_public = base64.b64encode(
        export_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")
    content_hash = verifier._content_hash(
        verifier._bundle_canonical_json_bytes(body)
    )
    bundle = {
        "schema_version": "keel.evidence_bundle/v1",
        "body": body,
        "signature_envelope": {
            "content_hash": content_hash,
            "signature": base64.b64encode(
                export_private.sign(content_hash.encode("utf-8"))
            ).decode("ascii"),
            "public_key_id": verifier._public_key_fingerprint(export_public),
            "public_key": export_public,
            "tsa_receipts": [],
            "tsa_attempts": [],
        },
    }
    export_path = tmp_path / f"{artifact_id}.json"
    export_path.write_text(
        json.dumps(bundle, sort_keys=True),
        encoding="utf-8",
    )
    trust_root = tmp_path / "binding-trust-root.json"
    trust_root.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "key_id": binding_key_id,
                        "algorithm": "ed25519",
                        "public_key": binding_public,
                        "purpose": "permit_binding_signing",
                        "status": "active",
                        "valid_from": "2026-01-01T00:00:00Z",
                        "valid_to": None,
                    }
                ]
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return export_path, trust_root


def _exact_export_args(export_path: Path, trust_root: Path) -> argparse.Namespace:
    return argparse.Namespace(
        export_file=str(export_path),
        manifest=None,
        as_json=True,
        as_raw=False,
        expected_public_key=None,
        key_manifest=str(trust_root),
        key_manifest_url=None,
        public_key=None,
        self_attested=False,
        allow_unsigned=False,
        walk_events=False,
        verify_closure=False,
        sidecar=None,
        checkpoint=None,
    )


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


def test_divergent_receipt_projection_is_rejected() -> None:
    body = _body()
    projected = body["permit_receipt"]["action"]["resource_attributes_json"]
    projected["permit_authorization_facts_v1"]["amount_minor"] = 1

    try:
        verify_permit_exact_body(body)
    except ValueError as exc:
        assert (
            "permit receipt projection versus signed permit decision resource "
            "attributes mismatch"
        ) in str(exc)
    else:
        raise AssertionError(
            "a divergent receipt projection must not authorize exact facts"
        )


def test_tampered_signed_decision_attributes_are_rejected() -> None:
    body = _body()
    body["permit_decision"]["resource_attributes_json"][
        "permit_authorization_facts_v1"
    ]["amount_minor"] = 1

    try:
        verify_permit_exact_body(body)
    except ValueError as exc:
        assert (
            "signed permit decision resource attributes commitment mismatch"
        ) in str(exc)
    else:
        raise AssertionError(
            "resource attributes outside the signed commitment must fail"
        )


def test_signed_exact_pack_rejects_divergent_receipt_projection(
    tmp_path: Path,
) -> None:
    export_path, trust_root = _signed_exact_bundle_case(
        tmp_path,
        divergent_receipt=True,
    )

    report = verifier.verify_export_structured(
        _exact_export_args(export_path, trust_root)
    )
    claims = {claim["name"]: claim for claim in report.to_dict()["claims"]}

    assert report.exit_code == 1
    assert claims["evidence_bundle.self_attesting.v1"]["verdict"] == "supported"
    assert claims["permit.decision.v1"]["verdict"] == "supported"
    assert claims["permit.exact_action.v1"]["verdict"] == "disproved"
    assert (
        claims["permit.exact_action.v1"]["reason_code"]
        == "PERMIT_EXACT_ACTION_DISPROVED"
    )
    assert "receipt projection" in claims["permit.exact_action.v1"]["message"]


def test_signed_future_exact_profile_fails_loudly(tmp_path: Path) -> None:
    export_path, trust_root = _signed_exact_bundle_case(
        tmp_path,
        divergent_receipt=False,
        profile="keel.permit_exact/v4",
    )

    report = verifier.verify_export_structured(
        _exact_export_args(export_path, trust_root)
    )

    assert report.ok is False
    assert report.exit_code == 1
    assert report.artifact["unsupported_profile"] is True
    assert report.artifact["profile"] == "keel.permit_exact/v4"
    assert report.error == (
        "PERMIT_EXACT_PROFILE_UNSUPPORTED: "
        "this verifier does not adjudicate keel.permit_exact/v4"
    )


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
