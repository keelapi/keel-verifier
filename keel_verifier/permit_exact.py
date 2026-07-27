"""Offline validation of ``keel.permit_exact/v1`` evidence-pack bodies."""

from __future__ import annotations

import hashlib
from importlib import resources
import json
from typing import Any, Mapping

import jsonschema
import rfc8785

from keel_verifier.action_classification_derivation import (
    default_trust_config,
    derive,
)


PROFILE = "keel.permit_exact/v1"
_DATA_ROOT = "data/permit_to_x"
_TRANSITION_SIGNED_FIELDS = (
    "event_type",
    "permit_id",
    "project_id",
    "decision_at",
    "actor_id",
    "actor_kind",
    "from_decision",
    "from_status",
    "to_decision",
    "to_status",
)


def _resource(path: str):
    return resources.files("keel_verifier").joinpath(f"{_DATA_ROOT}/{path}")


def _bytes(path: str) -> bytes:
    return _resource(path).read_bytes()


def _json(path: str) -> dict[str, Any]:
    value = json.loads(_resource(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"vendored artifact {path} must be an object")
    return value


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _jcs_digest(value: Mapping[str, Any]) -> str:
    return _sha256(rfc8785.dumps(dict(value)))


def _one_entry(
    values: Any,
    *,
    key: str,
    expected: str,
) -> dict[str, Any]:
    if not isinstance(values, list):
        raise ValueError(f"registry {key} entries are missing")
    matches = [
        dict(value)
        for value in values
        if isinstance(value, dict) and value.get(key) == expected
    ]
    if len(matches) != 1:
        raise ValueError(f"registry must contain exactly one {key}={expected}")
    return matches[0]


def _require_equal(actual: Any, expected: Any, *, field: str) -> None:
    if actual != expected:
        raise ValueError(f"{field} mismatch")


def verify_permit_exact_body(body: Mapping[str, Any]) -> dict[str, Any]:
    """Validate profile contracts, fact binding, derivation, and optional opening."""

    if body.get("profile") != PROFILE or body.get("profile_version") != 1:
        raise ValueError("body profile must be keel.permit_exact/v1 version 1")
    binding = body.get("semantic_binding")
    facts = body.get("authorization_facts")
    if not isinstance(binding, dict) or not isinstance(facts, dict):
        raise ValueError("semantic_binding and authorization_facts are required")
    _require_equal(
        binding.get("semantic_id"),
        "keel.action.payment_execute.v1",
        field="semantic_binding.semantic_id",
    )
    _require_equal(
        binding.get("fact_profile_id"),
        "keel.facts.payment_exact.v1",
        field="semantic_binding.fact_profile_id",
    )

    selector_registry = _json("semantic_registry/v3.json")
    selector_entry = _one_entry(
        selector_registry.get("entries"),
        key="semantic_id",
        expected="keel.action.payment_execute.v1",
    )
    _require_equal(
        binding.get("selector_registry_version"),
        selector_registry.get("version"),
        field="selector_registry_version",
    )
    _require_equal(
        binding.get("selector_registry_digest"),
        _sha256(_bytes("semantic_registry/v3.json")),
        field="selector_registry_digest",
    )
    _require_equal(
        binding.get("selector_entry_digest"),
        _jcs_digest(selector_entry),
        field="selector_entry_digest",
    )

    fact_registry = _json("fact_profiles/v1.json")
    fact_profile = _one_entry(
        fact_registry.get("profiles"),
        key="fact_profile_id",
        expected="keel.facts.payment_exact.v1",
    )
    schema = _json("schemas/payment-exact-facts-v1.schema.json")
    supplied_fact_contract = body.get("fact_contract")
    if not isinstance(supplied_fact_contract, dict):
        raise ValueError("fact_contract is required")
    _require_equal(
        supplied_fact_contract.get("registry_version"),
        fact_registry.get("version"),
        field="fact_contract.registry_version",
    )
    _require_equal(
        supplied_fact_contract.get("profile"),
        fact_profile,
        field="fact_contract.profile",
    )
    _require_equal(
        supplied_fact_contract.get("facts_schema"),
        schema,
        field="fact_contract.facts_schema",
    )
    supplied_semantic_contract = body.get("semantic_contract")
    if not isinstance(supplied_semantic_contract, dict):
        raise ValueError("semantic_contract is required")
    _require_equal(
        supplied_semantic_contract.get("registry_version"),
        selector_registry.get("version"),
        field="semantic_contract.registry_version",
    )
    _require_equal(
        supplied_semantic_contract.get("entry"),
        selector_entry,
        field="semantic_contract.entry",
    )
    _require_equal(
        binding.get("fact_profile_registry_version"),
        fact_registry.get("version"),
        field="fact_profile_registry_version",
    )
    _require_equal(
        binding.get("fact_profile_registry_digest"),
        _sha256(_bytes("fact_profiles/v1.json")),
        field="fact_profile_registry_digest",
    )
    _require_equal(
        binding.get("fact_profile_entry_digest"),
        _jcs_digest(fact_profile),
        field="fact_profile_entry_digest",
    )
    _require_equal(
        binding.get("authorization_facts_schema_digest"),
        _sha256(_bytes("schemas/payment-exact-facts-v1.schema.json")),
        field="authorization_facts_schema_digest",
    )
    _require_equal(
        binding.get("authorization_facts_digest"),
        _jcs_digest(facts),
        field="authorization_facts_digest",
    )
    _require_equal(
        binding.get("authorization_facts_canonicalization"),
        "rfc8785",
        field="authorization_facts_canonicalization",
    )
    jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    ).validate(facts)

    receipt = body.get("permit_receipt")
    if not isinstance(receipt, dict):
        raise ValueError("permit_receipt is required")
    action = receipt.get("action")
    attrs = action.get("resource_attributes_json") if isinstance(action, dict) else None
    if not isinstance(attrs, dict):
        raise ValueError("permit_receipt action resource attributes are required")
    _require_equal(
        attrs.get("permit_semantic_binding_v1"),
        binding,
        field="signed semantic binding",
    )
    _require_equal(
        attrs.get("permit_authorization_facts_v1"),
        facts,
        field="signed authorization facts",
    )

    classification = attrs.get("payment_classification_v1")
    if not isinstance(classification, dict):
        raise ValueError("signed payment classification is missing")
    derivation = derive(classification, default_trust_config())
    if derivation.outcome != "valid" or derivation.authorized_action != "payment.execute":
        raise ValueError(
            "signed payment classification does not re-derive payment.execute"
        )

    permit_decision = body.get("permit_decision")
    canonical_payload = (
        permit_decision.get("canonical_payload")
        if isinstance(permit_decision, dict)
        else None
    )
    if not isinstance(canonical_payload, dict):
        raise ValueError("permit_decision canonical_payload is required")
    _require_equal(
        str(canonical_payload.get("permit_id") or ""),
        str(body.get("permit_id") or ""),
        field="permit_decision permit_id",
    )
    project_id = str(canonical_payload.get("project_id") or "")
    if body.get("project_id") is not None:
        _require_equal(
            project_id,
            str(body.get("project_id") or ""),
            field="permit_decision project_id",
        )

    decision_state = body.get("decision_state")
    if not isinstance(decision_state, dict):
        raise ValueError("decision_state is required")
    initial_decision = str(canonical_payload.get("decision") or "").lower()
    final_decision = str(decision_state.get("decision") or "").lower()
    final_status = str(decision_state.get("status") or "").lower()
    transition = body.get("review_transition")
    transition_status = (
        transition.get("status") if isinstance(transition, dict) else None
    )
    if transition_status == "present":
        signed_event = transition.get("signed_event")
        if not isinstance(signed_event, dict):
            raise ValueError("present review_transition is missing signed_event")
        if set(signed_event) != {*_TRANSITION_SIGNED_FIELDS, "signature"}:
            raise ValueError("review_transition signed_event has an invalid shape")
        unsigned = {key: signed_event[key] for key in _TRANSITION_SIGNED_FIELDS}
        transition_hash = hashlib.sha256(
            json.dumps(
                unsigned,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        _require_equal(
            transition.get("canonical_hash"),
            transition_hash,
            field="review_transition canonical_hash",
        )
        _require_equal(
            signed_event.get("permit_id"),
            str(body.get("permit_id") or ""),
            field="review_transition permit_id",
        )
        _require_equal(
            signed_event.get("project_id"),
            project_id,
            field="review_transition project_id",
        )
        _require_equal(
            signed_event.get("from_decision"),
            initial_decision,
            field="review_transition from_decision",
        )
        _require_equal(
            signed_event.get("to_decision"),
            final_decision,
            field="review_transition to_decision",
        )
        _require_equal(
            signed_event.get("to_status"),
            final_status,
            field="review_transition to_status",
        )
    elif transition_status == "not_present":
        _require_equal(
            final_decision,
            initial_decision,
            field="decision_state without review transition",
        )
    else:
        raise ValueError("review_transition status must be present or not_present")

    authorization_status = (
        "approved"
        if final_decision == "allow"
        else "review_required"
        if final_decision == "challenge"
        else "denied"
    )
    opening = body.get("recipient_opening")
    recipient_value: str | None = None
    if isinstance(opening, dict) and opening.get("status") == "disclosed":
        payload = opening.get("opening")
        if not isinstance(payload, dict):
            raise ValueError("disclosed recipient opening is missing")
        recipient_value = str(payload.get("value") or "")
        salt = str(payload.get("salt") or "")
        commitment = facts.get("recipient_reference_commitment")
        expected = (
            commitment.get("digest") if isinstance(commitment, dict) else None
        )
        actual = _jcs_digest(
            {
                "profile": "keel.salted_sha256_jcs.v1",
                "salt": salt,
                "value": recipient_value,
            }
        )
        _require_equal(actual, expected, field="recipient opening commitment")

    return {
        "permit_id": str(body.get("permit_id") or ""),
        "title": "AI Permit-to-Pay",
        "decision": authorization_status,
        "authorized_action": "payment.execute",
        "amount_minor": facts.get("amount_minor"),
        "currency": facts.get("currency"),
        "payment_rail": facts.get("payment_rail"),
        "request_digest": facts.get("request_digest"),
        "recipient": recipient_value,
        "recipient_opening_status": (
            opening.get("status") if isinstance(opening, dict) else "missing"
        ),
    }


__all__ = ["PROFILE", "verify_permit_exact_body"]
