from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import rfc8785

from keel_verifier import verifier
from keel_verifier.canonical import permit_binding
from keel_verifier.work_chain import verify_work_chain_pack
from keel_verifier.work_chain_v2 import WORK_CLAIMS_V2


PROJECT = "11111111-1111-4111-8111-111111111111"
ROOT = "22222222-2222-4222-8222-222222222222"
PHONE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
BOOKER = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
PAY_CHILD = "33333333-3333-4333-8333-333333333331"
CALL_CHILD = "33333333-3333-4333-8333-333333333332"
REVIEW_CHILD = "33333333-3333-4333-8333-333333333333"
START = "2026-08-20T20:00:00Z"
CUTOFF = "2026-08-20T20:15:00Z"
END = "2026-08-21T20:00:00Z"


def _keypair() -> tuple[Ed25519PrivateKey, str]:
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private, "ed25519:" + base64.b64encode(raw).decode("ascii")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def _content_hash(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _signature(private: Ed25519PrivateKey, value: str) -> str:
    return "ed25519:" + base64.b64encode(private.sign(value.encode())).decode()


def _artifact(artifact_id: str, artifact_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "artifact_id": artifact_id,
        "artifact_type": artifact_type,
        "artifact_digest": _digest(payload),
        "payload": payload,
    }


def _ref(artifact: dict[str, Any]) -> dict[str, str]:
    return {
        "artifact_id": artifact["artifact_id"],
        "artifact_type": artifact["artifact_type"],
        "artifact_digest": artifact["artifact_digest"],
    }


def _load_data(name: str) -> tuple[dict[str, Any], bytes]:
    path = Path(__file__).resolve().parents[1] / "keel_verifier" / "data" / name
    raw = path.read_bytes()
    return json.loads(raw), raw


def _semantic(
    semantic_id: str,
    *,
    source: str,
    action: str,
    surface: str,
    presentation: str,
    facts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    selector, selector_raw = _load_data("permit_to_x/semantic_registry/v19.json")
    entry = next(item for item in selector["entries"] if item["semantic_id"] == semantic_id)
    claims, claims_raw = _load_data("claim_registry/v6.json")
    universal, universal_raw = _load_data("semantics/permit/universal_verification_v4.json")
    binding: dict[str, Any] = {
        "version": "keel.permit_semantic_binding.v2",
        "semantic_id": semantic_id,
        "selector_registry_version": selector["version"],
        "selector_registry_digest": _content_hash(selector_raw),
        "selector_entry_digest": _digest(entry),
        "trusted_source_kind": source,
        "chain_role": "work_root" if semantic_id == "keel.context.work.v1" else "action_child",
        "action_name": action,
        "operation": action,
        "governed_surface": surface,
        "non_authorizing_presentation_profile_id": presentation,
        "claim_registry_version": claims["version"],
        "claim_registry_digest": _content_hash(claims_raw),
        "universal_semantics_id": universal["id"],
        "universal_semantics_digest": _content_hash(universal_raw),
        "derived_at": START,
    }
    if facts is not None:
        registry, registry_raw = _load_data("permit_to_x/fact_profiles/v17.json")
        profile = next(
            item
            for item in registry["profiles"]
            if item["fact_profile_id"] == facts["fact_profile_id"]
        )
        _schema, schema_raw = _load_data("permit_to_x/" + profile["facts_schema"])
        binding.update(
            {
                "fact_profile_id": profile["fact_profile_id"],
                "fact_profile_registry_version": registry["version"],
                "fact_profile_registry_digest": _content_hash(registry_raw),
                "fact_profile_entry_digest": _digest(profile),
                "authorization_facts_schema_digest": _content_hash(schema_raw),
                "authorization_facts_digest": _digest(facts),
                "authorization_facts_canonicalization": "rfc8785",
            }
        )
    return binding


def _permit_artifact(
    *,
    private: Ed25519PrivateKey,
    public: str,
    permit_id: str,
    parent_id: str | None,
    role: str,
    action: str,
    subject: str,
    attrs: dict[str, Any],
    request_hex: str,
    decision: str,
    issued_at: str,
) -> dict[str, Any]:
    key_id = verifier._binding_key_id_from_public_key(public)
    canonical = permit_binding.canonical_binding_payload_v7(
        permit_id=permit_id,
        project_id=PROJECT,
        parent_permit_id=parent_id,
        decision=decision,
        reason="policy." + decision,
        provider="keel",
        model="work.v2",
        operation=action,
        action_name=action,
        request_fingerprint=request_hex,
        constraints={},
        routing=None,
        policy_id="concierge-policy",
        policy_version="1",
        policy_snapshot_hash="c" * 64,
        issued_at=issued_at,
        expires_at=END,
        is_dry_run=False,
        binding_key_id=key_id,
        final_request_hash=None,
        binding_session_id=None,
        binding_session_event_hash=None,
        binding_project_anchor_hash=None,
        permit_chain_role=role,
        inherits_from=None,
        authority_delta=None,
        spend_scope_hash=None,
        delegation_policy_hash=None,
        resource_attributes_canonical_hash=permit_binding.canonical_resource_attributes_payload(attrs),
        authority_chain_digest=None,
        quota_reservation_id=None,
        subject_id=subject,
        subject_type="agent",
        account_id=None,
        org_id=None,
    )
    canonical_hash = permit_binding.compute_canonical_binding_hash(canonical)
    capability = {
        "artifact_type": "permit_decision_binding",
        "artifact_version": "permit.decision.v1",
        "canonical_payload": canonical,
        "resource_attributes_json": attrs,
        "binding_canonical_hash": canonical_hash,
        "binding_signature": _signature(private, canonical_hash),
        "binding_key_id": key_id,
        "binding_issued_at": issued_at,
        "expected_decision": decision,
    }
    receipt = {
        "receipt_type": "permit_receipt",
        "project_id": PROJECT,
        "permit_id": permit_id,
        "action": {"action_name": action, "resource_attributes_json": attrs},
        "decision": {"decision": decision},
    }
    return _artifact(
        "urn:x-keel:permit:" + permit_id,
        "keel.work_permit_evidence.v1",
        {
            "version": "keel.work_permit_evidence.v1",
            "permit_receipt": receipt,
            "permit_decision_binding": capability,
        },
    )


def _signed_object(
    private: Ed25519PrivateKey,
    value: dict[str, Any],
) -> dict[str, Any]:
    result = copy.deepcopy(value)
    canonical_hash = _digest(result)
    result["canonical_hash"] = canonical_hash
    result["signature"] = _signature(private, canonical_hash.removeprefix("sha256:"))
    return result


def _event_hash(event: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(event)
    result["event_canonical_hash"] = _digest(result)
    return result


def _build_pack(
    tmp_path: Path,
    *,
    provider_verified: bool = False,
    revocation_kind: str | None = None,
    call_principal: str = PHONE,
    policy_narrowed: bool = False,
) -> tuple[dict[str, Any], Path]:
    export_private, export_public = _keypair()
    binding_private, binding_public = _keypair()
    provider_private, provider_public = _keypair()
    export_key_id = verifier._public_key_fingerprint(export_public)
    binding_key_id = verifier._binding_key_id_from_public_key(binding_public)
    provider_key_id = verifier._binding_key_id_from_public_key(provider_public)
    trust_root = tmp_path / "trust.json"
    trust_root.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "key_id": export_key_id,
                        "algorithm": "ed25519",
                        "public_key": export_public,
                        "purpose": "export_signing",
                        "status": "active",
                        "valid_from": "2026-01-01T00:00:00Z",
                        "valid_to": None,
                    }
                ]
            }
        )
    )
    keys = [
        {
            "key_id": export_key_id,
            "algorithm": "ed25519",
            "public_key": export_public,
            "purpose": "export_signing",
            "status": "active",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": None,
        },
        {
            "key_id": provider_key_id,
            "algorithm": "ed25519",
            "public_key": provider_public,
            "purpose": "provider_fact_signing",
            "status": "active",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": None,
        },
        {
            "key_id": binding_key_id,
            "algorithm": "ed25519",
            "public_key": binding_public,
            "purpose": "permit_binding_signing",
            "status": "active",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": None,
        },
    ]
    manifest = {
        "manifest_version": "keel.public_key_manifest.v1",
        "canonicalization_profile": "keel.canonical_json.payload.v1",
        "keys": keys,
    }
    manifest_hash = verifier._content_hash(verifier._manifest_signature_payload_bytes(manifest))
    manifest["manifest_signature"] = {
        "signature_type": "ed25519.content_hash.v1",
        "purpose": "export_signing",
        "key_id": export_key_id,
        "public_key": export_public,
        "content_hash": manifest_hash,
        "signature": _signature(export_private, manifest_hash),
        "canonicalization_profile": "keel.canonical_json.payload.v1",
        "signed_fields": ["manifest_version", "canonicalization_profile", "keys"],
    }
    key_artifact = _artifact("urn:x-keel:key-manifest", "keel.public_key_manifest.v1", manifest)

    resource = {"type": "concierge_job", "id": "trip-42", "digest": "sha256:" + "a" * 64}
    request_lanes = [
        {
            "authority_id": "call-lane",
            "requested_action": "call.outbound",
            "max_uses": 1,
            "requested_value_binding": "none",
            "automatic_review_threshold_minor": 0,
            "delegated_principal_id": PHONE,
        },
        {
            "authority_id": "pay-lane",
            "requested_action": "payment.execute",
            "max_uses": 2,
            "requested_value_binding": (
                "provider_verified" if provider_verified else "declared_bounded"
            ),
            "value_max_minor": 50_000,
            "currency": "USD",
            "automatic_review_threshold_minor": 3_500,
            "delegated_principal_id": BOOKER,
        },
    ]
    if policy_narrowed:
        request_lanes[0]["max_uses"] = 3
        request_lanes[1].update(
            {
                "max_uses": 4,
                "value_max_minor": 70_000,
                "automatic_review_threshold_minor": 7_000,
            }
        )
    request = {
        "version": "keel.work_request.v2",
        "declared_purpose": "Arrange one bounded trip",
        "job_reference": "trip-42",
        "resource": resource,
        "requested_authorities": request_lanes,
        "required_authority_ids": ["call-lane", "pay-lane"],
        "customer_value_pool": {
            "value_domain": "customer_economic_value",
            "value_max_minor": 70_000 if policy_narrowed else 50_000,
            "currency": "USD",
        },
        "not_before": START,
        "expires_at": END,
    }

    def authority(authority_id: str, semantic_id: str, action: str, mode: str, max_uses: int) -> dict[str, Any]:
        value: dict[str, Any] = {
            "version": "keel.work_authority.v2",
            "authority_id": authority_id,
            "project_id": PROJECT,
            "root_permit_id": ROOT,
            "semantic_id": semantic_id,
            "trusted_action": action,
            "trusted_source_reference": {
                "source_kind": "action_verb_execute",
                "source_id": action,
                "source_digest": "sha256:" + ("1" if mode == "none" else "2") * 64,
            },
            "resource_scope": resource,
            "comparator_version": "work-action-authority.v2",
            "max_uses": max_uses,
            "value_binding": mode,
            "automatic_review_threshold_minor": 0 if mode == "none" else 3_500,
            "not_before": START,
            "expires_at": END,
        }
        if mode != "none":
            value.update({"value_max_minor": 50_000, "currency": "USD"})
        value["authority_canonical_hash"] = _digest(value)
        return value

    authorities = [
        authority("call-lane", "keel.action.telephony_call_outbound.v1", "call.outbound", "none", 1),
        authority(
            "pay-lane",
            "keel.action.payment_execute.v1",
            "payment.execute",
            "provider_verified" if provider_verified else "declared_bounded",
            2,
        ),
    ]
    issued_refs = [
        {"authority_id": item["authority_id"], "authority_canonical_hash": item["authority_canonical_hash"]}
        for item in authorities
    ]
    delegations = [
        {
            "delegation_id": "dddddddd-dddd-4ddd-8ddd-dddddddddd01",
            "authority_id": "call-lane",
            "delegated_principal_id": PHONE,
        },
        {
            "delegation_id": "dddddddd-dddd-4ddd-8ddd-dddddddddd02",
            "authority_id": "pay-lane",
            "delegated_principal_id": BOOKER,
        },
    ]
    package = {
        "version": "keel.work_package.v2",
        "verified_root_principal_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        "declared_purpose": request["declared_purpose"],
        "job_reference": request["job_reference"],
        "resource": resource,
        "requested_authority_set_hash": _digest(request_lanes),
        "required_authority_ids": request["required_authority_ids"],
        "issued_authorities": issued_refs,
        "issued_authority_set_hash": _digest(sorted(issued_refs, key=lambda item: item["authority_id"])),
        "excluded_authorities": [],
        "authority_delegations": delegations,
        "customer_value_pool": {
            "value_domain": "customer_economic_value",
            "value_max_minor": 50_000,
            "currency": "USD",
        },
        "policy_snapshot": {
            "policy_id": "root-policy",
            "policy_version": "1",
            "policy_snapshot_hash": "sha256:" + "3" * 64,
        },
        "root_review_hash": "sha256:" + "4" * 64,
        "not_before": START,
        "expires_at": END,
    }
    root_semantic = _semantic(
        "keel.context.work.v1",
        source="work_request_server_reconciled",
        action="work.authorize",
        surface="permit_decision",
        presentation="permit_to_work.r1",
    )
    root_artifact = _permit_artifact(
        private=binding_private,
        public=binding_public,
        permit_id=ROOT,
        parent_id=None,
        role="work_root",
        action="work.authorize",
        subject=package["verified_root_principal_id"],
        attrs={
            "operation": "work.authorize",
            "work_request_v2": request,
            "work_package_v2": package,
            "permit_semantic_binding_v2": root_semantic,
        },
        request_hex="9" * 64,
        decision="allow",
        issued_at=START,
    )

    authority_by_id = {item["authority_id"]: item for item in authorities}

    def work_binding(
        authority_id: str,
        principal: str,
        credential_hex: str,
        body_hex: str,
        *,
        amount: int | None,
        review_hex: str | None,
    ) -> dict[str, Any]:
        delegation = next(item for item in delegations if item["authority_id"] == authority_id)
        value_request: dict[str, Any] = {
            "version": "keel.work_value_request.v2",
            "value_binding": authority_by_id[authority_id]["value_binding"],
        }
        if amount is not None:
            value_request.update({"declared_amount_minor": amount, "currency": "USD"})
        return {
            "version": "keel.work_binding.v2",
            "root_permit_id": ROOT,
            "authority_id": authority_id,
            "authority_canonical_hash": authority_by_id[authority_id]["authority_canonical_hash"],
            "root_manifest_hash": _digest(package),
            "exercised_by": {
                "verified_principal_id": principal,
                "root_principal_id": package["verified_root_principal_id"],
                "delegated_principal_id": principal,
                "delegation_id": delegation["delegation_id"],
                "authenticated_credential_id_digest": "sha256:" + credential_hex * 64,
            },
            "value_request": value_request,
            "provider_wire_body_digest": "sha256:" + body_hex * 64,
            "exact_request_commitment": (
                "sha256:" + review_hex * 64 if review_hex is not None else None
            ),
        }

    call_request = "5" * 64
    pay_request = "6" * 64
    review_request = "7" * 64
    call_binding = work_binding(
        "call-lane", call_principal, "5", "a", amount=None, review_hex=None
    )
    pay_binding = work_binding(
        "pay-lane",
        BOOKER,
        "6",
        "b",
        amount=None if provider_verified else 46_500,
        review_hex=None,
    )
    reviewed_binding = work_binding(
        "pay-lane",
        BOOKER,
        "7",
        "c",
        amount=None if provider_verified else 6_000,
        review_hex="d",
    )
    call_facts = {
        "version": "keel.telephony_call_outbound_exact_facts.v1",
        "fact_profile_id": "keel.facts.telephony_call_outbound_exact.v1",
        "action": "call.outbound",
        "connector_identity": "vocal-gateway-1",
        "connector_type": "vocal_bridge_direct",
        "provider_environment": "provider_sandbox",
        "destination_reference_commitment": {
            "method": "keel.salted_sha256_jcs.v1",
            "digest": "sha256:" + "e" * 64,
        },
        "destination_allowlisted": True,
        "destination_allowlist_digest": "sha256:" + "f" * 64,
        "destination_country_code": "1",
        "originating_principal_id": call_principal,
        "work_root_permit_id": ROOT,
        "work_authority_id": "call-lane",
        "action_access_level": "write",
        "action_risk_tags": ["external_communication"],
        "provider_wire_body_digest": call_binding["provider_wire_body_digest"],
        "request_digest": "sha256:" + call_request,
        "idempotency_digest": "sha256:" + "1" * 64,
    }
    call_semantic = _semantic(
        "keel.action.telephony_call_outbound.v1",
        source="telephony_origination_service",
        action="call.outbound",
        surface="telephony_provider",
        presentation="telephony_call_outbound.r1",
        facts=call_facts,
    )
    payment_semantic = _semantic(
        "keel.action.payment_execute.v1",
        source="action_verb_execute",
        action="payment.execute",
        surface="payment_rail",
        presentation="permit_to_pay.r1",
    )
    fact_artifact = _artifact(
        "urn:x-keel:call-facts",
        "keel.telephony_call_outbound_exact_facts.v1",
        call_facts,
    )
    provider_artifacts: list[dict[str, Any]] = []
    if provider_verified:
        for suffix, child_id, request_hex, binding, amount, observed_at in (
            ("pay", PAY_CHILD, pay_request, pay_binding, 46_500, "2026-08-20T20:03:00Z"),
            (
                "review",
                REVIEW_CHILD,
                review_request,
                reviewed_binding,
                6_000,
                "2026-08-20T20:08:30Z",
            ),
        ):
            payload = _signed_object(
                provider_private,
                {
                    "version": "keel.provider_value_fact.v1",
                    "fact_profile_id": "keel.facts.provider_booking_value.v1",
                    "project_id": PROJECT,
                    "root_permit_id": ROOT,
                    "authority_id": "pay-lane",
                    "child_permit_id": child_id,
                    "request_digest": "sha256:" + request_hex,
                    "connector_identity": "provider-gateway-1",
                    "connector_type": "direct_provider_api",
                    "provider_environment": "provider_sandbox",
                    "provider_wire_body_digest": binding["provider_wire_body_digest"],
                    "amount_minor": amount,
                    "currency": "USD",
                    "provider_response_digest": "sha256:" + ("4" if suffix == "pay" else "5") * 64,
                    "observed_at": observed_at,
                    "signing_key_id": provider_key_id,
                },
            )
            provider_artifacts.append(
                _artifact(
                    "urn:x-keel:provider-value:" + suffix,
                    "keel.provider_value_fact.v1",
                    payload,
                )
            )

    def child_permit(
        permit_id: str,
        action: str,
        principal: str,
        binding: dict[str, Any],
        semantic: dict[str, Any],
        request_hex: str,
        decision: str,
        issued_at: str,
    ) -> dict[str, Any]:
        return _permit_artifact(
            private=binding_private,
            public=binding_public,
            permit_id=permit_id,
            parent_id=ROOT,
            role="action_child",
            action=action,
            subject=principal,
            attrs={
                "operation": action,
                "work_binding_v2": binding,
                "work_resource_scope_v1": {"version": "keel.work_resource_scope.v1", **resource},
                "work_resource_digest": resource["digest"],
                "permit_semantic_binding_v2": semantic,
            },
            request_hex=request_hex,
            decision=decision,
            issued_at=issued_at,
        )

    call_permit = child_permit(
        CALL_CHILD,
        "call.outbound",
        call_principal,
        call_binding,
        call_semantic,
        call_request,
        "allow",
        "2026-08-20T20:04:00Z",
    )
    pay_permit = child_permit(PAY_CHILD, "payment.execute", BOOKER, pay_binding, payment_semantic, pay_request, "allow", "2026-08-20T20:04:00Z")
    review_permit = child_permit(REVIEW_CHILD, "payment.execute", BOOKER, reviewed_binding, payment_semantic, review_request, "challenge", "2026-08-20T20:09:00Z")

    def dispatch(child_id: str, authority_id: str, binding: dict[str, Any], request_hex: str, at: str, idem_hex: str, policy: str) -> dict[str, Any]:
        return _signed_object(
            binding_private,
            {
                "version": "keel.work_dispatch_boundary.v2",
                "event_type": "dispatch.egress_bound",
                "project_id": PROJECT,
                "root_permit_id": ROOT,
                "authority_id": authority_id,
                "child_permit_id": child_id,
                "dispatch_attempt_id": "88888888-8888-4888-8888-" + ("888888888881" if child_id == PAY_CHILD else "888888888882"),
                "request_digest": "sha256:" + request_hex,
                "provider_wire_body_digest": binding["provider_wire_body_digest"],
                "authenticated_credential_id_digest": binding["exercised_by"]["authenticated_credential_id_digest"],
                "idempotency_key_digest": "sha256:" + idem_hex * 64,
                "pre_effect": True,
                "gate_result": "allow",
                "dispatch_ownership_committed": True,
                "upstream_called": False,
                "liveness": {
                    "root_live": True,
                    "authority_live": True,
                    "child_live": True,
                    "delegation_live": True,
                    "principal_live": True,
                    "credential_live": True,
                    "approval_live": True,
                    "reservation_live": True,
                    "current_policy_epoch_matched": True,
                    "platform_safety_floor_passed": True,
                    "exact_request_matched": True,
                    "provider_wire_body_matched": True,
                },
                "execution_policy": {
                    "policy_id": policy,
                    "policy_version": "1",
                    "policy_snapshot_hash": "sha256:" + idem_hex * 64,
                },
                "asserts_provider_acceptance": False,
                "asserts_business_job_completed": False,
                "asserts_settlement": False,
                "occurred_at": at,
                "binding_key_id": binding_key_id,
            },
        )

    pay_boundary = dispatch(PAY_CHILD, "pay-lane", pay_binding, pay_request, "2026-08-20T20:06:00Z", "2", "pay-dispatch")
    call_boundary = dispatch(CALL_CHILD, "call-lane", call_binding, call_request, "2026-08-20T20:08:00Z", "3", "call-dispatch")
    pay_boundary_artifact = _artifact("urn:x-keel:dispatch:pay", "keel.work_dispatch_boundary.v2", pay_boundary)
    call_boundary_artifact = _artifact("urn:x-keel:dispatch:call", "keel.work_dispatch_boundary.v2", call_boundary)
    review = _signed_object(
        binding_private,
        {
            "version": "keel.work_review_transition.v1",
            "transition_id": "99999999-9999-4999-8999-999999999999",
            "event_type": "work.review_resolved",
            "permit_id": REVIEW_CHILD,
            "project_id": PROJECT,
            "root_permit_id": ROOT,
            "authority_id": "pay-lane",
            "actor_id": "user:approver",
            "actor_kind": "dashboard_user",
            "from_decision": "challenge",
            "from_status": "awaiting_attestation",
            "human_outcome": "approve",
            "final_decision": "deny",
            "final_status": "denied",
            "final_reason_code": "work.root_value_limit_exhausted",
            "frozen_request_digest": "sha256:" + review_request,
            "exact_request_commitment": reviewed_binding["exact_request_commitment"],
            "review_evidence_hash": _digest(
                {
                    "version": "keel.exact_request_review.v1",
                    "permit_id": REVIEW_CHILD,
                    "request_digest": "sha256:" + review_request,
                }
            ),
            "provider_wire_body_digest": reviewed_binding["provider_wire_body_digest"],
            "decided_at": "2026-08-20T20:10:00Z",
            "binding_key_id": binding_key_id,
        },
    )
    review_artifact = _artifact("urn:x-keel:review:1", "keel.work_review_transition.v1", review)

    first_event = _event_hash(
        {
            "version": "keel.work_value_event.v2",
            "event_id": "66666666-6666-4666-8666-666666666661",
            "project_id": PROJECT,
            "root_permit_id": ROOT,
            "authority_id": "pay-lane",
            "child_permit_id": PAY_CHILD,
            "reservation_id": "55555555-5555-4555-8555-555555555555",
            "root_sequence": 1,
            "previous_root_event_hash": None,
            "event_type": "reserved",
            "value_domain": "customer_economic_value",
            "amount_minor": 46_500,
            "currency": "USD",
            "idempotency_key_digest": "sha256:" + "8" * 64,
            "root_value_state_after": {
                "value_domain": "customer_economic_value",
                "value_max_minor": 50_000,
                "currency": "USD",
                "reserved_value_minor": 46_500,
                "consumed_value_minor": 0,
                "remaining_value_minor": 3_500,
            },
            "occurred_at": "2026-08-20T20:05:00Z",
        }
    )
    second_event = _event_hash(
        {
            "version": "keel.work_value_event.v2",
            "event_id": "66666666-6666-4666-8666-666666666662",
            "project_id": PROJECT,
            "root_permit_id": ROOT,
            "authority_id": "pay-lane",
            "child_permit_id": PAY_CHILD,
            "reservation_id": first_event["reservation_id"],
            "root_sequence": 2,
            "previous_root_event_hash": first_event["event_canonical_hash"],
            "event_type": "consumed",
            "value_domain": "customer_economic_value",
            "amount_minor": 46_500,
            "currency": "USD",
            "idempotency_key_digest": "sha256:" + "9" * 64,
            "root_value_state_after": {
                "value_domain": "customer_economic_value",
                "value_max_minor": 50_000,
                "currency": "USD",
                "reserved_value_minor": 0,
                "consumed_value_minor": 46_500,
                "remaining_value_minor": 3_500,
            },
            "occurred_at": "2026-08-20T20:07:00Z",
        }
    )
    issued_payload = {
        "event_id": "work-issued-1",
        "event_type": "work.issued",
        "permit_id": ROOT,
        "occurred_at": START,
    }
    issued_artifact = _artifact("urn:x-keel:lifecycle:issued", "governance_event", issued_payload)
    lifecycle = [
        {
            "event_id": "work-issued-1",
            "event_type": "work.issued",
            "permit_id": ROOT,
            "occurred_at": START,
            "event_digest": issued_artifact["artifact_digest"],
        }
    ]
    lifecycle_artifacts: list[dict[str, Any]] = []
    if revocation_kind is not None:
        revocation: dict[str, Any] = {
            "event_id": "work-revocation-1",
            "event_type": revocation_kind,
            "occurred_at": (
                "2026-08-20T20:05:30Z"
                if revocation_kind == "permit.revoked"
                else "2026-08-20T20:07:30Z"
            ),
        }
        if revocation_kind == "permit.revoked":
            revocation["permit_id"] = ROOT
        elif revocation_kind == "work.authority.revoked":
            revocation["authority_id"] = "call-lane"
        elif revocation_kind == "work.delegation.revoked":
            revocation["delegation_id"] = delegations[0]["delegation_id"]
        elif revocation_kind == "principal.revoked":
            revocation["principal_id"] = PHONE
        elif revocation_kind == "credential.revoked":
            revocation["authenticated_credential_id_digest"] = call_binding[
                "exercised_by"
            ]["authenticated_credential_id_digest"]
        else:
            raise AssertionError(f"unknown revocation kind: {revocation_kind}")
        revocation_artifact = _artifact(
            "urn:x-keel:lifecycle:revocation",
            "governance_event",
            revocation,
        )
        lifecycle_artifacts.append(revocation_artifact)
        lifecycle.append(
            {**revocation, "event_digest": revocation_artifact["artifact_digest"]}
        )

    children = [
        {
            "permit_id": PAY_CHILD,
            "work_authority_id": "pay-lane",
            "decision": "allow",
            "request_digest": "sha256:" + pay_request,
            "work_binding": pay_binding,
            "semantic_binding": payment_semantic,
            "authorization_fact_artifacts": [],
            **(
                {"provider_value_fact": _ref(provider_artifacts[0])}
                if provider_verified
                else {}
            ),
            "permit_artifact": _ref(pay_permit),
            "dispatch_boundary_evidence": _ref(pay_boundary_artifact),
        },
        {
            "permit_id": CALL_CHILD,
            "work_authority_id": "call-lane",
            "decision": "allow",
            "request_digest": "sha256:" + call_request,
            "work_binding": call_binding,
            "semantic_binding": call_semantic,
            "authorization_fact_artifacts": [_ref(fact_artifact)],
            "permit_artifact": _ref(call_permit),
            "dispatch_boundary_evidence": _ref(call_boundary_artifact),
        },
        {
            "permit_id": REVIEW_CHILD,
            "work_authority_id": "pay-lane",
            "decision": "deny",
            "request_digest": "sha256:" + review_request,
            "work_binding": reviewed_binding,
            "semantic_binding": payment_semantic,
            "authorization_fact_artifacts": [],
            **(
                {"provider_value_fact": _ref(provider_artifacts[1])}
                if provider_verified
                else {}
            ),
            "review_transition": _ref(review_artifact),
            "permit_artifact": _ref(review_permit),
        },
    ]
    policy_snapshots = [
        {"phase": "root_issuance", **package["policy_snapshot"]},
        {
            "phase": "dispatch",
            "permit_id": PAY_CHILD,
            **pay_boundary["execution_policy"],
        },
        {
            "phase": "dispatch",
            "permit_id": CALL_CHILD,
            **call_boundary["execution_policy"],
        },
        {
            "phase": "review_resume",
            "permit_id": REVIEW_CHILD,
            "policy_id": "review-policy",
            "policy_version": "2",
            "policy_snapshot_hash": "sha256:" + "4" * 64,
        },
    ]
    summary = {
        "version": "keel.work_summary.v1",
        "derivation": "verifier_from_verified_work_fields",
        "title": "AI Permit-to-Work",
        "state_label": "active",
        "text": "Keel authorized a bounded Work with 2 lanes. Customer economic value is limited to USD 500.00; USD 0.00 is reserved, USD 465.00 is consumed, and USD 35.00 remains. AI and model compute spend is governed separately. This evidence does not establish provider completion, settlement, call content, or agreement.",
        "root_permit_id": ROOT,
        "customer_value_pool": second_event["root_value_state_after"],
        "ai_compute_budget_boundary": "separate_keel_authority_not_in_work_customer_value_pool",
        "lanes": [
            {
                "authority_id": "call-lane",
                "action": "call.outbound",
                "permit_title": "AI Permit-to-Place-Outbound-Call",
                "principal_id": PHONE,
                "value_binding": "none",
                "max_uses": 1,
                "child_decisions": {"allow": 1, "deny": 0, "challenge": 0},
            },
            {
                "authority_id": "pay-lane",
                "action": "payment.execute",
                "permit_title": "AI Permit",
                "principal_id": BOOKER,
                "value_binding": (
                    "provider_verified" if provider_verified else "declared_bounded"
                ),
                "max_uses": 2,
                "child_decisions": {"allow": 1, "deny": 1, "challenge": 0},
            },
        ],
        "evidence_boundary": {
            "establishes": [
                "bounded heterogeneous Work authority",
                "signed worker delegation and child containment",
                "root customer-value conservation through the declared cutoff",
            ],
            "does_not_establish": [
                "provider completion",
                "financial settlement",
                "call answer, conversation content, or agreement",
                "AI or model compute spend",
            ],
        },
    }
    artifacts = [
        key_artifact,
        root_artifact,
        pay_permit,
        call_permit,
        review_permit,
        fact_artifact,
        pay_boundary_artifact,
        call_boundary_artifact,
        review_artifact,
        issued_artifact,
        *lifecycle_artifacts,
        *provider_artifacts,
    ]
    pack: dict[str, Any] = {
        "version": "keel.work_chain_pack.v2",
        "profile": "work-chain.v2",
        "project_id": PROJECT,
        "root_permit_id": ROOT,
        "export_source": {"source_kind": "keel_recorded_governance", "source_id": "test"},
        "declared_cutoff": {
            "recorded_through": CUTOFF,
            "checkpoint_id": "12121212-1212-4212-8212-121212121212",
            "checkpoint_digest": "sha256:" + "0" * 64,
        },
        "scope_commitment": {
            "version": "keel.work_scope_commitment.v2",
            "claim": "scope-faithful slice of Keel-recorded work evidence through the declared cutoff",
            "runtime_recording_claim": "not_asserted",
            "populations": [],
        },
        "scope_commitment_signature": {
            "version": "keel.work_scope_commitment_signature.v2",
            "signature_profile": "keel.canonical_json.payload.v1",
            "binding_key_id": binding_key_id,
            "canonical_hash": "sha256:" + "0" * 64,
            "signature": "ed25519:" + "A" * 86 + "==",
            "signed_at": CUTOFF,
        },
        "root": {
            "permit_artifact": _ref(root_artifact),
            "work_request": request,
            "work_package": package,
            "semantic_binding": root_semantic,
        },
        "authorities": authorities,
        "child_permits": children,
        "value_events": [first_event, second_event],
        "lifecycle_events": lifecycle,
        "review_transitions": [_ref(review_artifact)],
        "provider_value_facts": [_ref(item) for item in provider_artifacts],
        "policy_snapshots": policy_snapshots,
        "evidence_artifacts": [],
        "artifacts": artifacts,
        "requested_claims": list(WORK_CLAIMS_V2),
        "summary": summary,
    }
    if provider_verified:
        provider_reference = _ref(provider_artifacts[0])
        pack["value_events"][0]["trusted_value_fact"] = provider_reference
        pack["value_events"][1]["trusted_value_fact"] = provider_reference
        # Event hashes and their link commit the newly attached trusted fact.
        first = dict(pack["value_events"][0])
        first.pop("event_canonical_hash")
        pack["value_events"][0]["event_canonical_hash"] = _digest(first)
        pack["value_events"][1]["previous_root_event_hash"] = pack["value_events"][0][
            "event_canonical_hash"
        ]
        second = dict(pack["value_events"][1])
        second.pop("event_canonical_hash")
        pack["value_events"][1]["event_canonical_hash"] = _digest(second)
    population_sources = {
        "work_authorities": ("authorities", "permit_work_authorities"),
        "child_permits": ("child_permits", "permits"),
        "work_value_events": ("value_events", "permit_work_value_events"),
        "lifecycle_events": ("lifecycle_events", "governance_events"),
        "review_transitions": ("review_transitions", "governance_events"),
        "provider_value_facts": ("provider_value_facts", "permits"),
    }
    pack["scope_commitment"]["populations"] = [
        {
            "population": population,
            "source_relation": relation,
            "included_count": len(pack[field]),
            "included_set_hash": _digest(pack[field]),
        }
        for population, (field, relation) in population_sources.items()
    ]
    scope_payload = {
        "version": "keel.work_scope_commitment_signature_payload.v2",
        "project_id": PROJECT,
        "root_permit_id": ROOT,
        "export_source": pack["export_source"],
        "recorded_through": CUTOFF,
        "checkpoint_id": pack["declared_cutoff"]["checkpoint_id"],
        "scope_commitment": pack["scope_commitment"],
        "binding_key_id": binding_key_id,
    }
    scope_hash = _digest(scope_payload)
    pack["declared_cutoff"]["checkpoint_digest"] = scope_hash
    pack["scope_commitment_signature"]["canonical_hash"] = scope_hash
    pack["scope_commitment_signature"]["signature"] = _signature(
        binding_private, scope_hash.removeprefix("sha256:")
    )
    return pack, trust_root


def _refresh_scope(pack: dict[str, Any], private: Ed25519PrivateKey | None = None) -> None:
    # Mutations deliberately do not receive the private key: changing scoped
    # evidence must fail the already-issued checkpoint signature.
    del private


def test_work_v2_genuine_pack_supports_heterogeneous_delegated_review(tmp_path: Path) -> None:
    pack, trust_root = _build_pack(tmp_path)
    report = verify_work_chain_pack(pack, trust_root=trust_root)
    assert report.ok, report.to_dict()
    assert report.artifact["summary"] == pack["summary"]
    assert [claim.name for claim in report.claims] == list(WORK_CLAIMS_V2)


def test_work_v2_accepts_policy_narrowing_but_not_authority_expansion(
    tmp_path: Path,
) -> None:
    pack, trust_root = _build_pack(tmp_path, policy_narrowed=True)
    report = verify_work_chain_pack(pack, trust_root=trust_root)
    assert report.ok, report.to_dict()
    assert all(claim.aggregate_verdict == "supported" for claim in report.claims)


def test_work_v2_mutations_fail_closed(tmp_path: Path) -> None:
    pack, trust_root = _build_pack(tmp_path)
    mutations = {
        "action": lambda value: value["authorities"][0].__setitem__("trusted_action", "payment.execute"),
        "principal": lambda value: value["child_permits"][1]["work_binding"]["exercised_by"].__setitem__("verified_principal_id", BOOKER),
        "delegation": lambda value: value["root"]["work_package"]["authority_delegations"][0].__setitem__("delegated_principal_id", BOOKER),
        "value_binding": lambda value: value["authorities"][0].__setitem__("value_binding", "declared_bounded"),
        "root_cap": lambda value: value["root"]["work_package"]["customer_value_pool"].__setitem__("value_max_minor", 999_999),
        "amount": lambda value: value["value_events"][0].__setitem__("amount_minor", 1),
        "request": lambda value: value["child_permits"][0].__setitem__("request_digest", "sha256:" + "0" * 64),
        "summary": lambda value: value["summary"].__setitem__("text", "tampered"),
    }
    for name, mutate in mutations.items():
        changed = copy.deepcopy(pack)
        mutate(changed)
        report = verify_work_chain_pack(changed, trust_root=trust_root)
        assert not report.ok, (name, report.to_dict())


def test_work_v2_provider_verified_requires_signed_exact_provider_facts(
    tmp_path: Path,
) -> None:
    pack, trust_root = _build_pack(tmp_path, provider_verified=True)
    report = verify_work_chain_pack(pack, trust_root=trust_root)
    assert report.ok, report.to_dict()

    missing = copy.deepcopy(pack)
    missing["child_permits"][0].pop("provider_value_fact")
    missing_report = verify_work_chain_pack(missing, trust_root=trust_root)
    assert not missing_report.ok

    label_only = copy.deepcopy(pack)
    label_only["provider_value_facts"] = []
    label_only_report = verify_work_chain_pack(label_only, trust_root=trust_root)
    assert not label_only_report.ok


def test_work_v2_scoped_revocations_override_claimed_liveness(tmp_path: Path) -> None:
    for event_type in (
        "work.authority.revoked",
        "work.delegation.revoked",
        "principal.revoked",
        "credential.revoked",
    ):
        pack, trust_root = _build_pack(tmp_path, revocation_kind=event_type)
        report = verify_work_chain_pack(pack, trust_root=trust_root)
        assert not report.ok
        boundary = next(
            claim
            for claim in report.claims
            if claim.name == "permit_chain.execution_authorized_at_boundary.v2"
        )
        by_id = {subject.id: subject for subject in boundary.subjects}
        assert by_id[PAY_CHILD].verdict == "supported"
        assert by_id[CALL_CHILD].verdict == "disproved"
        assert by_id[CALL_CHILD].reason_code == "WORK_DISPATCH_LIVENESS_REVOKED"

    root_pack, root_trust = _build_pack(tmp_path, revocation_kind="permit.revoked")
    root_report = verify_work_chain_pack(root_pack, trust_root=root_trust)
    boundary = next(
        claim
        for claim in root_report.claims
        if claim.name == "permit_chain.execution_authorized_at_boundary.v2"
    )
    assert all(
        subject.verdict == "disproved"
        for subject in boundary.subjects
        if subject.id in {PAY_CHILD, CALL_CHILD}
    )


def test_work_v2_valid_project_principal_without_delegation_is_disproved(
    tmp_path: Path,
) -> None:
    p3 = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
    pack, trust_root = _build_pack(tmp_path, call_principal=p3)
    report = verify_work_chain_pack(pack, trust_root=trust_root)
    assert not report.ok
    child_claim = next(
        claim
        for claim in report.claims
        if claim.name == "permit.work_child_containment.v2"
    )
    call_subject = next(subject for subject in child_claim.subjects if subject.id == CALL_CHILD)
    assert call_subject.verdict == "disproved"
    assert call_subject.reason_code == "WORK_CHILD_OUTSIDE_AUTHORITY"


def test_future_work_version_fails_closed(tmp_path: Path) -> None:
    pack, trust_root = _build_pack(tmp_path)
    pack["version"] = "keel.work_chain_pack.v3"
    report = verify_work_chain_pack(pack, trust_root=trust_root)
    assert not report.ok
    assert all(
        subject.reason_code == "WORK_VERSION_UNSUPPORTED"
        for claim in report.claims
        for subject in claim.subjects
    )
