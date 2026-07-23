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
from keel_verifier.permit_presentation import (
    load_permit_presentation_registry,
    resolve_permit_presentation,
)
from keel_verifier.work_chain import WORK_CLAIMS, verify_work_chain_pack


PROJECT_ID = "11111111-1111-4111-8111-111111111111"
ROOT_ID = "22222222-2222-4222-8222-222222222222"
CHILD_ID = "33333333-3333-4333-8333-333333333333"
ISSUED_AT = "2026-07-21T16:05:00Z"
CUTOFF = "2026-07-21T16:10:00Z"


def _keypair() -> tuple[Ed25519PrivateKey, str]:
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private, f"ed25519:{base64.b64encode(raw).decode('ascii')}"


def _digest(value: Any) -> str:
    return f"sha256:{hashlib.sha256(rfc8785.dumps(value)).hexdigest()}"


def _signature(private: Ed25519PrivateKey, value: str) -> str:
    return "ed25519:" + base64.b64encode(private.sign(value.encode("utf-8"))).decode("ascii")


def _artifact(artifact_id: str, artifact_type: str, payload: dict[str, Any]) -> dict:
    return {
        "artifact_id": artifact_id,
        "artifact_type": artifact_type,
        "artifact_digest": _digest(payload),
        "payload": payload,
    }


def _reference(artifact: dict[str, Any]) -> dict[str, str]:
    return {
        "artifact_id": artifact["artifact_id"],
        "artifact_type": artifact["artifact_type"],
        "artifact_digest": artifact["artifact_digest"],
    }


def _semantic_binding(semantic_id: str) -> dict[str, Any]:
    root = Path(__file__).resolve().parents[1]
    raw = (
        root / "keel_verifier" / "data" / "permit_to_x" / "semantic_registry" / "v1.json"
    ).read_bytes()
    registry = json.loads(raw)
    entry = next(item for item in registry["entries"] if item["semantic_id"] == semantic_id)
    if semantic_id == "keel.context.work.v1":
        fields = {
            "trusted_source_kind": "work_request_server_reconciled",
            "chain_role": "work_root",
            "action_name": "work.authorize",
            "operation": "work.authorize",
            "governed_surface": "permit_decision",
            "non_authorizing_presentation_profile_id": "permit_to_work.r1",
        }
    else:
        fields = {
            "trusted_source_kind": "action_verb_execute",
            "chain_role": "action_child",
            "action_name": "payment.execute",
            "operation": "payment.execute",
            "governed_surface": "payment_rail",
            "non_authorizing_presentation_profile_id": "permit_to_pay.r1",
        }
    return {
        "version": "keel.permit_semantic_binding.v1",
        "semantic_id": semantic_id,
        "selector_registry_version": registry["version"],
        "selector_registry_digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
        "selector_entry_digest": _digest(entry),
        **fields,
        "derived_at": ISSUED_AT,
    }


def _permit_artifact(
    *,
    private_key: Ed25519PrivateKey,
    public_key: str,
    permit_id: str,
    parent_id: str | None,
    chain_role: str,
    action_name: str,
    operation: str,
    attrs: dict[str, Any],
    request_fingerprint: str,
    decision: str = "allow",
) -> dict[str, Any]:
    key_id = verifier._binding_key_id_from_public_key(public_key)
    canonical = permit_binding.canonical_binding_payload_v6(
        permit_id=permit_id,
        project_id=PROJECT_ID,
        parent_permit_id=parent_id,
        decision=decision,
        reason="policy.allow",
        provider="keel" if chain_role == "work_root" else "stripe_mpp",
        model="work.v1" if chain_role == "work_root" else "stripe.mpp.v1",
        operation=operation,
        action_name=action_name,
        request_fingerprint=request_fingerprint,
        constraints={},
        routing=None,
        policy_id="invoice-payment-policy",
        policy_version="7",
        policy_snapshot_hash="c" * 64,
        issued_at=ISSUED_AT,
        expires_at="2026-08-31T23:59:59Z",
        is_dry_run=False,
        binding_key_id=key_id,
        final_request_hash=None,
        binding_session_id=None,
        binding_session_event_hash=None,
        binding_project_anchor_hash=None,
        permit_chain_role=chain_role,
        inherits_from=None,
        authority_delta=None,
        spend_scope_hash=permit_binding.canonical_spend_scope_payload(attrs.get("spend_scope")),
        delegation_policy_hash=None,
        resource_attributes_canonical_hash=(
            permit_binding.canonical_resource_attributes_payload(attrs)
        ),
    )
    canonical_hash = permit_binding.compute_canonical_binding_hash(canonical)
    capability = {
        "artifact_type": "permit_decision_binding",
        "artifact_version": "permit.decision.v1",
        "canonical_payload": canonical,
        "resource_attributes_json": attrs,
        "binding_canonical_hash": canonical_hash,
        "binding_signature": _signature(private_key, canonical_hash),
        "binding_key_id": key_id,
        "binding_issued_at": ISSUED_AT,
        "expected_decision": decision,
    }
    receipt = {
        "receipt_type": "permit_receipt",
        "project_id": PROJECT_ID,
        "permit_id": permit_id,
        "action": {
            "action_name": action_name,
            "resource_attributes_json": attrs,
        },
        "decision": {"decision": decision},
    }
    return _artifact(
        f"urn:x-keel:artifact:permit:{permit_id}",
        "keel.work_permit_evidence.v1",
        {
            "version": "keel.work_permit_evidence.v1",
            "permit_receipt": receipt,
            "permit_decision_binding": capability,
        },
    )


def _build_pack(
    tmp_path: Path,
    *,
    child_amount: int = 8_400,
    boundary_live: bool = True,
    sequence_gap: bool = False,
) -> tuple[dict[str, Any], Path]:
    export_private, export_public = _keypair()
    binding_private, binding_public = _keypair()
    export_key_id = verifier._public_key_fingerprint(export_public)
    binding_key_id = verifier._binding_key_id_from_public_key(binding_public)
    trust_root = tmp_path / "work-trust-root.json"
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
        ),
        encoding="utf-8",
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
            "key_id": binding_key_id,
            "algorithm": "ed25519",
            "public_key": binding_public,
            "purpose": "permit_binding_signing",
            "status": "active",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": None,
        },
    ]
    key_manifest = {
        "manifest_version": "keel.public_key_manifest.v1",
        "canonicalization_profile": "keel.canonical_json.payload.v1",
        "keys": keys,
    }
    manifest_hash = verifier._content_hash(verifier._manifest_signature_payload_bytes(key_manifest))
    key_manifest["manifest_signature"] = {
        "signature_type": "ed25519.content_hash.v1",
        "purpose": "export_signing",
        "key_id": export_key_id,
        "public_key": export_public,
        "content_hash": manifest_hash,
        "signature": _signature(export_private, manifest_hash),
        "canonicalization_profile": "keel.canonical_json.payload.v1",
        "signed_fields": ["manifest_version", "canonicalization_profile", "keys"],
    }

    authority_without_hash = {
        "version": "keel.work_authority.v1",
        "authority_id": "payment-1",
        "project_id": PROJECT_ID,
        "root_permit_id": ROOT_ID,
        "semantic_id": "keel.action.payment_execute.v1",
        "trusted_action": "payment.execute",
        "trusted_source_reference": {
            "source_kind": "action_verb_execute",
            "source_id": "payment.execute",
            "source_digest": "sha256:" + "b" * 64,
        },
        "resource_scope": {
            "type": "invoice",
            "id": "INV-2048",
            "digest": "sha256:" + "a" * 64,
        },
        "comparator_version": "work-payment-authority.v1",
        "max_uses": 1,
        "value_max_minor": 50_000,
        "currency": "USD",
        "automatic_review_threshold_minor": 10_000,
        "recipient_digest": "sha256:" + "1" * 64,
        "purpose_digest": "sha256:" + "2" * 64,
        "not_before": "2026-07-21T16:00:00Z",
        "expires_at": "2026-08-31T23:59:59Z",
    }
    authority = {
        **authority_without_hash,
        "authority_canonical_hash": _digest(authority_without_hash),
    }
    issued_refs = [
        {
            "authority_id": "payment-1",
            "authority_canonical_hash": authority["authority_canonical_hash"],
        }
    ]
    package = {
        "version": "keel.work_package.v1",
        "verified_principal_id": "44444444-4444-4444-8444-444444444444",
        "declared_purpose": "Process invoice INV-2048",
        "job_reference": "INV-2048",
        "resource": authority["resource_scope"],
        "requested_authority_set_hash": "sha256:" + "e" * 64,
        "required_authority_ids": ["payment-1"],
        "issued_authorities": issued_refs,
        "issued_authority_set_hash": _digest(issued_refs),
        "excluded_authorities": [],
        "policy_snapshot": {
            "policy_id": "invoice-payment-policy",
            "policy_version": "7",
            "policy_snapshot_hash": "sha256:" + "c" * 64,
        },
        "root_review_hash": "sha256:" + "d" * 64,
        "not_before": "2026-07-21T16:00:00Z",
        "expires_at": "2026-08-31T23:59:59Z",
    }
    root_semantic = _semantic_binding("keel.context.work.v1")
    root_attrs = {
        "operation": "work.authorize",
        "work_package_v1": package,
        "permit_semantic_binding_v1": root_semantic,
    }
    root_artifact = _permit_artifact(
        private_key=binding_private,
        public_key=binding_public,
        permit_id=ROOT_ID,
        parent_id=None,
        chain_role="work_root",
        action_name="work.authorize",
        operation="work.authorize",
        attrs=root_attrs,
        request_fingerprint="a" * 64,
    )
    work_binding = {
        "version": "keel.work_binding.v1",
        "root_permit_id": ROOT_ID,
        "authority_id": "payment-1",
        "authority_canonical_hash": authority["authority_canonical_hash"],
        "root_manifest_hash": _digest(package),
    }
    child_semantic = _semantic_binding("keel.action.payment_execute.v1")
    child_attrs = {
        "operation": "payment.execute",
        "work_binding_v1": work_binding,
        "work_resource_scope_v1": {
            "version": "keel.work_resource_scope.v1",
            **authority["resource_scope"],
        },
        "permit_semantic_binding_v1": child_semantic,
        "work_resource_digest": authority["resource_scope"]["digest"],
        "spend_scope": {
            "amount_max": str(child_amount),
            "currency_class": "USD_FIAT",
            "cadence": "one_shot",
            "ttl_seconds": 3_600,
            "purpose_binding": "purchase.once",
            "recipient_address_digest": "1" * 64,
            "description_digest": "2" * 64,
        },
    }
    child_fingerprint = "3" * 64
    child_artifact = _permit_artifact(
        private_key=binding_private,
        public_key=binding_public,
        permit_id=CHILD_ID,
        parent_id=ROOT_ID,
        chain_role="action_child",
        action_name="payment.execute",
        operation="payment.execute",
        attrs=child_attrs,
        request_fingerprint=child_fingerprint,
    )
    issued_payload = {
        "event_id": "gev_work_issued",
        "event_type": "work.issued",
        "permit_id": ROOT_ID,
        "occurred_at": ISSUED_AT,
        "payload": {"version": "keel.work_lifecycle_event.v1"},
    }
    issued_artifact = _artifact(
        "urn:x-keel:artifact:governance_event:gev_work_issued",
        "governance_event",
        issued_payload,
    )
    boundary_payload = {
        "version": "keel.work_dispatch_boundary.v1",
        "event_type": "dispatch.egress_bound",
        "root_permit_id": ROOT_ID,
        "child_permit_id": CHILD_ID,
        "liveness": {
            "root_live": boundary_live,
            "authority_live": True,
            "child_live": True,
            "reservation_live": True,
            "current_policy_epoch_matched": True,
            "platform_safety_floor_passed": True,
        },
        "execution_policy": {
            "policy_id": "invoice-payment-policy",
            "policy_version": "7",
            "policy_snapshot_hash": "sha256:" + "c" * 64,
            "snapshot_source": "policy_snapshot_hash",
        },
        "asserts_provider_acceptance": False,
        "asserts_business_job_completed": False,
        "asserts_settlement": False,
    }
    boundary_artifact = _artifact(
        "urn:x-keel:artifact:governance_event:gev_dispatch",
        "governance_event",
        {
            "event_id": "gev_dispatch",
            "event_type": "dispatch.egress_bound",
            "permit_id": CHILD_ID,
            "occurred_at": "2026-07-21T16:07:00Z",
            "payload": boundary_payload,
        },
    )
    child = {
        "permit_id": CHILD_ID,
        "work_authority_id": "payment-1",
        "decision": "allow",
        "request_digest": "sha256:" + child_fingerprint,
        "work_binding": work_binding,
        "semantic_binding": child_semantic,
        "permit_artifact": _reference(child_artifact),
        "dispatch_boundary_evidence": _reference(boundary_artifact),
    }
    value_events = [
        {
            "version": "keel.work_value_event.v1",
            "event_id": "55555555-5555-4555-8555-555555555551",
            "project_id": PROJECT_ID,
            "root_permit_id": ROOT_ID,
            "authority_id": "payment-1",
            "child_permit_id": CHILD_ID,
            "authority_sequence": 1,
            "event_type": "reserved",
            "amount_minor": child_amount,
            "currency": "USD",
            "idempotency_key_digest": "sha256:" + "8" * 64,
            "occurred_at": "2026-07-21T16:06:00Z",
        },
        {
            "version": "keel.work_value_event.v1",
            "event_id": "55555555-5555-4555-8555-555555555552",
            "project_id": PROJECT_ID,
            "root_permit_id": ROOT_ID,
            "authority_id": "payment-1",
            "child_permit_id": CHILD_ID,
            "authority_sequence": 3 if sequence_gap else 2,
            "event_type": "dispatched",
            "amount_minor": child_amount,
            "currency": "USD",
            "idempotency_key_digest": "sha256:" + "9" * 64,
            "occurred_at": "2026-07-21T16:07:00Z",
        },
    ]
    lifecycle = [
        {
            "event_id": "gev_work_issued",
            "event_type": "work.issued",
            "permit_id": ROOT_ID,
            "occurred_at": ISSUED_AT,
            "event_digest": issued_artifact["artifact_digest"],
        },
        {
            "event_id": "gev_dispatch",
            "event_type": "dispatch.egress_bound",
            "permit_id": CHILD_ID,
            "occurred_at": "2026-07-21T16:07:00Z",
            "event_digest": boundary_artifact["artifact_digest"],
        },
    ]
    key_artifact = _artifact(
        "urn:x-keel:artifact:key_manifest:permit-binding",
        "keel.public_key_manifest.v1",
        key_manifest,
    )
    pack: dict[str, Any] = {
        "version": "keel.work_chain_pack.v1",
        "profile": "work-chain.v1",
        "project_id": PROJECT_ID,
        "root_permit_id": ROOT_ID,
        "export_source": {
            "source_kind": "keel_recorded_governance",
            "source_id": "test:project:1111",
        },
        "declared_cutoff": {
            "recorded_through": CUTOFF,
            "checkpoint_id": "66666666-6666-4666-8666-666666666666",
            "checkpoint_digest": "",
        },
        "scope_commitment": {},
        "scope_commitment_signature": {},
        "root": {
            "permit_artifact": _reference(root_artifact),
            "work_package": package,
            "semantic_binding": root_semantic,
        },
        "authorities": [authority],
        "child_permits": [child],
        "value_events": value_events,
        "lifecycle_events": lifecycle,
        "policy_snapshots": [
            {
                "phase": "root_issuance",
                "permit_id": ROOT_ID,
                **package["policy_snapshot"],
            },
            {
                "phase": "child_issuance",
                "permit_id": CHILD_ID,
                **package["policy_snapshot"],
            },
            {
                "phase": "dispatch",
                "permit_id": CHILD_ID,
                "policy_id": "invoice-payment-policy",
                "policy_version": "7",
                "policy_snapshot_hash": "sha256:" + "c" * 64,
            },
        ],
        "evidence_artifacts": [_reference(key_artifact)],
        "artifacts": [
            root_artifact,
            child_artifact,
            issued_artifact,
            boundary_artifact,
            key_artifact,
        ],
        "requested_claims": list(WORK_CLAIMS),
    }
    populations = [
        {
            "population": name,
            "source_relation": relation,
            "included_count": len(pack[field]),
            "included_set_hash": _digest(pack[field]),
        }
        for name, field, relation in (
            ("work_authorities", "authorities", "permit_work_authorities"),
            ("child_permits", "child_permits", "permits"),
            ("work_value_events", "value_events", "permit_work_value_events"),
            ("lifecycle_events", "lifecycle_events", "governance_events"),
        )
    ]
    scope = {
        "version": "keel.work_scope_commitment.v1",
        "claim": "scope-faithful slice of Keel-recorded work evidence through the declared cutoff",
        "runtime_recording_claim": "not_asserted",
        "populations": populations,
    }
    pack["scope_commitment"] = scope
    signature_payload = {
        "version": "keel.work_scope_commitment_signature_payload.v1",
        "project_id": PROJECT_ID,
        "root_permit_id": ROOT_ID,
        "export_source": pack["export_source"],
        "recorded_through": CUTOFF,
        "checkpoint_id": pack["declared_cutoff"]["checkpoint_id"],
        "scope_commitment": scope,
        "binding_key_id": binding_key_id,
    }
    scope_hash = _digest(signature_payload)
    pack["declared_cutoff"]["checkpoint_digest"] = scope_hash
    pack["scope_commitment_signature"] = {
        "version": "keel.work_scope_commitment_signature.v1",
        "signature_profile": "keel.canonical_json.payload.v1",
        "binding_key_id": binding_key_id,
        "canonical_hash": scope_hash,
        "signature": _signature(binding_private, scope_hash.removeprefix("sha256:")),
        "signed_at": CUTOFF,
    }
    return pack, trust_root


def _claim(report, name: str) -> dict[str, Any]:
    return next(item for item in report.to_dict()["claims"] if item["name"] == name)


def test_valid_work_chain_supports_all_four_claims(tmp_path: Path) -> None:
    pack, trust_root = _build_pack(tmp_path)
    report = verify_work_chain_pack(pack, trust_root=trust_root)

    assert report.ok is True
    assert report.exit_code == 0
    assert [claim.aggregate_verdict for claim in report.claims] == ["supported"] * 4
    assert report.artifact["runtime_recording_claim"] == "not_asserted"


def test_work_chain_cli_auto_detects_downloaded_pack(tmp_path: Path, run_cli) -> None:
    pack, trust_root = _build_pack(tmp_path)
    path = tmp_path / "work-chain.json"
    path.write_text(json.dumps(pack), encoding="utf-8")

    result = run_cli(str(path), "--trust-root", str(trust_root), "--json")

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["artifact"]["kind"] == "work_chain_pack"
    assert [claim["verdict"] for claim in payload["claims"]] == ["supported"] * 4


def test_embedded_artifact_tamper_is_disproved(tmp_path: Path) -> None:
    pack, trust_root = _build_pack(tmp_path)
    pack["artifacts"][0]["payload"]["permit_receipt"]["permit_id"] = CHILD_ID

    report = verify_work_chain_pack(pack, trust_root=trust_root)

    assert report.ok is False
    assert all(claim.aggregate_verdict == "disproved" for claim in report.claims)
    assert all(
        claim.subjects[0].reason_code == "WORK_ARTIFACT_INTEGRITY_INVALID"
        for claim in report.claims
    )


def test_population_omission_relative_to_signed_scope_is_disproved(tmp_path: Path) -> None:
    pack, trust_root = _build_pack(tmp_path)
    pack["child_permits"] = []

    report = verify_work_chain_pack(pack, trust_root=trust_root)

    assert report.ok is False
    assert report.claims[0].subjects[0].reason_code == "WORK_SCOPE_POPULATION_MISMATCH"


def test_allowed_child_outside_authority_is_disproved(tmp_path: Path) -> None:
    pack, trust_root = _build_pack(tmp_path, child_amount=60_000)

    report = verify_work_chain_pack(pack, trust_root=trust_root)

    claim = _claim(report, "permit.work_child_containment.v1")
    assert claim["verdict"] == "disproved"
    assert claim["reason_code"] == "WORK_CHILD_OUTSIDE_AUTHORITY"


def test_false_dispatch_liveness_is_disproved(tmp_path: Path) -> None:
    pack, trust_root = _build_pack(tmp_path, boundary_live=False)

    report = verify_work_chain_pack(pack, trust_root=trust_root)

    claim = _claim(report, "permit_chain.execution_authorized_at_boundary.v1")
    assert claim["verdict"] == "disproved"
    assert claim["reason_code"] == "WORK_ANCESTOR_NOT_LIVE_AT_DISPATCH"


def test_value_transition_gap_is_disproved(tmp_path: Path) -> None:
    pack, trust_root = _build_pack(tmp_path, sequence_gap=True)

    report = verify_work_chain_pack(pack, trust_root=trust_root)

    claim = _claim(report, "permit.work_value_conservation.v1")
    assert claim["verdict"] == "disproved"
    assert claim["reason_code"] == "WORK_VALUE_EVENT_SEQUENCE_INVALID"


def test_presentation_registry_cannot_change_work_verdicts(tmp_path: Path) -> None:
    pack, trust_root = _build_pack(tmp_path)
    before = verify_work_chain_pack(pack, trust_root=trust_root).to_dict()
    presentation = load_permit_presentation_registry()
    mutated = copy.deepcopy(presentation)
    mutated["profiles"][0]["customer_title"] = "A completely different label"
    profile = resolve_permit_presentation(
        pack["root"]["semantic_binding"], presentation_registry=mutated
    )
    after = verify_work_chain_pack(pack, trust_root=trust_root).to_dict()

    assert profile["customer_title"] == "A completely different label"
    for field in ("ok", "exit_code", "claims", "semantics"):
        assert after[field] == before[field]


def test_historical_and_realtime_titles_fail_safe() -> None:
    work = _semantic_binding("keel.context.work.v1")
    work["selector_registry_digest"] = "sha256:" + "f" * 64
    assert (
        resolve_permit_presentation(work)["customer_title"]
        == "AI Permit — specific title unavailable for this record"
    )

    realtime = copy.deepcopy(_semantic_binding("keel.context.work.v1"))
    realtime.update(
        {
            "semantic_id": "keel.context.realtime_session.v1",
            "trusted_source_kind": "realtime_session_service",
            "chain_role": "session_root",
            "operation": "realtime.session",
            "governed_surface": "realtime_session",
        }
    )
    realtime.pop("action_name")
    root = Path(__file__).resolve().parents[1]
    raw = (
        root / "keel_verifier" / "data" / "permit_to_x" / "semantic_registry" / "v1.json"
    ).read_bytes()
    registry = json.loads(raw)
    entry = next(
        item
        for item in registry["entries"]
        if item["semantic_id"] == "keel.context.realtime_session.v1"
    )
    realtime["selector_entry_digest"] = _digest(entry)
    assert resolve_permit_presentation(realtime)["customer_title"] == (
        "AI Permit — Realtime session"
    )
