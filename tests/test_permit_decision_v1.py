from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
from typing import Any

from conftest import (
    keypair as export_keypair,
    write_combined_key_manifest,
    write_json,
    write_signed_export,
)
from step4_permit_helpers import (
    decision_evidence,
    keypair,
    write_permit_trust_root,
)
from keel_verifier.canonical import permit_binding
from keel_verifier.semantics import (
    CLAIM_REGISTRY_HASH,
    CLAIM_REGISTRY_ID,
    EXPORT_MANIFEST_INTEGRITY_HASH,
    EXPORT_MANIFEST_INTEGRITY_ID,
    PERMIT_DECISION_HASH,
    PERMIT_DECISION_ID,
    RELEASED_ARTIFACT_PATHS,
)
from keel_verifier.verifier import (
    _adjudicate_permit_decision_v1,
    _binding_key_id_from_public_key,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
PERMIT_DECISION_GOLDEN_VECTOR_PATH = (
    FIXTURES_DIR / "permit_decision_binding_golden_vectors_v1_v6.json"
)


BASE_RESOURCE_ATTRIBUTES = {
    "operation": "responses.create",
    "spend_scope": {
        "amount_max": 5000,
        "currency_class": "usd_fiat",
        "cadence": "one_time",
        "ttl_seconds": 900,
        "purpose_binding": "purchase.once",
        "recipient_address_digest": "abc123",
        "merchant_id_digest": "def456",
        "description_digest": "789abc",
    },
    "delegation_policy": {
        "delegations": [
            {
                "verb": "purchase.create",
                "amount_max": 5000,
                "currency_class": "usd_fiat",
                "ttl_seconds": 900,
                "allowed_purpose_bindings": ["purchase.once", "purchase.recurring"],
            },
            {
                "verb": "refund.issue",
                "amount_max": None,
                "currency_class": None,
                "ttl_seconds": 300,
                "allowed_purpose_bindings": ["refund.once"],
            },
        ]
    },
}
BASE_BINDING_FIELDS = {
    "permit_id": "10000000-0000-4000-8000-000000000101",
    "project_id": "00000000-0000-0000-0000-000000000041",
    "parent_permit_id": None,
    "decision": "allow",
    "reason": "policy.allow",
    "provider": "openai",
    "model": "gpt-5",
    "operation": "responses.create",
    "action_name": "mpp.purchase",
    "request_fingerprint": "sha256:" + "1" * 64,
    "constraints": {"amount_max": 5000, "currency_class": "USD_FIAT"},
    "routing": {
        "requested_provider": "openai",
        "requested_model": "gpt-5",
        "selected_provider": "openai",
        "selected_model": "gpt-5",
        "fallback_chain": [],
        "reason_code": "primary_selected",
        "fallback_occurred": False,
        "reason_metadata": None,
    },
    "policy_id": "policy_mpp",
    "policy_version": "2026-06-04",
    "policy_snapshot_hash": "sha256:" + "2" * 64,
    "issued_at": "2026-06-04T10:00:00Z",
    "expires_at": "2026-06-04T11:00:00Z",
    "is_dry_run": False,
    "final_request_hash": "sha256:" + "3" * 64,
}
V2_BINDING_FIELDS = {
    "binding_session_id": "voice_session_123",
    "binding_session_event_hash": "sha256:" + "4" * 64,
    "binding_project_anchor_hash": "sha256:" + "5" * 64,
    "permit_chain_role": "session_child",
    "inherits_from": "20000000-0000-4000-8000-000000000202",
    "authority_delta": {"actions": ["payments.charge"], "amount_max": 5000},
}


def _claim(evidence: dict, trust_root: Path):
    return _adjudicate_permit_decision_v1(
        export_document={"permit_decision": evidence},
        key_manifest_source=str(trust_root),
    )


def _binding_payload(
    public_key: str,
    *,
    version: str,
    resource_attributes: dict[str, Any] | None = None,
    spend_scope_hash: str | None = None,
    delegation_policy_hash: str | None = None,
) -> dict[str, Any]:
    resource_attributes = (
        BASE_RESOURCE_ATTRIBUTES if resource_attributes is None else resource_attributes
    )
    fields = {
        **BASE_BINDING_FIELDS,
        **V2_BINDING_FIELDS,
        "binding_key_id": _binding_key_id_from_public_key(public_key),
    }
    if version == "v2":
        return permit_binding.canonical_binding_payload_v2(**fields)
    if version == "v3":
        return permit_binding.canonical_binding_payload_v3(
            **fields,
            spend_scope_hash=(
                spend_scope_hash
                if spend_scope_hash is not None
                else permit_binding.canonical_spend_scope_payload(
                    resource_attributes["spend_scope"]
                )
            ),
        )
    if version == "v4":
        return permit_binding.canonical_binding_payload_v4(
            **fields,
            spend_scope_hash=(
                spend_scope_hash
                if spend_scope_hash is not None
                else permit_binding.canonical_spend_scope_payload(
                    resource_attributes["spend_scope"]
                )
            ),
            delegation_policy_hash=(
                delegation_policy_hash
                if delegation_policy_hash is not None
                else permit_binding.canonical_delegation_policy_payload(
                    resource_attributes["delegation_policy"]
                )
            ),
        )
    if version == "v5":
        return permit_binding.canonical_binding_payload_v5(
            **fields,
            spend_scope_hash=(
                spend_scope_hash
                if spend_scope_hash is not None
                else permit_binding.canonical_spend_scope_payload(
                    resource_attributes["spend_scope"]
                )
            ),
            delegation_policy_hash=(
                delegation_policy_hash
                if delegation_policy_hash is not None
                else permit_binding.canonical_delegation_policy_payload(
                    resource_attributes["delegation_policy"]
                )
            ),
        )
    if version == "v6":
        return permit_binding.canonical_binding_payload_v6(
            **fields,
            spend_scope_hash=(
                spend_scope_hash
                if spend_scope_hash is not None
                else permit_binding.canonical_spend_scope_payload(
                    resource_attributes["spend_scope"]
                )
            ),
            delegation_policy_hash=(
                delegation_policy_hash
                if delegation_policy_hash is not None
                else permit_binding.canonical_delegation_policy_payload(
                    resource_attributes["delegation_policy"]
                )
            ),
            resource_attributes_canonical_hash=(
                permit_binding.canonical_resource_attributes_payload(
                    resource_attributes
                )
            ),
        )
    raise AssertionError(f"unsupported test binding version: {version}")


def _binding_evidence(
    private_key,
    public_key: str,
    *,
    version: str,
    resource_attributes: dict[str, Any] | None = None,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resource_attributes = copy.deepcopy(
        BASE_RESOURCE_ATTRIBUTES if resource_attributes is None else resource_attributes
    )
    canonical_payload = payload or _binding_payload(
        public_key,
        version=version,
        resource_attributes=resource_attributes,
    )
    canonical_hash = permit_binding.compute_canonical_binding_hash(canonical_payload)
    signature = base64.b64encode(
        private_key.sign(canonical_hash.encode("utf-8"))
    ).decode("ascii")
    return {
        "artifact_type": "permit_decision_binding",
        "artifact_version": "permit.decision.v1",
        "canonical_payload": canonical_payload,
        "resource_attributes_json": json.dumps(
            resource_attributes,
            sort_keys=True,
            separators=(",", ":"),
        ),
        "binding_canonical_hash": canonical_hash,
        "binding_signature": "ed25519:" + signature,
        "binding_issued_at": canonical_payload["issued_at"],
    }


def _add_permit_decision_pins(manifest_path: Path) -> None:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["claim_set"] = {
        "version": "verifier-claims.v0",
        "registry": {
            "id": CLAIM_REGISTRY_ID,
            "hash": CLAIM_REGISTRY_HASH,
            "path": RELEASED_ARTIFACT_PATHS[CLAIM_REGISTRY_ID],
        },
        "claims": [
            {"name": "export.integrity.v1", "required": True},
            {"name": "permit.decision.v1", "required": True},
        ],
    }
    manifest["semantics_pins"] = {
        "version": "keel-semantics-pins.v0",
        "mode": "pinned",
        "artifacts": [
            {
                "id": EXPORT_MANIFEST_INTEGRITY_ID,
                "hash": EXPORT_MANIFEST_INTEGRITY_HASH,
                "path": RELEASED_ARTIFACT_PATHS[EXPORT_MANIFEST_INTEGRITY_ID],
            },
            {
                "id": PERMIT_DECISION_ID,
                "hash": PERMIT_DECISION_HASH,
                "path": RELEASED_ARTIFACT_PATHS[PERMIT_DECISION_ID],
            },
        ],
    }
    write_json(manifest_path, manifest)


def test_golden_permit_decision_vectors_v1_to_v6_supported(tmp_path: Path) -> None:
    fixture = json.loads(
        PERMIT_DECISION_GOLDEN_VECTOR_PATH.read_text(encoding="utf-8")
    )
    trust_root = write_permit_trust_root(tmp_path, fixture["binding_public_key"])

    assert fixture["schema_version"] == "permit_decision_binding_golden_vectors.v1"
    assert [item["binding_version"] for item in fixture["vectors"]] == [
        "v1",
        "v2",
        "v3",
        "v4",
        "v5",
        "v6",
    ]
    for item in fixture["vectors"]:
        artifact = item["artifact"]
        assert (
            permit_binding.compute_canonical_binding_hash(
                artifact["canonical_payload"]
            )
            == artifact["binding_canonical_hash"]
        )
        claim = _claim(artifact, trust_root)
        assert claim.aggregate_verdict == item["expected_verdict"]
        assert claim.reason_code == item["expected_reason_code"]


def test_cli_verifies_v6_golden_permit_decision_offline(
    tmp_path: Path,
    run_cli,
) -> None:
    fixture = json.loads(
        PERMIT_DECISION_GOLDEN_VECTOR_PATH.read_text(encoding="utf-8")
    )
    evidence = copy.deepcopy(
        next(
            item["artifact"]
            for item in fixture["vectors"]
            if item["binding_version"] == "v6"
        )
    )
    export_private, export_public, export_key_id = export_keypair()
    key_manifest = write_combined_key_manifest(
        tmp_path,
        export_public_key=export_public,
        export_key_id=export_key_id,
        binding_public_key=fixture["binding_public_key"],
    )
    export_file, manifest = write_signed_export(
        tmp_path,
        {"permit_decision": evidence},
        export_private_key=export_private,
        export_public_key=export_public,
        export_key_id=export_key_id,
    )
    _add_permit_decision_pins(manifest)

    result = run_cli(
        "export",
        "--json",
        str(export_file),
        str(manifest),
        "--key-manifest",
        str(key_manifest),
        "--offline",
    )
    assert result.returncode == 0, result.stderr

    payload = json.loads(result.stdout)
    claim = next(
        claim for claim in payload["claims"] if claim["name"] == "permit.decision.v1"
    )

    assert claim["verdict"] == "supported"
    assert claim["reason_code"] == "PERMIT_DECISION_SUPPORTED"


def test_permit_decision_allow_supported(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"1" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)

    claim = _claim(decision_evidence(private_key, public_key), trust_root)

    assert claim.aggregate_verdict == "supported"
    assert claim.reason_code == "PERMIT_DECISION_SUPPORTED"


def test_existing_v1_permit_validation_unchanged(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"8" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)

    claim = _claim(decision_evidence(private_key, public_key), trust_root)

    assert claim.aggregate_verdict == "supported"
    assert claim.reason_code == "PERMIT_DECISION_SUPPORTED"
    assert claim.message == "permit decision canonical hash and signature are supported"


def test_v2_permit_recompute_succeeds_for_well_formed_binding(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"9" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)

    claim = _claim(
        _binding_evidence(private_key, public_key, version="v2"),
        trust_root,
    )

    assert claim.aggregate_verdict == "supported"
    assert claim.reason_code == "PERMIT_DECISION_SUPPORTED"


def test_v2_permit_recompute_has_no_spend_subhash_in_keel_api_source(
    tmp_path: Path,
) -> None:
    private_key, public_key = keypair(b"a" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    evidence = _binding_evidence(private_key, public_key, version="v2")
    resource_attributes = json.loads(evidence["resource_attributes_json"])
    resource_attributes["spend_scope"]["amount_max"] = 9999
    evidence["resource_attributes_json"] = json.dumps(resource_attributes)

    claim = _claim(evidence, trust_root)

    assert "spend_scope_hash" not in evidence["canonical_payload"]
    assert claim.aggregate_verdict == "supported"
    assert claim.reason_code == "PERMIT_DECISION_SUPPORTED"


def test_v3_permit_recompute_succeeds_for_well_formed_binding(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"b" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)

    claim = _claim(
        _binding_evidence(private_key, public_key, version="v3"),
        trust_root,
    )

    assert claim.aggregate_verdict == "supported"
    assert claim.reason_code == "PERMIT_DECISION_SUPPORTED"


def test_v3_permit_recompute_rejects_tampered_resource_attributes_json(
    tmp_path: Path,
) -> None:
    private_key, public_key = keypair(b"c" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    evidence = _binding_evidence(private_key, public_key, version="v3")
    resource_attributes = json.loads(evidence["resource_attributes_json"])
    resource_attributes["spend_scope"]["amount_max"] = 9999
    evidence["resource_attributes_json"] = json.dumps(resource_attributes)

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "permit.binding.v3.spend_scope_hash_mismatch"


def test_v3_permit_recompute_rejects_mismatched_hash(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"d" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    payload = _binding_payload(
        public_key,
        version="v3",
        spend_scope_hash="0" * 64,
    )

    claim = _claim(
        _binding_evidence(private_key, public_key, version="v3", payload=payload),
        trust_root,
    )

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "permit.binding.v3.spend_scope_hash_mismatch"


def test_v4_permit_recompute_succeeds_for_well_formed_binding(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"e" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)

    claim = _claim(
        _binding_evidence(private_key, public_key, version="v4"),
        trust_root,
    )

    assert claim.aggregate_verdict == "supported"
    assert claim.reason_code == "PERMIT_DECISION_SUPPORTED"


def test_v4_permit_recompute_rejects_tampered_resource_attributes_json(
    tmp_path: Path,
) -> None:
    private_key, public_key = keypair(b"f" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    evidence = _binding_evidence(private_key, public_key, version="v4")
    resource_attributes = json.loads(evidence["resource_attributes_json"])
    resource_attributes["delegation_policy"]["delegations"][0]["amount_max"] = 10000
    evidence["resource_attributes_json"] = json.dumps(resource_attributes)

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "permit.binding.v4.delegation_policy_hash_mismatch"


def test_v4_permit_recompute_rejects_mismatched_hash(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"g" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    payload = _binding_payload(
        public_key,
        version="v4",
        delegation_policy_hash="0" * 64,
    )

    claim = _claim(
        _binding_evidence(private_key, public_key, version="v4", payload=payload),
        trust_root,
    )

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "permit.binding.v4.delegation_policy_hash_mismatch"


def test_v5_permit_recompute_succeeds_for_well_formed_binding(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"j" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)

    claim = _claim(
        _binding_evidence(private_key, public_key, version="v5"),
        trust_root,
    )

    assert claim.aggregate_verdict == "supported"
    assert claim.reason_code == "PERMIT_DECISION_SUPPORTED"


def test_v5_permit_recompute_succeeds_with_wire_body_evidence(
    tmp_path: Path,
) -> None:
    private_key, public_key = keypair(b"m" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    wire_body = {
        "model": "gpt-5",
        "temperature": 1.0,
        "messages": [{"role": "user", "content": "approve"}],
    }
    wire_hash = permit_binding.canonical_provider_wire_body_hash(
        wire_body,
        binding_request_canonical_version="v5",
    )
    payload = _binding_payload(public_key, version="v5")
    payload["final_request_hash"] = "sha256:" + wire_hash
    evidence = _binding_evidence(
        private_key,
        public_key,
        version="v5",
        payload=payload,
    )
    evidence["binding_request_hash"] = wire_hash
    evidence["binding_request_canonical_version"] = "v5"
    evidence["binding_request_body"] = wire_body

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "supported"
    assert claim.reason_code == "PERMIT_DECISION_SUPPORTED"


def test_v5_permit_recompute_rejects_tampered_wire_body(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"n" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    wire_body = {
        "model": "gpt-5",
        "temperature": 1.0,
        "messages": [{"role": "user", "content": "approve"}],
    }
    wire_hash = permit_binding.canonical_provider_wire_body_hash(
        wire_body,
        binding_request_canonical_version="v5",
    )
    payload = _binding_payload(public_key, version="v5")
    payload["final_request_hash"] = "sha256:" + wire_hash
    evidence = _binding_evidence(
        private_key,
        public_key,
        version="v5",
        payload=payload,
    )
    evidence["binding_request_hash"] = wire_hash
    evidence["binding_request_canonical_version"] = "v5"
    evidence["binding_request_body"] = {
        **wire_body,
        "temperature": 0.5,
    }

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "permit.binding.v5.wire_body_hash_mismatch"


def test_v5_permit_recompute_rejects_tampered_spend_scope(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"k" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    evidence = _binding_evidence(private_key, public_key, version="v5")
    resource_attributes = json.loads(evidence["resource_attributes_json"])
    resource_attributes["spend_scope"]["amount_max"] = 9999
    evidence["resource_attributes_json"] = json.dumps(resource_attributes)

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "permit.binding.v5.spend_scope_hash_mismatch"


def test_v5_permit_recompute_rejects_tampered_delegation_policy(
    tmp_path: Path,
) -> None:
    private_key, public_key = keypair(b"l" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    evidence = _binding_evidence(private_key, public_key, version="v5")
    resource_attributes = json.loads(evidence["resource_attributes_json"])
    resource_attributes["delegation_policy"]["delegations"][0]["amount_max"] = 10000
    evidence["resource_attributes_json"] = json.dumps(resource_attributes)

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "permit.binding.v5.delegation_policy_hash_mismatch"


def test_v6_permit_recompute_succeeds_for_well_formed_binding(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"o" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)

    claim = _claim(
        _binding_evidence(private_key, public_key, version="v6"),
        trust_root,
    )

    assert claim.aggregate_verdict == "supported"
    assert claim.reason_code == "PERMIT_DECISION_SUPPORTED"


def test_v6_permit_recompute_rejects_tampered_resource_attributes_json(
    tmp_path: Path,
) -> None:
    private_key, public_key = keypair(b"p" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    resource_attributes = copy.deepcopy(BASE_RESOURCE_ATTRIBUTES)
    resource_attributes["tap"] = {"mandate_id": "tap_001", "amount": 5000}
    evidence = _binding_evidence(
        private_key,
        public_key,
        version="v6",
        resource_attributes=resource_attributes,
    )
    tampered = json.loads(evidence["resource_attributes_json"])
    tampered["tap"]["amount"] = 9999
    evidence["resource_attributes_json"] = json.dumps(tampered)

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "disproved"
    assert (
        claim.reason_code
        == "permit.binding.v6.resource_attributes_canonical_hash_mismatch"
    )


def test_v6_replay_rejects_missing_resource_attributes_canonical_hash(
    tmp_path: Path,
) -> None:
    private_key, public_key = keypair(b"q" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    payload = _binding_payload(public_key, version="v6")
    payload.pop("resource_attributes_canonical_hash")

    claim = _claim(
        _binding_evidence(private_key, public_key, version="v6", payload=payload),
        trust_root,
    )

    assert claim.aggregate_verdict == "disproved"
    assert (
        claim.reason_code
        == "permit.binding.v6.resource_attributes_canonical_hash_missing"
    )


def test_v6_replay_rejects_mismatched_resource_attributes_canonical_hash(
    tmp_path: Path,
) -> None:
    private_key, public_key = keypair(b"r" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    payload = _binding_payload(public_key, version="v6")
    payload["resource_attributes_canonical_hash"] = "0" * 64

    claim = _claim(
        _binding_evidence(private_key, public_key, version="v6", payload=payload),
        trust_root,
    )

    assert claim.aggregate_verdict == "disproved"
    assert (
        claim.reason_code
        == "permit.binding.v6.resource_attributes_canonical_hash_mismatch"
    )


def test_v6_replay_rejects_binding_hash_mismatch(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"s" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    evidence = _binding_evidence(private_key, public_key, version="v6")
    evidence["canonical_payload"] = copy.deepcopy(evidence["canonical_payload"])
    evidence["canonical_payload"]["reason"] = "policy.changed"

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "PERMIT_DECISION_CANONICAL_HASH_MISMATCH"


def test_v6_replay_rejects_missing_resource_attributes_json(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"t" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    evidence = _binding_evidence(private_key, public_key, version="v6")
    evidence.pop("resource_attributes_json")

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "insufficient_evidence"
    assert claim.reason_code == "permit.binding.resource_attributes_json_missing"


def test_v6_spend_scope_value_tamper_trips_subhash_and_resource_hash(
    tmp_path: Path,
) -> None:
    private_key, public_key = keypair(b"u" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    evidence = _binding_evidence(private_key, public_key, version="v6")
    canonical_payload = evidence["canonical_payload"]
    resource_attributes = json.loads(evidence["resource_attributes_json"])
    resource_attributes["spend_scope"]["amount_max"] = 9999
    evidence["resource_attributes_json"] = json.dumps(resource_attributes)

    assert (
        permit_binding.canonical_spend_scope_payload(
            resource_attributes["spend_scope"]
        )
        != canonical_payload["spend_scope_hash"]
    )
    assert (
        permit_binding.canonical_resource_attributes_payload(resource_attributes)
        != canonical_payload["resource_attributes_canonical_hash"]
    )

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "disproved"
    assert (
        claim.reason_code
        == "permit.binding.v6.resource_attributes_canonical_hash_mismatch"
    )


def test_v6_spend_scope_normalization_collision_trips_resource_hash_only(
    tmp_path: Path,
) -> None:
    private_key, public_key = keypair(b"v" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    evidence = _binding_evidence(private_key, public_key, version="v6")
    canonical_payload = evidence["canonical_payload"]
    resource_attributes = json.loads(evidence["resource_attributes_json"])
    resource_attributes["spend_scope"]["currency_class"] = "USD_FIAT"
    evidence["resource_attributes_json"] = json.dumps(resource_attributes)

    assert (
        permit_binding.canonical_spend_scope_payload(
            resource_attributes["spend_scope"]
        )
        == canonical_payload["spend_scope_hash"]
    )
    assert (
        permit_binding.canonical_resource_attributes_payload(resource_attributes)
        != canonical_payload["resource_attributes_canonical_hash"]
    )

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "disproved"
    assert (
        claim.reason_code
        == "permit.binding.v6.resource_attributes_canonical_hash_mismatch"
    )


def test_v5_permit_does_not_enter_v6_resource_hash_recompute_path(
    tmp_path: Path,
) -> None:
    private_key, public_key = keypair(b"w" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    evidence = _binding_evidence(private_key, public_key, version="v5")
    resource_attributes = json.loads(evidence["resource_attributes_json"])
    resource_attributes["spend_scope"]["currency_class"] = "USD_FIAT"
    evidence["resource_attributes_json"] = json.dumps(resource_attributes)

    claim = _claim(evidence, trust_root)

    assert "resource_attributes_canonical_hash" not in evidence["canonical_payload"]
    assert claim.aggregate_verdict == "supported"
    assert claim.reason_code == "PERMIT_DECISION_SUPPORTED"


def test_unknown_binding_version_rejected(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"h" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    evidence = decision_evidence(private_key, public_key)
    evidence["canonical_payload"] = copy.deepcopy(evidence["canonical_payload"])
    evidence["canonical_payload"]["binding_version"] = "v7"

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "unverifiable_scope"
    assert claim.reason_code == "PERMIT_DECISION_UNSUPPORTED_BINDING_VERSION"


def test_full_claim_verifies_mpp_spend_scope_binding(tmp_path: Path, run_cli) -> None:
    export_private, export_public, export_key_id = export_keypair()
    binding_private, binding_public = keypair(b"i" * 32)
    evidence = _binding_evidence(binding_private, binding_public, version="v3")
    key_manifest = write_combined_key_manifest(
        tmp_path,
        export_public_key=export_public,
        export_key_id=export_key_id,
        binding_public_key=binding_public,
    )
    export_file, manifest = write_signed_export(
        tmp_path,
        {"permit_decision": evidence},
        export_private_key=export_private,
        export_public_key=export_public,
        export_key_id=export_key_id,
    )
    _add_permit_decision_pins(manifest)

    result = run_cli(
        "export",
        "--json",
        str(export_file),
        str(manifest),
        "--key-manifest",
        str(key_manifest),
    )
    payload = json.loads(result.stdout)
    claim = next(
        claim for claim in payload["claims"] if claim["name"] == "permit.decision.v1"
    )

    assert result.returncode == 0, result.stderr
    assert claim["verdict"] == "supported"
    assert claim["reason_code"] == "PERMIT_DECISION_SUPPORTED"


def test_permit_decision_bad_signature_disproves(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"2" * 32)
    other_private_key, _other_public_key = keypair(b"3" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    evidence = decision_evidence(private_key, public_key)
    evidence["binding_signature"] = decision_evidence(
        other_private_key,
        public_key,
    )["binding_signature"]

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "PERMIT_DECISION_SIGNATURE_INVALID"


def test_permit_decision_tampered_decision_field_disproves(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"4" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    evidence = decision_evidence(private_key, public_key, decision="deny")
    evidence["canonical_payload"] = copy.deepcopy(evidence["canonical_payload"])
    evidence["canonical_payload"]["decision"] = "allow"

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "PERMIT_DECISION_CANONICAL_HASH_MISMATCH"


def test_permit_decision_untrusted_key_is_insufficient(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"5" * 32)
    _trusted_private_key, trusted_public_key = keypair(b"6" * 32)
    trust_root = write_permit_trust_root(tmp_path, trusted_public_key)

    claim = _claim(decision_evidence(private_key, public_key), trust_root)

    assert claim.aggregate_verdict == "insufficient_evidence"
    assert claim.reason_code == "PERMIT_DECISION_UNTRUSTED_KEY"


def test_permit_decision_canonical_payload_mismatch_disproves(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"7" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    evidence = decision_evidence(
        private_key,
        public_key,
        decision="allow",
        expected_decision="deny",
    )

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "PERMIT_DECISION_CANONICAL_PAYLOAD_MISMATCH"
