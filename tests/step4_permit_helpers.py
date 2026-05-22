from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from keel_verifier import verifier
from keel_verifier.verdicts import ClaimVerdict


PROJECT_ID = "00000000-0000-0000-0000-000000000041"
PERMIT_ID = "20000000-0000-4000-8000-000000000001"
ACTOR_ID = "30000000-0000-4000-8000-000000000001"
EFFECTIVE_AT = "2026-05-21T10:05:00.000000Z"
CHECKPOINT_AT = "2026-05-21T10:10:00.000000Z"
CHAIN_SCOPE = f"project:{PROJECT_ID}"


def keypair(seed: bytes | None = None) -> tuple[Ed25519PrivateKey, str]:
    private_key = (
        Ed25519PrivateKey.from_private_bytes(seed)
        if seed is not None
        else Ed25519PrivateKey.generate()
    )
    public_bytes = private_key.public_key().public_bytes(
        Encoding.Raw,
        PublicFormat.Raw,
    )
    return private_key, "ed25519:" + base64.b64encode(public_bytes).decode("ascii")


def write_permit_trust_root(tmp_path: Path, public_key: str) -> Path:
    path = tmp_path / "permit-binding-trust-root.json"
    path.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "key_id": verifier._binding_key_id_from_public_key(public_key),
                        "algorithm": "ed25519",
                        "public_key": public_key,
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
    return path


def decision_payload(public_key: str, *, decision: str = "allow") -> dict[str, Any]:
    return {
        "binding_version": "v1",
        "permit_id": "10000000-0000-4000-8000-000000000001",
        "project_id": PROJECT_ID,
        "parent_permit_id": None,
        "decision": decision,
        "reason": "policy.allow",
        "provider": "openai",
        "model": "gpt-5",
        "operation": "responses.create",
        "action_name": "dispatch",
        "request_fingerprint": "sha256:" + "1" * 64,
        "constraints": {},
        "routing": {},
        "policy_id": "policy_step4",
        "policy_version": "2026-05-21",
        "policy_snapshot_hash": "sha256:" + "2" * 64,
        "issued_at": "2026-05-21T10:00:00.000000Z",
        "expires_at": "2026-05-21T11:00:00.000000Z",
        "is_dry_run": False,
        "binding_key_id": verifier._binding_key_id_from_public_key(public_key),
        "final_request_hash": "sha256:" + "3" * 64,
    }


def decision_evidence(
    private_key: Ed25519PrivateKey,
    public_key: str,
    *,
    decision: str = "allow",
    expected_decision: str | None = None,
) -> dict[str, Any]:
    payload = decision_payload(public_key, decision=decision)
    canonical_hash = verifier._compute_canonical_binding_hash(payload)
    signature = base64.b64encode(private_key.sign(canonical_hash.encode("utf-8"))).decode(
        "ascii"
    )
    evidence: dict[str, Any] = {
        "artifact_type": "permit_decision_binding",
        "artifact_version": "permit.decision.v1",
        "canonical_payload": payload,
        "binding_canonical_hash": canonical_hash,
        "binding_signature": "ed25519:" + signature,
        "binding_issued_at": payload["issued_at"],
    }
    if expected_decision is not None:
        evidence["expected_decision"] = expected_decision
    return evidence


def revocation_event(
    private_key: Ed25519PrivateKey,
    *,
    permit_id: str = PERMIT_ID,
    project_id: str = PROJECT_ID,
    actor_id: str = ACTOR_ID,
    revoked_at: str = EFFECTIVE_AT,
    effective_at: str = EFFECTIVE_AT,
    actor_kind: str = "user",
    reason_code: str = "operator.requested",
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "permit_id": permit_id,
        "project_id": project_id,
        "actor_id": actor_id,
        "actor_kind": actor_kind,
        "reason_code": reason_code,
        "revoked_at": revoked_at,
        "effective_at": effective_at,
    }
    canonical_hash = verifier._compute_canonical_binding_hash(event)
    event["signature"] = base64.b64encode(
        private_key.sign(canonical_hash.encode("utf-8"))
    ).decode("ascii")
    return event


def supported_claim(name: str) -> ClaimVerdict:
    return ClaimVerdict(name=name, verdict="supported")


def absence_predicate(
    *,
    project_id: str = PROJECT_ID,
    permit_id: str = PERMIT_ID,
    effective_at: str = EFFECTIVE_AT,
    checkpoint_at: str = CHECKPOINT_AT,
) -> dict[str, Any]:
    return {
        "version": "keel.scope_predicate.v1",
        "operator": "and",
        "equals": {
            "project_id": project_id,
            "permit_id": permit_id,
            "event_type": "dispatch.egress_bound",
        },
        "ranges": {
            "occurred_at": {
                "gte": effective_at,
                "lt": checkpoint_at,
            }
        },
    }


def scope_record(
    *,
    event_type: str = "dispatch.egress_bound",
    occurred_at: str = EFFECTIVE_AT,
    project_id: str = PROJECT_ID,
    permit_id: str = PERMIT_ID,
    sequence_number: int = 2,
) -> dict[str, Any]:
    return {
        "event_id": f"evt_{sequence_number}",
        "event_type": event_type,
        "chain_scope": CHAIN_SCOPE,
        "sequence_number": sequence_number,
        "record_hash": f"{sequence_number:064x}",
        "prev_hash": f"{sequence_number - 1:064x}",
        "created_at": occurred_at,
        "chain_format_version": "v1",
        "payload_json": {
            "event_type": event_type,
            "occurred_at": occurred_at,
            "project_id": project_id,
            "permit_id": permit_id,
        },
    }


def absence_case(
    tmp_path: Path,
    *,
    matching_count: int = 0,
    predicate: dict[str, Any] | None = None,
    disclosure_records: list[dict[str, Any]] | None = None,
    proof_bridge_records: list[dict[str, Any]] | None = None,
    write_checkpoint: bool = True,
    write_sidecar: bool = True,
    event: dict[str, Any] | None = None,
) -> dict[str, Any]:
    pack_dir = tmp_path / "pack"
    sidecar_dir = tmp_path / "sidecars"
    pack_dir.mkdir()
    sidecar_dir.mkdir()
    manifest_path = pack_dir / "manifest.json"
    manifest_path.write_text("{}", encoding="utf-8")

    predicate_value = copy.deepcopy(predicate or absence_predicate())
    revocation = event or {
        "permit_id": PERMIT_ID,
        "project_id": PROJECT_ID,
        "actor_id": ACTOR_ID,
        "actor_kind": "user",
        "reason_code": "operator.requested",
        "revoked_at": EFFECTIVE_AT,
        "effective_at": EFFECTIVE_AT,
        "signature": base64.b64encode(b"0" * 64).decode("ascii"),
    }

    if write_checkpoint:
        (tmp_path / "checkpoint.json").write_text(
            json.dumps(
                {
                    "checkpoint_id": "40000000-0000-4000-8000-000000000001",
                    "computed_at": predicate_value.get("ranges", {})
                    .get("occurred_at", {})
                    .get("lt", CHECKPOINT_AT),
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
    if write_sidecar:
        (sidecar_dir / "checkpoint-scope-state-v1.json").write_text(
            json.dumps(
                {
                    "scope_commitments": [
                        {
                            "predicate_value_hash": verifier._predicate_hash(
                                predicate_value
                            ),
                            "matching_count": matching_count,
                        }
                    ]
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )

    export_document = {
        "project_id": revocation["project_id"],
        "permit_id": revocation["permit_id"],
        "revocation_event": {"event": revocation},
        "scope_faithfulness": {
            "version": "keel.export_scope_faithfulness.v1",
            "segments": [
                {
                    "segment_id": "dispatch-absence-after-revocation",
                    "declared_scope": {
                        "predicate": predicate_value,
                    },
                    "scope_state_reference": {
                        "artifact_type": "checkpoint_scope_state",
                    },
                    "chain_evidence": {
                        "disclosure_records": disclosure_records or [],
                        "proof_bridge_records": proof_bridge_records or [],
                    },
                }
            ],
        },
    }
    return {
        "export_document": export_document,
        "manifest": {},
        "manifest_path": manifest_path,
        "scope_claims": [
            supported_claim("checkpoint.scope_state.v1"),
            supported_claim("export.scope_faithfulness.v1"),
        ],
        "revocation_claim": supported_claim("permit.revoked.v1"),
    }
