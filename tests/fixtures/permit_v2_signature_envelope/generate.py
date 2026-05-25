from __future__ import annotations

import base64
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from keel_verifier import verifier  # noqa: E402
from keel_verifier.semantics import (  # noqa: E402
    CLAIM_REGISTRY_HASH,
    CLAIM_REGISTRY_ID,
    PERMIT_AUDIT_ATTESTATION_HASH,
    PERMIT_AUDIT_ATTESTATION_ID,
    PERMIT_COUNTER_SIGNATURE_HASH,
    PERMIT_COUNTER_SIGNATURE_ID,
    PERMIT_OPERATOR_APPROVAL_HASH,
    PERMIT_OPERATOR_APPROVAL_ID,
    RELEASED_ARTIFACT_PATHS,
    SEMANTICS_PINS_VERSION,
)

ROOT = Path(__file__).resolve().parent
ACCOUNT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
PROJECT_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
OPERATOR_ID = "22222222-bbbb-4bbb-8bbb-222222222222"
BUYER_ID = "33333333-cccc-4ccc-8ccc-333333333333"
ISSUER_SIGNATURE_HASH = "1" * 64
DISPATCH_HASH = "2" * 64
EXPORT_SIGNED_AT = "2026-05-23T13:00:00Z"


@dataclass(frozen=True)
class SlotConfig:
    claim: str
    slot_name: str
    payload_type: str
    semantic_id: str
    semantic_hash: str
    signer_id: str
    signer_field: str
    key_purpose: str
    signer_role: str


SLOTS = {
    "operator_approval": SlotConfig(
        claim="permit.operator_approval.v1",
        slot_name="operator_approval",
        payload_type="permit.operator_approval.v1",
        semantic_id=PERMIT_OPERATOR_APPROVAL_ID,
        semantic_hash=PERMIT_OPERATOR_APPROVAL_HASH,
        signer_id=OPERATOR_ID,
        signer_field="operator_id",
        key_purpose="permit_v2_operator",
        signer_role="operator",
    ),
    "counter_signature": SlotConfig(
        claim="permit.counter_signature.v1",
        slot_name="counter_signature",
        payload_type="permit.counter_signature.v1",
        semantic_id=PERMIT_COUNTER_SIGNATURE_ID,
        semantic_hash=PERMIT_COUNTER_SIGNATURE_HASH,
        signer_id=BUYER_ID,
        signer_field="buyer_principal_id",
        key_purpose="permit_v2_buyer_principal",
        signer_role="buyer_principal",
    ),
    "audit_attestation": SlotConfig(
        claim="permit.audit_attestation.v1",
        slot_name="audit_attestation",
        payload_type="permit.audit_attestation.v1",
        semantic_id=PERMIT_AUDIT_ATTESTATION_ID,
        semantic_hash=PERMIT_AUDIT_ATTESTATION_HASH,
        signer_id=BUYER_ID,
        signer_field="buyer_principal_id",
        key_purpose="permit_v2_buyer_principal",
        signer_role="buyer_principal",
    ),
}


def _private_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


def _public_key(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return "ed25519:" + base64.b64encode(raw).decode("ascii")


def _slot_key_id(public_key: str) -> str:
    raw = base64.b64decode(public_key.removeprefix("ed25519:"))
    return hashlib.sha256(raw).hexdigest()


def _export_key_id(public_key: str) -> str:
    raw = base64.b64decode(public_key.removeprefix("ed25519:"))
    return "sha256:" + hashlib.sha256(raw).hexdigest()[:32]


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _permit(index: int) -> dict[str, Any]:
    return {
        "account_id": ACCOUNT_ID,
        "action_name": "generate.text",
        "binding_request_hash": DISPATCH_HASH,
        "created_at": "2026-05-23T12:00:00.000000Z",
        "decision": "allow",
        "expires_at": "2026-05-23T14:00:00.000000Z",
        "id": f"11111111-aaaa-4aaa-8aaa-{index:012d}",
        "issuer_signature_hash": ISSUER_SIGNATURE_HASH,
        "permit_format_version": "v2",
        "project_id": PROJECT_ID,
        "reason": "policy.allow",
        "request_fingerprint": "3" * 64,
        "resource_attributes": {"operation": "generate.text"},
        "resource_model": f"gpt-4o-mini-{index}",
        "resource_provider": "openai",
        "signature": {
            "key_id": "issuer-key-v1",
            "signature": base64.b64encode(b"1" * 64).decode("ascii"),
            "signed_at": "2026-05-23T12:00:01.000000Z",
            "signed_payload_hash": "4" * 64,
            "signer_id": "55555555-eeee-4eee-8eee-555555555555",
        },
        "subject_id": f"subject-{index:03d}",
        "subject_type": "user",
    }


def _permit_canonical_hash(permit: dict[str, Any]) -> str:
    value = verifier._permit_v2_canonical_permit_hash(permit)
    assert value is not None
    return value


def _execution_intent_hash(permit: dict[str, Any], *, dispatch_hash: str = DISPATCH_HASH) -> str:
    payload = {
        "payload_type": "permit.counter_signature.execution_intent.v1",
        "permit_id": permit["id"],
        "permit_canonical_hash": _permit_canonical_hash(permit),
        "dispatch_request_hash": dispatch_hash,
        "resource_provider": permit["resource_provider"],
        "resource_model": permit["resource_model"],
        "resource_operation": permit["resource_attributes"]["operation"],
    }
    return hashlib.sha256(verifier._canonical_json_bytes(payload)).hexdigest()


def _slot_payload(
    permit: dict[str, Any],
    config: SlotConfig,
    slot: dict[str, Any],
) -> dict[str, Any]:
    payload = {
        "payload_type": config.payload_type,
        "permit_id": permit["id"],
        "issuer_signature_hash": ISSUER_SIGNATURE_HASH,
        "permit_canonical_hash": _permit_canonical_hash(permit),
        config.signer_field: slot["signer_id"],
        "signed_at": slot["signed_at"],
    }
    if config.slot_name == "counter_signature":
        payload["execution_intent_hash"] = slot["execution_intent_hash"]
    if config.slot_name == "audit_attestation":
        payload["batch_id"] = slot["batch_id"]
    return payload


def _signed_slot(
    permit: dict[str, Any],
    config: SlotConfig,
    private_key: Ed25519PrivateKey,
    public_key: str,
    *,
    signed_at: str,
    execution_intent_hash: str | None = None,
    batch_id: str = "batch-alpha",
    key_id: str | None = None,
) -> dict[str, Any]:
    slot = {
        "payload_type": config.payload_type,
        "signer_id": config.signer_id,
        "key_id": key_id or _slot_key_id(public_key),
        "signed_at": signed_at,
        "signed_payload_hash": "",
        "signature": "",
    }
    if config.slot_name == "counter_signature":
        slot["execution_intent_hash"] = execution_intent_hash or _execution_intent_hash(permit)
    if config.slot_name == "audit_attestation":
        slot["batch_id"] = batch_id
    payload_bytes = verifier._canonical_json_bytes(_slot_payload(permit, config, slot))
    slot["signed_payload_hash"] = hashlib.sha256(payload_bytes).hexdigest()
    slot["signature"] = base64.b64encode(private_key.sign(payload_bytes)).decode("ascii")
    return slot


def _key_manifest(
    config: SlotConfig,
    export_public_key: str,
    signer_public_key: str | None,
    *,
    signer_key_id: str | None = None,
    revoked_at: str | None = None,
    valid_from: str = "2026-01-01T00:00:00Z",
) -> dict[str, Any]:
    keys = [
        {
            "algorithm": "ed25519",
            "key_id": _export_key_id(export_public_key),
            "public_key": export_public_key,
            "purpose": "export_signing",
            "status": "active",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": None,
        }
    ]
    if signer_public_key is not None:
        keys.append(
            {
                "account_id": ACCOUNT_ID,
                "algorithm": "ed25519",
                "compromised_at": None,
                "key_id": signer_key_id or _slot_key_id(signer_public_key),
                "public_key": signer_public_key,
                "purpose": config.key_purpose,
                "revoked_at": revoked_at,
                "signer_id": config.signer_id,
                "signer_role": config.signer_role,
                "status": "active",
                "valid_from": valid_from,
                "valid_until": None,
            }
        )
    return {"keys": keys}


def _manifest(
    config: SlotConfig,
    export_path: Path,
    export_private_key: Ed25519PrivateKey,
    export_key_id: str,
) -> dict[str, Any]:
    digest = "sha256:" + hashlib.sha256(export_path.read_bytes()).hexdigest()
    signature = base64.b64encode(export_private_key.sign(digest.encode("utf-8"))).decode("ascii")
    return {
        "claim_set": {
            "version": "verifier-claims.v0",
            "registry": {
                "id": CLAIM_REGISTRY_ID,
                "hash": CLAIM_REGISTRY_HASH,
                "path": RELEASED_ARTIFACT_PATHS[CLAIM_REGISTRY_ID],
            },
            "claims": [{"name": config.claim, "required": True}],
        },
        "content_hash": digest,
        "key_id": export_key_id,
        "semantics_pins": {
            "version": SEMANTICS_PINS_VERSION,
            "mode": "pinned",
            "artifacts": [
                {
                    "id": config.semantic_id,
                    "hash": config.semantic_hash,
                    "path": RELEASED_ARTIFACT_PATHS[config.semantic_id],
                }
            ],
        },
        "signature": "ed25519:" + signature,
        "signed_at": EXPORT_SIGNED_AT,
    }


def _record(
    *,
    fixture_id: str,
    config: SlotConfig,
    kind: str,
    expected_verdict: str,
    expected_code: str,
) -> dict[str, Any]:
    return {
        "id": fixture_id,
        "claim": config.claim,
        "kind": kind,
        "expected_verdict": expected_verdict,
        "expected_code": expected_code,
        "pack": {
            "export_file": f"{fixture_id}/export.json",
            "manifest": f"{fixture_id}/manifest.json",
            "key_manifest": f"{fixture_id}/key_manifest.json",
        },
    }


def _write_fixture(
    *,
    fixture_id: str,
    config: SlotConfig,
    index: int,
    kind: str,
    expected_verdict: str,
    expected_code: str,
    mutate: str | None = None,
) -> dict[str, Any]:
    fixture_dir = ROOT / fixture_id
    fixture_dir.mkdir(parents=True, exist_ok=True)

    export_private = _private_key("export")
    export_public = _public_key(export_private)
    signer_private = _private_key(config.slot_name)
    signer_public = _public_key(signer_private)
    wrong_private = _private_key(config.slot_name + "-wrong")
    wrong_public = _public_key(wrong_private)

    permit = _permit(index)
    signed_at = "2026-05-23T12:30:00.123456Z"
    if mutate == "signed_at_outside_validity":
        signed_at = "2026-05-23T11:30:00.123456Z"
    intent_hash = _execution_intent_hash(permit)
    if mutate == "execution_intent_mismatch":
        intent_hash = _execution_intent_hash(permit, dispatch_hash="0" * 64)
    slot_public = signer_public
    slot_key_id = _slot_key_id(signer_public)
    if mutate == "wrong_key":
        slot_public = wrong_public
        slot_key_id = _slot_key_id(wrong_public)

    slot = _signed_slot(
        permit,
        config,
        signer_private,
        signer_public,
        signed_at=signed_at,
        execution_intent_hash=intent_hash,
        key_id=slot_key_id,
    )
    if mutate == "invalid_signature":
        slot["signature"] = base64.b64encode(b"\x00" * 64).decode("ascii")
    elif mutate == "signed_payload_hash_tampered":
        slot["signed_payload_hash"] = "f" * 64
    elif mutate == "payload_type_mismatch":
        slot["payload_type"] = (
            "permit.operator_approval.v1"
            if config.payload_type != "permit.operator_approval.v1"
            else "permit.counter_signature.v1"
        )
    permit[config.slot_name] = slot
    if mutate == "payload_tampered":
        permit["reason"] = "policy.tampered"

    export_doc = permit
    if config.slot_name == "audit_attestation":
        export_doc["audit_batches"] = [{"batch_id": slot["batch_id"]}]
    if mutate == "audit_batch_unknown":
        export_doc["audit_batches"] = [{"batch_id": "other-batch"}]
    if mutate == "counter_post_revocation":
        export_doc["revocation"] = {"effective_at": "2026-05-23T12:20:00.123456Z"}

    _write_json(fixture_dir / "export.json", export_doc)

    signer_key = slot_public
    signer_key_id = _slot_key_id(slot_public)
    revoked_at = None
    valid_from = "2026-01-01T00:00:00Z"
    if mutate == "key_revoked_after_signing":
        revoked_at = "2026-05-23T12:45:00.000000Z"
    if mutate == "missing_key_registry":
        signer_key = None
    key_manifest = _key_manifest(
        config,
        export_public,
        signer_key,
        signer_key_id=signer_key_id,
        revoked_at=revoked_at,
        valid_from=valid_from,
    )
    _write_json(fixture_dir / "key_manifest.json", key_manifest)
    manifest = _manifest(
        config,
        fixture_dir / "export.json",
        export_private,
        _export_key_id(export_public),
    )
    _write_json(fixture_dir / "manifest.json", manifest)
    return _record(
        fixture_id=fixture_id,
        config=config,
        kind=kind,
        expected_verdict=expected_verdict,
        expected_code=expected_code,
    )


def main() -> None:
    records: list[dict[str, Any]] = []
    for slot_index, (slot_name, config) in enumerate(SLOTS.items(), start=1):
        for positive_index in range(1, 7):
            records.append(
                _write_fixture(
                    fixture_id=f"{slot_name}_positive_{positive_index:02d}",
                    config=config,
                    index=slot_index * 100 + positive_index,
                    kind="positive",
                    expected_verdict="supported",
                    expected_code=f"PERMIT_{slot_name.upper()}_SUPPORTED",
                )
            )

        negative_cases = [
            ("invalid_signature", "disproved", f"PERMIT_{slot_name.upper()}_INVALID"),
            ("wrong_key", "disproved", f"PERMIT_{slot_name.upper()}_INVALID"),
            ("signed_payload_hash_tampered", "disproved", f"PERMIT_{slot_name.upper()}_INVALID"),
            ("payload_tampered", "disproved", f"PERMIT_{slot_name.upper()}_INVALID"),
            ("payload_type_mismatch", "disproved", "PAYLOAD_TYPE_MISMATCH"),
        ]
        if slot_name == "counter_signature":
            negative_cases.append(
                (
                    "execution_intent_mismatch",
                    "disproved",
                    "counter_signature.execution_intent_mismatch",
                )
            )
            negative_cases.append(
                ("counter_post_revocation", "disproved", f"PERMIT_{slot_name.upper()}_INVALID")
            )
        if slot_name == "audit_attestation":
            negative_cases.append(
                (
                    "audit_batch_unknown",
                    "disproved",
                    "PERMIT_AUDIT_ATTESTATION_BATCH_MISMATCH",
                )
            )
        for case_index, (case, verdict, code) in enumerate(negative_cases, start=1):
            records.append(
                _write_fixture(
                    fixture_id=f"{slot_name}_negative_{case}",
                    config=config,
                    index=slot_index * 100 + 20 + case_index,
                    kind="negative",
                    expected_verdict=verdict,
                    expected_code=code,
                    mutate=case,
                )
            )

        edge_cases = [
            ("key_revoked_after_signing", "supported", f"PERMIT_{slot_name.upper()}_SUPPORTED"),
            ("signed_at_outside_validity", "disproved", f"PERMIT_{slot_name.upper()}_INVALID"),
            ("missing_key_registry", "insufficient_evidence", f"PERMIT_{slot_name.upper()}_KEY_NOT_TRUSTED"),
        ]
        for case_index, (case, verdict, code) in enumerate(edge_cases, start=1):
            records.append(
                _write_fixture(
                    fixture_id=f"{slot_name}_edge_{case}",
                    config=config,
                    index=slot_index * 100 + 40 + case_index,
                    kind="edge",
                    expected_verdict=verdict,
                    expected_code=code,
                    mutate=case,
                )
            )

    corpus = {"records": records}
    _write_json(ROOT / "corpus.json", corpus)


if __name__ == "__main__":
    main()
