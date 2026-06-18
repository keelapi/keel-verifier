from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from keel_verifier import verifier


@pytest.fixture
def run_cli():
    def _run(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "keel_verifier", *args],
            cwd=str(cwd) if cwd else None,
            text=True,
            capture_output=True,
            check=False,
        )
    return _run


def keypair() -> tuple[Ed25519PrivateKey, str, str]:
    private_key = Ed25519PrivateKey.generate()
    pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
    public_key = f"ed25519:{pub_b64}"
    key_id = f"sha256:{hashlib.sha256(pub_bytes).hexdigest()[:32]}"
    return private_key, public_key, key_id


def permit_binding_key_id(public_key: str) -> str:
    raw = base64.b64decode(public_key.removeprefix("ed25519:"))
    return hashlib.sha256(raw).hexdigest()[:16]


def content_hash(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def write_json(path: Path, value: dict[str, Any]) -> Path:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def write_signed_export(
    tmp_path: Path,
    bundle: dict[str, Any],
    *,
    export_private_key: Ed25519PrivateKey,
    export_public_key: str,
    export_key_id: str,
) -> tuple[Path, Path]:
    export_path = write_json(tmp_path / "export.json", bundle)
    data = export_path.read_bytes()
    digest = content_hash(data)
    signature = base64.b64encode(export_private_key.sign(digest.encode("utf-8"))).decode("ascii")
    manifest = {
        "content_hash": digest,
        "signature": f"ed25519:{signature}",
        "public_key": export_public_key,
        "key_id": export_key_id,
        "signed_at": "2026-05-07T12:00:00Z",
    }
    manifest_path = write_json(tmp_path / "manifest.json", manifest)
    return export_path, manifest_path


def write_signed_payload(
    tmp_path: Path,
    file_name: str,
    payload: bytes,
    *,
    export_private_key: Ed25519PrivateKey,
    export_public_key: str,
    export_key_id: str,
    manifest_extra: dict[str, Any] | None = None,
) -> tuple[Path, Path]:
    export_path = tmp_path / file_name
    export_path.write_bytes(payload)
    digest = content_hash(payload)
    signature = base64.b64encode(export_private_key.sign(digest.encode("utf-8"))).decode("ascii")
    manifest = {
        "content_hash": digest,
        "signature": f"ed25519:{signature}",
        "public_key": export_public_key,
        "key_id": export_key_id,
        "signed_at": "2026-05-07T12:00:00Z",
        **(manifest_extra or {}),
    }
    manifest_path = write_json(tmp_path / "manifest.json", manifest)
    return export_path, manifest_path


def write_key_manifest(tmp_path: Path, *, public_key: str, purpose: str = "permit_binding_signing") -> Path:
    key_id = permit_binding_key_id(public_key) if purpose == "permit_binding_signing" else verifier._public_key_fingerprint(public_key)
    return write_json(
        tmp_path / f"{purpose}-keys.json",
        {
            "purpose": purpose,
            "keys": [
                {
                    "key_id": key_id,
                    "public_key_b64": public_key.removeprefix("ed25519:"),
                    "active_from": "2026-01-01T00:00:00Z",
                    "active_to": None,
                }
            ],
        },
    )



def write_combined_key_manifest(
    tmp_path: Path,
    *,
    export_public_key: str,
    export_key_id: str,
    binding_public_key: str,
) -> Path:
    return write_json(
        tmp_path / "combined-keys.json",
        {
            "keys": [
                {
                    "key_id": export_key_id,
                    "algorithm": "ed25519",
                    "public_key": export_public_key,
                    "purpose": "export_signing",
                    "status": "active",
                    "valid_from": "2026-01-01T00:00:00Z",
                    "valid_to": None,
                },
                {
                    "key_id": permit_binding_key_id(binding_public_key),
                    "algorithm": "ed25519",
                    "public_key": binding_public_key,
                    "purpose": "permit_binding_signing",
                    "status": "active",
                    "valid_from": "2026-01-01T00:00:00Z",
                    "valid_to": None,
                },
            ],
        },
    )


def chain_entry(
    *,
    event_id: str,
    event_type: str,
    sequence_number: int,
    prev_hash: str,
    chain_scope: str = "project:00000000-0000-0000-0000-000000000001",
    payload_json: dict[str, Any] | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    created = created_at or f"2026-05-07T12:00:{sequence_number:02d}.000000Z"
    record_hash = verifier._compute_record_hash_v1(
        event_id=event_id,
        event_type=event_type,
        resource_type="permit",
        resource_id="permit_123",
        outcome="success",
        severity="info",
        created_at=created,
        prev_hash=prev_hash,
        sequence_number=sequence_number,
    )
    return {
        "event_id": event_id,
        "event_type": event_type,
        "resource_type": "permit",
        "resource_id": "permit_123",
        "outcome": "success",
        "severity": "info",
        "created_at": created,
        "prev_hash": prev_hash,
        "record_hash": record_hash,
        "sequence_number": sequence_number,
        "chain_scope": chain_scope,
        "chain_format_version": "v1",
        "payload_json": payload_json or {},
    }


def audit_bundle(entries: list[dict[str, Any]], *, binding_request_hash: str | None = None) -> dict[str, Any]:
    permit: dict[str, Any] = {"id": "permit_123"}
    if binding_request_hash is not None:
        permit["binding_request_hash"] = binding_request_hash
    return {
        "bundle_type": "audit_export_bundle",
        "schema_version": 2,
        "include_chain_entries": True,
        "records": [
            {
                "permit": permit,
                "chain_entries": entries,
            }
        ],
    }


def linear_entries(payloads: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    prev = "0" * 64
    entries = []
    for index, (event_type, payload) in enumerate(payloads, start=1):
        entry = chain_entry(
            event_id=f"evt_{index:03d}",
            event_type=event_type,
            sequence_number=index,
            prev_hash=prev,
            payload_json=payload,
        )
        entries.append(entry)
        prev = entry["record_hash"]
    return entries


def signed_closure_v2(
    private_key: Ed25519PrivateKey,
    *,
    public_key: str,
    dispatch_digest: str,
    provider_digest: str,
    client_digest: str,
    binding_version: str = "closure_v2",
) -> dict[str, Any]:
    signed_at = datetime(2026, 5, 7, 12, 0, 30, tzinfo=timezone.utc)
    base = signed_at - timedelta(seconds=10)
    payload = {
        "binding_version": binding_version,
        "permit_id": "permit_123",
        "execution_id": "exec_123",
        "correlation_id": "corr_123",
        "provider": "openai",
        "model": "gpt-4o-mini",
        "dispatch_request_digest_v1": dispatch_digest,
        "provider_response_digest_v1": provider_digest,
        "client_response_digest_v1": client_digest,
        "closure_status": "closed",
        "status_code": 200,
        "provider_response_id": "resp_123",
        "dispatch_request_digest_semantics": "approved_request_body_bytes_at_dispatch_time",
        "provider_response_digest_semantics": "provider_bytes_received_by_keel",
        "client_response_digest_semantics": "response_bytes_handed_to_asgi_not_tcp_receipt",
        "request_created_at": base.isoformat().replace("+00:00", "Z"),
        "started_at": (base + timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "completed_at": (base + timedelta(seconds=5)).isoformat().replace("+00:00", "Z"),
        "provider_response_received_at": (base + timedelta(seconds=4)).isoformat().replace("+00:00", "Z"),
        "client_response_delivered_at": (base + timedelta(seconds=5)).isoformat().replace("+00:00", "Z"),
        "closure_signed_at": signed_at.isoformat().replace("+00:00", "Z"),
        "binding_key_id": permit_binding_key_id(public_key),
    }
    canonical_hash = verifier._compute_canonical_binding_hash(payload)
    signature = base64.b64encode(private_key.sign(canonical_hash.encode("utf-8"))).decode("ascii")
    return {
        **payload,
        "closure_canonical_hash": canonical_hash,
        "closure_signature_b64": signature,
    }


def workflow_declaration_intent(
    *,
    expected_calls: int | None = 2,
    max_calls: int | None = 5,
) -> dict[str, Any]:
    intent = {
        "expected_calls": expected_calls,
        "max_calls": max_calls,
        "expected_model": "gpt-4o-mini",
        "expected_input_tokens_per_call": 100,
        "expected_output_tokens_per_call": 50,
        "max_duration_seconds": 3600,
    }
    return {key: value for key, value in intent.items() if value is not None}


def workflow_amendment_delta(
    amendment: dict[str, Any],
) -> dict[str, Any]:
    return {
        key: amendment[key]
        for key in (
            "applied_against_version",
            "previous_max_calls",
            "new_max_calls",
            "previous_expected_calls",
            "new_expected_calls",
            "reason_provided",
        )
        if amendment.get(key) is not None
    }


def workflow_effective_intent_hash(
    declaration: dict[str, Any],
    amendments: list[dict[str, Any]],
    *,
    before_created_at: str | None = None,
) -> str:
    cutoff = None
    if before_created_at is not None:
        cutoff = datetime.fromisoformat(before_created_at.replace("Z", "+00:00"))
    ordered = sorted(
        amendments,
        key=lambda item: (
            datetime.fromisoformat(item["created_at"].replace("Z", "+00:00")),
            item["workflow_amendment_id"],
        ),
    )
    hasher = hashlib.sha256()
    hasher.update(
        verifier._canonical_workflow_json(declaration["intent_json"]).encode("utf-8")
    )
    for amendment in ordered:
        created = datetime.fromisoformat(amendment["created_at"].replace("Z", "+00:00"))
        if cutoff is not None and created >= cutoff:
            continue
        hasher.update(
            verifier._canonical_workflow_json(workflow_amendment_delta(amendment)).encode("utf-8")
        )
    return hasher.hexdigest()


def signed_workflow_declaration(
    private_key: Ed25519PrivateKey,
    *,
    public_key: str,
    project_id: str = "00000000-0000-0000-0000-000000000001",
    workflow_id: str = "wf_123",
    workflow_declaration_id: str = "10000000-0000-0000-0000-000000000001",
    intent: dict[str, Any] | None = None,
    version: int = 1,
    issued_at: datetime | None = None,
) -> dict[str, Any]:
    issued = issued_at or datetime(2026, 5, 7, 12, 0, 0, tzinfo=timezone.utc)
    intent_payload = intent or workflow_declaration_intent()
    projected_cost = {
        "amount_micros": 1234,
        "currency": "USD",
        "methodology": {
            "basis": "caller_declared_workflow_x_point_pricing",
            "provenance": "caller_declared_workflow",
            "expected_calls": intent_payload.get("expected_calls"),
        },
    }
    declared_by = {"api_key_id": "20000000-0000-0000-0000-000000000001"}
    signed_payload = {
        "binding_version": "workflow_declaration.v1",
        "project_id": project_id,
        "workflow_id": workflow_id,
        "intent": intent_payload,
        "budget_envelope_id": None,
        "declared_by": declared_by,
        "projected_cost": projected_cost,
        "status": "active",
        "issued_at": issued.isoformat(),
        "binding_key_id": permit_binding_key_id(public_key),
    }
    canonical_hash = verifier._compute_canonical_binding_hash(signed_payload)
    signature = base64.b64encode(private_key.sign(canonical_hash.encode("utf-8"))).decode("ascii")
    return {
        "workflow_id": workflow_id,
        "workflow_declaration_id": workflow_declaration_id,
        "project_id": project_id,
        "status": "active",
        "expected_calls": intent_payload.get("expected_calls"),
        "max_calls": intent_payload.get("max_calls"),
        "expected_model": intent_payload.get("expected_model"),
        "expected_input_tokens_per_call": intent_payload.get("expected_input_tokens_per_call"),
        "expected_output_tokens_per_call": intent_payload.get("expected_output_tokens_per_call"),
        "max_duration_seconds": intent_payload.get("max_duration_seconds"),
        "intent_json": intent_payload,
        "declared_at": issued.isoformat(),
        "completed_at": None,
        "declared_by": {
            "type": "api_key",
            "id": declared_by["api_key_id"],
        },
        "declared_via": None,
        "budget_envelope_id": None,
        "declaration_canonical_hash": canonical_hash,
        "declaration_signature_b64": signature,
        "declaration_signed_at": issued.isoformat(),
        "effective_intent_hash": "",
        "projection_amount_micros": projected_cost["amount_micros"],
        "projection_currency": "USD",
        "projection_methodology": projected_cost["methodology"],
        "version": version,
        "cached_actual_calls": 0,
    }


def signed_workflow_amendment(
    private_key: Ed25519PrivateKey,
    *,
    public_key: str,
    workflow_declaration_id: str = "10000000-0000-0000-0000-000000000001",
    workflow_amendment_id: str = "30000000-0000-0000-0000-000000000001",
    project_id: str = "00000000-0000-0000-0000-000000000001",
    applied_against_version: int = 1,
    previous_max_calls: int | None = 5,
    new_max_calls: int | None = 7,
    previous_expected_calls: int | None = 2,
    new_expected_calls: int | None = 4,
    created_at: datetime | None = None,
) -> dict[str, Any]:
    created = created_at or datetime(2026, 5, 7, 12, 5, 0, tzinfo=timezone.utc)
    record = {
        "workflow_amendment_id": workflow_amendment_id,
        "workflow_declaration_id": workflow_declaration_id,
        "project_id": project_id,
        "applied_against_version": applied_against_version,
        "previous_max_calls": previous_max_calls,
        "new_max_calls": new_max_calls,
        "previous_expected_calls": previous_expected_calls,
        "new_expected_calls": new_expected_calls,
        "reason_provided": "raise cap during incident run",
        "amended_by": {
            "type": "api_key",
            "id": "20000000-0000-0000-0000-000000000001",
        },
        "created_at": created.isoformat(),
    }
    signed_payload = {
        "binding_version": "workflow_amendment.v1",
        "project_id": project_id,
        "workflow_declaration_id": workflow_declaration_id,
        "amended_by": {"api_key_id": record["amended_by"]["id"]},
        "issued_at": created.isoformat(),
        "binding_key_id": permit_binding_key_id(public_key),
        "delta": workflow_amendment_delta(record),
    }
    canonical_hash = verifier._compute_canonical_binding_hash(signed_payload)
    signature = base64.b64encode(private_key.sign(canonical_hash.encode("utf-8"))).decode("ascii")
    return {
        **record,
        "amendment_canonical_hash": canonical_hash,
        "amendment_signature_b64": signature,
    }


def workflow_evidence_document(
    declarations: list[dict[str, Any]],
    amendments: list[dict[str, Any]],
) -> dict[str, Any]:
    for declaration in declarations:
        declaration["effective_intent_hash"] = workflow_effective_intent_hash(
            declaration,
            [
                amendment
                for amendment in amendments
                if amendment["workflow_declaration_id"] == declaration["workflow_declaration_id"]
            ],
        )
    return {
        "schema": "keel.workflow_evidence/v1",
        "source": "keel",
        "generated_at": "2026-05-07T12:10:00+00:00",
        "project_id": declarations[0]["project_id"] if declarations else "00000000-0000-0000-0000-000000000001",
        "export_id": "40000000-0000-0000-0000-000000000001",
        "declaration_count": len(declarations),
        "amendment_count": len(amendments),
        "declarations": declarations,
        "amendments": amendments,
    }
