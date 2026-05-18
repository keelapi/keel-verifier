from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from conftest import write_json
from keel_verifier import verifier
from keel_verifier.semantics import (
    AUTHORITY_ENVELOPE_V0_ID,
    AUTHORITY_ENVELOPE_V0_HASH,
    CLAIM_REGISTRY_HASH,
    CLAIM_REGISTRY_ID,
    GOVERNANCE_EVENT_INTEGRITY_DIGEST_HASH,
    GOVERNANCE_EVENT_INTEGRITY_DIGEST_ID,
    GOVERNANCE_RECORD_HASH_HASH,
    GOVERNANCE_RECORD_HASH_ID,
    RELEASED_ARTIFACT_PATHS,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_PERMIT = REPO_ROOT.parent / "keel-permit"


def _event(payload: dict[str, Any]) -> dict[str, Any]:
    event = {
        "event_id": "gev_permit_chain_test",
        "event_type": "permit.delegated_denied",
        "category": "permit",
        "severity": "warning",
        "occurred_at": "2026-05-20T12:00:00.000000+00:00",
        "sequence_number": 1,
        "prev_hash": verifier._GENESIS_HASH,
        "chain_scope": "project:11111111-1111-1111-1111-111111111111",
        "resource_type": "permit_delegation",
        "resource_id": "22222222-2222-2222-2222-222222222222",
        "outcome": "denied",
        "source_stage": "permit",
        "decision": "deny",
        "schema_version": 1,
        "payload_json": payload,
    }
    event["record_hash"] = verifier._compute_record_hash(
        event_id=event["event_id"],
        event_type=event["event_type"],
        resource_type=event["resource_type"],
        resource_id=event["resource_id"],
        outcome=event["outcome"],
        severity=event["severity"],
        occurred_at=event["occurred_at"],
        prev_hash=event["prev_hash"],
        sequence_number=event["sequence_number"],
    )
    return event


def _evidence(payload: dict[str, Any]) -> dict[str, Any]:
    event = _event(payload)
    covered_events = [
        {
            "event_id": event["event_id"],
            "event_type": event["event_type"],
            "event_hash": verifier._compute_governance_event_integrity_hash(event),
        }
    ]
    batch_hash = verifier._compute_integrity_batch_hash(covered_events)
    digest = {
        "event_id": "gev_permit_chain_digest",
        "event_type": "audit.integrity_digest",
        "category": "audit",
        "severity": "info",
        "occurred_at": "2026-05-20T12:00:01.000000+00:00",
        "sequence_number": 2,
        "prev_hash": event["record_hash"],
        "chain_scope": event["chain_scope"],
        "resource_type": "governance_event_batch",
        "resource_id": batch_hash[:32],
        "outcome": "success",
        "source_stage": "audit",
        "schema_version": 2,
        "payload_json": {
            "coverage_type": "unchained_governance_events",
            "coverage_mode": "commit_batch",
            "covered_event_count": 1,
            "covered_events": covered_events,
            "batch_hash": batch_hash,
        },
    }
    digest["record_hash"] = verifier._compute_record_hash(
        event_id=digest["event_id"],
        event_type=digest["event_type"],
        resource_type=digest["resource_type"],
        resource_id=digest["resource_id"],
        outcome=digest["outcome"],
        severity=digest["severity"],
        occurred_at=digest["occurred_at"],
        prev_hash=digest["prev_hash"],
        sequence_number=digest["sequence_number"],
    )
    return {"events": [event, digest]}


def _parent_envelope() -> dict[str, Any]:
    return {
        "actions": ["ai.generate.summary"],
        "tools": [],
        "providers": ["openai"],
        "models": ["gpt-4o-mini"],
        "data_classes": ["public"],
        "regions": ["us"],
        "expires_at": "2026-05-20T12:00:00Z",
    }


def _child_envelope(**overrides: Any) -> dict[str, Any]:
    child = {
        "actions": ["ai.generate.summary"],
        "tools": [],
        "providers": ["openai", "anthropic"],
        "models": ["gpt-4o-mini"],
        "data_classes": ["public"],
        "regions": ["us"],
        "expires_at": "2026-05-20T11:30:00Z",
    }
    child.update(overrides)
    return child


def _broadened_payload() -> dict[str, Any]:
    return {
        "reason_code": "authority_envelope.scope_broadened",
        "authority_envelope_version": "authority-envelope.v0",
        "parent_authority_envelope": _parent_envelope(),
        "child_requested_authority_envelope": _child_envelope(),
        "failed_fields": ["providers"],
    }


def test_record_hash_compat_adapter_reuses_public_record_hash_v1() -> None:
    event = _event(_broadened_payload())

    assert event["record_hash"] == verifier._compute_record_hash_v1(
        event_id=event["event_id"],
        event_type=event["event_type"],
        resource_type=event["resource_type"],
        resource_id=event["resource_id"],
        outcome=event["outcome"],
        severity=event["severity"],
        created_at=event["occurred_at"],
        prev_hash=event["prev_hash"],
        sequence_number=event["sequence_number"],
    )


def test_delegation_denied_correctly_verifier_supports_broadened_denial() -> None:
    result = verifier.verify_delegation_denied_correctly(
        _evidence(_broadened_payload())
    )

    assert result["status"] == "supported"
    assert result["failed_fields"] == ["providers"]


def test_delegation_denied_correctly_verifier_disproves_false_denial() -> None:
    payload = _broadened_payload()
    payload["child_requested_authority_envelope"] = _child_envelope(
        providers=["openai"]
    )

    result = verifier.verify_delegation_denied_correctly(_evidence(payload))

    assert result["status"] == "disproved"
    assert "comparator_allows_child_authority" in result["errors"]


def test_delegation_denied_correctly_verifier_rejects_unknown_version() -> None:
    payload = _broadened_payload()
    payload["authority_envelope_version"] = "authority-envelope.v9"

    result = verifier.verify_delegation_denied_correctly(_evidence(payload))

    assert result["status"] == "unverifiable_scope"


def test_delegation_denied_correctly_verifier_supports_parent_missing_denial() -> None:
    result = verifier.verify_delegation_denied_correctly(
        _evidence(
            {
                "reason_code": "authority_envelope.parent_missing",
                "authority_envelope_version": "authority-envelope.v0",
                "parent_authority_envelope": None,
                "child_requested_authority_envelope": _child_envelope(),
                "failed_fields": ["authority_envelope"],
            }
        )
    )

    assert result["status"] == "supported"
    assert "parent_authority_envelope_absent" in result["supported_checks"]


def test_delegation_denied_correctly_verifier_requires_payload_integrity() -> None:
    result = verifier.verify_delegation_denied_correctly(
        {"events": [_event(_broadened_payload())]}
    )

    assert result["status"] == "insufficient_evidence"
    assert "payload_integrity_digest" in result["missing_requirements"]


def test_delegation_denied_correctly_verifier_rejects_tampered_payload() -> None:
    evidence = _evidence(_broadened_payload())
    evidence["events"][0]["payload_json"]["child_requested_authority_envelope"][
        "providers"
    ] = ["openai"]

    result = verifier.verify_delegation_denied_correctly(evidence)

    assert result["status"] == "disproved"
    assert "payload_integrity_mismatch" in result["errors"]


def test_delegation_denied_correctly_verifier_requires_version_pin() -> None:
    payload = _broadened_payload()
    payload.pop("authority_envelope_version")

    result = verifier.verify_delegation_denied_correctly(_evidence(payload))

    assert result["status"] == "insufficient_evidence"
    assert "authority_envelope_version" in result["missing_requirements"]


def test_delegation_denied_correctly_verifier_rejects_unknown_parent_key() -> None:
    payload = _broadened_payload()
    payload["parent_authority_envelope"] = {
        **_parent_envelope(),
        "unversioned_scope": ["anything"],
    }

    result = verifier.verify_delegation_denied_correctly(_evidence(payload))

    assert result["status"] == "insufficient_evidence"
    assert "comparable_authority_envelopes" in result["missing_requirements"]


def test_delegation_denied_correctly_verifier_rejects_unknown_child_key() -> None:
    payload = _broadened_payload()
    payload["child_requested_authority_envelope"] = {
        **_child_envelope(),
        "unversioned_scope": ["anything"],
    }

    result = verifier.verify_delegation_denied_correctly(_evidence(payload))

    assert result["status"] == "insufficient_evidence"
    assert "comparable_authority_envelopes" in result["missing_requirements"]


def test_delegation_denied_correctly_verifier_rejects_malformed_parent_missing_child() -> None:
    result = verifier.verify_delegation_denied_correctly(
        _evidence(
            {
                "reason_code": "authority_envelope.parent_missing",
                "authority_envelope_version": "authority-envelope.v0",
                "parent_authority_envelope": None,
                "child_requested_authority_envelope": _child_envelope(providers=[123]),
                "failed_fields": ["authority_envelope"],
            }
        )
    )

    assert result["status"] == "insufficient_evidence"
    assert "child_requested_authority_envelope" in result["missing_requirements"]


def _artifact_ref(artifact_id: str, artifact_hash: str) -> dict[str, str]:
    path = SOURCE_PERMIT / RELEASED_ARTIFACT_PATHS[artifact_id]
    if not path.exists():
        pytest.skip(f"keel-permit artifact not checked out: {path}")
    return {
        "id": artifact_id,
        "hash": artifact_hash,
        "content_b64": base64.b64encode(path.read_bytes()).decode("ascii"),
    }


def _with_claim_pins(
    evidence: dict[str, Any],
    *,
    omit: set[str] | None = None,
    replace: dict[str, dict[str, str]] | None = None,
) -> dict[str, Any]:
    omit = omit or set()
    replace = replace or {}
    registry_path = REPO_ROOT / "keel_verifier" / "data" / "claim_registry_v0.json"
    artifacts = [
        _artifact_ref(GOVERNANCE_RECORD_HASH_ID, GOVERNANCE_RECORD_HASH_HASH),
        _artifact_ref(
            GOVERNANCE_EVENT_INTEGRITY_DIGEST_ID,
            GOVERNANCE_EVENT_INTEGRITY_DIGEST_HASH,
        ),
        _artifact_ref(AUTHORITY_ENVELOPE_V0_ID, AUTHORITY_ENVELOPE_V0_HASH),
    ]
    artifacts = [
        replace.get(artifact["id"], artifact)
        for artifact in artifacts
        if artifact["id"] not in omit
    ]
    return {
        **evidence,
        "claim_set": {
            "version": "verifier-claims.v0",
            "registry": {
                "id": CLAIM_REGISTRY_ID,
                "hash": CLAIM_REGISTRY_HASH,
                "content_b64": base64.b64encode(registry_path.read_bytes()).decode(
                    "ascii"
                ),
            },
            "claims": [
                {
                    "name": verifier.DELEGATION_DENIED_CLAIM_NAME,
                    "required": True,
                }
            ],
        },
        "semantics_pins": {
            "version": "keel-semantics-pins.v0",
            "mode": "pinned",
            "artifacts": artifacts,
        },
    }


def _unknown_artifact(artifact_id: str, version: str) -> dict[str, str]:
    raw = json.dumps(
        {
            "id": artifact_id,
            "version": version,
            "kind": "test_unknown_semantic",
            "status": "released",
            "body": {"test": "unknown allowlist hash"},
        },
        indent=2,
        sort_keys=True,
    ).encode("utf-8") + b"\n"
    return {
        "id": artifact_id,
        "hash": f"sha256:{hashlib.sha256(raw).hexdigest()}",
        "content_b64": base64.b64encode(raw).decode("ascii"),
    }


def test_pinned_claim_requires_authority_envelope_comparator_pin() -> None:
    evidence = _with_claim_pins(
        _evidence(_broadened_payload()),
        omit={AUTHORITY_ENVELOPE_V0_ID},
    )

    result = verifier.verify_delegation_denied_correctly(
        evidence,
        include_semantics=True,
    )

    assert result["status"] == "insufficient_evidence"
    assert result["reason_code"] == "SEMANTIC_PIN_MISSING"


def test_pinned_claim_rejects_unknown_authority_envelope_comparator_pin() -> None:
    evidence = _with_claim_pins(
        _evidence(_broadened_payload()),
        replace={
            AUTHORITY_ENVELOPE_V0_ID: _unknown_artifact(
                AUTHORITY_ENVELOPE_V0_ID,
                AUTHORITY_ENVELOPE_V0_ID,
            )
        },
    )

    result = verifier.verify_delegation_denied_correctly(
        evidence,
        include_semantics=True,
    )

    assert result["status"] == "unverifiable_scope"
    assert result["reason_code"] == "SEMANTIC_PIN_NOT_ALLOWLISTED"


def test_pinned_claim_requires_integrity_digest_pin() -> None:
    evidence = _with_claim_pins(
        _evidence(_broadened_payload()),
        omit={GOVERNANCE_EVENT_INTEGRITY_DIGEST_ID},
    )

    result = verifier.verify_delegation_denied_correctly(
        evidence,
        include_semantics=True,
    )

    assert result["status"] == "insufficient_evidence"
    assert result["reason_code"] == "SEMANTIC_PIN_MISSING"


def test_pinned_claim_rejects_unknown_integrity_digest_pin() -> None:
    evidence = _with_claim_pins(
        _evidence(_broadened_payload()),
        replace={
            GOVERNANCE_EVENT_INTEGRITY_DIGEST_ID: _unknown_artifact(
                GOVERNANCE_EVENT_INTEGRITY_DIGEST_ID,
                "v1",
            )
        },
    )

    result = verifier.verify_delegation_denied_correctly(
        evidence,
        include_semantics=True,
    )

    assert result["status"] == "unverifiable_scope"
    assert result["reason_code"] == "SEMANTIC_PIN_NOT_ALLOWLISTED"


def test_delegation_denied_correctly_cli_claim_command(tmp_path, run_cli) -> None:
    evidence_file = write_json(tmp_path / "evidence.json", _evidence(_broadened_payload()))

    result = run_cli(
        "claim",
        "delegation_denied_correctly",
        "--evidence-file",
        str(evidence_file),
    )
    payload = json.loads(result.stdout)

    assert result.returncode == 0, result.stderr
    assert payload["status"] == "supported"
    assert payload["semantics"]["mode"] == "legacy_unpinned"


def test_delegation_denied_correctly_cli_returns_failure_for_disproved(
    tmp_path,
    run_cli,
) -> None:
    payload = _broadened_payload()
    payload["child_requested_authority_envelope"] = _child_envelope(
        providers=["openai"]
    )
    evidence_file = write_json(tmp_path / "evidence.json", _evidence(payload))

    result = run_cli(
        "claim",
        "delegation_denied_correctly",
        "--evidence-file",
        str(evidence_file),
    )
    output = json.loads(result.stdout)

    assert result.returncode == 1
    assert output["status"] == "disproved"
