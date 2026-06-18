from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keel_verifier import verifier
from keel_verifier.verifier import (
    PERMIT_BINDING_SIGNING_PURPOSE,
    SCOPE_PREDICATE_VERSION,
    SCOPE_STATE_MERKLE_ID,
    _adjudicate_key_status_completeness_v1,
    _adjudicate_permit_operator_approval_v2,
    _binding_key_id_from_public_key,
    _composite_hash,
    _content_hash,
    _key_status_manifest_hash_from_payload,
    _key_status_predicate_for_head,
    _load_key_manifest,
    _manifest_signature_payload_bytes,
    _predicate_hash,
    _public_key_fingerprint,
    _scope_sidecar_signed_bytes,
    verify_export_structured,
)


ACCOUNT_ID = "11111111-2222-3333-4444-555555555555"
COMPARISON_INSTANT = "2026-06-17T12:05:00Z"
KEY_STATUS_MANIFEST_COMPUTED_AT = "2026-06-17T12:10:00Z"
PERMIT_V2_FIXTURE_ROOT = (
    Path(__file__).resolve().parent / "fixtures" / "permit_v2_signature_envelope"
)


def _private_key(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def _public_key(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "ed25519:" + base64.b64encode(raw).decode("ascii")


def _signature(private_key: Ed25519PrivateKey, message: bytes) -> str:
    return "ed25519:" + base64.b64encode(private_key.sign(message)).decode("ascii")


def _full_key_id(public_key: str) -> str:
    raw = base64.b64decode(public_key.removeprefix("ed25519:"))
    return hashlib.sha256(raw).hexdigest()


def _fixture_json(relative: str) -> dict[str, Any]:
    return json.loads((PERMIT_V2_FIXTURE_ROOT / relative).read_text(encoding="utf-8"))


def _install_pinned_trust_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    export_public: str,
    permit_public: str,
    infra_public: str,
) -> tuple[Path, list[dict[str, Any]]]:
    entries = [
        {
            "key_id": _public_key_fingerprint(export_public),
            "purpose": "export_signing",
            "public_key": export_public,
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": None,
            "status": "active",
        },
        {
            "key_id": _binding_key_id_from_public_key(permit_public),
            "purpose": PERMIT_BINDING_SIGNING_PURPOSE,
            "public_key": permit_public,
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": None,
            "status": "active",
        },
        {
            "key_id": _public_key_fingerprint(infra_public),
            "purpose": "integrity_checkpoint",
            "public_key": infra_public,
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": None,
            "status": "active",
        },
        {
            "key_id": _public_key_fingerprint(infra_public),
            "purpose": "scope_state",
            "public_key": infra_public,
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": None,
            "status": "active",
        },
    ]
    trust_root = {
        "schema_version": 1,
        "generated_at": "2026-06-17T12:00:00Z",
        "keys": entries,
    }
    trust_path = tmp_path / "pinned-trust-root.json"
    trust_path.write_text(json.dumps(trust_root, sort_keys=True), encoding="utf-8")
    monkeypatch.setattr(verifier, "DEFAULT_TRUST_ROOT_PATH", trust_path)
    monkeypatch.setattr(verifier, "CACHED_TRUST_ROOT_PATH", tmp_path / "missing-cache.json")
    return trust_path, entries


def _sign_public_key_manifest(
    *,
    entries: list[dict[str, Any]],
    export_key: Ed25519PrivateKey,
    export_key_id: str,
) -> dict[str, Any]:
    manifest = {
        "manifest_version": "keel.public_key_manifest.v1",
        "canonicalization_profile": "keel.canonical_json.payload.v1",
        "generated_at": "2026-06-17T12:00:00Z",
        "keys": copy.deepcopy(entries),
    }
    content_hash = _content_hash(_manifest_signature_payload_bytes(manifest))
    manifest["manifest_signature"] = {
        "signature_type": "ed25519.content_hash.v1",
        "purpose": "export_signing",
        "key_id": export_key_id,
        "content_hash": content_hash,
        "signature": _signature(export_key, content_hash.encode("utf-8")),
    }
    return manifest


def _signed_checkpoint(
    *,
    infra_key: Ed25519PrivateKey,
    infra_public: str,
    head_sequence: int,
) -> dict[str, Any]:
    chain_heads = {
        "admin_global": {
            "sequence_number": head_sequence,
            "last_record_hash": "a" * 64,
        }
    }
    composite_hash = _composite_hash(chain_heads)
    return {
        "checkpoint_id": "22222222-3333-4444-5555-666666666666",
        "chain_heads": chain_heads,
        "composite_hash": composite_hash,
        "signature": _signature(infra_key, composite_hash.encode("utf-8")),
        "key_id": _public_key_fingerprint(infra_public),
        "public_key": infra_public,
        "computed_at": "2026-06-17T12:08:00Z",
    }


def _signed_sidecar(
    *,
    infra_key: Ed25519PrivateKey,
    infra_public: str,
    checkpoint_id: str,
    head_sequence: int,
    matching_count: int,
) -> dict[str, Any]:
    predicate = _key_status_predicate_for_head(head_sequence)
    sidecar = {
        "artifact_type": "checkpoint_scope_state",
        "version": "checkpoint_scope_state.v1",
        "scope_state_id": "33333333-4444-5555-6666-777777777777",
        "checkpoint_id": checkpoint_id,
        "chain_scope": "admin_global",
        "predicate_grammar_version": SCOPE_PREDICATE_VERSION,
        "predicate_basis": {
            "canonicalization_profile": "keel.canonical_json.payload.v1",
            "supported_predicate_kinds": ["event_type", "sequence_number"],
            "reserved_namespaces": ["keel.internal"],
        },
        "commitment_profile": SCOPE_STATE_MERKLE_ID,
        "scope_commitments": [
            {
                "predicate_value": predicate,
                "predicate_value_hash": _predicate_hash(predicate),
                "first_matching_sequence": 1 if matching_count else None,
                "last_matching_sequence": 1 if matching_count else None,
                "matching_count": matching_count,
                "membership_root_hash": "sha256:" + "c" * 64,
            }
        ],
        "tree_size": matching_count,
        "signed_at": "2026-06-17T12:08:30Z",
        "signature": {
            "algorithm": "Ed25519",
            "key_id": _public_key_fingerprint(infra_public),
            "signature": "ed25519:placeholder",
        },
        "trust_root_reference": {
            "manifest_version": "keel.public_key_manifest.v1",
            "purpose": "scope_state",
            "key_id": _public_key_fingerprint(infra_public),
        },
    }
    sidecar["signature"]["signature"] = _signature(
        infra_key,
        _scope_sidecar_signed_bytes(sidecar),
    )
    return sidecar


def _sign_key_status_manifest(
    manifest: dict[str, Any],
    *,
    permit_key: Ed25519PrivateKey,
    permit_key_id: str,
) -> dict[str, Any]:
    signed = copy.deepcopy(manifest)
    signed["signer"] = {
        "purpose": PERMIT_BINDING_SIGNING_PURPOSE,
        "key_id": permit_key_id,
        "algorithm": "ed25519",
    }
    signed["manifest_hash"] = _key_status_manifest_hash_from_payload(signed)
    signed["signature"] = _signature(
        permit_key,
        signed["manifest_hash"].encode("utf-8"),
    )
    return signed


def _context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    event_refs: list[dict[str, Any]] | None = None,
    scope_count: int | None = None,
    key_status: str = "revoked",
    account_id: str = ACCOUNT_ID,
    key_scope: str = "buyer_principal",
    target_key_id: str | None = None,
    target_public: str | None = None,
    comparison_instant: str = COMPARISON_INSTANT,
    revoked_at: str | None = "2026-06-17T12:00:00Z",
    compromised_at: str | None = None,
) -> dict[str, Any]:
    export_key = _private_key(11)
    permit_key = _private_key(12)
    infra_key = _private_key(13)
    target_key = _private_key(14)
    export_public = _public_key(export_key)
    permit_public = _public_key(permit_key)
    infra_public = _public_key(infra_key)
    if target_public is None:
        target_public = _public_key(target_key)
    trust_path, trust_entries = _install_pinned_trust_root(
        tmp_path,
        monkeypatch,
        export_public=export_public,
        permit_public=permit_public,
        infra_public=infra_public,
    )
    if event_refs is None:
        event_refs = [
            {
                "event_type": "key.status.v1",
                "event_id": "evt-key-status-1",
                "record_hash": "b" * 64,
                "sequence_number": 1,
                "status": "revoked",
            }
        ]
    if scope_count is None:
        scope_count = len(event_refs)
    checkpoint = _signed_checkpoint(
        infra_key=infra_key,
        infra_public=infra_public,
        head_sequence=1,
    )
    sidecar = _signed_sidecar(
        infra_key=infra_key,
        infra_public=infra_public,
        checkpoint_id=checkpoint["checkpoint_id"],
        head_sequence=1,
        matching_count=scope_count,
    )
    if target_key_id is None:
        target_key_id = _full_key_id(target_public)
    manifest = {
        "manifest_type": "permit_v2.key_status_manifest.v1",
        "canonicalization_profile": "keel.canonical_json.payload.v1",
        "computed_at": KEY_STATUS_MANIFEST_COMPUTED_AT,
        "account_id": account_id,
        "key_scopes": [
            "operator",
            "buyer_principal",
            "mcp_server",
            "provider_principal",
        ],
        "keys": [
            {
                "account_id": account_id,
                "key_scope": key_scope,
                "key_id": target_key_id,
                "algorithm": "ed25519",
                "public_key": target_public,
                "status": key_status,
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": None,
                "revoked_at": revoked_at if key_status == "revoked" else None,
                "compromised_at": compromised_at if key_status == "compromised" else None,
                "metadata": {},
                "event_refs": event_refs,
                "principal": {
                    "principal_type": key_scope,
                    "principal_id": "buyer-1",
                },
            }
        ],
        "signer": {},
        "manifest_hash": "",
        "signature": "",
    }
    signed_manifest = _sign_key_status_manifest(
        manifest,
        permit_key=permit_key,
        permit_key_id=_binding_key_id_from_public_key(permit_public),
    )
    subject = {
        "account_id": account_id,
        "key_scope": key_scope,
        "key_id": target_key_id,
        "comparison_instant": comparison_instant,
        "comparison_instant_source": "signed_bytes",
        "expected_status": "revoked",
    }
    return {
        "trust_path": trust_path,
        "trust_entries": trust_entries,
        "export_key": export_key,
        "export_key_id": _public_key_fingerprint(export_public),
        "permit_key": permit_key,
        "permit_public": permit_public,
        "manifest": signed_manifest,
        "sidecar": sidecar,
        "checkpoint": checkpoint,
        "subject": subject,
    }


def test_signed_public_key_manifest_loader_rejects_signed_field_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _context(tmp_path, monkeypatch)
    public_manifest = _sign_public_key_manifest(
        entries=ctx["trust_entries"],
        export_key=ctx["export_key"],
        export_key_id=ctx["export_key_id"],
    )
    manifest_path = tmp_path / "signed-public-key-manifest.json"
    manifest_path.write_text(json.dumps(public_manifest), encoding="utf-8")

    assert len(_load_key_manifest(str(manifest_path))) == 4

    tampered = copy.deepcopy(public_manifest)
    tampered["keys"][1]["public_key"] = "ed25519:" + base64.b64encode(b"x" * 32).decode("ascii")
    manifest_path.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(ValueError, match="content_hash"):
        _load_key_manifest(str(manifest_path))


def test_key_status_completeness_supported_for_fresh_pinned_revocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _context(tmp_path, monkeypatch)

    claim = _adjudicate_key_status_completeness_v1(
        key_status_manifest=ctx["manifest"],
        subject=ctx["subject"],
        sidecar=ctx["sidecar"],
        checkpoint=ctx["checkpoint"],
    )

    assert claim.aggregate_verdict == "supported"
    assert claim.reason_code == "KEY_STATUS_COMPLETENESS_SUPPORTED"


def test_key_status_completeness_rejects_stale_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _context(tmp_path, monkeypatch)
    stale = copy.deepcopy(ctx["manifest"])
    stale["computed_at"] = COMPARISON_INSTANT
    stale = _sign_key_status_manifest(
        stale,
        permit_key=ctx["permit_key"],
        permit_key_id=_binding_key_id_from_public_key(ctx["permit_public"]),
    )

    claim = _adjudicate_key_status_completeness_v1(
        key_status_manifest=stale,
        subject=ctx["subject"],
        sidecar=ctx["sidecar"],
        checkpoint=ctx["checkpoint"],
    )

    assert claim.aggregate_verdict == "insufficient_evidence"
    assert claim.reason_code == "KEY_STATUS_COMPLETENESS_STALE_MANIFEST"


def test_key_status_completeness_rejects_signed_field_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _context(tmp_path, monkeypatch)
    tampered = copy.deepcopy(ctx["manifest"])
    tampered["keys"][0]["status"] = "active"

    claim = _adjudicate_key_status_completeness_v1(
        key_status_manifest=tampered,
        subject=ctx["subject"],
        sidecar=ctx["sidecar"],
        checkpoint=ctx["checkpoint"],
    )

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "KEY_STATUS_COMPLETENESS_MANIFEST_SIGNATURE_INVALID"


def test_key_status_completeness_rejects_scope_count_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _context(tmp_path, monkeypatch, scope_count=2)

    claim = _adjudicate_key_status_completeness_v1(
        key_status_manifest=ctx["manifest"],
        subject=ctx["subject"],
        sidecar=ctx["sidecar"],
        checkpoint=ctx["checkpoint"],
    )

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "KEY_STATUS_COMPLETENESS_EVENT_REF_COUNT_MISMATCH"


def test_key_status_completeness_requires_signed_comparison_instant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _context(tmp_path, monkeypatch)
    subject = copy.deepcopy(ctx["subject"])
    subject["comparison_instant_source"] = "caller_input"

    claim = _adjudicate_key_status_completeness_v1(
        key_status_manifest=ctx["manifest"],
        subject=subject,
        sidecar=ctx["sidecar"],
        checkpoint=ctx["checkpoint"],
    )

    assert claim.aggregate_verdict == "insufficient_evidence"
    assert claim.reason_code == "KEY_STATUS_COMPLETENESS_SUBJECT_MISSING"


def test_key_status_completeness_rejects_unpinned_manifest_signer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _context(tmp_path, monkeypatch)
    attacker_key = _private_key(19)
    attacker_public = _public_key(attacker_key)
    forged = _sign_key_status_manifest(
        ctx["manifest"],
        permit_key=attacker_key,
        permit_key_id=_binding_key_id_from_public_key(attacker_public),
    )

    claim = _adjudicate_key_status_completeness_v1(
        key_status_manifest=forged,
        subject=ctx["subject"],
        sidecar=ctx["sidecar"],
        checkpoint=ctx["checkpoint"],
    )

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "KEY_STATUS_COMPLETENESS_MANIFEST_SIGNATURE_INVALID"


def test_key_status_completeness_enforces_revoked_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _context(
        tmp_path,
        monkeypatch,
        event_refs=[],
        scope_count=0,
        key_status="active",
    )

    claim = _adjudicate_key_status_completeness_v1(
        key_status_manifest=ctx["manifest"],
        subject=ctx["subject"],
        sidecar=ctx["sidecar"],
        checkpoint=ctx["checkpoint"],
    )

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "KEY_STATUS_COMPLETENESS_STATUS_NOT_REVOKED"


def test_key_status_completeness_supports_bounded_zero_not_revoked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _context(
        tmp_path,
        monkeypatch,
        event_refs=[],
        scope_count=0,
        key_status="active",
    )
    subject = copy.deepcopy(ctx["subject"])
    subject["expected_status"] = "not_revoked"

    claim = _adjudicate_key_status_completeness_v1(
        key_status_manifest=ctx["manifest"],
        subject=subject,
        sidecar=ctx["sidecar"],
        checkpoint=ctx["checkpoint"],
    )

    assert claim.aggregate_verdict == "supported"
    assert claim.reason_code == "KEY_STATUS_COMPLETENESS_SUPPORTED"


def test_key_status_completeness_disproves_not_revoked_terminal_before_comparison(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctx = _context(tmp_path, monkeypatch)
    subject = copy.deepcopy(ctx["subject"])
    subject["expected_status"] = "not_revoked"

    claim = _adjudicate_key_status_completeness_v1(
        key_status_manifest=ctx["manifest"],
        subject=subject,
        sidecar=ctx["sidecar"],
        checkpoint=ctx["checkpoint"],
    )

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "KEY_STATUS_COMPLETENESS_TERMINAL_STATUS_AT_COMPARISON"


def _operator_approval_fixture() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]:
    root = PERMIT_V2_FIXTURE_ROOT / "operator_approval_positive_01"
    export_document = _fixture_json("operator_approval_positive_01/export.json")
    manifest = _fixture_json("operator_approval_positive_01/manifest.json")
    key_manifest = _fixture_json("operator_approval_positive_01/key_manifest.json")
    return export_document, manifest, key_manifest, str(root / "key_manifest.json")


def _verify_args(
    export_path: Path,
    manifest_path: Path,
    key_manifest_path: str,
) -> argparse.Namespace:
    return argparse.Namespace(
        export_file=str(export_path),
        manifest=str(manifest_path),
        key_manifest=key_manifest_path,
        key_manifest_url=None,
        expected_public_key=None,
        public_key=None,
        self_attested=False,
        offline=False,
        allow_unsigned=False,
        walk_events=False,
        verify_closure=False,
        as_json=True,
    )


def _report_claim(report: Any, name: str) -> dict[str, Any]:
    for claim in report.to_dict()["claims"]:
        if claim["name"] == name:
            return claim
    raise AssertionError(f"missing claim {name}")


def _write_manifest_with_key_status_evidence(
    tmp_path: Path,
    *,
    manifest: dict[str, Any],
    ctx: dict[str, Any],
    key_status_manifest: dict[str, Any] | None = None,
    legacy_default: bool = False,
) -> Path:
    manifest_with_evidence = copy.deepcopy(manifest)
    if legacy_default:
        manifest_with_evidence.pop("claim_set", None)
        manifest_with_evidence.pop("semantics_pins", None)
    manifest_with_evidence["key_status_manifest"] = (
        key_status_manifest or ctx["manifest"]
    )
    manifest_with_evidence["checkpoint_scope_state"] = ctx["sidecar"]
    manifest_with_evidence["key_status_checkpoint"] = ctx["checkpoint"]
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest_with_evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest_path


def _write_malicious_key_manifest(
    tmp_path: Path,
    *,
    base_key_manifest: dict[str, Any],
    attacker_public: str,
) -> Path:
    body = copy.deepcopy(base_key_manifest)
    body["keys"].append(
        {
            "algorithm": "ed25519",
            "key_id": _binding_key_id_from_public_key(attacker_public),
            "purpose": PERMIT_BINDING_SIGNING_PURPOSE,
            "public_key": attacker_public,
            "status": "active",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": None,
        }
    )
    path = tmp_path / "malicious-key-manifest.json"
    path.write_text(
        json.dumps(body, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def _slot_public_key(
    key_manifest: dict[str, Any],
    *,
    key_id: str,
) -> str:
    for entry in key_manifest["keys"]:
        if entry.get("key_id") == key_id:
            return str(entry["public_key"])
    raise AssertionError(f"missing key_id {key_id}")


def test_permit_operator_approval_v2_requires_supported_key_status_completeness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    export_document, manifest, key_manifest, key_manifest_path = _operator_approval_fixture()
    slot = export_document["operator_approval"]
    ctx = _context(
        tmp_path,
        monkeypatch,
        event_refs=[],
        scope_count=0,
        key_status="active",
        account_id=export_document["account_id"],
        key_scope="operator",
        target_key_id=slot["key_id"],
        target_public=_slot_public_key(key_manifest, key_id=slot["key_id"]),
        comparison_instant=slot["signed_at"],
    )

    claim = _adjudicate_permit_operator_approval_v2(
        export_document=export_document,
        manifest=manifest,
        key_manifest_source=key_manifest_path,
        key_status_manifest=ctx["manifest"],
        key_status_sidecar=ctx["sidecar"],
        key_status_checkpoint=ctx["checkpoint"],
    )

    assert claim.name == "permit.operator_approval.v2"
    assert claim.aggregate_verdict == "supported"
    assert claim.reason_code == "PERMIT_OPERATOR_APPROVAL_SUPPORTED"
    assert "key.status.completeness.v1" in claim.evidence


def test_full_verify_permit_v2_auto_required_floor_accepts_supported_key_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    export_document, manifest, key_manifest, key_manifest_path = _operator_approval_fixture()
    slot = export_document["operator_approval"]
    ctx = _context(
        tmp_path,
        monkeypatch,
        event_refs=[],
        scope_count=0,
        key_status="active",
        account_id=export_document["account_id"],
        key_scope="operator",
        target_key_id=slot["key_id"],
        target_public=_slot_public_key(key_manifest, key_id=slot["key_id"]),
        comparison_instant=slot["signed_at"],
    )
    manifest_path = _write_manifest_with_key_status_evidence(
        tmp_path,
        manifest=manifest,
        ctx=ctx,
    )
    export_path = PERMIT_V2_FIXTURE_ROOT / "operator_approval_positive_01" / "export.json"

    report = verify_export_structured(
        _verify_args(export_path, manifest_path, key_manifest_path)
    )

    assert report.exit_code == 0
    assert _report_claim(report, "permit.operator_approval.v1")["verdict"] == "supported"
    assert _report_claim(report, "key.status.completeness.v1")["verdict"] == "supported"
    assert _report_claim(report, "permit.operator_approval.v2")["verdict"] == "supported"


def test_default_verify_permit_v2_auto_required_floor_rejects_revoked_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    export_document, manifest, key_manifest, key_manifest_path = _operator_approval_fixture()
    slot = export_document["operator_approval"]
    ctx = _context(
        tmp_path,
        monkeypatch,
        key_status="revoked",
        account_id=export_document["account_id"],
        key_scope="operator",
        target_key_id=slot["key_id"],
        target_public=_slot_public_key(key_manifest, key_id=slot["key_id"]),
        comparison_instant=slot["signed_at"],
        revoked_at=slot["signed_at"],
    )
    manifest_path = _write_manifest_with_key_status_evidence(
        tmp_path,
        manifest=manifest,
        ctx=ctx,
        legacy_default=True,
    )
    export_path = PERMIT_V2_FIXTURE_ROOT / "operator_approval_positive_01" / "export.json"

    report = verify_export_structured(
        _verify_args(export_path, manifest_path, key_manifest_path)
    )

    assert report.exit_code == 1
    assert report.to_dict()["semantics"]["mode"] == "legacy_unpinned"
    assert _report_claim(report, "permit.operator_approval.v1")["verdict"] == "supported"
    completeness = _report_claim(report, "key.status.completeness.v1")
    assert completeness["verdict"] == "disproved"
    assert (
        completeness["reason_code"]
        == "KEY_STATUS_COMPLETENESS_TERMINAL_STATUS_AT_COMPARISON"
    )
    v2_claim = _report_claim(report, "permit.operator_approval.v2")
    assert v2_claim["verdict"] == "insufficient_evidence"
    assert (
        v2_claim["reason_code"]
        == "PERMIT_OPERATOR_APPROVAL_KEY_STATUS_COMPLETENESS_UNSUPPORTED"
    )


def test_default_verify_permit_v2_floor_allows_revocation_after_signed_at(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Temporal-boundary complement to the masking lock: the floor must NOT
    over-block.

    A revocation effective AFTER the slot's ``signed_at`` MUST NOT invalidate an
    otherwise-valid historical signature (keel-permit ``spec/permit-v2.md`` §10:
    "A revocation or compromise effective after signed_at MUST NOT invalidate an
    otherwise valid historical signature"). Completeness checks ``not_revoked``
    AS OF ``signed_at`` (``comparison_instant_source: signed_bytes``), so a key
    revoked strictly AFTER ``signed_at`` leaves the v2 slot ``supported`` and the
    overall export passes. This pairs with
    ``test_default_verify_permit_v2_auto_required_floor_rejects_revoked_key``
    (revoked at/before signed_at -> blocked) to lock both sides of the boundary.
    """
    export_document, manifest, key_manifest, key_manifest_path = _operator_approval_fixture()
    slot = export_document["operator_approval"]
    # slot.signed_at is 2026-05-23T12:30:00.123456Z; revoke strictly AFTER it.
    ctx = _context(
        tmp_path,
        monkeypatch,
        key_status="revoked",
        revoked_at="2026-06-01T00:00:00Z",
        account_id=export_document["account_id"],
        key_scope="operator",
        target_key_id=slot["key_id"],
        target_public=_slot_public_key(key_manifest, key_id=slot["key_id"]),
        comparison_instant=slot["signed_at"],
    )
    manifest_path = _write_manifest_with_key_status_evidence(
        tmp_path,
        manifest=manifest,
        ctx=ctx,
        legacy_default=True,
    )
    export_path = PERMIT_V2_FIXTURE_ROOT / "operator_approval_positive_01" / "export.json"

    report = verify_export_structured(
        _verify_args(export_path, manifest_path, key_manifest_path)
    )

    # Revocation is AFTER signed_at -> the historical signature remains valid.
    assert _report_claim(report, "permit.operator_approval.v1")["verdict"] == "supported"
    assert _report_claim(report, "key.status.completeness.v1")["verdict"] == "supported"
    assert _report_claim(report, "permit.operator_approval.v2")["verdict"] == "supported"
    assert report.exit_code == 0


def test_full_verify_key_status_force_pin_ignores_malicious_key_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    export_document, manifest, key_manifest, _key_manifest_path = _operator_approval_fixture()
    slot = export_document["operator_approval"]
    ctx = _context(
        tmp_path,
        monkeypatch,
        event_refs=[],
        scope_count=0,
        key_status="active",
        account_id=export_document["account_id"],
        key_scope="operator",
        target_key_id=slot["key_id"],
        target_public=_slot_public_key(key_manifest, key_id=slot["key_id"]),
        comparison_instant=slot["signed_at"],
    )
    attacker_key = _private_key(19)
    attacker_public = _public_key(attacker_key)
    forged_manifest = _sign_key_status_manifest(
        ctx["manifest"],
        permit_key=attacker_key,
        permit_key_id=_binding_key_id_from_public_key(attacker_public),
    )
    manifest_path = _write_manifest_with_key_status_evidence(
        tmp_path,
        manifest=manifest,
        ctx=ctx,
        key_status_manifest=forged_manifest,
    )
    malicious_key_manifest_path = _write_malicious_key_manifest(
        tmp_path,
        base_key_manifest=key_manifest,
        attacker_public=attacker_public,
    )
    export_path = PERMIT_V2_FIXTURE_ROOT / "operator_approval_positive_01" / "export.json"

    report = verify_export_structured(
        _verify_args(export_path, manifest_path, str(malicious_key_manifest_path))
    )

    assert report.exit_code == 1
    assert _report_claim(report, "permit.operator_approval.v1")["verdict"] == "supported"
    completeness = _report_claim(report, "key.status.completeness.v1")
    assert completeness["verdict"] == "disproved"
    assert (
        completeness["reason_code"]
        == "KEY_STATUS_COMPLETENESS_MANIFEST_SIGNATURE_INVALID"
    )


def test_permit_operator_approval_v2_blocks_without_completeness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _context(tmp_path, monkeypatch)
    export_document, manifest, _key_manifest, key_manifest_path = _operator_approval_fixture()

    claim = _adjudicate_permit_operator_approval_v2(
        export_document=export_document,
        manifest=manifest,
        key_manifest_source=key_manifest_path,
    )

    assert claim.aggregate_verdict == "insufficient_evidence"
    assert (
        claim.reason_code
        == "PERMIT_OPERATOR_APPROVAL_KEY_STATUS_COMPLETENESS_UNSUPPORTED"
    )
    assert claim.epistemic_state["operator_approval"] == "unverifiable"


def test_permit_operator_approval_v2_blocks_terminal_key_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    export_document, manifest, key_manifest, key_manifest_path = _operator_approval_fixture()
    slot = export_document["operator_approval"]
    ctx = _context(
        tmp_path,
        monkeypatch,
        key_status="revoked",
        account_id=export_document["account_id"],
        key_scope="operator",
        target_key_id=slot["key_id"],
        target_public=_slot_public_key(key_manifest, key_id=slot["key_id"]),
        comparison_instant=slot["signed_at"],
        revoked_at=slot["signed_at"],
    )

    claim = _adjudicate_permit_operator_approval_v2(
        export_document=export_document,
        manifest=manifest,
        key_manifest_source=key_manifest_path,
        key_status_manifest=ctx["manifest"],
        key_status_sidecar=ctx["sidecar"],
        key_status_checkpoint=ctx["checkpoint"],
    )

    assert claim.aggregate_verdict == "insufficient_evidence"
    assert (
        claim.reason_code
        == "PERMIT_OPERATOR_APPROVAL_KEY_STATUS_COMPLETENESS_UNSUPPORTED"
    )
