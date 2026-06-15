from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import keel_verifier.verifier as verifier_module
from keel_verifier.verifier import (
    _bundle_canonical_json_bytes,
    _content_hash,
    _public_key_fingerprint,
    cmd_export,
    verify_checkpoint,
    verify_export_structured,
)


def _artifact_ref(*, artifact_type: str, artifact_id: str, body: dict[str, Any]) -> dict[str, Any]:
    digest = "sha256:" + hashlib.sha256(_bundle_canonical_json_bytes(body)).hexdigest()
    return {
        "schema_version": "artifact_ref.v1",
        "type": artifact_type,
        "id": artifact_id,
        "urn": f"urn:x-keel:artifact:{artifact_type}:{artifact_id}",
        "region": "us-west-1",
        "path": f"/v1/test/{artifact_id}",
        "canonical_url": f"https://api.keelapi.com/v1/test/{artifact_id}",
        "digest": digest,
    }


def _signing_material() -> tuple[Ed25519PrivateKey, str, str]:
    private_key = Ed25519PrivateKey.generate()
    public_key = base64.b64encode(
        private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")
    return private_key, public_key, _public_key_fingerprint(public_key)


def _bundle(body: dict[str, Any], private_key: Ed25519PrivateKey, public_key: str, key_id: str) -> dict[str, Any]:
    content_hash = _content_hash(_bundle_canonical_json_bytes(body))
    signature = base64.b64encode(private_key.sign(content_hash.encode("utf-8"))).decode(
        "ascii"
    )
    return {
        "schema_version": "keel.evidence_bundle/v1",
        "body": body,
        "signature_envelope": {
            "content_hash": content_hash,
            "signature": signature,
            "public_key_id": key_id,
            "public_key": public_key,
            "tsa_receipts": [],
            "tsa_attempts": [],
        },
    }


def _write(path: Path, payload: dict[str, Any]) -> Path:
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    return path


def _export_args(path: Path, *, manifest: Path | None = None, as_json: bool = True) -> argparse.Namespace:
    return argparse.Namespace(
        export_file=str(path),
        manifest=str(manifest) if manifest is not None else None,
        as_json=as_json,
        expected_public_key=None,
        key_manifest=None,
        key_manifest_url=None,
        self_attested=False,
        allow_unsigned=False,
        walk_events=False,
        verify_closure=False,
        sidecar=None,
        checkpoint=None,
    )


def test_export_command_accepts_single_file_self_attesting_bundle(tmp_path: Path) -> None:
    private_key, public_key, key_id = _signing_material()
    body = {
        "schema": "keel.evidence/v1",
        "source": "keel",
        "generated_at": "2026-06-14T12:00:00Z",
        "project_id": "11111111-1111-4111-8111-111111111111",
        "export_id": "22222222-2222-4222-8222-222222222222",
        "decision_source": "Decision made by Keel",
        "record_count": 0,
        "records": [],
    }
    body["artifact_ref"] = _artifact_ref(
        artifact_type="compliance_export",
        artifact_id=body["export_id"],
        body=body,
    )
    body["anchor"] = {
        "kind": "published_checkpoint",
        "checkpoint_id": "33333333-3333-4333-8333-333333333333",
        "composite_hash": "sha256:" + "3" * 64,
        "published_at": "2026-06-14T12:05:00Z",
    }
    path = _write(tmp_path / "export_bundle.json", _bundle(body, private_key, public_key, key_id))

    report = verify_export_structured(_export_args(path))

    assert report.ok is True
    assert report.error is None
    assert report.claims[0].reason_code == "EVIDENCE_BUNDLE_SUPPORTED"
    assert any("bundle has no TSA receipts" in item for item in report.diagnostics)


def test_export_command_accepts_self_attesting_bundle_without_anchor(
    tmp_path: Path,
    capsys,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key, public_key, key_id = _signing_material()
    body = {
        "schema": "keel.evidence/v1",
        "source": "keel",
        "generated_at": "2026-06-14T12:00:00Z",
        "project_id": "11111111-1111-4111-8111-111111111111",
        "export_id": "22222222-2222-4222-8222-222222222222",
        "decision_source": "Decision made by Keel",
        "record_count": 0,
        "records": [],
    }
    body["artifact_ref"] = _artifact_ref(
        artifact_type="compliance_export",
        artifact_id=body["export_id"],
        body=body,
    )
    bundle = _bundle(body, private_key, public_key, key_id)
    bundle["signature_envelope"]["tsa_receipts"] = [
        {"provider": "tsa.test", "receipt_b64": "receipt-bytes"}
    ]
    path = _write(
        tmp_path / "export_bundle_without_anchor.json",
        bundle,
    )

    def _fail_tsa_check(receipt_b64: str, expected_hash_hex: str):
        raise AssertionError("TSA verification should be skipped without anchor")

    monkeypatch.setattr(
        verifier_module,
        "_verify_tsa_receipt",
        _fail_tsa_check,
    )

    report = verify_export_structured(_export_args(path))

    assert report.ok is True
    assert report.error is None
    assert "anchor" not in bundle["body"]
    assert report.claims[0].reason_code == "EVIDENCE_BUNDLE_SUPPORTED"
    assert any("no anchor" in item for item in report.diagnostics)
    assert any("skipping TSA imprint verification" in item for item in report.diagnostics)

    assert cmd_export(_export_args(path, as_json=False)) == 0
    captured = capsys.readouterr()
    assert "no anchor" in captured.err
    assert "VERIFIED" in captured.out


def test_bundle_content_hash_mismatch_fails_clearly(tmp_path: Path) -> None:
    private_key, public_key, key_id = _signing_material()
    body = {"schema": "keel.evidence/v1", "records": []}
    body["artifact_ref"] = _artifact_ref(
        artifact_type="compliance_export",
        artifact_id="bundle-content-mismatch",
        body=body,
    )
    bundle = _bundle(body, private_key, public_key, key_id)
    bundle["signature_envelope"]["content_hash"] = "sha256:" + "0" * 64
    path = _write(tmp_path / "tampered_bundle.json", bundle)

    report = verify_export_structured(_export_args(path))

    assert report.ok is False
    assert "content_hash mismatch" in str(report.error)
    assert report.claims[0].reason_code == "BUNDLE_CONTENT_HASH_MISMATCH"


def test_bundle_signature_mismatch_fails_clearly(tmp_path: Path) -> None:
    private_key, public_key, key_id = _signing_material()
    other_key = Ed25519PrivateKey.generate()
    body = {"schema": "keel.evidence/v1", "records": []}
    body["artifact_ref"] = _artifact_ref(
        artifact_type="compliance_export",
        artifact_id="bundle-signature-mismatch",
        body=body,
    )
    bundle = _bundle(body, private_key, public_key, key_id)
    bundle["signature_envelope"]["signature"] = base64.b64encode(
        other_key.sign(bundle["signature_envelope"]["content_hash"].encode("utf-8"))
    ).decode("ascii")
    path = _write(tmp_path / "bad_signature_bundle.json", bundle)

    report = verify_export_structured(_export_args(path))

    assert report.ok is False
    assert report.error == "bundle signature verification failed"
    assert report.claims[0].reason_code == "BUNDLE_SIGNATURE_INVALID"


def test_export_command_accepts_voice_chain_head_timestamp_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key, public_key, key_id = _signing_material()
    chain_head_hash = "sha256:" + "8" * 64
    receipt = {"provider": "tsa.test", "tsa_response_base64": "receipt-bytes"}
    body = {
        "schema": "keel.voice.attestation.phase_a",
        "artifact_version": "1.2.0",
        "schema_version": 3,
        "session_metadata": {"session_id": "session_voice_bundle"},
        "project_chain_head": {
            "chain_scope": "project:11111111-1111-4111-8111-111111111111",
            "content_hash": chain_head_hash,
            "sequence": 7,
        },
        "timestamp_receipts": [receipt],
    }
    body["artifact_ref"] = _artifact_ref(
        artifact_type="voice_session_attestation",
        artifact_id="session_voice_bundle",
        body=body,
    )
    body["anchor"] = {
        "kind": "chain_head_timestamp",
        "chain_scope_key": body["project_chain_head"]["chain_scope"],
        "chain_head_hash": chain_head_hash,
        "sequence_number": body["project_chain_head"]["sequence"],
        "timestamp_receipts": [receipt],
    }
    bundle = _bundle(body, private_key, public_key, key_id)
    bundle["signature_envelope"]["tsa_receipts"] = [receipt]
    bundle["signature_envelope"]["tsa_attempts"] = [
        {"provider": "tsa.test", "status": "ok"}
    ]
    checked_imprints: list[tuple[str, str]] = []

    def _fake_verify_tsa_receipt(receipt_b64: str, expected_hash_hex: str):
        checked_imprints.append((receipt_b64, expected_hash_hex))
        return True, "ok"

    monkeypatch.setattr(
        verifier_module,
        "_verify_tsa_receipt",
        _fake_verify_tsa_receipt,
    )
    path = _write(
        tmp_path / "voice_bundle.json",
        bundle,
    )

    report = verify_export_structured(_export_args(path))

    assert report.ok is True
    assert report.error is None
    assert report.claims[0].reason_code == "EVIDENCE_BUNDLE_SUPPORTED"
    assert checked_imprints == [("receipt-bytes", "8" * 64)]


def test_checkpoint_command_verifies_self_attesting_checkpoint_bundle(tmp_path: Path) -> None:
    private_key, public_key, key_id = _signing_material()
    chain_heads = {
        "project:11111111-1111-4111-8111-111111111111": {
            "sequence_number": 1,
            "last_record_hash": "abc",
        }
    }
    composite = "sha256:" + hashlib.sha256(
        b"project:11111111-1111-4111-8111-111111111111:1:abc"
    ).hexdigest()
    checkpoint = {
        "checkpoint_id": "44444444-4444-4444-8444-444444444444",
        "computed_at": "2026-06-14T12:00:00Z",
        "chain_heads": chain_heads,
        "composite_hash": composite,
        "signature": "ed25519:"
        + base64.b64encode(private_key.sign(composite.encode("utf-8"))).decode("ascii"),
        "public_key": "ed25519:" + public_key,
        "key_id": key_id,
        "tsa_receipts": [],
        "tsa_attempts": [],
    }
    checkpoint["artifact_ref"] = _artifact_ref(
        artifact_type="checkpoint_envelope",
        artifact_id=checkpoint["checkpoint_id"],
        body=checkpoint,
    )
    path = _write(
        tmp_path / "checkpoint_bundle.json",
        _bundle(checkpoint, private_key, public_key, key_id),
    )

    result = verify_checkpoint(path, self_attested=True, check_tsa=False)

    assert result.ok is True
    assert result.artifact["kind"] == "checkpoint_bundle"
    assert {claim.reason_code for claim in result.claims} >= {
        "EVIDENCE_BUNDLE_SUPPORTED",
        "CHECKPOINT_COMPOSITE_HASH_SUPPORTED",
        "CHECKPOINT_SIGNATURE_SUPPORTED",
    }


def test_legacy_split_file_export_still_verifies_with_warning(
    tmp_path: Path,
    capsys,
) -> None:
    verifier_module._LEGACY_SPLIT_EXPORT_WARNING_EMITTED = False
    private_key, public_key, key_id = _signing_material()
    export_path = tmp_path / "export.json"
    export_path.write_text('{"records":[]}', encoding="utf-8")
    content_hash = _content_hash(export_path.read_bytes())
    manifest = {
        "content_hash": content_hash,
        "signature": "ed25519:"
        + base64.b64encode(private_key.sign(content_hash.encode("utf-8"))).decode(
            "ascii"
        ),
        "public_key": "ed25519:" + public_key,
        "key_id": key_id,
        "signed_at": "2026-06-14T12:00:00Z",
    }
    manifest_path = _write(tmp_path / "manifest.json", manifest)
    args = _export_args(manifest_path, as_json=False)
    args.export_file = str(export_path)
    args.manifest = str(manifest_path)
    args.expected_public_key = "ed25519:" + public_key

    assert cmd_export(args) == 0

    captured = capsys.readouterr()
    assert "legacy split-file export input is deprecated" in captured.err
    assert "VERIFIED" in captured.out
