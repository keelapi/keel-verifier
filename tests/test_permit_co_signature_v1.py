from __future__ import annotations

import argparse
import base64
import copy
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from keel_verifier import verifier
from keel_verifier.permit_co_signature import verify_protocol


_CORPUS_CANDIDATES = [
    ancestor / "keel-permit" / "test-vectors" / "permit_co_signature" / "v1" / "corpus.json"
    for ancestor in Path(__file__).resolve().parents
]
CORPUS_PATH = next((candidate for candidate in _CORPUS_CANDIDATES if candidate.is_file()), None)
if CORPUS_PATH is None:
    raise RuntimeError(
        "keel-permit co-signature golden corpus not found. These vectors are the only "
        "thing proving this verifier still matches the normative contract; falling back "
        "to an empty set would collect zero cases and pass vacuously. "
        "Check out keelapi/keel-permit alongside this repo."
    )
CORPUS = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
if not CORPUS.get("vectors"):
    raise RuntimeError("keel-permit co-signature golden corpus is empty")


@pytest.mark.parametrize(
    "vector",
    CORPUS["vectors"],
    ids=lambda vector: vector["id"],
)
def test_phase0_golden_corpus_matches_verdict_and_reason(vector: dict[str, Any]) -> None:
    context = vector["verification_context"]
    result = verify_protocol(
        claim=vector["claim"],
        target_permit=context,
        registered_key=vector["registered_cose_key"],
        allowed_origins=context["allowed_origins"],
        require_user_verification=context["require_user_verification"],
    )

    assert result.verdict == vector["expected"]["verdict"]
    assert result.reason == vector["expected"]["reason"]


def test_wrong_registered_es256_key_is_disproved() -> None:
    positive = copy.deepcopy(next(v for v in CORPUS["vectors"] if v["id"] == "positive-es256"))
    numbers = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
    cose = (
        b"\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20"
        + numbers.x.to_bytes(32, "big")
        + b"\x22\x58\x20"
        + numbers.y.to_bytes(32, "big")
    )
    positive["registered_cose_key"]["public_key_cose"] = (
        base64.urlsafe_b64encode(cose).rstrip(b"=").decode("ascii")
    )
    context = positive["verification_context"]

    result = verify_protocol(
        claim=positive["claim"],
        target_permit=context,
        registered_key=positive["registered_cose_key"],
        allowed_origins=context["allowed_origins"],
        require_user_verification=context["require_user_verification"],
    )

    assert result.verdict == "disproved"
    assert result.reason == "CO_SIGNATURE_INVALID_SIGNATURE"


def _public_key(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return "ed25519:" + base64.b64encode(raw).decode("ascii")


def _signature(private_key: Ed25519PrivateKey, value: str) -> str:
    return "ed25519:" + base64.b64encode(private_key.sign(value.encode("utf-8"))).decode("ascii")


def _write_json(path: Path, value: dict[str, Any]) -> Path:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def _signed_trust_root(
    tmp_path: Path,
    *,
    export_private: Ed25519PrivateKey,
    binding_private: Ed25519PrivateKey,
) -> tuple[Path, str, str, str]:
    export_public = _public_key(export_private)
    binding_public = _public_key(binding_private)
    export_key_id = verifier._public_key_fingerprint(export_public)
    binding_key_id = verifier._binding_key_id_from_public_key(binding_public)
    root: dict[str, Any] = {
        "manifest_version": "keel.public_key_manifest.v1",
        "canonicalization_profile": "keel.canonical_json.payload.v1",
        "generated_at": "2026-07-14T12:00:00Z",
        "keys": [
            {
                "algorithm": "ed25519",
                "key_id": export_key_id,
                "public_key": export_public,
                "purpose": "export_signing",
                "status": "active",
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_to": None,
            },
            {
                "algorithm": "ed25519",
                "key_id": binding_key_id,
                "public_key": binding_public,
                "purpose": "permit_binding_signing",
                "status": "active",
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_to": None,
            },
        ],
    }
    digest = verifier._content_hash(verifier._manifest_signature_payload_bytes(root))
    root["manifest_signature"] = {
        "signature_type": "ed25519.content_hash.v1",
        "purpose": "export_signing",
        "key_id": export_key_id,
        "content_hash": digest,
        "signature": _signature(export_private, digest),
    }
    return (
        _write_json(tmp_path / "keel-trust-root.json", root),
        export_key_id,
        binding_key_id,
        export_public,
    )


def _key_status_manifest(
    *,
    vector: dict[str, Any],
    binding_private: Ed25519PrivateKey,
    binding_key_id: str,
) -> dict[str, Any]:
    context = vector["verification_context"]
    registered = vector["registered_cose_key"]
    account_id = "30000000-0000-4000-8000-000000000001"
    manifest: dict[str, Any] = {
        "manifest_type": "permit_v2.key_status_manifest.v1",
        "canonicalization_profile": "keel.canonical_json.payload.v1",
        "computed_at": "2026-07-14T12:00:00+00:00",
        "account_id": account_id,
        "key_scopes": list(verifier.KEY_STATUS_MANIFEST_SCOPES),
        "keys": [
            {
                "account_id": account_id,
                "key_scope": "co_signer",
                "key_id": registered["key_id"],
                "credential_id": registered["credential_id"],
                "public_key_cose": registered["public_key_cose"],
                "cose_alg": registered["cose_alg"],
                "rp_id": registered["rp_id"],
                "allowed_origins": context["allowed_origins"],
                "custody_tier": "human_passkey",
                "status": "active",
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": None,
                "revoked_at": None,
                "compromised_at": None,
                "aaguid": registered.get("aaguid"),
                "attestation_format": registered.get("attestation_format"),
                "attestation_statement": registered.get("attestation_statement"),
                "backup_eligible": registered.get("backup_eligible"),
                "backup_state": registered.get("backup_state"),
                "metadata": {"project_id": "40000000-0000-4000-8000-000000000001"},
                "event_refs": [],
                "principal": {
                    "kind": "co_signer",
                    "id": registered["co_signer_id"],
                },
            }
        ],
        "signer": {
            "purpose": "permit_binding_signing",
            "key_id": binding_key_id,
            "algorithm": "ed25519",
        },
    }
    manifest_hash = verifier._key_status_manifest_hash_from_payload(manifest)
    manifest["manifest_hash"] = manifest_hash
    manifest["signature"] = base64.b64encode(
        binding_private.sign(manifest_hash.encode("utf-8"))
    ).decode("ascii")
    return manifest


def _pack(vector: dict[str, Any], key_manifest: dict[str, Any]) -> dict[str, Any]:
    context = vector["verification_context"]
    target = {
        field: context[field]
        for field in (
            "permit_id",
            "permit_canonical_hash",
            "action",
            "resource",
            "modality",
        )
    }
    provider, model, operation = target["resource"].split(":", 2)
    return {
        "bundle_type": "audit_export_bundle",
        "schema_version": 1,
        "records": [
            {
                "permit": {
                    "id": target["permit_id"],
                    "permit_canonical_hash": target["permit_canonical_hash"],
                    "action_name": target["action"],
                    "resource_provider": provider,
                    "resource_model": model,
                    "resource_operation": operation,
                    "resource_modality": target["modality"],
                }
            }
        ],
        "co_signature_evidence": [
            {
                "claim": vector["claim"],
                "target_permit": target,
                "allowed_origins": context["allowed_origins"],
                "require_user_verification": context["require_user_verification"],
            }
        ],
        "key_status_manifest": key_manifest,
    }


def _args(export_path: Path, manifest_path: Path, trust_root: Path) -> argparse.Namespace:
    return argparse.Namespace(
        export_file=str(export_path),
        manifest=str(manifest_path),
        key_manifest=str(trust_root),
        key_manifest_url=None,
        expected_public_key=None,
        public_key=None,
        self_attested=False,
        offline=True,
        allow_unsigned=False,
        walk_events=False,
        verify_closure=False,
        as_json=True,
    )


def _case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, vector: dict[str, Any]):
    export_private = Ed25519PrivateKey.generate()
    binding_private = Ed25519PrivateKey.generate()
    trust_root, export_key_id, binding_key_id, export_public = _signed_trust_root(
        tmp_path,
        export_private=export_private,
        binding_private=binding_private,
    )
    monkeypatch.setattr(verifier, "DEFAULT_TRUST_ROOT_PATH", trust_root)
    key_manifest = _key_status_manifest(
        vector=vector,
        binding_private=binding_private,
        binding_key_id=binding_key_id,
    )
    export_path = _write_json(tmp_path / "export.json", _pack(vector, key_manifest))
    digest = verifier._content_hash(export_path.read_bytes())
    manifest_path = _write_json(
        tmp_path / "manifest.json",
        {
            "content_hash": digest,
            "signature": _signature(export_private, digest),
            "public_key": export_public,
            "key_id": export_key_id,
            "signed_at": "2026-07-14T12:00:00Z",
        },
    )
    return export_path, manifest_path, trust_root


def _claim(report) -> dict[str, Any]:
    return next(
        claim for claim in report.to_dict()["claims"] if claim["name"] == "permit.co_signature.v1"
    )


@pytest.mark.parametrize(
    "vector",
    CORPUS["vectors"],
    ids=lambda vector: f"signed-pack-{vector['id']}",
)
def test_signed_pack_adjudicator_matches_phase0_verdict_and_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    vector: dict[str, Any],
) -> None:
    export_path, manifest_path, trust_root = _case(tmp_path, monkeypatch, vector)

    report = verifier.verify_export_structured(_args(export_path, manifest_path, trust_root))
    claim = _claim(report)

    assert claim["verdict"] == vector["expected"]["verdict"]
    assert claim["reason_code"] == vector["expected"]["reason"]


def test_signed_pack_verifies_offline_with_servers_off(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    positive = next(v for v in CORPUS["vectors"] if v["id"] == "positive-es256")
    export_path, manifest_path, trust_root = _case(tmp_path, monkeypatch, positive)

    report = verifier.verify_export_structured(_args(export_path, manifest_path, trust_root))

    assert report.exit_code == 0
    assert _claim(report)["verdict"] == "supported"
    assert _claim(report)["reason_code"] == "CO_SIGNATURE_VERIFIED"
    assert _claim(report)["epistemic_state"] == {"custody_tier": "human_passkey"}


@pytest.mark.parametrize("missing", [True, False], ids=["missing", "unsigned"])
def test_missing_or_unsigned_pack_manifest_is_insufficient_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    missing: bool,
) -> None:
    positive = next(v for v in CORPUS["vectors"] if v["id"] == "positive-es256")
    export_path, manifest_path, trust_root = _case(tmp_path, monkeypatch, positive)
    if missing:
        manifest_path = tmp_path / "missing-manifest.json"
    else:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["signature"] = None
        _write_json(manifest_path, manifest)

    report = verifier.verify_export_structured(_args(export_path, manifest_path, trust_root))

    assert report.exit_code == 1
    assert _claim(report)["verdict"] == "insufficient_evidence"


def test_unsigned_key_manifest_is_insufficient_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    positive = next(v for v in CORPUS["vectors"] if v["id"] == "positive-es256")
    export_path, manifest_path, trust_root = _case(tmp_path, monkeypatch, positive)
    document = json.loads(export_path.read_text(encoding="utf-8"))
    document["key_status_manifest"]["signature"] = ""
    _write_json(export_path, document)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    digest = verifier._content_hash(export_path.read_bytes())
    manifest["content_hash"] = digest
    export_private = Ed25519PrivateKey.generate()
    # Preserve valid outer-pack integrity by trusting the replacement export key.
    root = json.loads(trust_root.read_text(encoding="utf-8"))
    export_public = _public_key(export_private)
    export_key_id = verifier._public_key_fingerprint(export_public)
    root["keys"][0].update(key_id=export_key_id, public_key=export_public)
    root_digest = verifier._content_hash(verifier._manifest_signature_payload_bytes(root))
    root["manifest_signature"].update(
        key_id=export_key_id,
        content_hash=root_digest,
        signature=_signature(export_private, root_digest),
    )
    _write_json(trust_root, root)
    manifest.update(
        key_id=export_key_id,
        public_key=export_public,
        signature=_signature(export_private, digest),
    )
    _write_json(manifest_path, manifest)

    report = verifier.verify_export_structured(_args(export_path, manifest_path, trust_root))

    assert report.exit_code == 1
    assert _claim(report)["verdict"] == "insufficient_evidence"


def test_unsigned_keel_trust_manifest_is_insufficient_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    positive = next(v for v in CORPUS["vectors"] if v["id"] == "positive-es256")
    export_path, manifest_path, trust_root = _case(tmp_path, monkeypatch, positive)
    root = json.loads(trust_root.read_text(encoding="utf-8"))
    root.pop("manifest_signature")
    _write_json(trust_root, root)
    args = _args(export_path, manifest_path, trust_root)
    args.expected_public_key = json.loads(manifest_path.read_text(encoding="utf-8"))["public_key"]

    report = verifier.verify_export_structured(args)

    assert report.exit_code == 1
    assert _claim(report)["verdict"] == "insufficient_evidence"
    assert _claim(report)["reason_code"] == "CO_SIGNATURE_KEY_MANIFEST_UNTRUSTED"


def test_unsupported_cose_algorithm_is_unverifiable_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    positive = copy.deepcopy(next(v for v in CORPUS["vectors"] if v["id"] == "positive-es256"))
    positive["claim"]["assertion"]["cose_alg"] = -257
    positive["registered_cose_key"]["cose_alg"] = -257
    export_path, manifest_path, trust_root = _case(tmp_path, monkeypatch, positive)

    report = verifier.verify_export_structured(_args(export_path, manifest_path, trust_root))

    assert report.exit_code == 1
    assert _claim(report)["verdict"] == "unverifiable_scope"
    assert _claim(report)["subjects"][0]["reason_code"] == "CO_SIGNATURE_ALGORITHM_UNSUPPORTED"
