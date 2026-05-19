from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from conftest import keypair, write_json, write_signed_export
from keel_verifier.semantics import (
    AUTHORITY_ENVELOPE_V0_HASH,
    AUTHORITY_ENVELOPE_V0_ID,
    CHECKPOINT_COMPOSITE_HASH_HASH,
    CHECKPOINT_COMPOSITE_HASH_ID,
    CHECKPOINT_SIGNATURE_HASH,
    CHECKPOINT_SIGNATURE_ID,
    CHECKPOINT_TSA_IMPRINT_HASH,
    CHECKPOINT_TSA_IMPRINT_ID,
    CLAIM_REGISTRY_HASH,
    CLAIM_REGISTRY_ID,
    EXPORT_MANIFEST_INTEGRITY_HASH,
    EXPORT_MANIFEST_INTEGRITY_ID,
    GOVERNANCE_EVENT_INTEGRITY_DIGEST_HASH,
    GOVERNANCE_EVENT_INTEGRITY_DIGEST_ID,
    GOVERNANCE_RECORD_HASH_HASH,
    GOVERNANCE_RECORD_HASH_ID,
    RELEASED_ARTIFACT_PATHS,
)
from keel_verifier.verifier import PERMANENT_ALLOWLIST


REPO_ROOT = Path(__file__).resolve().parents[1]
PRODUCT_ROOT = REPO_ROOT.parent
SOURCE_PERMIT = PRODUCT_ROOT / "keel-permit"


def _json_result(result):
    assert result.stdout, result.stderr
    return json.loads(result.stdout)


def _sha256(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _artifact_pin(artifact_id: str, artifact_hash: str) -> dict[str, str]:
    return {
        "id": artifact_id,
        "hash": artifact_hash,
        "path": RELEASED_ARTIFACT_PATHS[artifact_id],
    }


def _add_pins(
    manifest_path: Path,
    *,
    artifacts: list[dict[str, Any]],
    registry_hash: str = CLAIM_REGISTRY_HASH,
    claims: list[dict[str, Any]] | None = None,
) -> None:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["claim_set"] = {
        "version": "verifier-claims.v0",
        "registry": {
            "id": CLAIM_REGISTRY_ID,
            "hash": registry_hash,
            "path": RELEASED_ARTIFACT_PATHS[CLAIM_REGISTRY_ID],
        },
        "claims": claims
        or [
            {
                "name": "export.integrity.v1",
                "required": True,
            }
        ],
    }
    manifest["semantics_pins"] = {
        "version": "keel-semantics-pins.v0",
        "mode": "pinned",
        "artifacts": artifacts,
    }
    write_json(manifest_path, manifest)


def _add_checkpoint_pins(
    checkpoint_path: Path,
    *,
    artifacts: list[dict[str, Any]],
    claims: list[dict[str, Any]],
) -> None:
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    checkpoint["claim_set"] = {
        "version": "verifier-claims.v0",
        "registry": {
            "id": CLAIM_REGISTRY_ID,
            "hash": CLAIM_REGISTRY_HASH,
            "path": RELEASED_ARTIFACT_PATHS[CLAIM_REGISTRY_ID],
        },
        "claims": claims,
    }
    checkpoint["semantics_pins"] = {
        "version": "keel-semantics-pins.v0",
        "mode": "pinned",
        "artifacts": artifacts,
    }
    write_json(checkpoint_path, checkpoint)


def _signed_export_with_manifest(tmp_path: Path):
    export_private, export_public, export_key_id = keypair()
    return write_signed_export(
        tmp_path,
        {"records": []},
        export_private_key=export_private,
        export_public_key=export_public,
        export_key_id=export_key_id,
    )


def _sample_checkpoint_without_tsa(tmp_path: Path) -> Path:
    checkpoint = json.loads((REPO_ROOT / "sample" / "export.json").read_text())
    checkpoint.pop("tsa", None)
    checkpoint.pop("tsa_receipts", None)
    return write_json(tmp_path / "checkpoint.json", checkpoint)


def test_pinned_pack_resolves_and_dispatches_from_allowlist(tmp_path, run_cli):
    export_file, manifest = _signed_export_with_manifest(tmp_path)
    _add_pins(
        manifest,
        artifacts=[
            {
                "id": EXPORT_MANIFEST_INTEGRITY_ID,
                "hash": EXPORT_MANIFEST_INTEGRITY_HASH,
                "path": RELEASED_ARTIFACT_PATHS[EXPORT_MANIFEST_INTEGRITY_ID],
            }
        ],
    )

    result = run_cli(
        "export",
        "--json",
        str(export_file),
        str(manifest),
        "--self-attested",
    )
    payload = _json_result(result)

    assert result.returncode == 0, result.stderr
    assert payload["semantics"]["mode"] == "pinned"
    integrity = next(
        claim for claim in payload["claims"] if claim["name"] == "export.integrity.v1"
    )
    assert integrity["verdict"] == "supported"
    assert integrity["semantics"] == [
        {"id": EXPORT_MANIFEST_INTEGRITY_ID, "hash": EXPORT_MANIFEST_INTEGRITY_HASH}
    ]


def test_missing_required_pin_is_insufficient_without_build_default_fallback(
    tmp_path,
    run_cli,
):
    export_file, manifest = _signed_export_with_manifest(tmp_path)
    _add_pins(manifest, artifacts=[])

    result = run_cli(
        "export",
        "--json",
        str(export_file),
        str(manifest),
        "--self-attested",
    )
    payload = _json_result(result)

    assert result.returncode == 1
    integrity = next(
        claim for claim in payload["claims"] if claim["name"] == "export.integrity.v1"
    )
    assert integrity["verdict"] == "insufficient_evidence"
    assert integrity["reason_code"] == "SEMANTIC_PIN_MISSING"
    assert integrity["reason_code"] != "EXPORT_INTEGRITY_SUPPORTED"


def test_unknown_semantic_hash_is_unverifiable_scope_without_fallback(
    tmp_path,
    run_cli,
):
    export_file, manifest = _signed_export_with_manifest(tmp_path)
    unknown_artifact = (
        b'{\n'
        b'  "id": "keel.export_manifest.integrity.v1",\n'
        b'  "version": "v1",\n'
        b'  "kind": "export_manifest_integrity_recipe",\n'
        b'  "status": "released",\n'
        b'  "body": {"test": "unknown allowlist hash"}\n'
        b'}\n'
    )
    unknown_hash = _sha256(unknown_artifact)
    assert (EXPORT_MANIFEST_INTEGRITY_ID, unknown_hash) not in PERMANENT_ALLOWLIST
    _add_pins(
        manifest,
        artifacts=[
            {
                "id": EXPORT_MANIFEST_INTEGRITY_ID,
                "hash": unknown_hash,
                "content_b64": base64.b64encode(unknown_artifact).decode("ascii"),
            }
        ],
    )

    result = run_cli(
        "export",
        "--json",
        str(export_file),
        str(manifest),
        "--self-attested",
    )
    payload = _json_result(result)

    assert result.returncode == 1
    integrity = next(
        claim for claim in payload["claims"] if claim["name"] == "export.integrity.v1"
    )
    assert integrity["verdict"] == "unverifiable_scope"
    assert integrity["reason_code"] == "SEMANTIC_PIN_NOT_ALLOWLISTED"
    assert integrity["reason_code"] != "EXPORT_INTEGRITY_SUPPORTED"


def test_hash_mismatch_is_insufficient_with_top_level_integrity_error(
    tmp_path,
    run_cli,
):
    export_file, manifest = _signed_export_with_manifest(tmp_path)
    artifact_bytes = (
        SOURCE_PERMIT / RELEASED_ARTIFACT_PATHS[EXPORT_MANIFEST_INTEGRITY_ID]
    ).read_bytes()
    _add_pins(
        manifest,
        artifacts=[
            {
                "id": EXPORT_MANIFEST_INTEGRITY_ID,
                "hash": "sha256:" + "0" * 64,
                "content_b64": base64.b64encode(artifact_bytes).decode("ascii"),
            }
        ],
    )

    result = run_cli(
        "export",
        "--json",
        str(export_file),
        str(manifest),
        "--self-attested",
    )
    payload = _json_result(result)

    assert result.returncode == 1
    assert payload["ok"] is False
    assert "hash mismatch" in payload["error"]
    assert any("hash mismatch" in diagnostic for diagnostic in payload["diagnostics"])
    integrity = next(
        claim for claim in payload["claims"] if claim["name"] == "export.integrity.v1"
    )
    assert integrity["verdict"] == "insufficient_evidence"
    assert integrity["reason_code"] == "SEMANTIC_PIN_HASH_MISMATCH"


def test_required_export_claim_without_adjudication_fails_closed(
    tmp_path,
    run_cli,
):
    export_file, manifest = _signed_export_with_manifest(tmp_path)
    _add_pins(
        manifest,
        artifacts=[
            _artifact_pin(GOVERNANCE_RECORD_HASH_ID, GOVERNANCE_RECORD_HASH_HASH),
            _artifact_pin(
                GOVERNANCE_EVENT_INTEGRITY_DIGEST_ID,
                GOVERNANCE_EVENT_INTEGRITY_DIGEST_HASH,
            ),
            _artifact_pin(AUTHORITY_ENVELOPE_V0_ID, AUTHORITY_ENVELOPE_V0_HASH),
        ],
        claims=[
            {
                "name": "permit_chain.delegation_denied_correctly.v1",
                "required": True,
            }
        ],
    )

    result = run_cli(
        "export",
        "--json",
        str(export_file),
        str(manifest),
        "--self-attested",
    )
    payload = _json_result(result)

    assert result.returncode == 1
    assert payload["ok"] is False
    claim = next(
        claim
        for claim in payload["claims"]
        if claim["name"] == "permit_chain.delegation_denied_correctly.v1"
    )
    assert claim["required"] is True
    assert claim["verdict"] == "insufficient_evidence"
    assert claim["reason_code"] == "REQUIRED_CLAIM_NOT_ADJUDICATED"


def test_required_checkpoint_tsa_claim_without_receipt_fails_closed(
    tmp_path,
    run_cli,
):
    checkpoint = _sample_checkpoint_without_tsa(tmp_path)
    _add_checkpoint_pins(
        checkpoint,
        artifacts=[
            _artifact_pin(CHECKPOINT_COMPOSITE_HASH_ID, CHECKPOINT_COMPOSITE_HASH_HASH),
            _artifact_pin(CHECKPOINT_SIGNATURE_ID, CHECKPOINT_SIGNATURE_HASH),
            _artifact_pin(CHECKPOINT_TSA_IMPRINT_ID, CHECKPOINT_TSA_IMPRINT_HASH),
        ],
        claims=[
            {
                "name": "checkpoint.composite_hash.v1",
                "required": True,
            },
            {
                "name": "checkpoint.signature.v1",
                "required": True,
            },
            {
                "name": "checkpoint.tsa_imprint.v1",
                "required": True,
            },
        ],
    )

    result = run_cli(
        "checkpoint",
        "--json",
        str(checkpoint),
        "--self-attested",
    )
    payload = _json_result(result)

    assert result.returncode == 1
    assert payload["ok"] is False
    claim = next(
        claim
        for claim in payload["claims"]
        if claim["name"] == "checkpoint.tsa_imprint.v1"
    )
    assert claim["required"] is True
    assert claim["verdict"] == "insufficient_evidence"
    assert claim["reason_code"] == "REQUIRED_CLAIM_NOT_ADJUDICATED"


def test_permanent_allowlist_matches_released_keel_permit_artifacts():
    if not SOURCE_PERMIT.exists():
        message = (
            "keel-permit is not checked out next to keel-verifier: "
            f"{SOURCE_PERMIT}"
        )
        if os.getenv("KEEL_REQUIRE_GOLDEN_CORPUS"):
            raise FileNotFoundError(message)
        pytest.skip(message)

    allowlist_hashes = {
        artifact_id: artifact_hash
        for artifact_id, artifact_hash in PERMANENT_ALLOWLIST
    }

    assert set(allowlist_hashes) == set(RELEASED_ARTIFACT_PATHS)
    for artifact_id, relative_path in RELEASED_ARTIFACT_PATHS.items():
        artifact_path = SOURCE_PERMIT / relative_path
        assert artifact_path.exists(), artifact_path
        assert allowlist_hashes[artifact_id] == _sha256(artifact_path.read_bytes())
