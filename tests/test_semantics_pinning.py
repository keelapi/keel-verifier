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
    CLAIM_REGISTRY_HASH,
    CLAIM_REGISTRY_ID,
    EXPORT_MANIFEST_INTEGRITY_HASH,
    EXPORT_MANIFEST_INTEGRITY_ID,
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


def _signed_export_with_manifest(tmp_path: Path):
    export_private, export_public, export_key_id = keypair()
    return write_signed_export(
        tmp_path,
        {"records": []},
        export_private_key=export_private,
        export_public_key=export_public,
        export_key_id=export_key_id,
    )


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
