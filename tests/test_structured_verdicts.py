from __future__ import annotations

import json

from conftest import content_hash, keypair, write_json, write_signed_export

from keel_verifier.verdicts import (
    ClaimVerdict,
    LEGACY_PROFILE_WARNING,
    VERDICT_OUTPUT_JSON_SCHEMA,
)
from keel_verifier.semantics import LEGACY_PROFILE_HASH


def _json_result(result):
    assert result.stdout, result.stderr
    return json.loads(result.stdout)


def _write_unsigned_export(tmp_path):
    export_path = tmp_path / "export.json"
    export_path.write_text('{"records":[]}\n', encoding="utf-8")
    manifest_path = write_json(
        tmp_path / "manifest.json",
        {"content_hash": content_hash(export_path.read_bytes())},
    )
    return export_path, manifest_path


def test_export_json_matches_verdict_schema_shape(tmp_path, run_cli):
    export_private, export_public, export_key_id = keypair()
    export_file, manifest = write_signed_export(
        tmp_path,
        {"records": []},
        export_private_key=export_private,
        export_public_key=export_public,
        export_key_id=export_key_id,
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
    assert payload["schema"] == VERDICT_OUTPUT_JSON_SCHEMA["$id"]
    assert payload["ok"] is True
    assert payload["exit_code"] == 0
    assert isinstance(payload["diagnostics"], list)
    assert payload["semantics"]["mode"] == "legacy_unpinned"
    assert payload["semantics"]["profile_id"] == "keel.pre_pinning_default.v0"
    assert payload["semantics"]["profile_hash"] == LEGACY_PROFILE_HASH
    assert payload["semantics"]["warning"] == LEGACY_PROFILE_WARNING
    assert any(
        pin["id"] == "keel.export_manifest.integrity.v1"
        and pin["status"] == "allowlisted"
        for pin in payload["semantics"]["pins"]
    )
    verdicts = {claim["name"]: claim["verdict"] for claim in payload["claims"]}
    assert verdicts["export.integrity.v1"] == "supported"


def test_export_json_failure_preserves_exit_code_contract(tmp_path, run_cli):
    export_private, export_public, export_key_id = keypair()
    export_file, manifest = write_signed_export(
        tmp_path,
        {"records": []},
        export_private_key=export_private,
        export_public_key=export_public,
        export_key_id=export_key_id,
    )
    manifest_doc = json.loads(manifest.read_text(encoding="utf-8"))
    manifest_doc["signature"] = "ed25519:" + "A" * 88
    write_json(manifest, manifest_doc)

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
    assert payload["exit_code"] == 1
    verdicts = {claim["name"]: claim["verdict"] for claim in payload["claims"]}
    assert verdicts["export.integrity.v1"] == "disproved"


def test_allow_unsigned_json_keeps_exit_zero_but_signature_insufficient(
    tmp_path,
    run_cli,
):
    export_path, manifest_path = _write_unsigned_export(tmp_path)

    result = run_cli(
        "export",
        "--json",
        str(export_path),
        str(manifest_path),
        "--allow-unsigned",
    )
    payload = _json_result(result)

    assert result.returncode == 0
    integrity = next(
        claim for claim in payload["claims"] if claim["name"] == "export.integrity.v1"
    )
    assert integrity["verdict"] == "insufficient_evidence"
    signature = next(
        subject
        for subject in integrity["subjects"]
        if subject["type"] == "manifest_signature"
    )
    assert signature["verdict"] == "insufficient_evidence"
    assert "--allow-unsigned compatibility" in signature["message"]


def test_legacy_checkpoint_json_keys_are_preserved(run_cli):
    result = run_cli(
        "checkpoint",
        "--json",
        "sample/export.json",
        "--self-attested",
    )
    payload = _json_result(result)

    assert result.returncode == 0, result.stderr
    legacy_keys = {
        "ok",
        "error",
        "checkpoint_id",
        "computed_at",
        "composite_hash",
        "chain_heads_count",
        "public_key",
        "key_id",
        "trust_source",
        "self_attested",
        "tsa",
        "tsa_receipts",
        "diagnostics",
    }
    assert legacy_keys.issubset(payload.keys())
    assert {"schema", "exit_code", "artifact", "semantics", "claims"}.issubset(
        payload.keys()
    )


def test_claim_with_zero_evaluable_subjects_is_insufficient():
    claim = ClaimVerdict(name="checkpoint.tsa_imprint.v1")

    assert claim.to_dict()["verdict"] == "insufficient_evidence"
