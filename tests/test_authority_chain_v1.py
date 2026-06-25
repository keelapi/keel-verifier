from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

import pytest

from conftest import keypair, write_json, write_signed_export
from keel_verifier import semantics
from keel_verifier.verdicts import verifier_version
from keel_verifier.verifier import (
    _adjudicate_authority_root_status_temporal_v1,
    _adjudicate_authority_revocation_temporal_v1,
    _adjudicate_permit_authority_chain_v1,
    _authority_chain_payload_for_edges,
    _authority_rfc8785_bytes,
    _authority_sha256_hex,
    _root_status_canonical_hash,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PRODUCT_ROOT = REPO_ROOT.parent
DEFAULT_CAT09_ROOT = (
    PRODUCT_ROOT
    / ".worktrees"
    / "keel-permit-authority-edges"
    / "test-vectors"
    / "vectors"
    / "cat-09-authority-edges"
)


def _cat09_root() -> Path:
    env_root = os.getenv("KEEL_PERMIT_CAT09_ROOT")
    root = Path(env_root).expanduser() if env_root else DEFAULT_CAT09_ROOT
    if not root.exists():
        message = (
            "cat-09 authority corpus is not checked out at "
            f"{root}; set KEEL_PERMIT_CAT09_ROOT to run this local corpus test"
        )
        if os.getenv("KEEL_REQUIRE_GOLDEN_CORPUS"):
            raise FileNotFoundError(message)
        pytest.skip(message)
    return root


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _fixture_dirs(root: Path) -> list[Path]:
    return sorted(path for path in root.iterdir() if path.is_dir() and path.name.startswith("09-"))


def _adjudicate(input_doc: dict[str, Any], trust_root: dict[str, Any]):
    claim_name = input_doc["claim"]["name"]
    if claim_name == "permit.authority_chain.v1":
        return _adjudicate_permit_authority_chain_v1(
            export_document=input_doc,
            trust_root=trust_root,
        )
    if claim_name == "authority.revocation_temporal.v1":
        return _adjudicate_authority_revocation_temporal_v1(
            export_document=input_doc,
            trust_root=trust_root,
        )
    if claim_name == "authority.root_status_temporal.v1":
        return _adjudicate_authority_root_status_temporal_v1(
            export_document=input_doc,
            trust_root=trust_root,
        )
    raise AssertionError(f"unexpected claim in cat-09 fixture: {claim_name}")


def _claim_for_fixture(fixture_id: str):
    root = _cat09_root()
    fixture_dir = next(path for path in _fixture_dirs(root) if path.name.startswith(fixture_id))
    trust_root = _load_json(root / "trust-root.json")
    return (
        _adjudicate(_load_json(fixture_dir / "input.json"), trust_root),
        _load_json(fixture_dir / "expected.json"),
    )


def _semantic_ref(artifact_id: str) -> dict[str, str]:
    return {
        "id": artifact_id,
        "hash": semantics.RELEASED_ARTIFACT_HASHES[artifact_id],
        "path": semantics.RELEASED_ARTIFACT_PATHS[artifact_id],
    }


def _add_authority_pins(manifest_path: Path) -> None:
    manifest = _load_json(manifest_path)
    manifest["claim_set"] = {
        "version": semantics.CLAIM_REGISTRY_VERSION,
        "registry": _semantic_ref(semantics.CLAIM_REGISTRY_ID),
        "claims": [
            {"name": "export.integrity.v1", "required": True},
            {"name": "permit.authority_chain.v1", "required": True},
            {"name": "authority.revocation_temporal.v1", "required": True},
            {"name": "authority.root_status_temporal.v1", "required": True},
        ],
    }
    manifest["semantics_pins"] = {
        "version": semantics.SEMANTICS_PINS_VERSION,
        "mode": "pinned",
        "artifacts": [
            _semantic_ref(semantics.EXPORT_MANIFEST_INTEGRITY_ID),
            _semantic_ref(semantics.PERMIT_AUTHORITY_CHAIN_ID),
            _semantic_ref(semantics.AUTHORITY_REVOCATION_TEMPORAL_ID),
            _semantic_ref(semantics.AUTHORITY_ROOT_STATUS_TEMPORAL_ID),
        ],
    }
    write_json(manifest_path, manifest)


def _signed_authority_edge(
    *,
    private_key: Any,
    payload: dict[str, Any],
) -> dict[str, Any]:
    payload_bytes = _authority_rfc8785_bytes(payload)
    return {
        "edge_version": "authority_edge.v1",
        "edge_digest": _authority_sha256_hex(payload_bytes),
        "payload": payload,
        "signature": "ed25519:"
        + base64.b64encode(private_key.sign(payload_bytes)).decode("ascii"),
    }


def _signed_root_status_event(
    *,
    private_key: Any,
    export_document: dict[str, Any],
    status: str,
    status_changed_at: str,
    previous_status: str | None = None,
) -> dict[str, Any]:
    root_payload = export_document["authority_edges"][0]["payload"]
    root = root_payload["delegator"]
    event = {
        "project_id": root_payload["project_id"],
        "root_principal_type": root["principal_type"],
        "root_principal_id": root["principal_id"],
        "actor_id": "00000000-0000-0000-0000-000000000000",
        "actor_kind": "system",
        "previous_status": previous_status,
        "status": status,
        "status_changed_at": status_changed_at,
        "effective_at": status_changed_at,
        "last_attested_at": status_changed_at if status == "active" else None,
        "attestation_valid_until": None,
        "suspension_due_at": None,
        "needs_reattestation_at": (
            status_changed_at if status == "needs_reattestation" else None
        ),
        "suspended_at": status_changed_at if status == "suspended" else None,
    }
    canonical_hash = _root_status_canonical_hash(event)
    event["signature"] = base64.b64encode(
        private_key.sign(canonical_hash.encode("utf-8"))
    ).decode("ascii")
    return event


def _supported_authority_export() -> tuple[dict[str, Any], dict[str, Any]]:
    authority_private_key, authority_public_key, authority_key_id = keypair()
    user_id = "user_ci_root"
    agent_id = "agent_ci_leaf"
    project_id = "project_ci"
    edge = _signed_authority_edge(
        private_key=authority_private_key,
        payload={
            "edge_version": "authority_edge.v1",
            "org_id": "org_ci",
            "project_id": project_id,
            "parent_edge_digest": None,
            "delegator": {
                "principal_type": "user",
                "principal_id": user_id,
            },
            "delegate": {
                "principal_type": "agent",
                "principal_id": agent_id,
            },
            "signing_key": {
                "key_id": authority_key_id,
                "custody_tier": "org_key",
            },
            "scope": {
                "action_verbs": ["execute"],
                "action_classes": ["llm.invoke"],
                "resources": {"project_ids": [project_id]},
                "data_classes": ["prompt"],
                "constraints": {},
            },
            "budget_partition": None,
            "creation_policy": {
                "remaining_depth": 0,
                "max_children": 0,
            },
            "validity": {
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-12-31T00:00:00Z",
            },
            "policy_version": "policy_ci_v1",
            "signed_at": "2026-06-01T00:00:00Z",
        },
    )
    chain_payload = _authority_chain_payload_for_edges([edge])
    export_document = {
        "permit": {
            "permit_id": "permit_ci_authority",
            "binding_version": "v7",
            "subject_type": "agent",
            "subject_id": agent_id,
            "authority_chain_digest": _authority_sha256_hex(
                _authority_rfc8785_bytes(chain_payload)
            ),
        },
        "authority_chain": {
            "chain_version": "authority_chain.v1",
            "payload": chain_payload,
        },
        "authority_edges": [edge],
        "resolution_time": "2026-06-01T00:00:00Z",
        "requested_action": {
            "kind": "execute",
        },
        "action_class_map": {
            "execute": ["llm.invoke"],
        },
    }
    trust_root = {
        "keys": [
            {
                "key_id": authority_key_id,
                "algorithm": "ed25519",
                "public_key_bytes": authority_public_key,
                "signer_id": user_id,
                "custody_tier": "org_key",
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": None,
                "revoked_at": None,
                "compromised_at": None,
            }
        ],
    }
    return export_document, trust_root


def _key_manifest_for_authority_export(
    tmp_path: Path,
    *,
    export_public_key: str,
    export_key_id: str,
    trust_root: dict[str, Any],
) -> Path:
    return write_json(
        tmp_path / "keys.json",
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
                    "key_id": export_key_id,
                    "algorithm": "ed25519",
                    "public_key": export_public_key,
                    "purpose": "permit_binding_signing",
                    "status": "active",
                    "valid_from": "2026-01-01T00:00:00Z",
                    "valid_to": None,
                },
                *trust_root["keys"],
            ],
        },
    )


def test_authority_chain_corpus_matches_expected_full_adjudication() -> None:
    root = _cat09_root()
    trust_root = _load_json(root / "trust-root.json")
    fixture_dirs = _fixture_dirs(root)

    assert len(fixture_dirs) == 47

    for fixture_dir in fixture_dirs:
        input_doc = _load_json(fixture_dir / "input.json")
        expected = _load_json(fixture_dir / "expected.json")
        claim = _adjudicate(input_doc, trust_root)

        assert expected["structural_level_only"] is False, fixture_dir.name
        assert expected["adjudication_level"] == "full", fixture_dir.name
        assert claim.aggregate_verdict == expected["expected_verdict"], fixture_dir.name
        if expected["expected_failure_code"] is None:
            assert claim.aggregate_verdict == "supported", fixture_dir.name
        else:
            assert claim.reason_code == expected["expected_failure_code"], fixture_dir.name


def test_cli_full_verify_resolves_authority_claims_from_registry(
    tmp_path: Path,
    run_cli,
) -> None:
    input_doc, trust_root = _supported_authority_export()
    export_private_key, export_public_key, export_key_id = keypair()
    key_manifest = _key_manifest_for_authority_export(
        tmp_path,
        export_public_key=export_public_key,
        export_key_id=export_key_id,
        trust_root=trust_root,
    )
    input_doc["root_status_events"] = [
        _signed_root_status_event(
            private_key=export_private_key,
            export_document=input_doc,
            status="active",
            status_changed_at="2026-05-01T00:00:00Z",
        )
    ]
    export_file, manifest = write_signed_export(
        tmp_path,
        input_doc,
        export_private_key=export_private_key,
        export_public_key=export_public_key,
        export_key_id=export_key_id,
    )
    _add_authority_pins(manifest)

    result = run_cli(
        "export",
        "--json",
        str(export_file),
        str(manifest),
        "--key-manifest",
        str(key_manifest),
        "--offline",
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    claims = {claim["name"]: claim for claim in payload["claims"]}

    assert claims["permit.authority_chain.v1"]["verdict"] == "supported"
    assert claims["permit.authority_chain.v1"]["reason_code"] == (
        "AUTHORITY_CHAIN_SUPPORTED"
    )
    assert claims["authority.revocation_temporal.v1"]["verdict"] == "supported"
    assert claims["authority.revocation_temporal.v1"]["reason_code"] == (
        "AUTHORITY_REVOCATION_TEMPORAL_SUPPORTED"
    )
    assert claims["authority.root_status_temporal.v1"]["verdict"] == "supported"
    assert claims["authority.root_status_temporal.v1"]["reason_code"] == (
        "AUTHORITY_ROOT_STATUS_TEMPORAL_SUPPORTED"
    )


def test_v10_subject_type_conditioning_and_v11_order_are_pinned() -> None:
    agent_null, expected_agent_null = _claim_for_fixture("09-44")
    system_null, expected_system_null = _claim_for_fixture("09-46")
    digest_and_leaf, expected_digest_and_leaf = _claim_for_fixture("09-45")

    assert expected_agent_null["expected_failure_code"] == "authority_chain.agent_without_chain"
    assert agent_null.aggregate_verdict == "insufficient_evidence"
    assert agent_null.reason_code == "authority_chain.agent_without_chain"

    assert expected_system_null["expected_failure_code"] == "authority_chain.typed_absence"
    assert system_null.aggregate_verdict == "unverifiable_scope"
    assert system_null.reason_code == "authority_chain.typed_absence"

    assert expected_digest_and_leaf["expected_failure_code"] == "authority_chain.chain_digest_mismatch"
    assert digest_and_leaf.aggregate_verdict == "disproved"
    assert digest_and_leaf.reason_code == "authority_chain.chain_digest_mismatch"


def test_authority_revocation_temporal_empty_edge_domain_is_insufficient() -> None:
    claim = _adjudicate_authority_revocation_temporal_v1(
        export_document={
            "permit": {"id": "permit_empty_edges"},
            "authority_chain": {"payload": {"edge_digests": []}},
            "authority_edges": [],
        },
        trust_root={"keys": []},
    )

    assert claim.aggregate_verdict == "insufficient_evidence"
    assert claim.reason_code is None
    assert claim.subjects
    assert claim.subjects[0].verdict == "insufficient_evidence"


def test_authority_root_status_temporal_suspended_root_is_disproved(
    tmp_path: Path,
) -> None:
    input_doc, trust_root = _supported_authority_export()
    binding_private_key, binding_public_key, binding_key_id = keypair()
    key_manifest = _key_manifest_for_authority_export(
        tmp_path,
        export_public_key=binding_public_key,
        export_key_id=binding_key_id,
        trust_root=trust_root,
    )
    input_doc["root_status_events"] = [
        _signed_root_status_event(
            private_key=binding_private_key,
            export_document=input_doc,
            status="active",
            status_changed_at="2026-05-01T00:00:00Z",
        ),
        _signed_root_status_event(
            private_key=binding_private_key,
            export_document=input_doc,
            previous_status="active",
            status="suspended",
            status_changed_at="2026-06-01T00:00:00Z",
        ),
    ]

    claim = _adjudicate_authority_root_status_temporal_v1(
        export_document=input_doc,
        key_manifest_source=str(key_manifest),
        trust_root=trust_root,
    )

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "authority_root_status.root_suspended_at_resolution"


def test_authority_root_status_temporal_missing_status_evidence_is_insufficient(
    tmp_path: Path,
) -> None:
    input_doc, trust_root = _supported_authority_export()
    binding_private_key, binding_public_key, binding_key_id = keypair()
    key_manifest = _key_manifest_for_authority_export(
        tmp_path,
        export_public_key=binding_public_key,
        export_key_id=binding_key_id,
        trust_root=trust_root,
    )
    del binding_private_key

    claim = _adjudicate_authority_root_status_temporal_v1(
        export_document=input_doc,
        key_manifest_source=str(key_manifest),
        trust_root=trust_root,
    )

    assert claim.aggregate_verdict == "insufficient_evidence"
    assert claim.reason_code == "authority_root_status.status_evidence_missing"


def test_authority_chain_semantics_pin_scalar_failure_code_verdicts() -> None:
    authority_chain_path = (
        REPO_ROOT
        / "keel_verifier"
        / "data"
        / semantics.RELEASED_ARTIFACT_PATHS[semantics.PERMIT_AUTHORITY_CHAIN_ID]
    )
    revocation_path = (
        REPO_ROOT
        / "keel_verifier"
        / "data"
        / semantics.RELEASED_ARTIFACT_PATHS[semantics.AUTHORITY_REVOCATION_TEMPORAL_ID]
    )
    root_status_path = (
        REPO_ROOT
        / "keel_verifier"
        / "data"
        / semantics.RELEASED_ARTIFACT_PATHS[semantics.AUTHORITY_ROOT_STATUS_TEMPORAL_ID]
    )
    authority_chain = _load_json(authority_chain_path)
    revocation = _load_json(revocation_path)
    root_status = _load_json(root_status_path)

    authority_failures = authority_chain["body"]["failure_codes"]
    revocation_failures = revocation["body"]["failure_codes"]
    root_status_failures = root_status["body"]["failure_codes"]

    assert len(authority_failures) == 25
    assert len(revocation_failures) == 2
    assert len(root_status_failures) == 2
    assert {
        item["code"]: item["verdict"]
        for item in authority_failures
    }["authority_chain.agent_without_chain"] == "insufficient_evidence"
    assert all(isinstance(item["verdict"], str) for item in authority_failures)
    assert all(isinstance(item["verdict"], str) for item in revocation_failures)
    assert all(isinstance(item["verdict"], str) for item in root_status_failures)


def test_authority_chain_verdict_outputs_render_verifier_version() -> None:
    claim, _expected = _claim_for_fixture("09-43")
    payload = claim.to_dict()

    assert payload["verifier_version"] == verifier_version()
    assert payload["reason_code"] == "authority_chain.leaf_subject_mismatch"
    assert payload["subjects"]
    assert all(subject["verifier_version"] == verifier_version() for subject in payload["subjects"])
