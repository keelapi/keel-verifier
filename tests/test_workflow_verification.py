from __future__ import annotations

import base64
import io
import json
from datetime import datetime, timezone
import zipfile

from conftest import (
    content_hash,
    keypair,
    signed_workflow_amendment,
    signed_workflow_declaration,
    workflow_effective_intent_hash,
    workflow_evidence_document,
    write_combined_key_manifest,
    write_json,
    write_signed_export,
    write_signed_payload,
)


def _workflow_fixture(tmp_path, *, with_amendment: bool = True):
    export_private, export_public, export_key_id = keypair()
    binding_private, binding_public, _binding_key_id = keypair()
    key_manifest = write_combined_key_manifest(
        tmp_path,
        export_public_key=export_public,
        export_key_id=export_key_id,
        binding_public_key=binding_public,
    )
    declaration = signed_workflow_declaration(
        binding_private,
        public_key=binding_public,
        version=2 if with_amendment else 1,
    )
    amendments = []
    if with_amendment:
        amendments.append(
            signed_workflow_amendment(
                binding_private,
                public_key=binding_public,
            )
        )
    document = workflow_evidence_document([declaration], amendments)
    return {
        "export_private": export_private,
        "export_public": export_public,
        "export_key_id": export_key_id,
        "binding_private": binding_private,
        "binding_public": binding_public,
        "key_manifest": key_manifest,
        "declaration": declaration,
        "amendments": amendments,
        "document": document,
    }


def _write_workflow_sibling(tmp_path, fixture, workflow_document):
    payload = (
        json.dumps(workflow_document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    workflow_path = tmp_path / "workflow_evidence.json"
    workflow_path.write_bytes(payload)
    workflow_digest = content_hash(payload)
    workflow_signature = base64.b64encode(
        fixture["export_private"].sign(workflow_digest.encode("utf-8"))
    ).decode("ascii")
    return workflow_path, {
        "schema": "keel.vanta.workflow_evidence/v1",
        "workflow_evidence_file": str(workflow_path),
        "workflow_evidence": {
            "file_name": "workflow_evidence.json",
            "content_hash": workflow_digest,
            "signature": f"ed25519:{workflow_signature}",
            "public_key": fixture["export_public"],
            "key_id": fixture["export_key_id"],
            "signed_at": "2026-05-07T12:10:00Z",
            "declaration_count": workflow_document["declaration_count"],
            "amendment_count": workflow_document["amendment_count"],
        },
    }


def test_vanta_workflow_sibling_and_permit_snapshot_verify_clean(tmp_path, run_cli):
    fixture = _workflow_fixture(tmp_path)
    declaration = fixture["declaration"]
    amendments = fixture["amendments"]
    permit_created_at = "2026-05-07T12:06:00+00:00"
    expected_hash = workflow_effective_intent_hash(
        declaration,
        amendments,
        before_created_at=permit_created_at,
    )
    export_file, manifest = write_signed_export(
        tmp_path,
        {
            "schema": "keel.vanta.evidence/v1",
            "records": [
                {
                    "permit_id": "permit_123",
                    "decision": "allow",
                    "timestamp": permit_created_at,
                    "workflow_state_json": {
                        "workflow_id": declaration["workflow_id"],
                        "workflow_declaration_id": declaration[
                            "workflow_declaration_id"
                        ],
                        "effective_intent_hash": expected_hash,
                        "declaration_version_at_decision": 2,
                        "actual_calls_at_decision": 1,
                    },
                }
            ],
        },
        export_private_key=fixture["export_private"],
        export_public_key=fixture["export_public"],
        export_key_id=fixture["export_key_id"],
    )
    _workflow_path, sibling = _write_workflow_sibling(
        tmp_path,
        fixture,
        fixture["document"],
    )
    manifest_doc = json.loads(manifest.read_text(encoding="utf-8"))
    manifest_doc["sibling_artifacts"] = {"workflow_evidence": sibling}
    write_json(manifest, manifest_doc)

    result = run_cli(
        "export",
        str(export_file),
        str(manifest),
        "--key-manifest",
        str(fixture["key_manifest"]),
    )

    assert result.returncode == 0, result.stderr
    assert "WORKFLOW-EVIDENCE: VERIFIED" in result.stdout
    assert "workflow_state_json checks: 1 PASS" in result.stdout


def test_workflow_declaration_signature_tamper_fails(tmp_path, run_cli):
    fixture = _workflow_fixture(tmp_path, with_amendment=False)
    document = fixture["document"]
    document["declarations"][0]["declaration_signature_b64"] = "A" * 88
    export_file, manifest = write_signed_export(
        tmp_path,
        document,
        export_private_key=fixture["export_private"],
        export_public_key=fixture["export_public"],
        export_key_id=fixture["export_key_id"],
    )

    result = run_cli(
        "export",
        str(export_file),
        str(manifest),
        "--key-manifest",
        str(fixture["key_manifest"]),
    )

    assert result.returncode == 1
    assert "WORKFLOW_SIGNATURE_INVALID" in result.stderr


def test_workflow_amendment_order_tamper_fails(tmp_path, run_cli):
    fixture = _workflow_fixture(tmp_path, with_amendment=False)
    declaration = fixture["declaration"]
    declaration["version"] = 3
    first = signed_workflow_amendment(
        fixture["binding_private"],
        public_key=fixture["binding_public"],
        workflow_amendment_id="30000000-0000-0000-0000-000000000001",
        applied_against_version=1,
        created_at=datetime(2026, 5, 7, 12, 5, 0, tzinfo=timezone.utc),
    )
    second = signed_workflow_amendment(
        fixture["binding_private"],
        public_key=fixture["binding_public"],
        workflow_amendment_id="30000000-0000-0000-0000-000000000002",
        applied_against_version=2,
        previous_max_calls=7,
        new_max_calls=9,
        previous_expected_calls=4,
        new_expected_calls=6,
        created_at=datetime(2026, 5, 7, 12, 10, 0, tzinfo=timezone.utc),
    )
    document = workflow_evidence_document([declaration], [first, second])
    document["amendments"] = [second, first]
    export_file, manifest = write_signed_export(
        tmp_path,
        document,
        export_private_key=fixture["export_private"],
        export_public_key=fixture["export_public"],
        export_key_id=fixture["export_key_id"],
    )

    result = run_cli(
        "export",
        str(export_file),
        str(manifest),
        "--key-manifest",
        str(fixture["key_manifest"]),
    )

    assert result.returncode == 1
    assert "WORKFLOW_AMENDMENT_ORDER_INVALID" in result.stderr


def test_workflow_amendment_signature_tamper_fails(tmp_path, run_cli):
    fixture = _workflow_fixture(tmp_path)
    fixture["document"]["amendments"][0]["amendment_signature_b64"] = "A" * 88
    export_file, manifest = write_signed_export(
        tmp_path,
        fixture["document"],
        export_private_key=fixture["export_private"],
        export_public_key=fixture["export_public"],
        export_key_id=fixture["export_key_id"],
    )

    result = run_cli(
        "export",
        str(export_file),
        str(manifest),
        "--key-manifest",
        str(fixture["key_manifest"]),
    )

    assert result.returncode == 1
    assert "WORKFLOW_SIGNATURE_INVALID" in result.stderr


def test_permit_effective_intent_hash_mismatch_fails(tmp_path, run_cli):
    fixture = _workflow_fixture(tmp_path)
    declaration = fixture["declaration"]
    export_file, manifest = write_signed_export(
        tmp_path,
        {
            "schema": "keel.vanta.evidence/v1",
            "records": [
                {
                    "permit_id": "permit_123",
                    "decision": "allow",
                    "timestamp": "2026-05-07T12:06:00+00:00",
                    "workflow_state_json": {
                        "workflow_id": declaration["workflow_id"],
                        "workflow_declaration_id": declaration[
                            "workflow_declaration_id"
                        ],
                        "effective_intent_hash": "0" * 64,
                        "declaration_version_at_decision": 2,
                        "actual_calls_at_decision": 1,
                    },
                }
            ],
        },
        export_private_key=fixture["export_private"],
        export_public_key=fixture["export_public"],
        export_key_id=fixture["export_key_id"],
    )
    _workflow_path, sibling = _write_workflow_sibling(
        tmp_path,
        fixture,
        fixture["document"],
    )
    manifest_doc = json.loads(manifest.read_text(encoding="utf-8"))
    manifest_doc["sibling_artifacts"] = {"workflow_evidence": sibling}
    write_json(manifest, manifest_doc)

    result = run_cli(
        "export",
        str(export_file),
        str(manifest),
        "--key-manifest",
        str(fixture["key_manifest"]),
    )

    assert result.returncode == 1
    assert "WORKFLOW_EFFECTIVE_INTENT_HASH_MISMATCH" in result.stderr


def test_incident_manifest_v2_with_workflows_verifies(tmp_path, run_cli):
    fixture = _workflow_fixture(tmp_path)
    declaration = fixture["declaration"]
    amendments = fixture["amendments"]
    permit_created_at = "2026-05-07T12:06:00+00:00"
    expected_hash = workflow_effective_intent_hash(
        declaration,
        amendments,
        before_created_at=permit_created_at,
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr(
            "permits.jsonl",
            json.dumps(
                {
                    "id": "permit_123",
                    "created_at": permit_created_at,
                    "decision": "allow",
                    "workflow_state_json": {
                        "workflow_id": declaration["workflow_id"],
                        "workflow_declaration_id": declaration[
                            "workflow_declaration_id"
                        ],
                        "effective_intent_hash": expected_hash,
                        "declaration_version_at_decision": 2,
                    },
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
        )
        zip_file.writestr(
            "workflow_declarations.jsonl",
            json.dumps(declaration, sort_keys=True, separators=(",", ":")) + "\n",
        )
        zip_file.writestr(
            "workflow_amendments.jsonl",
            json.dumps(amendments[0], sort_keys=True, separators=(",", ":")) + "\n",
        )
        zip_file.writestr("governance_events.jsonl", "")
        zip_file.writestr("admin_actions.jsonl", "")
        zip_file.writestr("bracket_checkpoints.json", "{}")
        zip_file.writestr(
            "incident_metadata.json",
            json.dumps(
                {"schema": "keel.incident_evidence/v1", "record_counts": {}},
                sort_keys=True,
                separators=(",", ":"),
            ),
        )
        zip_file.writestr("mcp_tool_decisions.jsonl", "")
    export_file, manifest = write_signed_payload(
        tmp_path,
        "incident.zip",
        buffer.getvalue(),
        export_private_key=fixture["export_private"],
        export_public_key=fixture["export_public"],
        export_key_id=fixture["export_key_id"],
        manifest_extra={
            "export_type": "incident_evidence",
            "manifest_version": 2,
            "files": [
                {"name": "admin_actions.jsonl", "schema": "keel.admin_actions/v1"},
                {
                    "name": "bracket_checkpoints.json",
                    "schema": "keel.bracket_checkpoints/v1",
                },
                {
                    "name": "governance_events.jsonl",
                    "schema": "keel.governance_events/v1",
                },
                {
                    "name": "incident_metadata.json",
                    "schema": "keel.incident_metadata/v1",
                },
                {"name": "permits.jsonl", "schema": "keel.permits/v1"},
                {
                    "name": "workflow_declarations.jsonl",
                    "schema": "keel.workflow_declarations/v1",
                },
                {
                    "name": "workflow_amendments.jsonl",
                    "schema": "keel.workflow_amendments/v1",
                },
                {
                    "name": "mcp_tool_decisions.jsonl",
                    "schema": "keel.mcp_tool_decisions/v1",
                },
            ],
        },
    )

    result = run_cli(
        "export",
        str(export_file),
        str(manifest),
        "--key-manifest",
        str(fixture["key_manifest"]),
    )

    assert result.returncode == 0, result.stderr
    assert "INCIDENT-BUNDLE: VERIFIED" in result.stdout


def test_incident_manifest_v2_missing_auxiliary_files_fails(tmp_path, run_cli):
    fixture = _workflow_fixture(tmp_path)
    declaration = fixture["declaration"]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr("permits.jsonl", "")
        zip_file.writestr(
            "workflow_declarations.jsonl",
            json.dumps(declaration, sort_keys=True, separators=(",", ":")) + "\n",
        )
        zip_file.writestr("workflow_amendments.jsonl", "")
    export_file, manifest = write_signed_payload(
        tmp_path,
        "incident.zip",
        buffer.getvalue(),
        export_private_key=fixture["export_private"],
        export_public_key=fixture["export_public"],
        export_key_id=fixture["export_key_id"],
        manifest_extra={
            "export_type": "incident_evidence",
            "manifest_version": 2,
            "files": [
                {"name": "permits.jsonl", "schema": "keel.permits/v1"},
                {
                    "name": "workflow_declarations.jsonl",
                    "schema": "keel.workflow_declarations/v1",
                },
                {
                    "name": "workflow_amendments.jsonl",
                    "schema": "keel.workflow_amendments/v1",
                },
            ],
        },
    )

    result = run_cli(
        "export",
        str(export_file),
        str(manifest),
        "--key-manifest",
        str(fixture["key_manifest"]),
    )

    assert result.returncode == 1
    assert "INCIDENT_MANIFEST_SCHEMA_INVALID" in result.stderr
    assert "admin_actions.jsonl" in result.stderr


def test_incident_manifest_v1_without_workflows_still_verifies(tmp_path, run_cli):
    fixture = _workflow_fixture(tmp_path, with_amendment=False)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr("governance_events.jsonl", "")
        zip_file.writestr("permits.jsonl", "")
        zip_file.writestr("admin_actions.jsonl", "")
        zip_file.writestr("bracket_checkpoints.json", "{}")
        zip_file.writestr("incident_metadata.json", "{}")
    export_file, manifest = write_signed_payload(
        tmp_path,
        "incident.zip",
        buffer.getvalue(),
        export_private_key=fixture["export_private"],
        export_public_key=fixture["export_public"],
        export_key_id=fixture["export_key_id"],
        manifest_extra={
            "export_type": "incident_evidence",
            "manifest_version": 1,
            "files": [
                {"name": "permits.jsonl", "schema": "keel.permits/v1"},
            ],
        },
    )

    result = run_cli(
        "export",
        str(export_file),
        str(manifest),
        "--key-manifest",
        str(fixture["key_manifest"]),
    )

    assert result.returncode == 0, result.stderr
    assert "VERIFIED" in result.stdout
    assert "INCIDENT-BUNDLE" not in result.stdout


def test_incident_unknown_manifest_version_fails_gracefully(tmp_path, run_cli):
    fixture = _workflow_fixture(tmp_path, with_amendment=False)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr("permits.jsonl", "")
    export_file, manifest = write_signed_payload(
        tmp_path,
        "incident.zip",
        buffer.getvalue(),
        export_private_key=fixture["export_private"],
        export_public_key=fixture["export_public"],
        export_key_id=fixture["export_key_id"],
        manifest_extra={
            "export_type": "incident_evidence",
            "manifest_version": 3,
            "files": [],
        },
    )

    result = run_cli(
        "export",
        str(export_file),
        str(manifest),
        "--key-manifest",
        str(fixture["key_manifest"]),
    )

    assert result.returncode == 1
    assert "INCIDENT_UNKNOWN_MANIFEST_VERSION" in result.stderr
