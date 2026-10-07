"""Public export CLI keeps Work termination distinct from execution closure."""

import base64
import json
import pytest
from conftest import keypair, write_signed_export, write_combined_key_manifest
from keel_verifier import verifier

PROJECT = "11111111-1111-4111-8111-111111111111"
ROOT = "22222222-2222-4222-8222-222222222222"
ACTOR = "33333333-3333-4333-8333-333333333333"


def fixture(tmp_path, defect=None):
    export_private, export_public, export_id = keypair()
    private, public, _ = keypair()
    unsigned = {
        "version": "keel.work_authority_ended.v1",
        "project_id": PROJECT,
        "root_permit_id": ROOT,
        "actor_id": ACTOR,
        "actor_kind": "api_key",
        "reason_code": "customer_requested",
        "close_request_hash": "sha256:" + "a" * 64,
        "ended_at": "2026-05-07T12:00:00Z",
        "released_reservation_count": 1,
        "asserts_business_job_completed": False,
        "binding_key_id": verifier._binding_key_id_from_public_key(public),
    }
    digest = verifier._compute_canonical_binding_hash(unsigned)
    signed = {
        **unsigned,
        "canonical_hash": digest,
        "signature": "ed25519:" + base64.b64encode(private.sign(digest.encode())).decode(),
    }
    if defect == "tamper":
        signed["released_reservation_count"] = 2
    if defect == "wrong_root":
        signed["root_permit_id"] = ACTOR
    if defect == "wrong_project":
        signed["project_id"] = ACTOR
    if defect == "missing_signature":
        signed.pop("signature")
    if defect == "effect_claim":
        signed["asserts_business_job_completed"] = True
    if defect == "wrong_time":
        signed["ended_at"] = "2099-01-01T00:00:00Z"
    if defect == "extra_field":
        signed["provider_execution"] = True
    entry = {
        "event_id": "evt_end",
        "event_type": "permit.closed",
        "permit_id": ROOT,
        "chain_scope": "project:" + PROJECT,
        "created_at": "2026-05-07T12:00:00Z",
        "payload_json": {"closure_status": "authority_ended", "work_authority_ended_event": signed},
    }
    bundle = {
        "bundle_type": "audit_export_bundle",
        "schema_version": 2,
        "include_chain_entries": True,
        "records": [{"permit": {"id": ROOT}, "chain_entries": [entry]}],
    }
    export, manifest = write_signed_export(
        tmp_path,
        bundle,
        export_private_key=export_private,
        export_public_key=export_public,
        export_key_id=export_id,
    )
    keys = write_combined_key_manifest(
        tmp_path,
        export_public_key=export_public,
        export_key_id=export_id,
        binding_public_key=public,
    )
    return export, manifest, keys


def test_authority_end_authenticates_without_execution_closure_claim(tmp_path, run_cli):
    export, manifest, keys = fixture(tmp_path)
    raw = run_cli(
        "export",
        str(export),
        str(manifest),
        "--key-manifest",
        str(keys),
        "--offline",
        "--verify-closure",
        "--raw",
    )
    assert raw.returncode != 0
    assert "CLOSURE_NO_EVALUABLE_SUBJECTS" in raw.stderr
    assert "closures_verified:   0" in raw.stdout
    assert "authority_lifecycles_verified: 1" in raw.stdout
    report = run_cli(
        "export",
        str(export),
        str(manifest),
        "--key-manifest",
        str(keys),
        "--offline",
        "--verify-closure",
        "--json",
    )
    assert report.returncode != 0
    claims = json.loads(report.stdout)["claims"]
    closure = next(c for c in claims if c["name"] == "closure.signature.v1")
    assert closure["verdict"] == "insufficient_evidence"
    assert closure["reason_code"] == "CLOSURE_NO_EVALUABLE_SUBJECTS"


@pytest.mark.parametrize(
    "defect",
    [
        "tamper",
        "wrong_root",
        "wrong_project",
        "missing_signature",
        "effect_claim",
        "wrong_time",
        "extra_field",
    ],
)
def test_authority_end_refuses_invalid_signed_lifecycle(tmp_path, run_cli, defect):
    export, manifest, keys = fixture(tmp_path, defect)
    result = run_cli(
        "export",
        str(export),
        str(manifest),
        "--key-manifest",
        str(keys),
        "--offline",
        "--verify-closure",
        "--raw",
    )
    assert result.returncode != 0
    assert "WALK_UNKNOWN_CLOSURE_FORMAT" in result.stderr
