"""An explicitly requested claim that is not supported fails the verification.

3.27.0 appended ``governance_chain.local_continuity.v1`` and
``closure.signature.v1`` with failing verdicts when ``--walk-events`` or
``--verify-closure`` found nothing to verify, yet still reported ``ok: true``
and exit 0 (and ``--raw`` printed success). Every output mode must agree:
a requested, required claim that is not supported is not a successful
verification.
"""

from __future__ import annotations

import json

from conftest import (
    audit_bundle,
    keypair,
    linear_entries,
    signed_closure_v2,
    write_combined_key_manifest,
    write_signed_export,
)


def _records_only_bundle() -> dict:
    # What a compliance export without ?include_chain_entries=true carries.
    return {
        "bundle_type": "audit_export_bundle",
        "schema_version": 1,
        "records": [{"permit": {"id": "permit_123"}}],
    }


def _export(tmp_path, bundle):
    export_private, export_public, export_key_id = keypair()
    _binding_private, binding_public, _ = keypair()
    key_manifest = write_combined_key_manifest(
        tmp_path,
        export_public_key=export_public,
        export_key_id=export_key_id,
        binding_public_key=binding_public,
    )
    export_file, manifest = write_signed_export(
        tmp_path,
        bundle,
        export_private_key=export_private,
        export_public_key=export_public,
        export_key_id=export_key_id,
    )
    return export_file, manifest, key_manifest


def _json_report(run_cli, *args):
    result = run_cli("export", "--json", *args)
    return result, json.loads(result.stdout)


def _claim(report, name):
    return next(claim for claim in report["claims"] if claim["name"] == name)


def test_unrequested_walk_leaves_a_records_only_export_verified(tmp_path, run_cli):
    export_file, manifest, key_manifest = _export(tmp_path, _records_only_bundle())

    result, report = _json_report(
        run_cli, str(export_file), str(manifest), "--key-manifest", str(key_manifest)
    )

    assert result.returncode == 0, result.stderr
    assert report["ok"] is True


def test_requested_walk_without_chain_entries_fails(tmp_path, run_cli):
    export_file, manifest, key_manifest = _export(tmp_path, _records_only_bundle())

    result, report = _json_report(
        run_cli,
        str(export_file),
        str(manifest),
        "--key-manifest",
        str(key_manifest),
        "--walk-events",
    )

    assert result.returncode == 1
    assert report["ok"] is False
    assert report["exit_code"] == 1
    assert "governance_chain.local_continuity.v1" in report["error"]
    walk = _claim(report, "governance_chain.local_continuity.v1")
    assert walk["verdict"] == "unverifiable_scope"
    assert walk["reason_code"] == "WALK_NO_CHAIN_ENTRIES"


def test_requested_closure_without_chain_entries_fails(tmp_path, run_cli):
    export_file, manifest, key_manifest = _export(tmp_path, _records_only_bundle())

    result, report = _json_report(
        run_cli,
        str(export_file),
        str(manifest),
        "--key-manifest",
        str(key_manifest),
        "--verify-closure",
    )

    assert result.returncode == 1
    assert report["ok"] is False
    closure = _claim(report, "closure.signature.v1")
    assert closure["verdict"] == "unverifiable_scope"
    assert closure["reason_code"] == "CLOSURE_NO_CHAIN_ENTRIES"


def test_requested_closure_with_no_closed_permit_fails(tmp_path, run_cli):
    entries = linear_entries([("permit.issued", {"permit_id": "permit_123"})])
    export_file, manifest, key_manifest = _export(tmp_path, audit_bundle(entries))

    result, report = _json_report(
        run_cli,
        str(export_file),
        str(manifest),
        "--key-manifest",
        str(key_manifest),
        "--walk-events",
        "--verify-closure",
    )

    assert result.returncode == 1
    assert report["ok"] is False
    assert _claim(report, "governance_chain.local_continuity.v1")["verdict"] == "supported"
    closure = _claim(report, "closure.signature.v1")
    assert closure["verdict"] == "insufficient_evidence"
    assert closure["reason_code"] == "CLOSURE_NO_EVALUABLE_SUBJECTS"


def test_requested_walk_and_closure_succeed_when_supported(tmp_path, run_cli):
    export_private, export_public, export_key_id = keypair()
    binding_private, binding_public, _ = keypair()
    key_manifest = write_combined_key_manifest(
        tmp_path,
        export_public_key=export_public,
        export_key_id=export_key_id,
        binding_public_key=binding_public,
    )
    dispatch_digest = "c" * 64
    provider_digest = "a" * 64
    client_digest = "b" * 64
    closure = signed_closure_v2(
        binding_private,
        public_key=binding_public,
        dispatch_digest=dispatch_digest,
        provider_digest=provider_digest,
        client_digest=client_digest,
    )
    entries = linear_entries(
        [
            (
                "provider.response.received",
                {"permit_id": "permit_123", "provider_response_digest_v1": provider_digest},
            ),
            (
                "client.response.delivered",
                {"permit_id": "permit_123", "client_response_digest_v1": client_digest},
            ),
            ("permit.closed", closure),
        ]
    )
    export_file, manifest = write_signed_export(
        tmp_path,
        audit_bundle(entries, binding_request_hash=dispatch_digest),
        export_private_key=export_private,
        export_public_key=export_public,
        export_key_id=export_key_id,
    )

    result, report = _json_report(
        run_cli,
        str(export_file),
        str(manifest),
        "--key-manifest",
        str(key_manifest),
        "--walk-events",
        "--verify-closure",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert report["ok"] is True
    for name in (
        "governance_chain.local_continuity.v1",
        "closure.signature.v1",
        "closure.digest_consistency.v1",
        "closure.dispatch_binding.v1",
    ):
        assert _claim(report, name)["verdict"] == "supported", name


def test_raw_and_report_modes_agree_with_json(tmp_path, run_cli):
    export_file, manifest, key_manifest = _export(tmp_path, _records_only_bundle())
    common = [str(export_file), str(manifest), "--key-manifest", str(key_manifest)]

    raw = run_cli("export", "--raw", *common, "--walk-events", "--verify-closure")
    report = run_cli("export", *common, "--walk-events", "--verify-closure")

    assert raw.returncode == 1
    assert "FAILED: WALK_NO_CHAIN_ENTRIES" in raw.stderr
    assert report.returncode == 1
