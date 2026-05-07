from __future__ import annotations

from conftest import audit_bundle, keypair, linear_entries, write_signed_export


def test_walk_events_verifies_clean_bundle(tmp_path, run_cli):
    export_private, export_public, export_key_id = keypair()
    entries = linear_entries([
        ("permit.created", {"permit_id": "permit_123"}),
        ("provider.response.received", {"permit_id": "permit_123", "provider_response_digest_v1": "a" * 64}),
    ])
    export_file, manifest = write_signed_export(
        tmp_path,
        audit_bundle(entries),
        export_private_key=export_private,
        export_public_key=export_public,
        export_key_id=export_key_id,
    )

    result = run_cli("export", str(export_file), str(manifest), "--self-attested", "--walk-events")

    assert result.returncode == 0, result.stderr
    assert "WALK-EVENTS: VERIFIED" in result.stdout
    assert "record_hash_checks:  2 PASS" in result.stdout


def test_walk_events_detects_record_hash_tampering(tmp_path, run_cli):
    export_private, export_public, export_key_id = keypair()
    entries = linear_entries([
        ("permit.created", {"permit_id": "permit_123"}),
        ("provider.response.received", {"permit_id": "permit_123", "provider_response_digest_v1": "a" * 64}),
    ])
    entries[1]["event_type"] = "provider.response.mutated"
    export_file, manifest = write_signed_export(
        tmp_path,
        audit_bundle(entries),
        export_private_key=export_private,
        export_public_key=export_public,
        export_key_id=export_key_id,
    )

    result = run_cli("export", str(export_file), str(manifest), "--self-attested", "--walk-events")

    assert result.returncode == 1
    assert "WALK_RECORD_HASH_MISMATCH" in result.stderr
