from __future__ import annotations

import gzip
import json

from conftest import (
    audit_bundle,
    keypair,
    linear_entries,
    write_signed_export,
    write_signed_payload,
)


def test_walk_events_verifies_clean_bundle(tmp_path, run_cli):
    export_private, export_public, export_key_id = keypair()
    entries = linear_entries(
        [
            ("permit.created", {"permit_id": "permit_123"}),
            (
                "provider.response.received",
                {
                    "permit_id": "permit_123",
                    "provider_response_digest_v1": "a" * 64,
                },
            ),
        ]
    )
    export_file, manifest = write_signed_export(
        tmp_path,
        audit_bundle(entries),
        export_private_key=export_private,
        export_public_key=export_public,
        export_key_id=export_key_id,
    )

    result = run_cli(
        "export",
        str(export_file),
        str(manifest),
        "--self-attested",
        "--walk-events",
    )

    assert result.returncode == 0, result.stderr
    assert "WALK-EVENTS: VERIFIED" in result.stdout
    assert "record_hash_checks:  2 PASS" in result.stdout


def test_walk_events_verifies_direct_governance_events_json_jsonl_and_gzip(tmp_path, run_cli):
    export_private, export_public, export_key_id = keypair()
    entries = linear_entries(
        [
            ("permit.created", {"permit_id": "permit_123"}),
            ("dispatch.egress_bound", {"permit_id": "permit_123"}),
        ]
    )
    document = {
        "schema": "keel.governance_events/v1",
        "project_id": "00000000-0000-0000-0000-000000000001",
        "record_count": len(entries),
        "records": entries,
    }

    json_dir = tmp_path / "json"
    jsonl_dir = tmp_path / "jsonl"
    gzip_dir = tmp_path / "gzip"
    json_dir.mkdir()
    jsonl_dir.mkdir()
    gzip_dir.mkdir()

    json_export, json_manifest = write_signed_export(
        json_dir,
        document,
        export_private_key=export_private,
        export_public_key=export_public,
        export_key_id=export_key_id,
    )
    jsonl_payload = (
        "\n".join(json.dumps(entry, sort_keys=True, separators=(",", ":")) for entry in entries)
        + "\n"
    ).encode("utf-8")
    jsonl_export, jsonl_manifest = write_signed_payload(
        jsonl_dir,
        "events.jsonl",
        jsonl_payload,
        export_private_key=export_private,
        export_public_key=export_public,
        export_key_id=export_key_id,
    )
    gzip_export, gzip_manifest = write_signed_payload(
        gzip_dir,
        "events.jsonl.gz",
        gzip.compress(jsonl_payload),
        export_private_key=export_private,
        export_public_key=export_public,
        export_key_id=export_key_id,
    )

    for export_file, manifest in (
        (json_export, json_manifest),
        (jsonl_export, jsonl_manifest),
        (gzip_export, gzip_manifest),
    ):
        result = run_cli(
            "export",
            str(export_file),
            str(manifest),
            "--self-attested",
            "--walk-events",
        )

        assert result.returncode == 0, result.stderr
        assert "WALK-EVENTS: VERIFIED" in result.stdout
        assert "entries_walked:      2" in result.stdout


def test_walk_events_verifies_bundle_level_chain_entries(tmp_path, run_cli):
    export_private, export_public, export_key_id = keypair()
    entries = linear_entries(
        [
            ("permit.created", {"permit_id": "permit_123"}),
            ("dispatch.egress_bound", {"permit_id": "permit_123"}),
        ]
    )
    bundle = audit_bundle(entries)
    bundle["chain_entries"] = bundle["records"][0].pop("chain_entries")

    export_file, manifest = write_signed_export(
        tmp_path,
        bundle,
        export_private_key=export_private,
        export_public_key=export_public,
        export_key_id=export_key_id,
    )

    result = run_cli(
        "export",
        str(export_file),
        str(manifest),
        "--self-attested",
        "--walk-events",
    )

    assert result.returncode == 0, result.stderr
    assert "WALK-EVENTS: VERIFIED" in result.stdout
    assert "entries_walked:      2" in result.stdout


def test_walk_events_detects_array_reorder_inversion(tmp_path, run_cli):
    """Reordering chain entries in JSON array order must fail before sorting."""
    export_private, export_public, export_key_id = keypair()
    entries = linear_entries(
        [
            ("permit.created", {"permit_id": "permit_123"}),
            ("dispatch.egress_bound", {"permit_id": "permit_123"}),
            ("provider.response.received", {"permit_id": "permit_123"}),
        ]
    )
    entries[1], entries[2] = entries[2], entries[1]
    export_file, manifest = write_signed_export(
        tmp_path,
        audit_bundle(entries),
        export_private_key=export_private,
        export_public_key=export_public,
        export_key_id=export_key_id,
    )

    result = run_cli(
        "export",
        str(export_file),
        str(manifest),
        "--self-attested",
        "--walk-events",
    )

    assert result.returncode == 1
    assert "WALK_SEQUENCE_INVERSION" in result.stderr
    assert entries[0]["event_id"] not in result.stderr
    assert entries[1]["event_id"] in result.stderr
    assert entries[2]["event_id"] in result.stderr


def test_walk_events_detects_duplicate_sequence_number(tmp_path, run_cli):
    export_private, export_public, export_key_id = keypair()
    entries = linear_entries(
        [
            ("permit.created", {"permit_id": "permit_123"}),
            ("dispatch.egress_bound", {"permit_id": "permit_123"}),
            ("provider.response.received", {"permit_id": "permit_123"}),
        ]
    )
    entries[2]["sequence_number"] = 2
    export_file, manifest = write_signed_export(
        tmp_path,
        audit_bundle(entries),
        export_private_key=export_private,
        export_public_key=export_public,
        export_key_id=export_key_id,
    )

    result = run_cli(
        "export",
        str(export_file),
        str(manifest),
        "--self-attested",
        "--walk-events",
    )

    assert result.returncode == 1
    assert "WALK_SEQUENCE_INVERSION" in result.stderr
    assert "duplicate_sequence_number=2" in result.stderr


def test_walk_events_detects_record_hash_tampering(tmp_path, run_cli):
    export_private, export_public, export_key_id = keypair()
    entries = linear_entries(
        [
            ("permit.created", {"permit_id": "permit_123"}),
            (
                "provider.response.received",
                {
                    "permit_id": "permit_123",
                    "provider_response_digest_v1": "a" * 64,
                },
            ),
        ]
    )
    entries[1]["event_type"] = "provider.response.mutated"
    export_file, manifest = write_signed_export(
        tmp_path,
        audit_bundle(entries),
        export_private_key=export_private,
        export_public_key=export_public,
        export_key_id=export_key_id,
    )

    result = run_cli(
        "export",
        str(export_file),
        str(manifest),
        "--self-attested",
        "--walk-events",
    )

    assert result.returncode == 1
    assert "WALK_RECORD_HASH_MISMATCH" in result.stderr
