from __future__ import annotations

from conftest import (
    audit_bundle,
    keypair,
    linear_entries,
    signed_closure_v2,
    write_combined_key_manifest,
    write_signed_export,
)


def _closure_bundle(binding_private, binding_public, *, closure_dispatch_digest: str, record_dispatch_digest: str):
    provider_digest = "a" * 64
    client_digest = "b" * 64
    closure = signed_closure_v2(
        binding_private,
        public_key=binding_public,
        dispatch_digest=closure_dispatch_digest,
        provider_digest=provider_digest,
        client_digest=client_digest,
    )
    entries = linear_entries([
        ("provider.response.received", {"permit_id": "permit_123", "provider_response_digest_v1": provider_digest}),
        ("client.response.delivered", {"permit_id": "permit_123", "client_response_digest_v1": client_digest}),
        ("permit.closed", closure),
    ])
    return audit_bundle(entries, binding_request_hash=record_dispatch_digest)


def _closure_bundle_with_execution_completed_alias(
    binding_private,
    binding_public,
    *,
    dispatch_digest: str,
):
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
                "execution.completed",
                {
                    "permit_id": "permit_123",
                    "provider_response_digest_v1": provider_digest,
                    "client_response_digest_v1": client_digest,
                },
            ),
            ("permit.closed", closure),
        ]
    )
    return audit_bundle(entries, binding_request_hash=dispatch_digest)


def test_verify_closure_verifies_clean_closure_v2(tmp_path, run_cli):
    export_private, export_public, export_key_id = keypair()
    binding_private, binding_public, _binding_key_id = keypair()
    key_manifest = write_combined_key_manifest(
        tmp_path,
        export_public_key=export_public,
        export_key_id=export_key_id,
        binding_public_key=binding_public,
    )
    dispatch_digest = "c" * 64
    export_file, manifest = write_signed_export(
        tmp_path,
        _closure_bundle(
            binding_private,
            binding_public,
            closure_dispatch_digest=dispatch_digest,
            record_dispatch_digest=dispatch_digest,
        ),
        export_private_key=export_private,
        export_public_key=export_public,
        export_key_id=export_key_id,
    )

    result = run_cli(
        "export",
        str(export_file),
        str(manifest),
        "--key-manifest",
        str(key_manifest),
        "--walk-events",
        "--verify-closure",
    )

    assert result.returncode == 0, result.stderr
    assert "WALK-EVENTS: VERIFIED" in result.stdout
    assert "VERIFY-CLOSURE: VERIFIED" in result.stdout
    assert "dispatch_digest_check: PASS" in result.stdout


def test_verify_closure_accepts_execution_completed_digest_alias(tmp_path, run_cli):
    export_private, export_public, export_key_id = keypair()
    binding_private, binding_public, _binding_key_id = keypair()
    key_manifest = write_combined_key_manifest(
        tmp_path,
        export_public_key=export_public,
        export_key_id=export_key_id,
        binding_public_key=binding_public,
    )
    dispatch_digest = "c" * 64
    export_file, manifest = write_signed_export(
        tmp_path,
        _closure_bundle_with_execution_completed_alias(
            binding_private,
            binding_public,
            dispatch_digest=dispatch_digest,
        ),
        export_private_key=export_private,
        export_public_key=export_public,
        export_key_id=export_key_id,
    )

    result = run_cli(
        "export",
        str(export_file),
        str(manifest),
        "--key-manifest",
        str(key_manifest),
        "--verify-closure",
    )

    assert result.returncode == 0, result.stderr
    assert "VERIFY-CLOSURE: VERIFIED" in result.stdout


def test_verify_closure_detects_dispatch_digest_mismatch(tmp_path, run_cli):
    export_private, export_public, export_key_id = keypair()
    binding_private, binding_public, _binding_key_id = keypair()
    key_manifest = write_combined_key_manifest(
        tmp_path,
        export_public_key=export_public,
        export_key_id=export_key_id,
        binding_public_key=binding_public,
    )
    export_file, manifest = write_signed_export(
        tmp_path,
        _closure_bundle(
            binding_private,
            binding_public,
            closure_dispatch_digest="d" * 64,
            record_dispatch_digest="c" * 64,
        ),
        export_private_key=export_private,
        export_public_key=export_public,
        export_key_id=export_key_id,
    )

    result = run_cli(
        "export",
        str(export_file),
        str(manifest),
        "--key-manifest",
        str(key_manifest),
        "--verify-closure",
    )

    assert result.returncode == 1
    assert "WALK_CLOSURE_DISPATCH_DIGEST_MISMATCH" in result.stderr
