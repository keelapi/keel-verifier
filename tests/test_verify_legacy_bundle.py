from __future__ import annotations

from conftest import keypair, write_signed_export

from keel_verifier.verifier import LEGACY_ARTIFACT_REF_WARNING


def test_legacy_bundle_verifies_with_deprecation_warning(tmp_path, run_cli) -> None:
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
        str(export_file),
        str(manifest),
        "--self-attested",
    )

    assert result.returncode == 0, result.stderr
    assert "VERIFIED" in result.stdout
    assert result.stderr.count(LEGACY_ARTIFACT_REF_WARNING) == 1
