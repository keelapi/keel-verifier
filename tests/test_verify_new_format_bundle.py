from __future__ import annotations

import json
from typing import Any

from conftest import keypair, write_signed_export


ARTIFACT_ID = "40000000-0000-0000-0000-000000000001"
ARTIFACT_URN = f"urn:x-keel:artifact:compliance_export:{ARTIFACT_ID}"


def _new_format_bundle() -> dict[str, Any]:
    return {
        "artifact_ref": {
            "schema_version": "artifact_ref.v1",
            "type": "compliance_export",
            "id": ARTIFACT_ID,
            "urn": ARTIFACT_URN,
            "region": "us-east-1",
            "path": f"/v1/compliance/exports/{ARTIFACT_ID}",
            "canonical_url": f"https://api.keelapi.com/v1/compliance/exports/{ARTIFACT_ID}",
            "digest": "sha256:" + "c" * 64,
        },
        "records": [],
    }


def test_new_format_bundle_verifies_and_surfaces_urn(tmp_path, run_cli) -> None:
    export_private, export_public, export_key_id = keypair()
    export_file, manifest = write_signed_export(
        tmp_path,
        _new_format_bundle(),
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
    assert f"Artifact URN: {ARTIFACT_URN}" in result.stdout
    assert "compliance_export" in result.stdout
    assert result.stderr == ""


def test_new_format_bundle_json_output_includes_artifact_ref(
    tmp_path,
    run_cli,
) -> None:
    export_private, export_public, export_key_id = keypair()
    export_file, manifest = write_signed_export(
        tmp_path,
        _new_format_bundle(),
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
    payload = json.loads(result.stdout)

    assert result.returncode == 0, result.stderr
    assert payload["artifact"]["artifact_ref"]["urn"] == ARTIFACT_URN
    assert payload["artifact"]["artifact_ref"]["type"] == "compliance_export"
    assert result.stderr == ""
