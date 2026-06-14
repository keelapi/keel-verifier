from __future__ import annotations

import argparse
import contextlib
from typing import Any

from conftest import keypair, write_signed_export

from keel_verifier import verifier


def _new_format_bundle() -> dict[str, Any]:
    artifact_id = "40000000-0000-0000-0000-000000000001"
    return {
        "artifact_ref": {
            "schema_version": "artifact_ref.v1",
            "type": "compliance_export",
            "id": artifact_id,
            "urn": f"urn:x-keel:artifact:compliance_export:{artifact_id}",
            "region": "us-east-1",
            "path": f"/v1/compliance/exports/{artifact_id}",
            "canonical_url": f"https://api.keelapi.com/v1/compliance/exports/{artifact_id}",
            "digest": "sha256:" + "b" * 64,
        },
        "records": [],
    }


def _disable_network(monkeypatch) -> None:
    def fail_network(*_args, **_kwargs):
        raise AssertionError("verification attempted a network call")

    monkeypatch.setattr(verifier.urllib.request, "urlopen", fail_network)

    with contextlib.suppress(ImportError):
        import requests

        monkeypatch.setattr(requests.sessions.Session, "request", fail_network)
    with contextlib.suppress(ImportError):
        import httpx

        monkeypatch.setattr(httpx.Client, "request", fail_network)
        monkeypatch.setattr(httpx.AsyncClient, "request", fail_network)


def test_export_verification_succeeds_with_network_disabled(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    export_private, export_public, export_key_id = keypair()
    export_file, manifest = write_signed_export(
        tmp_path,
        _new_format_bundle(),
        export_private_key=export_private,
        export_public_key=export_public,
        export_key_id=export_key_id,
    )
    _disable_network(monkeypatch)

    rc = verifier.cmd_export(
        argparse.Namespace(
            export_file=str(export_file),
            manifest=str(manifest),
            expected_public_key=None,
            key_manifest=None,
            key_manifest_url=None,
            self_attested=True,
            offline=True,
            allow_unsigned=False,
            walk_events=False,
            verify_closure=False,
            as_json=False,
            sidecar=None,
            checkpoint=None,
        )
    )

    captured = capsys.readouterr()
    assert rc == 0
    assert "VERIFIED" in captured.out
    assert "Artifact URN:" in captured.out
    assert captured.err == ""
