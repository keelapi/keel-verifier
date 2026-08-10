from __future__ import annotations

import hashlib
import json
from pathlib import Path
import zipfile

import pytest

from keel_verifier.permit_package import verify_package_inventory


def _digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _package(
    path: Path,
    *,
    manifest_mutator=None,
    payload_mutator=None,
    extra_members: dict[str, bytes] | None = None,
) -> None:
    payloads = {
        "permit.json": b'{"title":"AI Permit-to-Pay"}',
        "verification-report.json": b'{"ok":true}',
        "evidence/permit-exact.json": b'{"schema_version":"keel.evidence_bundle/v1"}',
    }
    if payload_mutator is not None:
        payload_mutator(payloads)
    manifest = {
        "version": "keel.permit_package_manifest.v1",
        "artifact_id": "package-1",
        "created_at": "2026-08-09T12:00:00Z",
        "primary_view": "permit.json",
        "signed_evidence": "evidence/permit-exact.json",
        "trust_rule": "verify_signed_evidence_and_regenerate_human_view",
        "entries": [
            {
                "path": "permit.json",
                "role": "human_view",
                "media_type": "application/json",
                "sha256": _digest(payloads["permit.json"]),
                "size_bytes": len(payloads["permit.json"]),
            },
            {
                "path": "verification-report.json",
                "role": "verification_report",
                "media_type": "application/json",
                "sha256": _digest(payloads["verification-report.json"]),
                "size_bytes": len(payloads["verification-report.json"]),
            },
            {
                "path": "evidence/permit-exact.json",
                "role": "signed_evidence",
                "media_type": "application/json",
                "sha256": _digest(payloads["evidence/permit-exact.json"]),
                "size_bytes": len(payloads["evidence/permit-exact.json"]),
            },
        ],
    }
    if manifest_mutator is not None:
        manifest_mutator(manifest)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        for name, payload in payloads.items():
            archive.writestr(name, payload)
        for name, payload in (extra_members or {}).items():
            archive.writestr(name, payload)


def test_valid_package_inventory_returns_only_untrusted_views_and_evidence(
    tmp_path: Path,
) -> None:
    path = tmp_path / "valid.keelpermit"
    _package(path)
    verified = verify_package_inventory(path)
    assert verified.manifest["artifact_id"] == "package-1"
    assert verified.primary_view == b'{"title":"AI Permit-to-Pay"}'
    assert verified.signed_evidence.startswith(b'{"schema_version"')


def test_package_digest_mismatch_fails(tmp_path: Path) -> None:
    path = tmp_path / "digest.keelpermit"

    def mutate(manifest: dict) -> None:
        manifest["entries"][0]["sha256"] = "sha256:" + "0" * 64

    _package(path, manifest_mutator=mutate)
    with pytest.raises(ValueError, match="digest mismatch"):
        verify_package_inventory(path)


def test_package_path_traversal_fails_before_any_extraction(tmp_path: Path) -> None:
    path = tmp_path / "traversal.keelpermit"
    _package(path, extra_members={"../escape.json": b"{}"})
    with pytest.raises(ValueError, match="unsafe path"):
        verify_package_inventory(path)


def test_package_inventory_cannot_point_signed_evidence_at_human_view(
    tmp_path: Path,
) -> None:
    path = tmp_path / "pointer.keelpermit"

    def mutate(manifest: dict) -> None:
        manifest["signed_evidence"] = "permit.json"

    _package(path, manifest_mutator=mutate)
    with pytest.raises(ValueError, match="not the signed evidence"):
        verify_package_inventory(path)


def test_package_cannot_hide_an_uninventoried_file(tmp_path: Path) -> None:
    path = tmp_path / "extra.keelpermit"
    _package(path, extra_members={"extra.json": b"{}"})
    with pytest.raises(ValueError, match="inventory diverges"):
        verify_package_inventory(path)
