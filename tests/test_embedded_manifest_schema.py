from __future__ import annotations

import copy

import pytest

from keel_verifier.self_check import (
    SelfCheckError,
    _normalize_manifest_path,
    validate_embedded_manifest,
)


def _embedded_manifest() -> dict:
    return {
        "version": "1.0",
        "release_name": "keel-verifier",
        "version_tag": "v2.4.0",
        "expected_signing_identity": (
            "https://github.com/keelapi/keel-verifier/.github/workflows/"
            "release.yml@refs/tags/v2.4.0"
        ),
        "release_manifest_url": (
            "https://github.com/keelapi/keel-verifier/releases/download/v2.4.0/manifest.json"
        ),
        "release_manifest_signature_url": (
            "https://github.com/keelapi/keel-verifier/releases/download/"
            "v2.4.0/manifest.json.sigstore"
        ),
        "release_manifest_tsa_witness_url": (
            "https://github.com/keelapi/keel-verifier/releases/download/"
            "v2.4.0/manifest.json.tsa.json"
        ),
        "per_file_digests": {
            "keel_verifier/__init__.py": "0" * 64,
        },
    }


def test_embedded_manifest_schema_accepts_release_manifest_urls() -> None:
    validate_embedded_manifest(_embedded_manifest())


@pytest.mark.parametrize("field", ["embedded_manifests", "tsa_receipts", "rekor_log_index"])
def test_embedded_manifest_schema_rejects_forbidden_outer_fields(field: str) -> None:
    manifest = _embedded_manifest()
    manifest[field] = []

    with pytest.raises(SelfCheckError) as exc:
        validate_embedded_manifest(manifest)

    assert exc.value.code == "SELF_CHECK_FORBIDDEN_EMBEDDED_FIELD"


def test_embedded_manifest_schema_rejects_signature_url_pointing_to_wheel() -> None:
    manifest = _embedded_manifest()
    manifest["release_manifest_signature_url"] = (
        "https://github.com/keelapi/keel-verifier/releases/download/"
        "v2.4.0/keel_verifier-2.4.0-py3-none-any.whl"
    )

    with pytest.raises(SelfCheckError) as exc:
        validate_embedded_manifest(manifest)

    assert exc.value.code == "SELF_CHECK_EMBEDDED_MANIFEST_INVALID"


def test_embedded_manifest_schema_rejects_self_digest_cycle() -> None:
    manifest = copy.deepcopy(_embedded_manifest())
    manifest["per_file_digests"]["keel_verifier/_release_manifest.json"] = "0" * 64

    with pytest.raises(SelfCheckError) as exc:
        validate_embedded_manifest(manifest)

    assert exc.value.code == "SELF_CHECK_FORBIDDEN_EMBEDDED_FIELD"


def test_windows_style_package_paths_normalize_to_posix() -> None:
    assert (
        _normalize_manifest_path("keel_verifier\\data\\trust_root.json")
        == "keel_verifier/data/trust_root.json"
    )
