from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import rfc8785

from keel_verifier import self_check


def _embedded_manifest() -> dict:
    return {
        "version": "1.0",
        "release_name": "keel-verifier",
        "version_tag": "v2.4.0",
        "expected_signing_identity": (
            "https://github.com/keelapi/keel-verifier/.github/workflows/"
            "release.yml@refs/tags/v2.4.0"
        ),
        "release_manifest_url": "https://example.invalid/manifest.json",
        "release_manifest_signature_url": "https://example.invalid/manifest.json.sigstore",
        "release_manifest_tsa_witness_url": "https://example.invalid/manifest.json.tsa.json",
        "per_file_digests": {
            "keel_verifier/__init__.py": "0" * 64,
        },
    }


def _signed_manifest(embedded_manifest: dict) -> dict:
    embedded_hash = hashlib.sha256(rfc8785.dumps(embedded_manifest)).hexdigest()
    return {
        "version": "1.0",
        "release_name": "keel-verifier",
        "version_tag": "v2.4.0",
        "signing_identity": embedded_manifest["expected_signing_identity"],
        "artifacts": [
            {
                "filename": "keel_verifier-2.4.0-py3-none-any.whl",
                "sha256": "f" * 64,
            }
        ],
        "embedded_manifests": [
            {
                "artifact": "wheel",
                "path": "keel_verifier/_release_manifest.json",
                "media_type": "application/json",
                "canonicalization": "rfc8785-jcs",
                "sha256": f"sha256:{embedded_hash}",
            }
        ],
    }


def test_self_check_happy_path_with_sigstore_mock(monkeypatch, tmp_path: Path) -> None:
    embedded_manifest = _embedded_manifest()
    manifest_bytes = json.dumps(_signed_manifest(embedded_manifest)).encode("utf-8")
    signature_bytes = b'{"mock":"sigstore"}'
    sidecar_bytes = b'{"mock":"tsa"}'

    monkeypatch.setattr(self_check, "detect_form", lambda: "wheel")
    monkeypatch.setattr(self_check, "load_embedded_manifest", lambda form: embedded_manifest)

    def fake_fetch(url, **kwargs):
        del kwargs
        if url.endswith("manifest.json"):
            return manifest_bytes
        if url.endswith("manifest.json.sigstore"):
            return signature_bytes
        if url.endswith("manifest.json.tsa.json"):
            return sidecar_bytes
        raise AssertionError(url)

    monkeypatch.setattr(self_check, "fetch_signed_manifest", fake_fetch)
    monkeypatch.setattr(self_check, "_fetch_url", fake_fetch)
    monkeypatch.setattr(
        self_check,
        "verify_sigstore",
        lambda *args, **kwargs: self_check.SigstoreVerification(log_index=42),
    )
    monkeypatch.setattr(
        self_check,
        "verify_rekor",
        lambda *args, **kwargs: self_check.RekorVerification(
            log_index=42,
            checkpoint_present=True,
        ),
    )
    monkeypatch.setattr(
        self_check,
        "verify_tsa",
        lambda *args, **kwargs: self_check.TSAVerification(
            providers=["digicert", "globalsign"],
            message_imprint=self_check._sha256_prefixed(manifest_bytes),
        ),
    )
    monkeypatch.setattr(
        self_check,
        "verify_per_file_digests",
        lambda manifest: self_check.PerFileDigestVerification(checked=1),
    )

    result = self_check.run_self_check(
        argparse.Namespace(
            form="auto",
            offline=False,
            no_cache=False,
            cache_dir=str(tmp_path),
        )
    )

    assert result.ok is True
    assert [stage.name for stage in result.stages] == [
        "form",
        "embedded_manifest",
        "fetch",
        "sigstore_signature",
        "rekor_inclusion",
        "tsa_witnesses",
        "embedded_binding",
        "per_file_digests",
    ]
    assert result.to_dict()["form"] == "wheel"
