from __future__ import annotations

import argparse
import hashlib
import json
import logging
from pathlib import Path

import rfc8785

from keel_verifier import self_check


REPO_ROOT = Path(__file__).resolve().parents[1]
SIGSTORE_FIXTURES = REPO_ROOT / "tests" / "fixtures" / "sigstore"


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
    monkeypatch.setattr(
        self_check,
        "verify_import_isolation",
        lambda: self_check.ImportIsolationVerification(
            imported_path=Path("/site-packages/keel_verifier/__init__.py"),
            checked=True,
        ),
    )
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
        "import_isolation",
        "embedded_manifest",
        "fetch",
        "sigstore_signature",
        "rekor_inclusion",
        "tsa_witnesses",
        "embedded_binding",
        "per_file_digests",
    ]
    assert result.to_dict()["form"] == "wheel"


def test_unpublished_candidate_never_falls_back_to_prior_release(
    monkeypatch, tmp_path: Path
) -> None:
    requested_urls: list[str] = []
    manifest = self_check.load_embedded_manifest("wheel")

    assert manifest["version_tag"] == "v3.25.2"
    assert all(
        "v3.25.1" not in manifest[field]
        for field in (
            "expected_signing_identity",
            "release_manifest_url",
            "release_manifest_signature_url",
            "release_manifest_tsa_witness_url",
        )
    )

    monkeypatch.setattr(self_check, "detect_form", lambda: "wheel")
    monkeypatch.setattr(
        self_check,
        "verify_import_isolation",
        lambda: self_check.ImportIsolationVerification(
            imported_path=Path("/site-packages/keel_verifier/__init__.py"),
            checked=True,
        ),
    )

    def unavailable(url: str, **kwargs) -> bytes:
        del kwargs
        requested_urls.append(url)
        raise self_check.SelfCheckError(
            "SELF_CHECK_FETCH_FAILED",
            "3.25.2 signed release artifacts do not exist",
        )

    monkeypatch.setattr(self_check, "fetch_signed_manifest", unavailable)

    result = self_check.run_self_check(
        argparse.Namespace(
            form="auto",
            offline=False,
            no_cache=True,
            cache_dir=str(tmp_path),
            published_wheel=None,
        )
    )

    assert result.ok is False
    assert result.stages[-1].name == "fetch"
    assert result.stages[-1].code == "SELF_CHECK_FETCH_FAILED"
    assert requested_urls == [manifest["release_manifest_url"]]
    assert "/v3.25.2/" in requested_urls[0]
    assert "/v3.25.1/" not in requested_urls[0]


def test_sigstore_4_verifies_historical_rekor_v1_fixture_offline(
    caplog,
    capsys,
    monkeypatch,
    tmp_path: Path,
) -> None:
    from sigstore._internal import tuf

    manifest_bytes = (SIGSTORE_FIXTURES / "v2.4.2-manifest.json").read_bytes()
    signature = (SIGSTORE_FIXTURES / "v2.4.2-manifest.json.sigstore").read_bytes()
    expected_identity = json.loads(manifest_bytes)["signing_identity"]
    tuf_cache = tmp_path / "sigstore-tuf"

    monkeypatch.setattr(
        tuf,
        "_get_dirs",
        lambda url: (tuf_cache / "metadata", tuf_cache / "targets"),
    )
    caplog.set_level(logging.WARNING, logger="sigstore._internal.trust")

    sigstore_result = self_check.verify_sigstore(
        manifest_bytes,
        signature,
        expected_identity,
        offline=True,
    )
    rekor_result = self_check.verify_rekor(manifest_bytes, signature)
    captured = capsys.readouterr()

    assert sigstore_result.log_index == 1613425410
    assert sigstore_result.integrated_time == 1779518408
    assert sigstore_result.log_id
    assert rekor_result.log_index == 1613425410
    assert rekor_result.checkpoint_present is True
    assert captured.err == ""
    assert "Failed to load a trusted root key" not in caplog.text
