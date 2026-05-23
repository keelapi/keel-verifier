from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

import pytest

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


def test_per_file_digest_tampering_has_specific_error_code() -> None:
    manifest = _embedded_manifest()
    manifest["per_file_digests"] = {"keel_verifier/__init__.py": "0" * 64}

    with pytest.raises(self_check.SelfCheckError) as exc:
        self_check.verify_per_file_digests(manifest)

    assert exc.value.code == "SELF_CHECK_FILE_DIGEST_MISMATCH"


def test_tampered_embedded_manifest_binding_has_specific_error_code() -> None:
    embedded_manifest = _embedded_manifest()
    signed_manifest = {
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
                "sha256": "sha256:" + "0" * 64,
            }
        ],
    }

    with pytest.raises(self_check.SelfCheckError) as exc:
        self_check.verify_embedded_manifest_binding(signed_manifest, embedded_manifest)

    assert exc.value.code == "SELF_CHECK_EMBEDDED_BINDING_MISMATCH"


def test_missing_tsa_receipt_has_specific_error_code() -> None:
    sidecar = {
        "message_imprint": self_check._sha256_prefixed(b"manifest"),
        "receipt_format": "rfc3161-timestamp-response-der",
        "receipts": [
            {
                "provider": "digicert",
                "receipt_b64": base64.b64encode(b"not-real").decode("ascii"),
                "receipt_hash": "sha256:" + hashlib.sha256(b"not-real").hexdigest(),
            }
        ],
    }

    with pytest.raises(self_check.SelfCheckError) as exc:
        self_check.verify_tsa(b"manifest", sidecar)

    assert exc.value.code == "SELF_CHECK_TSA_MISSING"


def test_expired_or_invalid_tsa_receipt_has_specific_error_code(monkeypatch) -> None:
    class FakeResponse:
        status = 0

    class FakeVerifier:
        def verify_message(self, response, message):
            del response, message
            raise ValueError("certificate expired at timestamp generation time")

    receipt_der = b"fake-response"
    sidecar = {
        "message_imprint": self_check._sha256_prefixed(b"manifest"),
        "receipt_format": "rfc3161-timestamp-response-der",
        "receipts": [
            {
                "provider": provider,
                "receipt_b64": base64.b64encode(receipt_der).decode("ascii"),
                "receipt_hash": self_check._sha256_prefixed(receipt_der),
            }
            for provider in ["digicert", "globalsign"]
        ],
    }
    monkeypatch.setattr(self_check, "_tsa_verifier", lambda: FakeVerifier())
    monkeypatch.setattr(self_check, "_decode_tsa_response", lambda raw: FakeResponse())

    with pytest.raises(self_check.SelfCheckError) as exc:
        self_check.verify_tsa(b"manifest", sidecar)

    assert exc.value.code == "SELF_CHECK_TSA_INVALID"


def test_offline_without_cache_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(self_check.SelfCheckError) as exc:
        self_check.fetch_signed_manifest(
            "https://example.invalid/manifest.json",
            offline=True,
            cache_dir=tmp_path,
        )

    assert exc.value.code == "SELF_CHECK_FETCH_FAILED"


@pytest.mark.parametrize(
    ("stage_name", "code", "patch_name"),
    [
        (
            "sigstore_signature",
            "SELF_CHECK_SIGNING_IDENTITY_MISMATCH",
            "verify_sigstore",
        ),
        ("rekor_inclusion", "SELF_CHECK_REKOR_INVALID", "verify_rekor"),
    ],
)
def test_self_check_orchestration_preserves_specific_error_codes(
    monkeypatch,
    tmp_path: Path,
    stage_name: str,
    code: str,
    patch_name: str,
) -> None:
    embedded_manifest = _embedded_manifest()
    manifest_bytes = json.dumps(
        {
            "artifacts": [
                {
                    "filename": "keel_verifier-2.4.0-py3-none-any.whl",
                    "sha256": "f" * 64,
                }
            ],
            "embedded_manifests": [],
        }
    ).encode("utf-8")

    monkeypatch.setattr(self_check, "detect_form", lambda: "wheel")
    monkeypatch.setattr(self_check, "load_embedded_manifest", lambda form: embedded_manifest)
    monkeypatch.setattr(self_check, "fetch_signed_manifest", lambda *args, **kwargs: manifest_bytes)
    monkeypatch.setattr(self_check, "_fetch_url", lambda *args, **kwargs: b"{}")
    if patch_name == "verify_sigstore":
        monkeypatch.setattr(
            self_check,
            "verify_sigstore",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                self_check.SelfCheckError(code, "specific failure")
            ),
        )
    else:
        monkeypatch.setattr(
            self_check,
            "verify_sigstore",
            lambda *args, **kwargs: self_check.SigstoreVerification(log_index=1),
        )
        monkeypatch.setattr(
            self_check,
            "verify_rekor",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                self_check.SelfCheckError(code, "specific failure")
            ),
        )

    result = self_check.run_self_check(
        argparse.Namespace(
            form="auto",
            offline=False,
            no_cache=False,
            cache_dir=str(tmp_path),
        )
    )

    failed = result.stages[-1]
    assert failed.name == stage_name
    assert failed.code == code
