from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

import pytest

from keel_verifier import self_check


REPO_ROOT = Path(__file__).resolve().parents[1]
TSA_FIXTURES = REPO_ROOT / "tests" / "fixtures" / "tsa"


def _real_sidecar() -> tuple[dict, bytes]:
    """Build a valid sidecar from captured DigiCert + GlobalSign receipts."""
    known_message = (TSA_FIXTURES / "known_message.txt").read_bytes()
    digicert_der = (TSA_FIXTURES / "digicert_receipt_for_known_message.der").read_bytes()
    globalsign_der = (TSA_FIXTURES / "globalsign_receipt_for_known_message.der").read_bytes()
    sidecar = {
        "version": "1.0",
        "artifact": "manifest.json",
        "message_imprint": self_check._sha256_prefixed(known_message),
        "receipt_format": "rfc3161-timestamp-response-der",
        "receipts": [
            {
                "provider": "digicert",
                "tsa_url": "http://timestamp.digicert.com",
                "receipt_b64": base64.b64encode(digicert_der).decode("ascii"),
                "receipt_hash": self_check._sha256_prefixed(digicert_der),
            },
            {
                "provider": "globalsign",
                "tsa_url": "http://timestamp.globalsign.com/tsa/r6advanced1",
                "receipt_b64": base64.b64encode(globalsign_der).decode("ascii"),
                "receipt_hash": self_check._sha256_prefixed(globalsign_der),
            },
        ],
    }
    return sidecar, known_message


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


def test_malformed_tsa_receipt_has_specific_error_code() -> None:
    """Non-DER bytes in receipt_b64 should produce SELF_CHECK_TSA_INVALID.

    Bind-level verification: the receipt fails to decode as TimeStampResp.
    """
    receipt_der = b"not-a-real-der-encoded-timestamp-response"
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

    with pytest.raises(self_check.SelfCheckError) as exc:
        self_check.verify_tsa(b"manifest", sidecar)

    assert exc.value.code == "SELF_CHECK_TSA_INVALID"


def test_tsa_receipt_hash_mismatch_has_specific_error_code() -> None:
    """Receipt bytes whose SHA-256 does not match receipt_hash → TSA_INVALID."""
    receipt_der = b"some-receipt-bytes"
    sidecar = {
        "message_imprint": self_check._sha256_prefixed(b"manifest"),
        "receipt_format": "rfc3161-timestamp-response-der",
        "receipts": [
            {
                "provider": provider,
                "receipt_b64": base64.b64encode(receipt_der).decode("ascii"),
                # Deliberately wrong hash
                "receipt_hash": "sha256:" + "0" * 64,
            }
            for provider in ["digicert", "globalsign"]
        ],
    }

    with pytest.raises(self_check.SelfCheckError) as exc:
        self_check.verify_tsa(b"manifest", sidecar)

    assert exc.value.code == "SELF_CHECK_TSA_INVALID"
    assert "receipt_hash mismatch" in exc.value.message


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
    monkeypatch.setattr(
        self_check,
        "verify_import_isolation",
        lambda: self_check.ImportIsolationVerification(
            imported_path=Path("/site-packages/keel_verifier/__init__.py"),
            checked=True,
        ),
    )
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


# ---------------------------------------------------------------------------
# Fixture-based tests using real captured DigiCert + GlobalSign receipts.
#
# Captured once via the live TSA endpoints against a known deterministic
# message (tests/fixtures/tsa/known_message.txt). The fixtures are stable
# bytes-on-disk; the tests don't hit the network.
# ---------------------------------------------------------------------------


def test_tsa_real_fixtures_happy_path() -> None:
    """Captured DigiCert + GlobalSign receipts pass bind-level verification."""
    sidecar, manifest_bytes = _real_sidecar()
    result = self_check.verify_tsa(manifest_bytes, sidecar)
    assert sorted(result.providers) == ["digicert", "globalsign"]


def test_tsa_trailing_data_rejected() -> None:
    """Regression: strict=True must reject TimeStampResp with trailing bytes.

    Without strict=True, an attacker who controls the sidecar storage could
    append arbitrary data after a valid receipt, update receipt_hash to match
    the new (longer) blob, and pass verification. asn1crypto's strict mode
    requires the parser to consume the entire input.
    """
    sidecar, manifest_bytes = _real_sidecar()
    # Mutate DigiCert receipt: append garbage, update receipt_hash to match
    digicert_der = base64.b64decode(sidecar["receipts"][0]["receipt_b64"])
    tampered_der = digicert_der + b"\x00\x01\x02 trailing attacker bytes"
    sidecar["receipts"][0]["receipt_b64"] = base64.b64encode(tampered_der).decode("ascii")
    sidecar["receipts"][0]["receipt_hash"] = self_check._sha256_prefixed(tampered_der)

    with pytest.raises(self_check.SelfCheckError) as exc:
        self_check.verify_tsa(manifest_bytes, sidecar)
    assert exc.value.code == "SELF_CHECK_TSA_INVALID"
    assert "TimeStampResp" in exc.value.message or "valid" in exc.value.message.lower()


def test_tsa_imprint_mismatch_rejected_using_real_fixture() -> None:
    """A valid receipt for message A must not verify against bytes B."""
    sidecar, _known_message = _real_sidecar()
    wrong_manifest = b"completely-different-manifest-bytes"
    # message_imprint at the sidecar level needs to match, or we fail on the
    # outer check before getting to per-receipt verification. So update it
    # to match the wrong manifest — this isolates the per-receipt imprint
    # check (which compares TST receipt's hashedMessage against
    # sha256(wrong_manifest)).
    sidecar["message_imprint"] = self_check._sha256_prefixed(wrong_manifest)

    with pytest.raises(self_check.SelfCheckError) as exc:
        self_check.verify_tsa(wrong_manifest, sidecar)
    assert exc.value.code == "SELF_CHECK_TSA_INVALID"
    assert "does not witness the signed manifest hash" in exc.value.message


def test_tsa_response_without_token_rejected() -> None:
    """A TimeStampResp without a time_stamp_token is rejected.

    Hand-crafted minimal rejection-style response:
        SEQUENCE {
            PKIStatusInfo SEQUENCE {
                status INTEGER 2  -- rejection
            }
        }
    asn1crypto's strict parser requires the time_stamp_token (even though the
    ASN.1 spec marks it OPTIONAL); this is acceptable because a granted-but-
    tokenless response would not give us anything to bind the manifest hash
    to, and a non-granted response carries no valid receipt to verify. Either
    parse failure or status failure produces SELF_CHECK_TSA_INVALID.
    """
    # 30 05 30 03 02 01 02
    # outer SEQUENCE(len=5) -> inner SEQUENCE(len=3) -> INTEGER(len=1) value=2
    receipt_der = bytes.fromhex("30053003020102")

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

    with pytest.raises(self_check.SelfCheckError) as exc:
        self_check.verify_tsa(b"manifest", sidecar)
    assert exc.value.code == "SELF_CHECK_TSA_INVALID"
