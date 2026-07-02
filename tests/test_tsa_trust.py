from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from argparse import Namespace
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from keel_verifier import verifier
from keel_verifier.semantics import (
    CHECKPOINT_COMPOSITE_HASH_HASH,
    CHECKPOINT_COMPOSITE_HASH_ID,
    CHECKPOINT_SIGNATURE_HASH,
    CHECKPOINT_SIGNATURE_ID,
    CHECKPOINT_TSA_CHAIN_HASH,
    CHECKPOINT_TSA_CHAIN_ID,
    CHECKPOINT_TSA_IMPRINT_HASH,
    CHECKPOINT_TSA_IMPRINT_ID,
    CLAIM_REGISTRY_HASH,
    CLAIM_REGISTRY_ID,
    RELEASED_ARTIFACT_PATHS,
    SEMANTICS_PINS_VERSION,
)
from keel_verifier.verdicts import ClaimVerdict


REPO_ROOT = Path(__file__).resolve().parents[1]


def _json_result(result):
    assert result.stdout, result.stderr
    return json.loads(result.stdout)


def _sample_checkpoint() -> dict:
    return json.loads((REPO_ROOT / "sample" / "export.json").read_text(encoding="utf-8"))


def _write_checkpoint(tmp_path: Path, checkpoint: dict) -> Path:
    checkpoint_path = tmp_path / "checkpoint.json"
    checkpoint_path.write_text(json.dumps(checkpoint), encoding="utf-8")
    return checkpoint_path


def test_checkpoint_tsa_claim_empty_subject_domain_is_insufficient() -> None:
    claim = verifier._checkpoint_tsa_claim([])

    assert claim.aggregate_verdict == "insufficient_evidence"
    assert claim.reason_code == "CHECKPOINT_TSA_IMPRINT_MISSING"
    assert claim.subjects == []


def _run_openssl(args: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [verifier._openssl_tsa_bin(), *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )


def _require_openssl_3_for_tsa() -> str:
    openssl_bin = verifier._openssl_tsa_bin()
    try:
        completed = subprocess.run(
            [openssl_bin, "version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except FileNotFoundError:
        pytest.skip(f"openssl executable not available: {openssl_bin}")
    version = (completed.stdout or completed.stderr or "").strip()
    if completed.returncode != 0:
        pytest.skip(f"openssl version failed: {version or completed.returncode}")
    supported, error = verifier._parse_openssl_version_for_tsa(version)
    if not supported:
        pytest.skip(error or "OpenSSL 3.x or newer required for TSA trust tests")
    return version


def _openssl_tsa_receipt(
    tmp_path: Path,
    content_hash: bytes,
) -> tuple[dict, Path, Path]:
    _require_openssl_3_for_tsa()
    workdir = tmp_path / "openssl-tsa-cli"
    workdir.mkdir()
    (workdir / "serial.txt").write_text("01\n", encoding="utf-8")
    _run_openssl(
        [
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-subj",
            "/CN=Keel Test TSA Root",
            "-days",
            "2",
        ],
        cwd=workdir,
    )
    _run_openssl(
        [
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "wrong-ca.key",
            "-out",
            "wrong-ca.pem",
            "-subj",
            "/CN=Keel Wrong TSA Root",
            "-days",
            "2",
        ],
        cwd=workdir,
    )
    _run_openssl(
        [
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "tsa.key",
            "-out",
            "tsa.csr",
            "-subj",
            "/CN=Keel Test TSA",
        ],
        cwd=workdir,
    )
    (workdir / "tsa_ext.cnf").write_text(
        "\n".join(
            [
                "[tsa_ext]",
                "basicConstraints=critical,CA:FALSE",
                "keyUsage=critical,digitalSignature,nonRepudiation",
                "extendedKeyUsage=critical,timeStamping",
                "subjectKeyIdentifier=hash",
                "authorityKeyIdentifier=keyid,issuer",
                "",
            ]
        ),
        encoding="utf-8",
    )
    _run_openssl(
        [
            "x509",
            "-req",
            "-in",
            "tsa.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-out",
            "tsa.pem",
            "-days",
            "2",
            "-extfile",
            "tsa_ext.cnf",
            "-extensions",
            "tsa_ext",
        ],
        cwd=workdir,
    )
    (workdir / "ts.cnf").write_text(
        "\n".join(
            [
                "[ tsa ]",
                "default_tsa = tsa_config1",
                "",
                "[ tsa_config1 ]",
                "serial = serial.txt",
                "signer_cert = tsa.pem",
                "certs = ca.pem",
                "signer_key = tsa.key",
                "signer_digest = sha256",
                "default_policy = 1.2.3.4.1",
                "other_policies = 1.2.3.4.1",
                "digests = sha256",
                "accuracy = secs:1",
                "ordering = yes",
                "tsa_name = yes",
                "ess_cert_id_chain = yes",
                "ess_cert_id_alg = sha256",
                "",
            ]
        ),
        encoding="utf-8",
    )
    _run_openssl(
        [
            "ts",
            "-query",
            "-digest",
            content_hash.hex(),
            "-sha256",
            "-cert",
            "-out",
            "req.tsq",
        ],
        cwd=workdir,
    )
    _run_openssl(
        [
            "ts",
            "-reply",
            "-queryfile",
            "req.tsq",
            "-config",
            "ts.cnf",
            "-out",
            "resp.tsr",
        ],
        cwd=workdir,
    )
    _run_openssl(
        [
            "ts",
            "-reply",
            "-in",
            "resp.tsr",
            "-token_out",
            "-out",
            "token.der",
        ],
        cwd=workdir,
    )
    token_der = (workdir / "token.der").read_bytes()
    return (
        {
            "provider": "local_test_tsa",
            "url": "https://tsa.local/tsr",
            "requested_at": "2026-05-17T00:00:00Z",
            "receipt_b64": base64.b64encode(token_der).decode("ascii"),
            "receipt_hash": f"sha256:{hashlib.sha256(token_der).hexdigest()}",
        },
        workdir / "ca.pem",
        workdir / "wrong-ca.pem",
    )


def _checkpoint_with_receipt(tmp_path: Path, receipt: dict) -> Path:
    checkpoint = _sample_checkpoint()
    checkpoint["tsa"] = receipt
    checkpoint["tsa_receipts"] = [receipt]
    return _write_checkpoint(tmp_path, checkpoint)


def _artifact_pin(artifact_id: str, artifact_hash: str) -> dict[str, str]:
    return {
        "id": artifact_id,
        "hash": artifact_hash,
        "path": RELEASED_ARTIFACT_PATHS[artifact_id],
    }


def test_openssl_version_parser_for_tsa_runtime_gate():
    supported, error = verifier._parse_openssl_version_for_tsa(
        "OpenSSL 3.0.13 30 Jan 2024"
    )
    assert supported is True
    assert error is None

    supported, error = verifier._parse_openssl_version_for_tsa(
        "OpenSSL 1.1.1w 11 Sep 2023"
    )
    assert supported is False
    assert "too old" in str(error)

    supported, error = verifier._parse_openssl_version_for_tsa("LibreSSL 3.3.6")
    assert supported is False
    assert "LibreSSL" in str(error)


def test_tsa_trust_runtime_gate_missing_openssl(monkeypatch, tmp_path: Path):
    checkpoint = _sample_checkpoint()
    content_hash_hex = checkpoint["composite_hash"].removeprefix("sha256:")
    receipt, _ca_bundle, _wrong_ca_bundle = _openssl_tsa_receipt(
        tmp_path,
        bytes.fromhex(content_hash_hex),
    )
    ca_bundle = tmp_path / "ca.pem"
    ca_bundle.write_text("not a real ca", encoding="utf-8")

    def fake_run(cmd, *_args, **_kwargs):
        if cmd[-1:] == ["version"]:
            raise FileNotFoundError
        raise AssertionError("openssl ts -verify should not run")

    monkeypatch.setattr(verifier.subprocess, "run", fake_run)
    report = verifier._build_tsa_trust_report(
        [receipt],
        content_hash_hex,
        ca_bundle_path=str(ca_bundle),
    )

    receipt = report["receipts"][0]
    assert receipt["tsa_trust_status"] == "unsupported_runtime"
    assert receipt["imprint_match"] is True
    assert "not found" in receipt["verification_error"]


def test_checkpoint_tsa_trust_custom_bundle_json_and_human_output(
    tmp_path: Path,
    run_cli,
):
    checkpoint = _sample_checkpoint()
    content_hash = bytes.fromhex(checkpoint["composite_hash"].removeprefix("sha256:"))
    receipt, ca_bundle, _wrong_ca_bundle = _openssl_tsa_receipt(
        tmp_path,
        content_hash,
    )
    checkpoint_path = _checkpoint_with_receipt(tmp_path, receipt)

    result = run_cli(
        "checkpoint",
        "--json",
        str(checkpoint_path),
        "--self-attested",
        "--tsa-ca-bundle",
        str(ca_bundle),
    )
    payload = _json_result(result)

    assert result.returncode == 0, result.stderr
    assert payload["ok"] is True
    assert payload["exit_code"] == 0
    assert payload["tsa_chain_validation"] == "not_validated"
    assert payload["tsa_trust"]["ca_bundle"] == str(ca_bundle)
    assert payload["tsa_trust"]["openssl_version"].startswith("OpenSSL 3")
    assert payload["tsa_trust"]["revocation_checked"] is False
    trust_receipt = payload["tsa_trust"]["receipts"][0]
    assert trust_receipt["provider"] == "local_test_tsa"
    assert trust_receipt["tsa_trust_status"] == "not_validated"
    assert trust_receipt["tsa_chain_validation"] == "not_validated"
    assert trust_receipt["imprint_match"] is True
    assert trust_receipt["cms_signature_valid"] is True
    assert trust_receipt["certificate_chain_valid"] is True
    assert trust_receipt["eku_checked"] is True
    assert trust_receipt["eku_valid"] is True
    assert trust_receipt["revocation_checked"] is False
    assert trust_receipt["revocation_valid"] is None
    assert (
        trust_receipt["reason_code"]
        == "not_validated_release_pinned_revocation_unavailable"
    )
    assert "no release-pinned revocation snapshot" in trust_receipt["verification_error"]

    human = run_cli(
        "checkpoint",
        str(checkpoint_path),
        "--self-attested",
        "--tsa-ca-bundle",
        str(ca_bundle),
    )
    assert human.returncode == 0, human.stderr
    assert "TSA[1] TRUST: NOT VALIDATED" in human.stderr
    assert "against supplied CA bundle" in human.stdout
    assert "release-pinned revocation snapshot not available" in human.stdout

    strict = run_cli(
        "checkpoint",
        "--json",
        str(checkpoint_path),
        "--self-attested",
        "--tsa-ca-bundle",
        str(ca_bundle),
        "--require-tsa-chain",
    )
    strict_payload = _json_result(strict)
    assert strict.returncode == 1
    assert strict_payload["ok"] is False
    assert strict_payload["exit_code"] == 1
    assert strict_payload["tsa_chain_validation"] == "not_validated"
    assert "required but not validated" in strict_payload["error"]


def test_checkpoint_tsa_trust_wrong_ca_bundle_invalid_additive_unless_strict(
    tmp_path: Path,
    run_cli,
):
    checkpoint = _sample_checkpoint()
    content_hash = bytes.fromhex(checkpoint["composite_hash"].removeprefix("sha256:"))
    receipt, _ca_bundle, wrong_ca_bundle = _openssl_tsa_receipt(
        tmp_path,
        content_hash,
    )
    checkpoint_path = _checkpoint_with_receipt(tmp_path, receipt)

    result = run_cli(
        "checkpoint",
        "--json",
        str(checkpoint_path),
        "--self-attested",
        "--tsa-ca-bundle",
        str(wrong_ca_bundle),
    )
    payload = _json_result(result)

    assert result.returncode == 0
    assert payload["ok"] is True
    assert payload["exit_code"] == 0
    assert payload["tsa_chain_validation"] == "invalid"
    trust_receipt = payload["tsa_trust"]["receipts"][0]
    assert trust_receipt["tsa_trust_status"] == "invalid"
    assert trust_receipt["tsa_chain_validation"] == "invalid"
    assert trust_receipt["imprint_match"] is True
    assert trust_receipt["cms_signature_valid"] is False
    assert trust_receipt["certificate_chain_valid"] is False
    assert trust_receipt["eku_checked"] is True
    assert trust_receipt["eku_valid"] is False
    assert trust_receipt["verification_error"]

    strict = run_cli(
        "checkpoint",
        "--json",
        str(checkpoint_path),
        "--self-attested",
        "--tsa-ca-bundle",
        str(wrong_ca_bundle),
        "--require-tsa-chain",
    )
    strict_payload = _json_result(strict)
    assert strict.returncode == 1
    assert strict_payload["ok"] is False
    assert strict_payload["exit_code"] == 1
    assert strict_payload["tsa_chain_validation"] == "invalid"


def test_checkpoint_custom_bundle_reenforces_required_tsa_chain_claim(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    checkpoint_path = _write_checkpoint(
        tmp_path,
        {
            "checkpoint_id": "ckpt-required-chain",
            "composite_hash": "sha256:" + "a" * 64,
            "tsa_receipts": [{"provider": "test", "receipt_b64": "abc"}],
            "claim_set": {
                "version": "verifier-claims.v0",
                "registry": {
                    "id": CLAIM_REGISTRY_ID,
                    "hash": CLAIM_REGISTRY_HASH,
                    "path": RELEASED_ARTIFACT_PATHS[CLAIM_REGISTRY_ID],
                },
                "claims": [
                    {"name": "checkpoint.composite_hash.v1", "required": True},
                    {"name": "checkpoint.signature.v1", "required": True},
                    {"name": "checkpoint.tsa_imprint.v1", "required": True},
                    {"name": "checkpoint.tsa_chain.v1", "required": True},
                ],
            },
            "semantics_pins": {
                "version": SEMANTICS_PINS_VERSION,
                "mode": "pinned",
                "artifacts": [
                    _artifact_pin(CHECKPOINT_COMPOSITE_HASH_ID, CHECKPOINT_COMPOSITE_HASH_HASH),
                    _artifact_pin(CHECKPOINT_SIGNATURE_ID, CHECKPOINT_SIGNATURE_HASH),
                    _artifact_pin(CHECKPOINT_TSA_IMPRINT_ID, CHECKPOINT_TSA_IMPRINT_HASH),
                    _artifact_pin(CHECKPOINT_TSA_CHAIN_ID, CHECKPOINT_TSA_CHAIN_HASH),
                ],
            },
        },
    )
    ca_bundle = tmp_path / "custom-ca.pem"
    ca_bundle.write_text("not used by monkeypatch", encoding="utf-8")
    validated_report = {
        "tsa_chain_validation": "validated",
        "receipts": [
            verifier._tsa_trust_receipt_result(
                provider="test",
                tsa_trust_status="valid",
                imprint_match=True,
                cms_signature_valid=True,
                certificate_chain_valid=True,
                eku_checked=True,
                eku_valid=True,
                tsa_chain_validation=verifier.TSA_CHAIN_VALIDATED,
                reason_code="tsa_chain_validated",
            )
        ],
    }
    invalid_report = {
        "tsa_chain_validation": "invalid",
        "receipts": [
            verifier._tsa_trust_receipt_result(
                provider="test",
                tsa_trust_status="invalid",
                imprint_match=True,
                cms_signature_valid=False,
                certificate_chain_valid=False,
                eku_checked=True,
                eku_valid=False,
                tsa_chain_validation=verifier.TSA_CHAIN_INVALID,
                reason_code="tsa_chain_validation_failed",
                verification_error="custom bundle rejected the TSA chain",
            )
        ],
    }

    monkeypatch.setattr(
        verifier,
        "verify_checkpoint",
        lambda *_args, **_kwargs: verifier.VerifyResult(
            ok=True,
            exit_code=0,
            checkpoint_id="ckpt-required-chain",
            composite_hash="sha256:" + "a" * 64,
            tsa_trust=validated_report,
            tsa_chain_validation=verifier.TSA_CHAIN_VALIDATED,
            claims=[
                ClaimVerdict(
                    name="checkpoint.tsa_chain.v1",
                    required=True,
                    verdict="supported",
                    reason_code="CHECKPOINT_TSA_CHAIN_VALIDATED",
                    message="release-pinned TSA chain validated",
                )
            ],
        ),
    )
    monkeypatch.setattr(
        verifier,
        "_load_checkpoint_body_for_tsa_trust",
        lambda _path: {"tsa_receipts": [{"provider": "test", "receipt_b64": "abc"}]},
    )
    monkeypatch.setattr(
        verifier,
        "_build_tsa_trust_report",
        lambda *_args, **_kwargs: invalid_report,
    )

    exit_code = verifier.cmd_checkpoint(
        Namespace(
            checkpoint_file=str(checkpoint_path),
            expected_public_key=None,
            public_key_url=None,
            key_manifest=None,
            key_manifest_url=None,
            self_attested=True,
            tsa_ca_bundle=str(ca_bundle),
            require_tsa_chain=False,
            as_report=False,
            as_json=True,
        )
    )
    payload = json.loads(capsys.readouterr().out)
    chain_claim = next(
        claim for claim in payload["claims"] if claim["name"] == "checkpoint.tsa_chain.v1"
    )

    assert exit_code == 1
    assert payload["ok"] is False
    assert payload["error"] == "required claims not supported: checkpoint.tsa_chain.v1"
    assert chain_claim["required"] is True
    assert chain_claim["verdict"] == "disproved"


def test_checkpoint_default_release_bundle_is_additive_and_imprint_claim_stable(
    tmp_path: Path,
    run_cli,
):
    checkpoint = _sample_checkpoint()
    content_hash = bytes.fromhex(checkpoint["composite_hash"].removeprefix("sha256:"))
    receipt, ca_bundle, _wrong_ca_bundle = _openssl_tsa_receipt(
        tmp_path,
        content_hash,
    )
    checkpoint_path = _checkpoint_with_receipt(tmp_path, receipt)

    plain = run_cli(
        "checkpoint",
        "--json",
        str(checkpoint_path),
        "--self-attested",
    )
    trusted = run_cli(
        "checkpoint",
        "--json",
        str(checkpoint_path),
        "--self-attested",
        "--tsa-ca-bundle",
        str(ca_bundle),
    )
    plain_payload = _json_result(plain)
    trusted_payload = _json_result(trusted)

    assert plain.returncode == 0, plain.stderr
    assert trusted.returncode == 0, trusted.stderr
    plain_receipt = plain_payload["tsa_trust"]["receipts"][0]
    assert plain_receipt["tsa_trust_status"] == "not_validated"
    assert plain_receipt["tsa_chain_validation"] == "not_validated"
    assert plain_receipt["reason_code"] == "not_validated_release_pinned_trust_unavailable"
    assert plain_payload["ok"] == trusted_payload["ok"]
    plain_imprint = next(
        claim
        for claim in plain_payload["claims"]
        if claim["name"] == "checkpoint.tsa_imprint.v1"
    )
    trusted_imprint = next(
        claim
        for claim in trusted_payload["claims"]
        if claim["name"] == "checkpoint.tsa_imprint.v1"
    )
    assert plain_imprint == trusted_imprint
    assert plain_payload["semantics"] == trusted_payload["semantics"]
    assert plain_payload["tsa"] == trusted_payload["tsa"]
    assert plain_payload["tsa_receipts"] == trusted_payload["tsa_receipts"]

    human_plain = run_cli(
        "checkpoint",
        str(checkpoint_path),
        "--self-attested",
    )
    assert human_plain.returncode == 0, human_plain.stderr
    assert "TSA TRUST" not in human_plain.stdout
    assert "TSA[1] TRUST" not in human_plain.stderr


def test_release_pinned_public_ca_receipts_validate_offline() -> None:
    _require_openssl_3_for_tsa()
    fixtures = json.loads(
        (REPO_ROOT / "tests" / "fixtures" / "tsa" / "public_ca_receipts_v1.json")
        .read_text(encoding="utf-8")
    )

    for receipt in fixtures["receipts"]:
        report = verifier._build_tsa_trust_report(
            [receipt],
            receipt["content_hash_hex"],
            ca_bundle_path=None,
        )

        trust_receipt = report["receipts"][0]
        assert report["trust_bundle"]["id"] == verifier.TSA_TRUST_BUNDLE_ID
        assert report["trust_bundle"]["hash"] == verifier.TSA_TRUST_BUNDLE_V1_HASH
        assert report["tsa_chain_validation"] == "validated"
        assert report["revocation_checked"] is True
        assert trust_receipt["provider"] == receipt["provider"]
        assert trust_receipt["tsa_trust_status"] == "valid"
        assert trust_receipt["tsa_chain_validation"] == "validated"
        assert trust_receipt["imprint_match"] is True
        assert trust_receipt["cms_signature_valid"] is True
        assert trust_receipt["certificate_chain_valid"] is True
        assert trust_receipt["eku_checked"] is True
        assert trust_receipt["eku_valid"] is True
        assert trust_receipt["revocation_checked"] is True
        assert trust_receipt["revocation_valid"] is True
        assert trust_receipt["reason_code"] == "tsa_chain_validated"
        assert trust_receipt["verification_error"] is None


def test_release_pinned_public_ca_receipt_tamper_rejects_imprint() -> None:
    _require_openssl_3_for_tsa()
    fixtures = json.loads(
        (REPO_ROOT / "tests" / "fixtures" / "tsa" / "public_ca_receipts_v1.json")
        .read_text(encoding="utf-8")
    )
    receipt = fixtures["receipts"][0]

    report = verifier._build_tsa_trust_report(
        [receipt],
        "0" * 64,
        ca_bundle_path=None,
    )

    trust_receipt = report["receipts"][0]
    assert report["tsa_chain_validation"] == "invalid"
    assert trust_receipt["tsa_trust_status"] == "invalid"
    assert trust_receipt["tsa_chain_validation"] == "invalid"
    assert trust_receipt["imprint_match"] is False
    assert trust_receipt["reason_code"] == "tsa_imprint_mismatch"


def test_self_signed_receipt_is_not_validated_by_release_bundle(tmp_path: Path) -> None:
    checkpoint = _sample_checkpoint()
    content_hash_hex = checkpoint["composite_hash"].removeprefix("sha256:")
    receipt, _ca_bundle, _wrong_ca_bundle = _openssl_tsa_receipt(
        tmp_path,
        bytes.fromhex(content_hash_hex),
    )

    report = verifier._build_tsa_trust_report(
        [receipt],
        content_hash_hex,
        ca_bundle_path=None,
    )

    trust_receipt = report["receipts"][0]
    assert report["tsa_chain_validation"] == "not_validated"
    assert trust_receipt["tsa_trust_status"] == "not_validated"
    assert trust_receipt["tsa_chain_validation"] == "not_validated"
    assert trust_receipt["imprint_match"] is True
    assert trust_receipt["reason_code"] == "not_validated_release_pinned_trust_unavailable"


@pytest.mark.parametrize(
    ("openssl_error", "reason_code"),
    [
        ("Verify error: unsuitable certificate purpose", "tsa_timestamping_eku_invalid"),
        (
            "Verify error: certificate has expired",
            "tsa_certificate_time_invalid_at_gentime",
        ),
        (
            "Verify error: unable to get local issuer certificate",
            "tsa_chain_validation_failed",
        ),
        ("Verify error: CRL has expired", "not_validated_revocation_snapshot_stale"),
        ("Verify error: certificate revoked", "tsa_certificate_revoked_at_gentime"),
    ],
)
def test_release_pinned_chain_openssl_failures_fail_closed(
    monkeypatch,
    tmp_path: Path,
    openssl_error: str,
    reason_code: str,
) -> None:
    checkpoint = _sample_checkpoint()
    content_hash_hex = checkpoint["composite_hash"].removeprefix("sha256:")
    receipt, _ca_bundle, _wrong_ca_bundle = _openssl_tsa_receipt(
        tmp_path,
        bytes.fromhex(content_hash_hex),
    )
    receipt["provider"] = "digicert"

    def fake_run(cmd, *_args, **_kwargs):
        if cmd[-1:] == ["version"]:
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout="OpenSSL 3.2.0 23 Nov 2023\n",
                stderr="",
            )
        if "ts" in cmd and "-verify" in cmd:
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=1,
                stdout="",
                stderr=openssl_error,
            )
        raise AssertionError(f"unexpected subprocess command: {cmd!r}")

    monkeypatch.setattr(verifier.subprocess, "run", fake_run)

    report = verifier._build_tsa_trust_report(
        [receipt],
        content_hash_hex,
        ca_bundle_path=None,
    )

    trust_receipt = report["receipts"][0]
    assert report["tsa_chain_validation"] == "invalid"
    assert trust_receipt["tsa_trust_status"] == "invalid"
    assert trust_receipt["tsa_chain_validation"] == "invalid"
    assert trust_receipt["reason_code"] == reason_code


def _revocation_details_for_local_receipt(tmp_path: Path):
    checkpoint = _sample_checkpoint()
    content_hash_hex = checkpoint["composite_hash"].removeprefix("sha256:")
    receipt, ca_bundle, _wrong_ca_bundle = _openssl_tsa_receipt(
        tmp_path,
        bytes.fromhex(content_hash_hex),
    )
    workdir = ca_bundle.parent
    details = verifier._extract_rfc3161_token_details(receipt["receipt_b64"])
    ca_cert = x509.load_pem_x509_certificate((workdir / "ca.pem").read_bytes())
    ca_key = serialization.load_pem_private_key(
        (workdir / "ca.key").read_bytes(),
        password=None,
    )
    return details, ca_cert, ca_key


def test_release_pinned_revocation_stale_snapshot_fails_closed(tmp_path: Path) -> None:
    details, ca_cert, ca_key = _revocation_details_for_local_receipt(tmp_path)
    gen_time = details["gen_time"]
    stale_crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(gen_time - timedelta(days=2))
        .next_update(gen_time)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    ok, reason_code, error = verifier._check_release_pinned_revocation(
        details=details,
        bundle={"certificates": [ca_cert], "crls": [stale_crl]},
    )

    assert ok is False
    assert reason_code == "not_validated_revocation_snapshot_stale"
    assert "does not cover" in str(error)


def test_release_pinned_revocation_future_snapshot_fails_closed(tmp_path: Path) -> None:
    details, ca_cert, ca_key = _revocation_details_for_local_receipt(tmp_path)
    gen_time = details["gen_time"]
    future_crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(gen_time + timedelta(seconds=1))
        .next_update(gen_time + timedelta(days=1))
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    ok, reason_code, error = verifier._check_release_pinned_revocation(
        details=details,
        bundle={"certificates": [ca_cert], "crls": [future_crl]},
    )

    assert ok is False
    assert reason_code == "not_validated_revocation_snapshot_stale"
    assert "does not cover" in str(error)


def test_release_pinned_revocation_invalidity_before_gentime_fails(
    tmp_path: Path,
) -> None:
    details, ca_cert, ca_key = _revocation_details_for_local_receipt(tmp_path)
    gen_time = details["gen_time"]
    signer_cert = details["signer_cert"]
    revoked = (
        x509.RevokedCertificateBuilder()
        .serial_number(signer_cert.serial_number)
        .revocation_date(gen_time + timedelta(days=1))
        .add_extension(x509.InvalidityDate(gen_time - timedelta(seconds=1)), critical=False)
        .build()
    )
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(gen_time - timedelta(days=1))
        .next_update(gen_time + timedelta(days=1))
        .add_revoked_certificate(revoked)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    ok, reason_code, error = verifier._check_release_pinned_revocation(
        details=details,
        bundle={"certificates": [ca_cert], "crls": [crl]},
    )

    assert ok is False
    assert reason_code == "tsa_certificate_revoked_at_gentime"
    assert "revoked or invalid" in str(error)


def test_checkpoint_tsa_trust_malformed_receipt_uses_imprint_failure_path(
    tmp_path: Path,
    run_cli,
):
    receipt = {
        "provider": "bad_local_tsa",
        "url": "https://tsa.local/bad",
        "requested_at": "2026-05-17T00:00:00Z",
        "receipt_b64": "not a valid timestamp token",
    }
    checkpoint_path = _checkpoint_with_receipt(tmp_path, receipt)

    result = run_cli(
        "checkpoint",
        "--json",
        str(checkpoint_path),
        "--self-attested",
        "--tsa-ca-bundle",
        str(tmp_path / "missing-ca.pem"),
    )
    payload = _json_result(result)

    assert result.returncode == 1
    assert payload["ok"] is False
    trust_receipt = payload["tsa_trust"]["receipts"][0]
    assert trust_receipt["tsa_trust_status"] == "invalid"
    assert trust_receipt["imprint_match"] is False
    assert trust_receipt["cms_signature_valid"] is False
    assert trust_receipt["certificate_chain_valid"] is False
    assert trust_receipt["eku_checked"] is False
    assert "TSA parse/verify failed" in trust_receipt["verification_error"]
