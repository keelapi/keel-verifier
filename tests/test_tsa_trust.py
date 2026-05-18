from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from keel_verifier import verifier


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


def _run_openssl(args: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["openssl", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )


def _require_openssl_3_for_tsa() -> str:
    try:
        completed = subprocess.run(
            ["openssl", "version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except FileNotFoundError:
        pytest.skip("openssl executable not available")
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
    ca_bundle = tmp_path / "ca.pem"
    ca_bundle.write_text("not a real ca", encoding="utf-8")

    def fake_run(cmd, *_args, **_kwargs):
        if cmd == ["openssl", "version"]:
            raise FileNotFoundError
        raise AssertionError("openssl ts -verify should not run")

    monkeypatch.setattr(verifier.subprocess, "run", fake_run)
    report = verifier._build_tsa_trust_report(
        [checkpoint["tsa"]],
        checkpoint["composite_hash"].removeprefix("sha256:"),
        ca_bundle_path=str(ca_bundle),
    )

    receipt = report["receipts"][0]
    assert receipt["tsa_trust_status"] == "unsupported_runtime"
    assert receipt["imprint_match"] is True
    assert "not found" in receipt["verification_error"]


def test_checkpoint_tsa_trust_valid_bundle_json_and_human_output(
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
    assert payload["tsa_trust"]["ca_bundle"] == str(ca_bundle)
    assert payload["tsa_trust"]["openssl_version"].startswith("OpenSSL 3")
    assert payload["tsa_trust"]["revocation_checked"] is False
    assert "not checked" in payload["tsa_trust"]["revocation_note"]
    trust_receipt = payload["tsa_trust"]["receipts"][0]
    assert trust_receipt["provider"] == "local_test_tsa"
    assert trust_receipt["tsa_trust_status"] == "valid"
    assert trust_receipt["imprint_match"] is True
    assert trust_receipt["cms_signature_valid"] is True
    assert trust_receipt["certificate_chain_valid"] is True
    assert trust_receipt["eku_checked"] is True
    assert trust_receipt["eku_valid"] is True
    assert trust_receipt["verification_error"] is None

    human = run_cli(
        "checkpoint",
        str(checkpoint_path),
        "--self-attested",
        "--tsa-ca-bundle",
        str(ca_bundle),
    )
    assert human.returncode == 0, human.stderr
    assert "TSA[1] TRUST: OK" in human.stdout
    assert "against supplied CA bundle" in human.stdout
    assert "historical revocation status at issuance is not checked" in human.stdout


def test_checkpoint_tsa_trust_wrong_ca_bundle_invalid_exit_one(
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

    assert result.returncode == 1
    assert payload["ok"] is True
    assert payload["exit_code"] == 1
    trust_receipt = payload["tsa_trust"]["receipts"][0]
    assert trust_receipt["tsa_trust_status"] == "invalid"
    assert trust_receipt["imprint_match"] is True
    assert trust_receipt["cms_signature_valid"] is False
    assert trust_receipt["certificate_chain_valid"] is False
    assert trust_receipt["eku_checked"] is True
    assert trust_receipt["eku_valid"] is False
    assert trust_receipt["verification_error"]


def test_checkpoint_without_tsa_ca_bundle_skips_trust_and_leaves_claims_unchanged(
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
    assert plain_payload["tsa_trust"]["receipts"][0]["tsa_trust_status"] == "skipped"
    assert plain_payload["ok"] == trusted_payload["ok"]
    assert plain_payload["claims"] == trusted_payload["claims"]
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
    assert "TSA[1] TRUST" not in human_plain.stdout


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
