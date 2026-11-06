from __future__ import annotations

import base64
import json

import pytest

from conftest import keypair, write_json
from pathlib import Path

from keel_verifier import verifier


REPO_ROOT = Path(__file__).resolve().parents[1]
VOICE_SAMPLE = REPO_ROOT / "sample" / "voice_session_export.json"
VOICE_SAMPLE_V3 = REPO_ROOT / "sample" / "voice_session_export_v3.json"


def test_phase_a_voice_attestation_v1_happy_path(run_cli):
    result = run_cli(str(VOICE_SAMPLE), "--self-attested", "--no-tsa")

    assert result.returncode == 0, result.stderr
    assert "SELF-ATTESTED (UNTRUSTED):" in result.stdout
    assert "VERIFIED:" not in result.stdout
    assert "sess_voice_sample_phase_a" in result.stdout
    assert "[PASS] issuer_signature" in result.stdout
    assert "[PASS] chain_integrity (2 events)" in result.stdout
    assert "[SKIP] rfc3161_timestamp_receipt (0 receipt(s))" in result.stdout


def test_phase_a_voice_attestation_v3_happy_path(run_cli):
    result = run_cli(str(VOICE_SAMPLE_V3), "--self-attested", "--no-tsa")

    assert result.returncode == 0, result.stderr
    assert "SELF-ATTESTED (UNTRUSTED):" in result.stdout
    assert "VERIFIED:" not in result.stdout
    assert "sess_voice_sample_phase_a" in result.stdout
    assert "[PASS] issuer_signature" in result.stdout
    assert "[PASS] chain_integrity (2 events)" in result.stdout
    assert "[SKIP] rfc3161_timestamp_receipt (0 receipt(s))" in result.stdout


def test_phase_a_voice_attestation_v1_tamper_detection(tmp_path, run_cli):
    artifact = json.loads(VOICE_SAMPLE.read_text(encoding="utf-8"))
    artifact["chain"][1]["decision"] = "denied"
    tampered_path = tmp_path / "voice_session_export_tampered.json"
    tampered_path.write_text(json.dumps(artifact), encoding="utf-8")

    result = run_cli(str(tampered_path))

    assert result.returncode == 1
    assert "FAILED:" in result.stderr
    assert "issuer_signature" in result.stderr
    assert "chain_integrity" in result.stderr


def test_phase_a_voice_attestation_v3_hash_tamper_detection(tmp_path, run_cli):
    artifact = json.loads(VOICE_SAMPLE_V3.read_text(encoding="utf-8"))
    artifact["chain"][0]["canonicalized_payload_hash"] = (
        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    )
    tampered_path = tmp_path / "voice_session_export_v3_tampered.json"
    tampered_path.write_text(json.dumps(artifact), encoding="utf-8")

    result = run_cli(str(tampered_path))

    assert result.returncode == 1
    assert "FAILED:" in result.stderr
    assert "issuer_signature" in result.stderr
    assert "chain_integrity" in result.stderr


def test_phase_a_format_auto_detection_programmatic_api():
    result = verifier.verify(VOICE_SAMPLE, self_attested=True, check_tsa=False)

    assert result.ok
    assert result.artifact["kind"] == "voice_session_attestation"
    assert result.artifact["session_id"] == "sess_voice_sample_phase_a"


def test_phase_a_v3_format_auto_detection_programmatic_api():
    result = verifier.verify(VOICE_SAMPLE_V3, self_attested=True, check_tsa=False)

    assert result.ok
    assert result.artifact["kind"] == "voice_session_attestation"
    assert result.artifact["session_id"] == "sess_voice_sample_phase_a"


def test_legacy_checkpoint_still_uses_legacy_verification_path():
    result = verifier.verify(REPO_ROOT / "sample" / "export.json", self_attested=True)

    assert result.ok
    assert result.artifact["kind"] == "checkpoint"
    assert result.checkpoint_id == "11111111-2222-3333-4444-555555555555"


def _resign(artifact, private_key, public_key, key_id):
    canonical = verifier._voice_attestation_canonical_json_bytes(
        verifier._voice_attestation_signature_payload(artifact)
    )
    artifact["signatures"] = [{
        "algorithm": "ed25519", "public_key": public_key, "key_id": key_id,
        "key_purpose": "export_signing",
        "content_hash": verifier._voice_attestation_sha256_prefixed(canonical),
        "signature": "ed25519:" + base64.b64encode(private_key.sign(canonical)).decode(),
        "signed_at": "2000-01-01T00:00:00Z",
    }]
    return artifact


@pytest.mark.parametrize("sample", [VOICE_SAMPLE, VOICE_SAMPLE_V3])
def test_fresh_embedded_key_rejected_by_default(tmp_path, run_cli, sample):
    private, public, key_id = keypair()
    artifact = _resign(json.loads(sample.read_text()), private, public, key_id)
    path = write_json(tmp_path / "attacker.json", artifact)
    # The same internally valid object is rejected through both public entry points.
    assert verifier.verify_attestation_artifact(artifact, check_tsa=False)["verdict"] == "fail"
    assert not verifier.verify(path, check_tsa=False).ok
    result = run_cli(str(path), "--no-tsa")
    assert result.returncode == 1
    assert "issuer_signature" in result.stderr
    assert "VERIFIED:" not in result.stdout
    assert verifier.verify(path, public_key=public, check_tsa=False).ok
    assert not verifier.verify(path, public_key=keypair()[1], check_tsa=False).ok


def test_self_attested_json_provenance_and_skipped_tsa(run_cli):
    result = run_cli(str(VOICE_SAMPLE), "--self-attested", "--no-tsa", "--json")
    assert result.returncode == 0
    report = json.loads(result.stdout)
    assert report["self_attested"] is True
    assert report["trust_source"].startswith("self-attested")
    assert report["tsa"]["checked"] is False
    assert report["tsa"]["verified"] is None
    assert report["tsa_chain_validation"] == "not_validated"
    assert report["tsa_receipts"][0]["verified"] is None


@pytest.mark.parametrize("status,valid_from,valid_to,accepted", [
    ("active", "2026-01-01T00:00:00Z", None, True),
    ("retired", "2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z", True),
    ("revoked", "2026-01-01T00:00:00Z", None, False),
    ("compromised", "2026-01-01T00:00:00Z", None, False),
    ("active", "2026-06-01T00:00:00Z", None, False),
    ("retired", "2026-01-01T00:00:00Z", "2026-05-01T00:00:00Z", False),
])
def test_manifest_key_lifecycle_uses_signed_issued_at(
    tmp_path, status, valid_from, valid_to, accepted,
):
    private, public, key_id = keypair()
    artifact = _resign(json.loads(VOICE_SAMPLE.read_text()), private, public, key_id)
    manifest = write_json(tmp_path / "keys.json", {"keys": [{
        "key_id": key_id, "public_key": public, "purpose": "export_signing",
        "status": status, "valid_from": valid_from, "valid_to": valid_to,
    }]})
    result = verifier.verify_attestation_artifact(
        artifact, key_manifest=str(manifest), check_tsa=False,
    )
    assert (result["verdict"] == "pass") is accepted


@pytest.mark.parametrize("sample", [VOICE_SAMPLE, VOICE_SAMPLE_V3])
def test_matching_imprint_unsigned_cms_rejected(run_cli, sample):
    # Shipped samples contain a matching imprint but no authentic CMS signer.
    artifact = json.loads(sample.read_text())
    receipt = artifact["rfc3161_timestamp_receipt"]
    assert verifier._verify_tsa_receipt(
        receipt["tsa_response_base64"], receipt["request_hash"].removeprefix("sha256:")
    )[0]
    result = verifier.verify_attestation_artifact(artifact, self_attested=True)
    timestamp = next(c for c in result["checks"] if c["name"] == "rfc3161_timestamp_receipt")
    assert timestamp["result"] == "fail"
    assert result["verdict"] == "fail"
    cli = run_cli(str(sample), "--self-attested")
    assert cli.returncode == 1


def _public_tsa_artifact():
    artifact = json.loads(VOICE_SAMPLE.read_text())
    receipt = json.loads(
        (REPO_ROOT / "tests/fixtures/tsa/public_ca_receipts_v1.json").read_text()
    )["receipts"][0]
    head = "sha256:" + receipt["content_hash_hex"]
    artifact["project_chain_head"]["content_hash"] = head
    artifact["timestamp_receipts"] = [{
        "request_hash": head, "covers_chain_head_hash": head,
        "tsa_response_base64": receipt["receipt_b64"], "provider": receipt["provider"],
    }]
    artifact.pop("rfc3161_timestamp_receipt")
    private, public, key_id = keypair()
    return _resign(artifact, private, public, key_id), public


def test_trusted_voice_and_real_tsa_success(tmp_path, run_cli):
    artifact, public = _public_tsa_artifact()
    path = write_json(tmp_path / "voice.json", artifact)
    result = verifier.verify(path, public_key=public)
    assert result.ok, result.error
    assert result.trust_source == "user-supplied"
    assert not result.self_attested
    assert result.tsa_verified is True
    assert result.tsa_chain_validation == "validated"
    assert result.tsa_trust["revocation_checked"] is True
    cli = run_cli(str(path), "--public-key", public)
    assert cli.returncode == 0, cli.stderr
    assert "VERIFIED:" in cli.stdout


def test_tsa_unsupported_runtime_fails_closed(monkeypatch):
    artifact, public = _public_tsa_artifact()
    monkeypatch.setattr(verifier, "_openssl_tsa_runtime_status", lambda: {
        "supported": False, "verification_error": "unsupported test runtime",
    })
    result = verifier.verify_attestation_artifact(artifact, public_key=public)
    assert result["verdict"] == "fail"
    assert result["tsa_trust"]["tsa_chain_validation"] == "not_validated"


def test_tsa_other_receipt_copy_cannot_bypass_binding():
    artifact, public = _public_tsa_artifact()
    artifact["rfc3161_timestamp_receipt"] = {
        **artifact["timestamp_receipts"][0], "request_hash": "sha256:" + "00" * 32,
    }
    # Pinning the issuer cannot make a mismatching receipt pass.
    private, public, key_id = keypair()
    _resign(artifact, private, public, key_id)
    result = verifier.verify_attestation_artifact(artifact, public_key=public)
    assert result["verdict"] == "fail"
    assert any("project_chain_head" in c.get("reason", "") for c in result["failed_checks"])
