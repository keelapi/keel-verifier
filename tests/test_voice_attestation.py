from __future__ import annotations

import json
from pathlib import Path

from keel_verifier import verifier


REPO_ROOT = Path(__file__).resolve().parents[1]
VOICE_SAMPLE = REPO_ROOT / "sample" / "voice_session_export.json"
VOICE_SAMPLE_V3 = REPO_ROOT / "sample" / "voice_session_export_v3.json"


def test_phase_a_voice_attestation_v1_happy_path(run_cli):
    result = run_cli(str(VOICE_SAMPLE))

    assert result.returncode == 0, result.stderr
    assert "VERIFIED:" in result.stdout
    assert "sess_voice_sample_phase_a" in result.stdout
    assert "[PASS] issuer_signature" in result.stdout
    assert "[PASS] chain_integrity (2 events)" in result.stdout
    assert "[PASS] rfc3161_timestamp_receipt (1 receipt(s))" in result.stdout


def test_phase_a_voice_attestation_v3_happy_path(run_cli):
    result = run_cli(str(VOICE_SAMPLE_V3))

    assert result.returncode == 0, result.stderr
    assert "VERIFIED:" in result.stdout
    assert "sess_voice_sample_phase_a" in result.stdout
    assert "[PASS] issuer_signature" in result.stdout
    assert "[PASS] chain_integrity (2 events)" in result.stdout
    assert "[PASS] rfc3161_timestamp_receipt (1 receipt(s))" in result.stdout


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
    result = verifier.verify(VOICE_SAMPLE)

    assert result.ok
    assert result.artifact["kind"] == "voice_session_attestation"
    assert result.artifact["session_id"] == "sess_voice_sample_phase_a"


def test_phase_a_v3_format_auto_detection_programmatic_api():
    result = verifier.verify(VOICE_SAMPLE_V3)

    assert result.ok
    assert result.artifact["kind"] == "voice_session_attestation"
    assert result.artifact["session_id"] == "sess_voice_sample_phase_a"


def test_legacy_checkpoint_still_uses_legacy_verification_path():
    result = verifier.verify(REPO_ROOT / "sample" / "export.json", self_attested=True)

    assert result.ok
    assert result.artifact["kind"] == "checkpoint"
    assert result.checkpoint_id == "11111111-2222-3333-4444-555555555555"
