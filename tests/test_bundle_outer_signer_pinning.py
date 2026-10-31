"""The outer signer of a self-attesting bundle must be anchored to a trusted key.

Through 3.28.2 the bundle envelope was checked against its own embedded
``public_key``, so anyone could fabricate or re-sign a bundle with a fresh key
and the default verifier reported it as verified. Every case here is a bundle
whose envelope signature is mathematically valid under the embedded key; only
the trust root decides whether it verifies.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from keel_verifier import verifier
from keel_verifier.cli import main
from keel_verifier.report_render import render_human

FIXTURES = Path(__file__).parent / "fixtures"
PRODUCTION_BUNDLES = FIXTURES / "production_bundles"
JOURNEY_KEYS = FIXTURES / "mcp_review_journey_keys.json"


@pytest.fixture(autouse=True)
def bundled_root_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Default mode must resolve the wheel's bundled root, not a user cache."""
    monkeypatch.setattr(
        verifier, "CACHED_TRUST_ROOT_PATH", tmp_path / "no-cached-trust-root.json"
    )


def _keypair() -> tuple[Ed25519PrivateKey, str, str]:
    private_key = Ed25519PrivateKey.generate()
    public_key = base64.b64encode(
        private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")
    return private_key, public_key, verifier._public_key_fingerprint(public_key)


def _refresh_artifact_ref(body: dict[str, Any]) -> None:
    body["artifact_ref"]["digest"] = verifier._artifact_ref_digest_for_body(
        verifier._bundle_artifact_ref_material(body)
    )


def _sign(
    bundle: dict[str, Any],
    private_key: Ed25519PrivateKey,
    public_key: str,
    key_id: str,
) -> dict[str, Any]:
    content_hash = verifier._content_hash(
        verifier._bundle_canonical_json_bytes(bundle["body"])
    )
    envelope = bundle.setdefault("signature_envelope", {})
    envelope.update(
        {
            "content_hash": content_hash,
            "signature": base64.b64encode(
                private_key.sign(content_hash.encode("utf-8"))
            ).decode("ascii"),
            "public_key": public_key,
            "public_key_id": key_id,
        }
    )
    envelope.setdefault("tsa_receipts", [])
    envelope.setdefault("tsa_attempts", [])
    return bundle


def _resign_with_fresh_key(bundle: dict[str, Any]) -> dict[str, Any]:
    private_key, public_key, key_id = _keypair()
    return _sign(bundle, private_key, public_key, key_id)


def _new_bundle(
    body: dict[str, Any],
    *,
    artifact_type: str,
    artifact_id: str,
    schema_version: str = "keel.evidence_bundle/v1",
) -> dict[str, Any]:
    body = copy.deepcopy(body)
    body["artifact_ref"] = {
        "schema_version": "artifact_ref.v1",
        "type": artifact_type,
        "id": artifact_id,
        "urn": f"urn:x-keel:artifact:{artifact_type}:{artifact_id}",
        "region": "us-west-1",
        "path": f"/v1/test/{artifact_id}",
        "canonical_url": f"https://api.keelapi.com/v1/test/{artifact_id}",
        "digest": "",
    }
    _refresh_artifact_ref(body)
    return {"schema_version": schema_version, "body": body}


def _write(tmp_path: Path, name: str, payload: dict[str, Any]) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    return path


def _manifest(tmp_path: Path, *entries: tuple[str, str, str]) -> Path:
    """Write a key manifest of ``(purpose, key_id, public_key)`` entries."""
    keys = [
        {
            "key_id": key_id,
            "algorithm": "ed25519",
            "public_key": "ed25519:" + public_key.removeprefix("ed25519:"),
            "purpose": purpose,
            "status": "active",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": None,
        }
        for purpose, key_id, public_key in entries
    ]
    return _write(tmp_path, "test-trust-root.json", {"keys": keys})


def _args(
    path: Path,
    *,
    key_manifest: Path | None = None,
    self_attested: bool = False,
    as_json: bool = True,
    as_raw: bool = False,
) -> argparse.Namespace:
    return argparse.Namespace(
        export_file=str(path),
        manifest=None,
        as_json=as_json,
        as_raw=as_raw,
        expected_public_key=None,
        key_manifest=str(key_manifest) if key_manifest is not None else None,
        key_manifest_url=None,
        self_attested=self_attested,
        allow_unsigned=False,
        walk_events=False,
        verify_closure=False,
        sidecar=None,
        checkpoint=None,
    )


def _envelope_claim(report: Any) -> dict[str, Any]:
    return next(
        claim
        for claim in report.to_dict()["claims"]
        if claim["name"] == "evidence_bundle.self_attesting.v1"
    )


def _assert_untrusted(report: Any) -> None:
    assert report.ok is False
    assert report.exit_code == 1
    claim = _envelope_claim(report)
    assert claim["reason_code"] == "BUNDLE_SIGNER_UNTRUSTED"
    assert claim["verdict"] == "insufficient_evidence"
    assert report.artifact["trust_source"] == verifier.UNTRUSTED_BUNDLE_SIGNER_TRUST_SOURCE


def _compliance_export() -> dict[str, Any]:
    return _new_bundle(
        {
            "schema": "keel.evidence/v1",
            "source": "keel",
            "generated_at": "2026-10-30T12:00:00Z",
            "project_id": "11111111-1111-4111-8111-111111111111",
            "export_id": "22222222-2222-4222-8222-222222222222",
            "decision_source": "Decision made by Keel",
            "record_count": 1,
            "records": [
                {
                    "decision": "allow",
                    "action": "wire transfer 2,500,000 USD",
                    "created_at": "2026-10-30T11:59:00Z",
                }
            ],
        },
        artifact_type="compliance_export",
        artifact_id="22222222-2222-4222-8222-222222222222",
    )


# ── fabricated bundles signed by a key the trust root has never seen ───────


def test_fabricated_compliance_export_fails_under_bundled_root(tmp_path: Path) -> None:
    path = _write(tmp_path, "fabricated.json", _resign_with_fresh_key(_compliance_export()))

    report = verifier.verify_export_structured(_args(path))

    _assert_untrusted(report)
    rendered = render_human(report.to_dict())
    assert "UNTRUSTED SIGNER" in rendered
    assert "VERIFIED" not in rendered


def test_fabricated_compliance_export_fails_under_explicit_manifest(
    tmp_path: Path,
) -> None:
    path = _write(tmp_path, "fabricated.json", _resign_with_fresh_key(_compliance_export()))

    report = verifier.verify_export_structured(_args(path, key_manifest=JOURNEY_KEYS))

    _assert_untrusted(report)


@pytest.mark.parametrize(
    "argv",
    [
        pytest.param(["{path}"], id="bare-file"),
        pytest.param(["export", "{path}"], id="export"),
        pytest.param(["export", "--offline", "{path}"], id="export-offline"),
        pytest.param(["export", "--json", "{path}"], id="export-json"),
        pytest.param(["export", "--raw", "{path}"], id="export-raw"),
    ],
)
def test_fabricated_compliance_export_exits_nonzero_on_every_cli_form(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    argv: list[str],
) -> None:
    path = _write(tmp_path, "fabricated.json", _resign_with_fresh_key(_compliance_export()))

    exit_code = main([arg.format(path=path) for arg in argv])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "VERIFIED" not in captured.out
    assert (
        "BUNDLE_SIGNER_UNTRUSTED" in captured.out
        or "UNTRUSTED SIGNER" in captured.out
        or "not anchored to a trusted key" in captured.err
    )


def test_fabricated_voice_attestation_fails(tmp_path: Path) -> None:
    bundle = _new_bundle(
        {
            "schema": "keel.voice.attestation.phase_a",
            "artifact_version": "1.2.0",
            "schema_version": 3,
            "session_metadata": {"session_id": "session_fabricated"},
            "project_chain_head": {
                "chain_scope": "project:11111111-1111-4111-8111-111111111111",
                "content_hash": "sha256:" + "8" * 64,
                "sequence": 7,
            },
            "timestamp_receipts": [],
        },
        artifact_type="voice_session_attestation",
        artifact_id="session_fabricated",
    )
    path = _write(tmp_path, "voice.json", _resign_with_fresh_key(bundle))

    _assert_untrusted(verifier.verify_export_structured(_args(path)))


# ── genuine production bundles re-signed by an attacker ────────────────────


@pytest.mark.parametrize(
    "name", ["homepage-compliance-export.json", "ai-ptrm-a66f7f81.json"]
)
def test_production_bundle_verifies_against_bundled_root(name: str) -> None:
    report = verifier.verify_export_structured(_args(PRODUCTION_BUNDLES / name))

    assert report.ok is True, report.to_dict().get("error")
    assert report.artifact["trust_source"].startswith(
        "bundled Keel production trust root"
    )
    assert "Keel production trust root" in render_human(report.to_dict())


@pytest.mark.parametrize(
    "name", ["homepage-compliance-export.json", "ai-ptrm-a66f7f81.json"]
)
def test_untampered_production_bundle_resigned_by_attacker_fails(
    tmp_path: Path, name: str
) -> None:
    bundle = json.loads((PRODUCTION_BUNDLES / name).read_text(encoding="utf-8"))
    path = _write(tmp_path, name, _resign_with_fresh_key(bundle))

    _assert_untrusted(verifier.verify_export_structured(_args(path)))


def test_permit_exact_with_emptied_declared_claims_resigned_fails(
    tmp_path: Path,
) -> None:
    bundle = json.loads(
        (PRODUCTION_BUNDLES / "ai-ptrm-a66f7f81.json").read_text(encoding="utf-8")
    )
    bundle["body"]["declared_claims"] = []
    _refresh_artifact_ref(bundle["body"])
    path = _write(tmp_path, "shrunk-claims.json", _resign_with_fresh_key(bundle))

    _assert_untrusted(verifier.verify_export_structured(_args(path)))


def test_attacker_key_presented_under_trusted_key_id_is_disproved(
    tmp_path: Path,
) -> None:
    bundle = json.loads(
        (PRODUCTION_BUNDLES / "homepage-compliance-export.json").read_text(
            encoding="utf-8"
        )
    )
    trusted_key_id = bundle["signature_envelope"]["public_key_id"]
    private_key, public_key, _ = _keypair()
    path = _write(
        tmp_path, "spoofed-key-id.json", _sign(bundle, private_key, public_key, trusted_key_id)
    )

    report = verifier.verify_export_structured(_args(path))

    assert report.ok is False
    assert report.exit_code == 1
    claim = _envelope_claim(report)
    assert claim["reason_code"] == "BUNDLE_SIGNER_KEY_MISMATCH"
    assert claim["verdict"] == "disproved"


def test_trusted_key_under_unknown_key_id_fails(tmp_path: Path) -> None:
    private_key, public_key, key_id = _keypair()
    manifest = _manifest(tmp_path, ("export_signing", key_id, public_key))
    bundle = _sign(_compliance_export(), private_key, public_key, key_id)
    genuine = _write(tmp_path, "genuine.json", bundle)
    assert verifier.verify_export_structured(_args(genuine, key_manifest=manifest)).ok

    bundle["signature_envelope"]["public_key_id"] = "sha256:" + "0" * 32
    path = _write(tmp_path, "unknown-key-id.json", bundle)

    _assert_untrusted(verifier.verify_export_structured(_args(path, key_manifest=manifest)))


# ── MCP review journeys: outer and nested envelopes ────────────────────────


def _journey() -> dict[str, Any]:
    return json.loads((FIXTURES / "mcp_review_journey_v1.json").read_text(encoding="utf-8"))


def _journey_manifest_with(tmp_path: Path, public_key: str, key_id: str) -> Path:
    """The journey fixture's keys plus one more export key the test controls."""
    manifest = json.loads(JOURNEY_KEYS.read_text(encoding="utf-8"))
    manifest["keys"].append(
        {
            "key_id": key_id,
            "algorithm": "ed25519",
            "public_key": "ed25519:" + public_key,
            "purpose": "export_signing",
            "status": "active",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": None,
        }
    )
    return _write(tmp_path, "journey-keys-plus.json", manifest)


def test_untampered_journey_resigned_by_attacker_fails(tmp_path: Path) -> None:
    path = _write(tmp_path, "journey.json", _resign_with_fresh_key(_journey()))

    _assert_untrusted(verifier.verify_export_structured(_args(path, key_manifest=JOURNEY_KEYS)))


@pytest.mark.parametrize("mutation", ["strip_does_not_establish", "backdate_generated_at"])
def test_mutated_journey_resigned_by_attacker_fails(tmp_path: Path, mutation: str) -> None:
    bundle = _journey()
    if mutation == "strip_does_not_establish":
        bundle["body"]["does_not_establish"] = []
    else:
        bundle["body"]["generated_at"] = "2026-01-01T00:00:00Z"
    _refresh_artifact_ref(bundle["body"])
    path = _write(tmp_path, f"journey-{mutation}.json", _resign_with_fresh_key(bundle))

    _assert_untrusted(verifier.verify_export_structured(_args(path, key_manifest=JOURNEY_KEYS)))


def test_journey_outer_signed_by_second_trusted_key_verifies(tmp_path: Path) -> None:
    private_key, public_key, key_id = _keypair()
    manifest = _journey_manifest_with(tmp_path, public_key, key_id)
    path = _write(tmp_path, "journey.json", _sign(_journey(), private_key, public_key, key_id))

    report = verifier.verify_export_structured(_args(path, key_manifest=manifest))

    assert report.ok is True, report.to_dict().get("error")


def test_journey_nested_bundle_resigned_by_attacker_fails(tmp_path: Path) -> None:
    private_key, public_key, key_id = _keypair()
    manifest = _journey_manifest_with(tmp_path, public_key, key_id)
    bundle = _journey()
    _resign_with_fresh_key(bundle["body"]["reviewed_permit_bundle"])
    _refresh_artifact_ref(bundle["body"])
    path = _write(tmp_path, "journey.json", _sign(bundle, private_key, public_key, key_id))

    report = verifier.verify_export_structured(_args(path, key_manifest=manifest))

    assert report.ok is False
    assert report.exit_code == 1
    assert any(
        claim["reason_code"] == "MCP_JOURNEY_BUNDLE_INVALID"
        and "reviewed_permit_bundle" in claim["message"]
        for claim in report.to_dict()["claims"]
    )


# ── integrity-checkpoint wrapper ───────────────────────────────────────────


def _checkpoint_bundle(
    tmp_path: Path,
    *,
    wrapper_key: tuple[Ed25519PrivateKey, str, str],
    checkpoint_key: tuple[Ed25519PrivateKey, str, str],
) -> Path:
    checkpoint_private, checkpoint_public, checkpoint_key_id = checkpoint_key
    scope = "project:11111111-1111-4111-8111-111111111111"
    composite = "sha256:" + hashlib.sha256(f"{scope}:1:abc".encode("utf-8")).hexdigest()
    checkpoint = {
        "checkpoint_id": "44444444-4444-4444-8444-444444444444",
        "computed_at": "2026-10-30T12:00:00Z",
        "chain_heads": {scope: {"sequence_number": 1, "last_record_hash": "abc"}},
        "composite_hash": composite,
        "signature": "ed25519:"
        + base64.b64encode(checkpoint_private.sign(composite.encode("utf-8"))).decode(
            "ascii"
        ),
        "public_key": "ed25519:" + checkpoint_public,
        "key_id": checkpoint_key_id,
        "tsa_receipts": [],
        "tsa_attempts": [],
    }
    bundle = _new_bundle(
        checkpoint,
        artifact_type="checkpoint_envelope",
        artifact_id=checkpoint["checkpoint_id"],
    )
    return _write(tmp_path, "checkpoint.json", _sign(bundle, *wrapper_key))


def test_checkpoint_wrapper_signed_by_untrusted_key_fails(tmp_path: Path) -> None:
    checkpoint_key = _keypair()
    _, checkpoint_public, checkpoint_key_id = checkpoint_key
    manifest = _manifest(
        tmp_path, ("integrity_checkpoint", checkpoint_key_id, checkpoint_public)
    )
    path = _checkpoint_bundle(tmp_path, wrapper_key=_keypair(), checkpoint_key=checkpoint_key)

    result = verifier.verify_checkpoint(path, key_manifest=str(manifest), check_tsa=False)

    assert result.ok is False
    assert {claim.reason_code for claim in result.claims} == {"BUNDLE_SIGNER_UNTRUSTED"}
    assert result.artifact["trust_source"] == verifier.UNTRUSTED_BUNDLE_SIGNER_TRUST_SOURCE


def test_checkpoint_wrapper_signed_by_trusted_key_verifies(tmp_path: Path) -> None:
    key = _keypair()
    _, public_key, key_id = key
    manifest = _manifest(
        tmp_path,
        ("integrity_checkpoint", key_id, public_key),
        ("export_signing", key_id, public_key),
    )
    path = _checkpoint_bundle(tmp_path, wrapper_key=key, checkpoint_key=key)

    result = verifier.verify_checkpoint(path, key_manifest=str(manifest), check_tsa=False)

    assert result.ok is True, result.error
    assert "EVIDENCE_BUNDLE_SUPPORTED" in {claim.reason_code for claim in result.claims}


def test_checkpoint_pin_does_not_pin_the_wrapper_signer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkpoint_key = _keypair()
    _, checkpoint_public, _ = checkpoint_key
    wrapper_key = _keypair()
    _, wrapper_public, wrapper_key_id = wrapper_key
    cached = _manifest(tmp_path, ("export_signing", wrapper_key_id, wrapper_public))
    monkeypatch.setattr(verifier, "CACHED_TRUST_ROOT_PATH", cached)
    path = _checkpoint_bundle(tmp_path, wrapper_key=wrapper_key, checkpoint_key=checkpoint_key)

    result = verifier.verify_checkpoint(
        path, expected_public_key="ed25519:" + checkpoint_public, check_tsa=False
    )

    assert result.ok is True, result.error
    assert "EVIDENCE_BUNDLE_SUPPORTED" in {claim.reason_code for claim in result.claims}


# ── --self-attested keeps the integrity-only check, labelled as such ───────


def test_self_attested_accepts_unknown_signer_but_says_so(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = _write(tmp_path, "fabricated.json", _resign_with_fresh_key(_compliance_export()))

    report = verifier.verify_export_structured(_args(path, self_attested=True))

    assert report.ok is True
    assert report.artifact["trust_source"].startswith("self-attested")
    assert "signer not authenticated" in _envelope_claim(report)["message"]
    assert any("does not prove Keel signed" in item for item in report.diagnostics)

    assert main(["export", "--self-attested", str(path)]) == 0
    rendered = capsys.readouterr().out
    assert "Self-attested (embedded key only)" in rendered
    assert "Does not prove Keel signed this artifact" in rendered
    assert "Keel production trust root" not in rendered
    assert "Pinned key" not in rendered
