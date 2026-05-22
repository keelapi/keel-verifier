from __future__ import annotations

from pathlib import Path

from step4_permit_helpers import (
    PROJECT_ID,
    keypair,
    revocation_event,
    write_permit_trust_root,
)
from keel_verifier.verifier import _adjudicate_permit_revoked_v1


def _claim(event: dict, trust_root: Path, *, project_id: str = PROJECT_ID):
    return _adjudicate_permit_revoked_v1(
        export_document={
            "project_id": project_id,
            "revocation_event": {"event": event},
        },
        manifest={},
        key_manifest_source=str(trust_root),
    )


def test_permit_revoked_supported(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"a" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)

    claim = _claim(revocation_event(private_key), trust_root)

    assert claim.aggregate_verdict == "supported"
    assert claim.reason_code == "PERMIT_REVOKED_SUPPORTED"


def test_permit_revoked_bad_signature_disproves(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"b" * 32)
    other_private_key, _other_public_key = keypair(b"c" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    event = revocation_event(private_key)
    event["signature"] = revocation_event(other_private_key)["signature"]

    claim = _claim(event, trust_root)

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "PERMIT_REVOKED_SIGNATURE_INVALID"


def test_permit_revoked_project_id_mismatch_disproves(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"d" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)

    claim = _claim(
        revocation_event(private_key),
        trust_root,
        project_id="00000000-0000-0000-0000-000000000099",
    )

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "PERMIT_REVOKED_PROJECT_ID_MISMATCH"


def test_permit_revoked_effective_at_must_equal_revoked_at(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"e" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)

    claim = _claim(
        revocation_event(
            private_key,
            effective_at="2026-05-21T10:06:00.000000Z",
        ),
        trust_root,
    )

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "PERMIT_REVOKED_EFFECTIVE_AT_MISMATCH"


def test_permit_revoked_missing_required_field_is_insufficient(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"f" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    event = revocation_event(private_key)
    event.pop("reason_code")

    claim = _claim(event, trust_root)

    assert claim.aggregate_verdict == "insufficient_evidence"
    assert claim.reason_code == "PERMIT_REVOKED_EVIDENCE_MISSING"


def test_permit_revoked_actor_pii_detected(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"g" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)

    claim = _claim(
        revocation_event(private_key, actor_id="operator@example.com"),
        trust_root,
    )

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "PERMIT_REVOKED_ACTOR_PII_DETECTED"
