from __future__ import annotations

import copy
from pathlib import Path

from step4_permit_helpers import (
    decision_evidence,
    keypair,
    write_permit_trust_root,
)
from keel_verifier.verifier import _adjudicate_permit_decision_v1


def _claim(evidence: dict, trust_root: Path):
    return _adjudicate_permit_decision_v1(
        export_document={"permit_decision": evidence},
        key_manifest_source=str(trust_root),
    )


def test_permit_decision_allow_supported(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"1" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)

    claim = _claim(decision_evidence(private_key, public_key), trust_root)

    assert claim.aggregate_verdict == "supported"
    assert claim.reason_code == "PERMIT_DECISION_SUPPORTED"


def test_permit_decision_bad_signature_disproves(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"2" * 32)
    other_private_key, _other_public_key = keypair(b"3" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    evidence = decision_evidence(private_key, public_key)
    evidence["binding_signature"] = decision_evidence(
        other_private_key,
        public_key,
    )["binding_signature"]

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "PERMIT_DECISION_SIGNATURE_INVALID"


def test_permit_decision_tampered_decision_field_disproves(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"4" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    evidence = decision_evidence(private_key, public_key, decision="deny")
    evidence["canonical_payload"] = copy.deepcopy(evidence["canonical_payload"])
    evidence["canonical_payload"]["decision"] = "allow"

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "PERMIT_DECISION_CANONICAL_HASH_MISMATCH"


def test_permit_decision_untrusted_key_is_insufficient(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"5" * 32)
    _trusted_private_key, trusted_public_key = keypair(b"6" * 32)
    trust_root = write_permit_trust_root(tmp_path, trusted_public_key)

    claim = _claim(decision_evidence(private_key, public_key), trust_root)

    assert claim.aggregate_verdict == "insufficient_evidence"
    assert claim.reason_code == "PERMIT_DECISION_UNTRUSTED_KEY"


def test_permit_decision_canonical_payload_mismatch_disproves(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"7" * 32)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    evidence = decision_evidence(
        private_key,
        public_key,
        decision="allow",
        expected_decision="deny",
    )

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "PERMIT_DECISION_CANONICAL_PAYLOAD_MISMATCH"
