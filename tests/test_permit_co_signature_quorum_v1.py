from __future__ import annotations

import copy
import hashlib
from typing import Any

import rfc8785

from keel_verifier.verdicts import ClaimVerdict, VerdictSubject
from keel_verifier.verifier import (
    _adjudicate_permit_co_signature_quorum_v1,
)


PERMIT_ID = "10000000-0000-4000-8000-000000000001"
SIGNER_ID = "20000000-0000-4000-8000-000000000001"
DECISION_HASH = "a" * 64


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _document() -> dict[str, Any]:
    requirement = {
        "type": "require_co_signature",
        "role": "approver",
        "signer_set": [{"user_id": SIGNER_ID}],
        "min_approvals": 1,
        "separation_of_duties": False,
        "timeout_seconds": 600,
        "phase": "pre_execution",
        "min_assurance": "any",
        "require_user_verification": True,
    }
    requirement_digest = _sha256(rfc8785.dumps(requirement))
    member = {
        "payload_type": "permit.co_signature.v2",
        "permit_id": PERMIT_ID,
        "permit_decision_canonical_hash": DECISION_HASH,
        "co_signer_id": SIGNER_ID,
        "role": "approver",
        "key_id": "sha256:" + "b" * 64,
        "custody_tier": "human_passkey",
        "signed_at": "2026-07-30T12:01:00.000000Z",
        "assertion": {
            "credential_id": "test",
            "authenticator_data": "test",
            "client_data_json": "test",
            "signature": "test",
            "cose_alg": -8,
        },
    }
    member_digest = _sha256(rfc8785.dumps(member))
    return {
        "permit_decision": {
            "canonical_payload": {
                "permit_id": PERMIT_ID,
                "issued_at": "2026-07-30T12:00:00.000000Z",
            },
            "binding_canonical_hash": DECISION_HASH,
            "resource_attributes_json": {
                "permit_co_signature_requirement_v1": {
                    "requirement": requirement,
                    "requirement_canonicalization": "rfc8785",
                    "requirement_digest": requirement_digest,
                }
            },
        },
        "co_signature_evidence": [
            {
                "claim": member,
                "allowed_origins": ["https://permit.example.test"],
                "require_user_verification": True,
            }
        ],
        "co_signature_quorum_evidence": {
            "payload_type": "permit.co_signature.quorum_evidence.v1",
            "permit_id": PERMIT_ID,
            "permit_decision_canonical_hash": DECISION_HASH,
            "requirement": requirement,
            "requirement_canonicalization": "rfc8785",
            "requirement_digest": requirement_digest,
            "eligible_co_signer_ids": [SIGNER_ID],
            "requester_id": None,
            "co_signature_refs": [
                {
                    "co_signer_id": SIGNER_ID,
                    "claim_digest": member_digest,
                }
            ],
        },
    }


def _decision_claim() -> ClaimVerdict:
    return ClaimVerdict(name="permit.decision.v1", verdict="supported")


def _member_claim(*, verdict: str = "supported") -> ClaimVerdict:
    return ClaimVerdict(
        name="permit.co_signature.v2",
        subjects=[
            VerdictSubject(
                type="permit_co_signature",
                id=SIGNER_ID,
                verdict=verdict,
            )
        ],
    )


def test_target_bound_quorum_is_supported() -> None:
    claim = _adjudicate_permit_co_signature_quorum_v1(
        export_document=_document(),
        decision_claim=_decision_claim(),
        member_claim=_member_claim(),
    )

    assert claim.aggregate_verdict == "supported"
    assert claim.reason_code == "CO_SIGNATURE_QUORUM_SUPPORTED"


def test_unsigned_requirement_copy_cannot_satisfy_quorum() -> None:
    document = _document()
    document["permit_decision"]["resource_attributes_json"].pop(
        "permit_co_signature_requirement_v1"
    )

    claim = _adjudicate_permit_co_signature_quorum_v1(
        export_document=document,
        decision_claim=_decision_claim(),
        member_claim=_member_claim(),
    )

    assert claim.aggregate_verdict == "insufficient_evidence"
    assert claim.reason_code == "CO_SIGNATURE_QUORUM_SIGNED_REQUIREMENT_MISSING"


def test_unsupported_member_cannot_satisfy_quorum() -> None:
    claim = _adjudicate_permit_co_signature_quorum_v1(
        export_document=_document(),
        decision_claim=_decision_claim(),
        member_claim=_member_claim(verdict="disproved"),
    )

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "CO_SIGNATURE_QUORUM_MEMBER_UNSUPPORTED"


def test_duplicate_signer_is_disproved() -> None:
    document = _document()
    document["co_signature_quorum_evidence"]["co_signature_refs"].append(
        copy.deepcopy(
            document["co_signature_quorum_evidence"]["co_signature_refs"][0]
        )
    )

    claim = _adjudicate_permit_co_signature_quorum_v1(
        export_document=document,
        decision_claim=_decision_claim(),
        member_claim=_member_claim(),
    )

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "CO_SIGNATURE_QUORUM_DUPLICATE_SIGNER"
