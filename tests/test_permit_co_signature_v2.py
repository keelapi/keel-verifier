from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keel_verifier import verifier
from keel_verifier.permit_co_signature import verify_protocol
from step4_permit_helpers import decision_payload
from test_permit_co_signature_v1 import (
    _args,
    _key_status_manifest,
    _public_key,
    _signature,
    _signed_trust_root,
    _write_json,
)


CORPUS_PATH = (
    Path(__file__).resolve().parents[1]
    / "keel_verifier"
    / "data"
    / "permit_to_x"
    / "test_vectors"
    / "permit_co_signature"
    / "v2"
    / "corpus.json"
)
if not CORPUS_PATH.is_file():
    raise RuntimeError(
        "bundled permit.co_signature.v2 corpus is missing; target-binding "
        "conformance must not pass vacuously"
    )
CORPUS = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
if not CORPUS.get("vectors"):
    raise RuntimeError("bundled permit.co_signature.v2 corpus is empty")


@pytest.mark.parametrize(
    "vector",
    CORPUS["vectors"],
    ids=lambda vector: vector["id"],
)
def test_v2_golden_corpus_matches_verdict_and_reason(
    vector: dict[str, Any],
) -> None:
    context = vector["verification_context"]
    result = verify_protocol(
        claim=vector["claim"],
        target_permit=context["permit_decision"],
        registered_key=vector["registered_cose_key"],
        allowed_origins=context["allowed_origins"],
        require_user_verification=context["require_user_verification"],
    )

    assert result.verdict == vector["expected"]["verdict"]
    assert result.reason == vector["expected"]["reason"]


def test_false_target_vector_is_valid_signature_but_disproved_binding() -> None:
    vector = next(
        vector
        for vector in CORPUS["vectors"]
        if vector["id"] == "negative-replay-different-permit"
    )
    context = vector["verification_context"]

    result = verify_protocol(
        claim=vector["claim"],
        target_permit=context["permit_decision"],
        registered_key=vector["registered_cose_key"],
        allowed_origins=context["allowed_origins"],
        require_user_verification=context["require_user_verification"],
    )

    assert result.verdict == "disproved"
    assert result.reason == "CO_SIGNATURE_PERMIT_BINDING_MISMATCH"


def test_signed_pack_rejects_valid_v2_assertion_for_false_signed_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vector = copy.deepcopy(
        next(
            vector
            for vector in CORPUS["vectors"]
            if vector["id"] == "negative-replay-different-permit"
        )
    )
    claim = vector["claim"]
    false_target = {
        "claim_name": "permit.decision.v1",
        "verdict": "supported",
        "permit_id": claim["permit_id"],
        "binding_canonical_hash": claim["permit_decision_canonical_hash"],
    }
    assertion_check = verify_protocol(
        claim=claim,
        target_permit=false_target,
        registered_key=vector["registered_cose_key"],
        allowed_origins=vector["verification_context"]["allowed_origins"],
        require_user_verification=True,
    )
    assert assertion_check.verdict == "supported"
    assert assertion_check.reason == "CO_SIGNATURE_VERIFIED"

    export_private = Ed25519PrivateKey.generate()
    binding_private = Ed25519PrivateKey.generate()
    trust_root, export_key_id, binding_key_id, export_public = _signed_trust_root(
        tmp_path,
        export_private=export_private,
        binding_private=binding_private,
    )
    monkeypatch.setattr(verifier, "DEFAULT_TRUST_ROOT_PATH", trust_root)
    binding_public = _public_key(binding_private)
    actual_payload = decision_payload(binding_public)
    actual_payload["permit_id"] = (
        vector["verification_context"]["permit_decision"]["permit_id"]
    )
    actual_hash = verifier._compute_canonical_binding_hash(actual_payload)
    permit_decision = {
        "artifact_type": "permit_decision_binding",
        "artifact_version": "permit.decision.v1",
        "canonical_payload": actual_payload,
        "binding_canonical_hash": actual_hash,
        "binding_signature": "ed25519:"
        + base64.b64encode(
            binding_private.sign(actual_hash.encode("utf-8"))
        ).decode("ascii"),
        "binding_issued_at": actual_payload["issued_at"],
    }
    key_manifest = _key_status_manifest(
        vector=vector,
        binding_private=binding_private,
        binding_key_id=binding_key_id,
    )
    export_document = {
        "bundle_type": "audit_export_bundle",
        "schema_version": 1,
        "permit_decision": permit_decision,
        "co_signature_evidence": [
            {
                "claim": claim,
                "allowed_origins": vector["verification_context"][
                    "allowed_origins"
                ],
                "require_user_verification": True,
            }
        ],
        "key_status_manifest": key_manifest,
    }
    export_path = _write_json(tmp_path / "export.json", export_document)
    digest = verifier._content_hash(export_path.read_bytes())
    manifest_path = _write_json(
        tmp_path / "manifest.json",
        {
            "content_hash": digest,
            "signature": _signature(export_private, digest),
            "public_key": export_public,
            "key_id": export_key_id,
            "signed_at": "2026-07-14T12:00:00Z",
        },
    )

    report = verifier.verify_export_structured(
        _args(export_path, manifest_path, trust_root)
    )
    claims = {claim["name"]: claim for claim in report.to_dict()["claims"]}

    assert report.exit_code == 1
    assert claims["permit.decision.v1"]["verdict"] == "supported"
    assert claims["permit.co_signature.v2"]["verdict"] == "disproved"
    assert (
        claims["permit.co_signature.v2"]["reason_code"]
        == "CO_SIGNATURE_PERMIT_BINDING_MISMATCH"
    )
