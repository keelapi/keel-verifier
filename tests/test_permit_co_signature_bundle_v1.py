"""Single-file ``keel.permit_co_signature/v1`` evidence-bundle adjudication.

These vectors are minted end to end — ES256 passkey, WebAuthn assertion,
Ed25519 Permit decision binding, Keel-signed key status manifest — so the
negative cases exercise real cryptography rather than shape assertions.

The outer evidence-bundle envelope is deliberately signed with a throwaway key.
That mirrors production: the envelope binds the parts together but is not
pinned to the Keel trust root, so every negative below must still fail on
independently pinned material.
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
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from keel_verifier import verifier
from keel_verifier.canonical.permit_binding import (
    canonical_resource_attributes_payload,
)

from test_permit_co_signature_v1 import (
    _public_key,
    _signature,
    _signed_trust_root,
    _write_json,
)


PERMIT_ID = "8e5c9672-387e-455c-84c5-c8709da93b93"
OTHER_PERMIT_ID = "11111111-2222-4333-8444-555555555555"
PROJECT_ID = "40a5edbc-8869-4579-80a3-26c739de30d0"
CO_SIGNER_ID = "60a0eed5-5cfb-4b60-8eaa-851536379144"
RP_ID = "dashboard.keelapi.com"
ORIGIN = "https://dashboard.keelapi.com"
CREDENTIAL_ID = "b5pioyJiCnOiwooD7TH72KMdrdk"


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _cose_es256(public_key: ec.EllipticCurvePublicKey) -> str:
    numbers = public_key.public_numbers()
    cose = (
        b"\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20"
        + numbers.x.to_bytes(32, "big")
        + b"\x22\x58\x20"
        + numbers.y.to_bytes(32, "big")
    )
    return _b64u(cose)


def _mint_assertion(
    private_key: ec.EllipticCurvePrivateKey,
    *,
    challenge_hex: str,
    origin: str = ORIGIN,
    rp_id: str = RP_ID,
    user_verified: bool = True,
    user_present: bool = True,
) -> dict[str, Any]:
    client_data = {
        "type": "webauthn.get",
        "challenge": _b64u(bytes.fromhex(challenge_hex)),
        "origin": origin,
        "crossOrigin": False,
    }
    client_data_bytes = json.dumps(
        client_data, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    flags = 0
    if user_present:
        flags |= 0x01
    if user_verified:
        flags |= 0x04
    # Backup eligible + backup state, matching a real synced passkey.
    flags |= 0x08 | 0x10
    auth_data = (
        hashlib.sha256(rp_id.encode("utf-8")).digest()
        + bytes([flags])
        + (7).to_bytes(4, "big")
    )
    signature = private_key.sign(
        auth_data + hashlib.sha256(client_data_bytes).digest(),
        ec.ECDSA(SHA256()),
    )
    return {
        "credential_id": CREDENTIAL_ID,
        "authenticator_data": _b64u(auth_data),
        "client_data_json": _b64u(client_data_bytes),
        "signature": _b64u(signature),
        "cose_alg": -7,
    }


def _requirement() -> dict[str, Any]:
    return {
        "type": "require_co_signature",
        "role": "approver",
        "phase": "pre_execution",
        "min_approvals": 1,
        "min_assurance": "any",
        "timeout_seconds": 3600,
    }


def _resource_attributes(*, requirement: dict[str, Any] | None) -> dict[str, Any]:
    attributes: dict[str, Any] = {
        "provider": "openai",
        "model": "gpt-5",
        "operation": "responses.create",
        "modality": "text",
    }
    if requirement is not None:
        attributes["permit_co_signature_requirement_v1"] = {
            "requirement": copy.deepcopy(requirement),
            "requirement_canonicalization": "rfc8785",
            "requirement_digest": verifier._prefixed_sha256(
                verifier.rfc8785.dumps(copy.deepcopy(requirement))
            ),
        }
    return attributes


def _permit_decision(
    binding_private: Ed25519PrivateKey,
    *,
    permit_id: str = PERMIT_ID,
    project_id: str = PROJECT_ID,
    requirement: dict[str, Any] | None,
    binding_version: str = "v7",
    binding_key_id: str | None = None,
) -> dict[str, Any]:
    attributes = _resource_attributes(requirement=requirement)
    # Mirrors the signed field set a production v7 binding carries; the
    # verifier rejects a canonical_payload that omits any of them.
    canonical_payload: dict[str, Any] = {
        "account_id": None,
        "action_name": "ai.generate.external_review_rehearsal",
        "authority_chain_digest": None,
        "authority_delta": None,
        "binding_key_id": binding_key_id
        or verifier._binding_key_id_from_public_key(_public_key(binding_private)),
        "binding_project_anchor_hash": None,
        "binding_session_event_hash": None,
        "binding_session_id": None,
        "binding_version": binding_version,
        "constraints": {"schema_version": 1},
        "decision": "challenge",
        "delegation_policy_hash": None,
        "expires_at": "2026-08-05T01:00:45.179351+00:00",
        "final_request_hash": None,
        "inherits_from": None,
        "is_dry_run": False,
        "issued_at": "2026-08-05T00:00:45.179351+00:00",
        "model": "gpt-4o-mini",
        "operation": "generate.text",
        "org_id": None,
        "parent_permit_id": None,
        "permit_chain_role": "session_root",
        "permit_id": permit_id,
        "policy_id": "4a010e53-c272-49ab-a386-c580d8014719",
        "policy_snapshot_hash": "5" * 64,
        "policy_version": "1",
        "project_id": project_id,
        "provider": "openai",
        "quota_reservation_id": None,
        "reason": "attestation_required",
        "request_fingerprint": "b" * 64,
        "routing": {"reason_code": "explicit_request", "fallback_chain": []},
        "spend_scope_hash": None,
        "subject_id": "external-review-requester",
        "subject_type": "service_principal",
    }
    if binding_version in {"v6", "v7"}:
        canonical_payload["resource_attributes_canonical_hash"] = (
            canonical_resource_attributes_payload(attributes)
        )
    binding_hash = verifier._compute_canonical_binding_hash(canonical_payload)
    return {
        "artifact_type": "permit_decision_binding",
        "artifact_version": "permit.decision.v1",
        "binding_version": binding_version,
        "canonical_payload": canonical_payload,
        "resource_attributes_json": attributes,
        "binding_canonical_hash": binding_hash,
        "binding_signature": "ed25519:"
        + base64.b64encode(
            binding_private.sign(binding_hash.encode("utf-8"))
        ).decode("ascii"),
        "binding_issued_at": canonical_payload["issued_at"],
        "expected_decision": "challenge",
    }


def _key_manifest(
    binding_private: Ed25519PrivateKey,
    *,
    binding_key_id: str,
    cose_key: str,
    key_id: str,
    allowed_origins: list[str],
    status: str = "active",
    valid_from: str = "2026-08-01T00:00:00+00:00",
    valid_until: str | None = None,
    revoked_at: str | None = None,
    compromised_at: str | None = None,
) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "manifest_type": "permit_v2.key_status_manifest.v1",
        "canonicalization_profile": "keel.canonical_json.payload.v1",
        "computed_at": "2026-08-05T00:07:23.718509+00:00",
        "account_id": PROJECT_ID,
        "key_scopes": list(verifier.KEY_STATUS_MANIFEST_SCOPES),
        "keys": [
            {
                "account_id": PROJECT_ID,
                "key_scope": "co_signer",
                "key_id": key_id,
                "credential_id": CREDENTIAL_ID,
                "public_key_cose": cose_key,
                "cose_alg": -7,
                "rp_id": RP_ID,
                "allowed_origins": allowed_origins,
                "custody_tier": "human_passkey",
                "status": status,
                "valid_from": valid_from,
                "valid_until": valid_until,
                "revoked_at": revoked_at,
                "compromised_at": compromised_at,
                "aaguid": "fbfc3007-154e-4ecc-8c0b-6e020557d7bd",
                "attestation_format": "none",
                "attestation_statement": None,
                "backup_eligible": True,
                "backup_state": True,
                "metadata": {"project_id": PROJECT_ID},
                "event_refs": [],
                "principal": {"kind": "co_signer", "id": CO_SIGNER_ID},
            }
        ],
        "signer": {
            "purpose": "permit_binding_signing",
            "key_id": binding_key_id,
            "algorithm": "ed25519",
        },
    }
    manifest_hash = verifier._key_status_manifest_hash_from_payload(manifest)
    manifest["manifest_hash"] = manifest_hash
    manifest["signature"] = base64.b64encode(
        binding_private.sign(manifest_hash.encode("utf-8"))
    ).decode("ascii")
    return manifest


def _wrap_bundle(
    body: dict[str, Any],
    *,
    schema_version: str = "keel.evidence_bundle/v2",
) -> dict[str, Any]:
    """Wrap a body in a self-attesting container with a throwaway envelope key.

    Co-signature bundles ship as v2 so that a verifier which cannot adjudicate
    the body profile refuses the file instead of reporting the envelope alone.
    """
    body = copy.deepcopy(body)
    material = {k: v for k, v in body.items() if k not in {"artifact_ref", "anchor"}}
    body["artifact_ref"] = {
        "id": body.get("permit_id"),
        "type": "permit_co_signature_evidence",
        "schema_version": 1,
        "digest": verifier._content_hash(
            verifier._bundle_canonical_json_bytes(material)
        ),
    }
    content_hash = verifier._content_hash(verifier._bundle_canonical_json_bytes(body))
    envelope_private = Ed25519PrivateKey.from_private_bytes(b"\x07" * 32)
    return {
        "schema_version": schema_version,
        "body": body,
        "signature_envelope": {
            "content_hash": content_hash,
            "signature": base64.b64encode(
                envelope_private.sign(content_hash.encode("utf-8"))
            ).decode("ascii"),
            "public_key_id": "test-envelope-key",
            "public_key": base64.b64encode(
                envelope_private.public_key().public_bytes(
                    Encoding.Raw, PublicFormat.Raw
                )
            ).decode("ascii"),
            "tsa_receipts": [],
            "tsa_attempts": [],
        },
    }


def _bundle_args(export_path: Path, trust_root: Path) -> argparse.Namespace:
    return argparse.Namespace(
        export_file=str(export_path),
        manifest=None,
        key_manifest=str(trust_root),
        key_manifest_url=None,
        expected_public_key=None,
        public_key=None,
        self_attested=False,
        offline=True,
        allow_unsigned=False,
        walk_events=False,
        verify_closure=False,
        as_json=True,
        sidecar=None,
        checkpoint=None,
    )


class Pack:
    """A complete, valid co-signature evidence bundle plus its trust root."""

    def __init__(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        *,
        with_requirement: bool = True,
    ) -> None:
        self.tmp_path = tmp_path
        self.export_private = Ed25519PrivateKey.generate()
        self.binding_private = Ed25519PrivateKey.generate()
        (
            self.trust_root,
            self.export_key_id,
            self.binding_key_id,
            self.export_public,
        ) = _signed_trust_root(
            tmp_path,
            export_private=self.export_private,
            binding_private=self.binding_private,
        )
        monkeypatch.setattr(verifier, "DEFAULT_TRUST_ROOT_PATH", self.trust_root)
        self.cosigner_private = ec.generate_private_key(ec.SECP256R1())
        self.cose_key = _cose_es256(self.cosigner_private.public_key())
        self.key_id = "sha256:" + hashlib.sha256(
            self.cose_key.encode("utf-8")
        ).hexdigest()
        self.requirement = _requirement() if with_requirement else None
        self.decision = _permit_decision(
            self.binding_private, requirement=self.requirement
        )
        self.manifest = _key_manifest(
            self.binding_private,
            binding_key_id=self.binding_key_id,
            cose_key=self.cose_key,
            key_id=self.key_id,
            allowed_origins=[ORIGIN],
        )
        self.claim = self._claim(self.decision["binding_canonical_hash"])

    def _claim(self, decision_hash: str, *, role: str = "approver") -> dict[str, Any]:
        return {
            "payload_type": "permit.co_signature.v2",
            "permit_id": PERMIT_ID,
            "permit_decision_canonical_hash": decision_hash,
            "co_signer_id": CO_SIGNER_ID,
            "role": role,
            "key_id": self.key_id,
            "custody_tier": "human_passkey",
            "signed_at": "2026-08-05T00:05:00+00:00",
            "assertion": _mint_assertion(
                self.cosigner_private, challenge_hex=decision_hash
            ),
        }

    def body(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "profile": "keel.permit_co_signature/v1",
            "profile_version": 1,
            "generated_at": "2026-08-05T00:07:23.718509+00:00",
            "permit_id": PERMIT_ID,
            "project_id": PROJECT_ID,
            "permit_decision": copy.deepcopy(self.decision),
            "co_signature_evidence": [
                {
                    "claim": copy.deepcopy(self.claim),
                    "allowed_origins": [ORIGIN],
                    "require_user_verification": True,
                }
            ],
            "key_status_manifest": copy.deepcopy(self.manifest),
            "claim_boundary": {
                "does_not_establish": [
                    "the legal identity of the co-signer",
                    "the correctness of the approver's judgement",
                ]
            },
        }
        if self.requirement is not None:
            body["co_signature_quorum_evidence"] = {
                "payload_type": "permit.co_signature.quorum_evidence.v1",
                "permit_id": PERMIT_ID,
                "permit_decision_canonical_hash": self.decision[
                    "binding_canonical_hash"
                ],
                "requirement": copy.deepcopy(self.requirement),
                "requirement_canonicalization": "rfc8785",
                "requirement_digest": verifier._prefixed_sha256(
                    verifier.rfc8785.dumps(copy.deepcopy(self.requirement))
                ),
                "eligible_co_signer_ids": [CO_SIGNER_ID],
                "co_signature_refs": [
                    {
                        "co_signer_id": CO_SIGNER_ID,
                        "claim_digest": verifier._prefixed_sha256(
                            verifier.rfc8785.dumps(copy.deepcopy(self.claim))
                        ),
                    }
                ],
            }
        return body

    def report(self, body: dict[str, Any]) -> Any:
        path = _write_json(self.tmp_path / "bundle.json", _wrap_bundle(body))
        return verifier.verify_export_structured(
            _bundle_args(path, self.trust_root)
        )


def _claims(report: Any) -> dict[str, dict[str, Any]]:
    return {claim["name"]: claim for claim in report.to_dict()["claims"]}


@pytest.fixture
def pack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Pack:
    return Pack(tmp_path, monkeypatch)


# ── positive ───────────────────────────────────────────────────────────────


def test_valid_bundle_verifies_and_reports_v2_claim(pack: Pack) -> None:
    report = pack.report(pack.body())
    claims = _claims(report)

    assert report.exit_code == 0, report.to_dict().get("error")
    assert claims["permit.decision.v1"]["verdict"] == "supported"
    assert claims["permit.co_signature.v2"]["verdict"] == "supported"
    assert claims["permit.co_signature.v2"]["reason_code"] == "CO_SIGNATURE_VERIFIED"
    assert claims["permit.co_signature.quorum.v1"]["verdict"] == "supported"


def test_generic_permit_without_exact_binding_still_verifies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Offline co-signature proof must not require an exact fact profile."""
    pack = Pack(tmp_path, monkeypatch, with_requirement=False)
    body = pack.body()
    assert "generate_text_exact_candidate_v1" not in body["permit_decision"][
        "resource_attributes_json"
    ]

    report = pack.report(body)
    claims = _claims(report)

    assert report.exit_code == 0
    assert claims["permit.co_signature.v2"]["verdict"] == "supported"
    assert "permit.co_signature.quorum.v1" not in claims


# ── tamper negatives ───────────────────────────────────────────────────────


def test_modified_permit_id_fails(pack: Pack) -> None:
    body = pack.body()
    body["co_signature_evidence"][0]["claim"]["permit_id"] = OTHER_PERMIT_ID

    report = pack.report(body)

    assert report.exit_code == 1
    assert _claims(report)["permit.co_signature.v2"]["verdict"] == "disproved"


def test_modified_decision_hash_fails(pack: Pack) -> None:
    body = pack.body()
    body["permit_decision"]["binding_canonical_hash"] = "a" * 64

    report = pack.report(body)

    assert report.exit_code == 1
    assert _claims(report)["permit.decision.v1"]["verdict"] != "supported"


def test_modified_co_signature_claim_fails(pack: Pack) -> None:
    body = pack.body()
    body["co_signature_evidence"][0]["claim"]["custody_tier"] = "software_key"

    report = pack.report(body)

    assert report.exit_code == 1
    assert _claims(report)["permit.co_signature.v2"]["verdict"] == "disproved"


def test_substituted_co_signer_identity_fails(pack: Pack) -> None:
    body = pack.body()
    body["co_signature_evidence"][0]["claim"]["co_signer_id"] = (
        "99999999-9999-4999-8999-999999999999"
    )

    report = pack.report(body)
    claim = _claims(report)["permit.co_signature.v2"]

    assert report.exit_code == 1
    assert claim["verdict"] != "supported"
    assert claim["reason_code"] == "CO_SIGNATURE_KEY_NOT_TRUSTED"


def test_signed_at_outside_quorum_timeout_fails(pack: Pack) -> None:
    """signed_at is not attested by the ceremony, but the quorum bounds it."""
    body = pack.body()
    claim = body["co_signature_evidence"][0]["claim"]
    # Well past issued_at + timeout_seconds, still inside the key validity window.
    claim["signed_at"] = "2026-08-05T20:00:00+00:00"
    body["co_signature_quorum_evidence"]["co_signature_refs"] = [
        {
            "co_signer_id": CO_SIGNER_ID,
            "claim_digest": verifier._prefixed_sha256(verifier.rfc8785.dumps(claim)),
        }
    ]

    report = pack.report(body)

    assert report.exit_code == 1
    assert _claims(report)["permit.co_signature.quorum.v1"]["verdict"] != "supported"


def test_modified_allowed_origin_fails(pack: Pack) -> None:
    body = pack.body()
    body["co_signature_evidence"][0]["allowed_origins"] = ["https://evil.example"]

    report = pack.report(body)
    claim = _claims(report)["permit.co_signature.v2"]

    assert report.exit_code == 1
    assert claim["verdict"] == "disproved"
    assert claim["reason_code"] == "CO_SIGNATURE_ORIGIN_NOT_ALLOWED"


def test_widened_allowed_origin_with_matching_assertion_fails(pack: Pack) -> None:
    """The load-bearing origin case.

    Narrowing the origin list is caught by the ceremony itself. Widening it —
    and supplying a genuine assertion collected at the attacker's origin — is
    caught only by the cross-check against the Keel-signed key record. This is
    the case that fails if that cross-check is ever removed.
    """
    body = pack.body()
    body["co_signature_evidence"][0]["allowed_origins"] = [
        ORIGIN,
        "https://evil.example",
    ]
    body["co_signature_evidence"][0]["claim"]["assertion"] = _mint_assertion(
        pack.cosigner_private,
        challenge_hex=pack.decision["binding_canonical_hash"],
        origin="https://evil.example",
    )

    report = pack.report(body)
    claim = _claims(report)["permit.co_signature.v2"]

    assert report.exit_code == 1
    assert claim["verdict"] == "disproved"
    assert claim["reason_code"] == "CO_SIGNATURE_ORIGIN_NOT_ALLOWED"


def test_modified_webauthn_assertion_fails(pack: Pack) -> None:
    body = pack.body()
    assertion = body["co_signature_evidence"][0]["claim"]["assertion"]
    raw = bytearray(base64.urlsafe_b64decode(assertion["signature"] + "=="))
    raw[-1] ^= 0xFF
    assertion["signature"] = _b64u(bytes(raw))

    report = pack.report(body)

    assert report.exit_code == 1
    assert _claims(report)["permit.co_signature.v2"]["verdict"] == "disproved"


def test_missing_key_status_manifest_fails(pack: Pack) -> None:
    body = pack.body()
    del body["key_status_manifest"]

    report = pack.report(body)
    claim = _claims(report)["permit.co_signature.v2"]

    assert report.exit_code == 1
    assert claim["reason_code"] == "CO_SIGNATURE_KEY_MANIFEST_UNTRUSTED"


def test_modified_key_status_manifest_fails(pack: Pack) -> None:
    body = pack.body()
    body["key_status_manifest"]["keys"][0]["rp_id"] = "evil.example"

    report = pack.report(body)
    claim = _claims(report)["permit.co_signature.v2"]

    assert report.exit_code == 1
    assert claim["reason_code"] == "CO_SIGNATURE_KEY_MANIFEST_UNTRUSTED"


def test_revoked_signing_key_fails(pack: Pack) -> None:
    pack.manifest = _key_manifest(
        pack.binding_private,
        binding_key_id=pack.binding_key_id,
        cose_key=pack.cose_key,
        key_id=pack.key_id,
        allowed_origins=[ORIGIN],
        status="revoked",
        revoked_at="2026-08-04T00:00:00+00:00",
    )

    report = pack.report(pack.body())
    claim = _claims(report)["permit.co_signature.v2"]

    assert report.exit_code == 1
    assert claim["reason_code"] == "CO_SIGNATURE_KEY_NOT_VALID"


def test_key_outside_validity_interval_fails(pack: Pack) -> None:
    pack.manifest = _key_manifest(
        pack.binding_private,
        binding_key_id=pack.binding_key_id,
        cose_key=pack.cose_key,
        key_id=pack.key_id,
        allowed_origins=[ORIGIN],
        valid_from="2026-08-05T06:00:00+00:00",
    )

    report = pack.report(pack.body())
    claim = _claims(report)["permit.co_signature.v2"]

    assert report.exit_code == 1
    assert claim["reason_code"] == "CO_SIGNATURE_KEY_NOT_VALID"


def test_valid_co_signature_bound_to_a_different_permit_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pack = Pack(tmp_path, monkeypatch)
    other_decision = _permit_decision(
        pack.binding_private,
        permit_id=OTHER_PERMIT_ID,
        requirement=pack.requirement,
    )
    body = pack.body()
    # A genuine, correctly signed ceremony — for the wrong Permit decision.
    body["permit_decision"] = other_decision

    report = pack.report(body)
    claim = _claims(report)["permit.co_signature.v2"]

    assert report.exit_code == 1
    assert claim["verdict"] == "disproved"
    assert claim["reason_code"] == "CO_SIGNATURE_PERMIT_BINDING_MISMATCH"


def test_user_verification_downgrade_is_rejected(pack: Pack) -> None:
    body = pack.body()
    body["co_signature_evidence"][0]["claim"]["assertion"] = _mint_assertion(
        pack.cosigner_private,
        challenge_hex=pack.decision["binding_canonical_hash"],
        user_verified=False,
    )
    body["co_signature_evidence"][0]["require_user_verification"] = False

    report = pack.report(body)
    claim = _claims(report)["permit.co_signature.v2"]

    assert report.exit_code == 1
    assert claim["reason_code"] == "CO_SIGNATURE_USER_VERIFICATION_DOWNGRADED"


# ── quorum / requirement negatives ─────────────────────────────────────────


def test_wrong_co_signature_requirement_fails(pack: Pack) -> None:
    body = pack.body()
    tampered = _requirement()
    tampered["min_approvals"] = 2
    body["co_signature_quorum_evidence"]["requirement"] = tampered
    body["co_signature_quorum_evidence"]["requirement_digest"] = (
        verifier._prefixed_sha256(verifier.rfc8785.dumps(tampered))
    )

    report = pack.report(body)
    claim = _claims(report)["permit.co_signature.quorum.v1"]

    assert report.exit_code == 1
    assert claim["reason_code"] == "CO_SIGNATURE_QUORUM_SIGNED_REQUIREMENT_MISMATCH"


def test_approver_witness_role_substitution_fails(pack: Pack) -> None:
    body = pack.body()
    claim = body["co_signature_evidence"][0]["claim"]
    claim["role"] = "witness"
    claim["assertion"] = _mint_assertion(
        pack.cosigner_private,
        challenge_hex=pack.decision["binding_canonical_hash"],
    )
    body["co_signature_quorum_evidence"]["co_signature_refs"] = [
        {
            "co_signer_id": CO_SIGNER_ID,
            "claim_digest": verifier._prefixed_sha256(verifier.rfc8785.dumps(claim)),
        }
    ]

    report = pack.report(body)

    assert report.exit_code == 1
    assert _claims(report)["permit.co_signature.quorum.v1"]["verdict"] != "supported"


def test_unsatisfied_quorum_fails(pack: Pack) -> None:
    body = pack.body()
    body["co_signature_quorum_evidence"]["co_signature_refs"] = []

    report = pack.report(body)

    assert report.exit_code == 1
    assert _claims(report)["permit.co_signature.quorum.v1"]["verdict"] != "supported"


def test_stripped_quorum_evidence_with_signed_requirement_fails(pack: Pack) -> None:
    """Removing quorum evidence must not silently narrow a green report."""
    body = pack.body()
    del body["co_signature_quorum_evidence"]

    report = pack.report(body)

    assert report.exit_code == 1
    assert (
        _claims(report)["permit.co_signature.quorum.v1"]["reason_code"]
        == "CO_SIGNATURE_QUORUM_EVIDENCE_MISSING"
    )


def test_quorum_on_unbound_resource_attributes_is_unverifiable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Below v6 the attributes are unsigned, so a requirement there is not proof."""
    pack = Pack(tmp_path, monkeypatch)
    pack.decision = _permit_decision(
        pack.binding_private,
        requirement=pack.requirement,
        binding_version="v1",
    )
    pack.claim = pack._claim(pack.decision["binding_canonical_hash"])

    report = pack.report(pack.body())
    claim = _claims(report)["permit.co_signature.quorum.v1"]

    assert report.exit_code == 1
    assert claim["reason_code"] == "CO_SIGNATURE_QUORUM_ATTRIBUTES_UNBOUND"


def test_wrong_project_fails(pack: Pack) -> None:
    body = pack.body()
    body["permit_decision"]["canonical_payload"]["project_id"] = OTHER_PERMIT_ID

    report = pack.report(body)

    assert report.exit_code == 1
    assert _claims(report)["permit.decision.v1"]["verdict"] != "supported"


# ── container / profile negatives ──────────────────────────────────────────


def test_unsigned_legacy_audit_bundle_is_not_self_attesting(
    pack: Pack, tmp_path: Path
) -> None:
    """The historical PermitAuditBundle must never pass as a signed bundle."""
    legacy = {
        "bundle_type": "permit_audit_bundle",
        "schema_version": 1,
        "permit_id": PERMIT_ID,
        "project_id": PROJECT_ID,
        "permit_decision": copy.deepcopy(pack.decision),
        "co_signature_evidence": [
            {
                "claim": copy.deepcopy(pack.claim),
                "allowed_origins": [ORIGIN],
                "require_user_verification": True,
            }
        ],
        "key_status_manifest": copy.deepcopy(pack.manifest),
    }
    path = _write_json(tmp_path / "legacy.json", legacy)

    report = verifier.verify_export_structured(
        _bundle_args(path, pack.trust_root)
    )

    assert report.exit_code == 1
    assert "keel.evidence_bundle/v1" in (report.to_dict().get("error") or "")


def test_unknown_co_signature_profile_fails_closed(pack: Pack) -> None:
    body = pack.body()
    body["profile"] = "keel.permit_co_signature/v9"

    report = pack.report(body)

    assert report.exit_code == 1
    assert "PERMIT_CO_SIGNATURE_PROFILE_UNSUPPORTED" in (
        report.to_dict().get("error") or ""
    )


def test_co_signature_evidence_without_declared_profile_fails_closed(
    pack: Pack,
) -> None:
    """The false-green hole: evidence present, no profile, envelope valid."""
    body = pack.body()
    del body["profile"]

    report = pack.report(body)

    assert report.exit_code == 1
    assert "CO_SIGNATURE_PROFILE_UNDECLARED" in (report.to_dict().get("error") or "")


def test_envelope_tamper_after_signing_fails(pack: Pack) -> None:
    """Re-signing is required to alter the body; a raw edit must not verify."""
    bundle = _wrap_bundle(pack.body())
    bundle["body"]["permit_id"] = OTHER_PERMIT_ID
    path = _write_json(pack.tmp_path / "tampered.json", bundle)

    report = verifier.verify_export_structured(
        _bundle_args(path, pack.trust_root)
    )

    assert report.exit_code == 1


# ── container-version contract ─────────────────────────────────────────────


def test_v1_container_still_verifies_for_existing_artifacts(pack: Pack) -> None:
    """Every previously issued keel.evidence_bundle/v1 must keep working."""
    body = {
        "profile": "keel.some_other_pack/v1",
        "permit_id": PERMIT_ID,
        "note": "a v1 bundle with no co-signature evidence",
    }
    path = _write_json(
        pack.tmp_path / "legacy-v1.json",
        _wrap_bundle(body, schema_version="keel.evidence_bundle/v1"),
    )

    report = verifier.verify_export_structured(_bundle_args(path, pack.trust_root))

    assert report.exit_code == 0, report.to_dict().get("error")
    assert (
        _claims(report)["evidence_bundle.self_attesting.v1"]["reason_code"]
        == "EVIDENCE_BUNDLE_SUPPORTED"
    )


def test_v2_container_with_unadjudicable_profile_fails_closed(pack: Pack) -> None:
    """v2's whole purpose: an unrecognised profile must not pass as green."""
    body = {
        "profile": "keel.future_pack/v1",
        "permit_id": PERMIT_ID,
    }
    path = _write_json(
        pack.tmp_path / "future-v2.json",
        _wrap_bundle(body, schema_version="keel.evidence_bundle/v2"),
    )

    report = verifier.verify_export_structured(_bundle_args(path, pack.trust_root))

    assert report.exit_code == 1
    assert "EVIDENCE_BUNDLE_V2_PROFILE_UNADJUDICATED" in (
        report.to_dict().get("error") or ""
    )


def test_unknown_container_version_fails_closed(pack: Pack) -> None:
    path = _write_json(
        pack.tmp_path / "future-v3.json",
        _wrap_bundle(pack.body(), schema_version="keel.evidence_bundle/v3"),
    )

    report = verifier.verify_export_structured(_bundle_args(path, pack.trust_root))

    assert report.exit_code == 1


def test_role_is_not_established_without_a_signed_requirement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Honest boundary, asserted rather than assumed.

    The WebAuthn assertion covers the Permit decision hash, not the role label.
    With no signed requirement there is no quorum claim to bind role against, so
    swapping approver->witness cannot fail — and the artifact must say so rather
    than let a reader infer the role was proven.
    """
    pack = Pack(tmp_path, monkeypatch, with_requirement=False)
    body = pack.body()
    body["co_signature_evidence"][0]["claim"]["role"] = "witness"
    body["co_signature_evidence"][0]["claim"]["assertion"] = _mint_assertion(
        pack.cosigner_private,
        challenge_hex=pack.decision["binding_canonical_hash"],
    )

    report = pack.report(body)
    summary = report.to_dict()["artifact"]["permit"]

    assert report.exit_code == 0
    assert summary["quorum_established"] is False
    assert summary["co_signatures"][0]["role_established"] is False
    assert any("role" in item for item in summary["does_not_establish"])


def test_role_is_established_when_quorum_binds_it(pack: Pack) -> None:
    report = pack.report(pack.body())
    summary = report.to_dict()["artifact"]["permit"]

    assert report.exit_code == 0
    assert summary["quorum_established"] is True
    assert summary["co_signatures"][0]["role_established"] is True
    assert "does_not_establish" not in summary
