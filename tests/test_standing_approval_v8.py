"""Standing-approval covered permits: signed reason, v8 binding, receipt block.

Earned-autonomy spec v4, piece V (sections 1.10 and 1.13). The verifier ships
before keel-api emits any of this, so these tests are the contract keel-api
must match.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import standing_approval_vectors as sav
from step4_permit_helpers import write_permit_trust_root
from keel_verifier import verifier
from keel_verifier.canonical import permit_binding
from keel_verifier.human_artifact import derive_human_artifact, derive_human_summary
from keel_verifier.report_render import build_report_lines, render_human
from keel_verifier.standing_approval import (
    STANDING_APPROVAL_COVERED_REASON,
    STANDING_APPROVAL_NOT_HUMAN_REVIEWED,
    coverage_view,
)
from keel_verifier.verdicts import ClaimVerdict

REPO_ROOT = Path(__file__).resolve().parents[1]
VECTORS_PATH = (
    REPO_ROOT / "tests" / "fixtures" / "permit_decision_binding_v8_standing_approval_vectors.json"
)
ALL_VERSIONS = ("v1", "v2", "v3", "v4", "v5", "v6", "v7")
HUMAN_REVIEW_WORDING = ("human-reviewed", "reviewed by", "approved by")


@pytest.fixture()
def trust_root(tmp_path: Path) -> Path:
    _private, public_key = sav.signing_key()
    return write_permit_trust_root(tmp_path, public_key)


def _claim(doc: dict[str, Any], trust_root: Path) -> ClaimVerdict:
    return verifier._adjudicate_permit_decision_v1(
        export_document=doc,
        key_manifest_source=str(trust_root),
    )


def _supported_statement(version_id: str | None = None) -> str:
    if version_id is not None:
        return f"pre-approved by standing approval version {version_id}; no per-action review"
    return (
        f"pre-approved by standing approval {sav.STANDING_APPROVAL_ID} v3; "
        "no per-action review"
    )


def _assert_never_human_reviewed(text: str) -> None:
    lowered = text.lower()
    for phrase in ("human-reviewed", "reviewed by a human", "reviewed by"):
        assert phrase not in lowered, text


# --- v8 canonicalization -----------------------------------------------------


def test_v8_payload_is_v7_plus_two_fields() -> None:
    v7 = permit_binding.canonical_binding_payload(
        binding_version="v7", **sav.builder_fields("v7")
    )
    v8 = permit_binding.canonical_binding_payload(
        binding_version="v8", **sav.builder_fields("v8")
    )
    assert set(v8) - set(v7) == {"standing_approval_version_id", "terms_digest"}
    assert {k: v for k, v in v8.items() if k in v7 and k != "binding_version"} == {
        k: v for k, v in v7.items() if k != "binding_version"
    }
    assert v8["binding_version"] == "v8"
    assert set(v8) == set(verifier._PERMIT_DECISION_CANONICAL_FIELDS_BY_VERSION["v8"])
    assert permit_binding.canonical_binding_bytes("v8", v8) == __import__(
        "rfc8785"
    ).dumps(v8)


def test_v8_builder_normalizes_and_requires_its_fields() -> None:
    fields = sav.builder_fields(
        "v8",
        standing_approval_version_id=sav.STANDING_APPROVAL_VERSION_ID.upper(),
        terms_digest="  " + sav.TERMS_DIGEST.upper().replace("SHA256:", "sha256:") + " ",
    )
    payload = permit_binding.canonical_binding_payload(binding_version="v8", **fields)
    assert payload["standing_approval_version_id"] == sav.STANDING_APPROVAL_VERSION_ID
    assert payload["terms_digest"] == sav.TERMS_DIGEST
    for override in (
        {"standing_approval_version_id": None},
        {"standing_approval_version_id": "not-a-uuid"},
        {"terms_digest": None},
        {"terms_digest": "sha256:abc"},
        {"terms_digest": "a" * 64},
    ):
        with pytest.raises(ValueError):
            permit_binding.canonical_binding_payload(
                binding_version="v8", **sav.builder_fields("v8", **override)
            )


def test_golden_vectors_are_byte_stable(trust_root: Path) -> None:
    fixture = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    assert fixture == json.loads(json.dumps(sav.golden_vectors(), sort_keys=True))
    public = Ed25519PublicKey.from_public_bytes(
        base64.b64decode(fixture["binding_public_key"].removeprefix("ed25519:"))
    )
    for vector in fixture["vectors"]:
        version = vector["binding_version"]
        payload = permit_binding.canonical_binding_payload(
            binding_version=version, **vector["builder_inputs"]
        )
        assert payload == vector["canonical_payload"]
        canonical = permit_binding.canonical_binding_bytes(version, payload)
        assert canonical.decode("utf-8") == vector["canonical_bytes_utf8"]
        assert list(json.loads(canonical)) == vector["canonical_key_order"]
        assert permit_binding.compute_canonical_binding_hash(payload) == (
            vector["binding_canonical_hash"]
        )
        public.verify(
            base64.b64decode(vector["binding_signature"].removeprefix("ed25519:")),
            vector["binding_canonical_hash"].encode("utf-8"),
        )
        evidence = {
            "artifact_type": "permit_decision_binding",
            "artifact_version": "permit.decision.v1",
            "canonical_payload": vector["canonical_payload"],
            "binding_canonical_hash": vector["binding_canonical_hash"],
            "binding_signature": vector["binding_signature"],
            "binding_issued_at": vector["canonical_payload"]["issued_at"],
            "resource_attributes_json": vector["resource_attributes_json"],
        }
        doc = sav.document(evidence, block=vector["permit_receipt_standing_approval"])
        claim = _claim(doc, trust_root)
        assert claim.aggregate_verdict == "supported", claim.message
        assert _supported_statement() in str(claim.message)


def test_v8_canonical_key_order_is_documented() -> None:
    fixture = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    v8 = next(v for v in fixture["vectors"] if v["binding_version"] == "v8")
    assert v8["canonical_key_order"] == sorted(
        verifier._PERMIT_DECISION_CANONICAL_FIELDS_BY_VERSION["v8"]
    )


# --- v8 verification ---------------------------------------------------------


def test_v8_signed_with_test_key_verifies_with_receipt(trust_root: Path) -> None:
    doc = sav.document(sav.decision_evidence("v8"), block=sav.receipt_block())
    claim = _claim(doc, trust_root)
    assert claim.aggregate_verdict == "supported", claim.message
    assert claim.reason_code == "PERMIT_DECISION_SUPPORTED"
    assert str(claim.message).endswith(_supported_statement())
    assert STANDING_APPROVAL_NOT_HUMAN_REVIEWED in claim.does_not_establish
    assert not any("below v8" in value for value in claim.does_not_establish)
    _assert_never_human_reviewed(str(claim.message))


def test_v8_without_receipt_block_names_the_signed_version(trust_root: Path) -> None:
    for include_receipt in (True, False):
        doc = sav.document(sav.decision_evidence("v8"), include_receipt=include_receipt)
        claim = _claim(doc, trust_root)
        assert claim.aggregate_verdict == "supported", claim.message
        assert str(claim.message).endswith(
            _supported_statement(sav.STANDING_APPROVAL_VERSION_ID)
        )


def test_v8_tampered_signed_terms_digest_fails(trust_root: Path) -> None:
    evidence = sav.decision_evidence("v8")
    evidence["canonical_payload"]["terms_digest"] = "sha256:" + "f" * 64
    claim = _claim(sav.document(evidence, block=sav.receipt_block()), trust_root)
    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "PERMIT_DECISION_CANONICAL_HASH_MISMATCH"


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("terms_digest", "sha256:" + "f" * 64),
        ("standing_approval_version_id", "5a000000-0000-4000-8000-0000000000ff"),
    ),
)
def test_v8_receipt_disagreeing_with_signed_binding_fails(
    trust_root: Path, field: str, value: str
) -> None:
    doc = sav.document(sav.decision_evidence("v8"), block=sav.receipt_block(**{field: value}))
    claim = _claim(doc, trust_root)
    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "STANDING_APPROVAL_RECEIPT_MISMATCH"
    assert f"permit_receipt.standing_approval.{field}" in claim.evidence


@pytest.mark.parametrize(
    ("overrides", "fragment"),
    (
        ({"terms_digest": "sha256:" + "F" * 64}, "terms_digest"),
        ({"terms_digest": "abc"}, "terms_digest"),
        ({"standing_approval_version_id": "nope"}, "standing_approval_version_id"),
        ({"reason": "policy.allow"}, "reason"),
        ({"decision": "deny"}, "decision"),
    ),
)
def test_v8_signed_payload_must_be_a_covered_binding(
    trust_root: Path, overrides: dict[str, Any], fragment: str
) -> None:
    # Bypass the builder's own checks: a hostile issuer can sign anything.
    payload = permit_binding.canonical_binding_payload(
        binding_version="v8", **sav.builder_fields("v8")
    )
    payload.update(overrides)
    claim = _claim(sav.document(sav.sign_payload(payload)), trust_root)
    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "PERMIT_DECISION_SCHEMA_INVALID"
    assert fragment in str(claim.message)


def test_v8_missing_signed_field_is_rejected(trust_root: Path) -> None:
    payload = permit_binding.canonical_binding_payload(
        binding_version="v8", **sav.builder_fields("v8")
    )
    del payload["terms_digest"]
    claim = _claim(sav.document(sav.sign_payload(payload)), trust_root)
    assert claim.aggregate_verdict == "insufficient_evidence"
    assert "terms_digest" in str(claim.message)


# --- v1-v7 with the covered reason ------------------------------------------


@pytest.mark.parametrize("version", ALL_VERSIONS)
def test_v1_to_v7_covered_reason_verifies_with_preapproved_wording(
    trust_root: Path, version: str
) -> None:
    evidence = sav.decision_evidence(version)
    assert evidence["canonical_payload"]["reason"] == STANDING_APPROVAL_COVERED_REASON

    bare = _claim(sav.document(evidence, include_receipt=False), trust_root)
    assert bare.aggregate_verdict == "supported", bare.message
    assert str(bare.message).endswith(
        "pre-approved by a standing approval; no per-action review"
    )
    assert STANDING_APPROVAL_NOT_HUMAN_REVIEWED in bare.does_not_establish
    assert any("below v8" in value for value in bare.does_not_establish)

    with_receipt = _claim(sav.document(evidence, block=sav.receipt_block()), trust_root)
    assert with_receipt.aggregate_verdict == "supported", with_receipt.message
    assert str(with_receipt.message).endswith(_supported_statement())
    _assert_never_human_reviewed(str(with_receipt.message))


@pytest.mark.parametrize("version", ALL_VERSIONS)
def test_covered_reason_on_v1_to_v7_does_not_cross_check_unsigned_ids(
    trust_root: Path, version: str
) -> None:
    # Below v8 nothing signs the version id or terms digest, so a receipt value
    # cannot contradict a signature; it is reported as receipt-stated only.
    block = sav.receipt_block(terms_digest="sha256:" + "e" * 64)
    claim = _claim(sav.document(sav.decision_evidence(version), block=block), trust_root)
    assert claim.aggregate_verdict == "supported", claim.message
    view = verifier._standing_approval_permit_view(
        sav.document(sav.decision_evidence(version), block=block)
    )
    assert view is not None
    assert view["signed"]["terms_digest"] is None
    assert view["receipt_reported"]["terms_digest"] == "sha256:" + "e" * 64


# --- older receipts ----------------------------------------------------------


@pytest.mark.parametrize("version", ("v1", "v7"))
def test_older_receipts_and_ordinary_permits_are_unaffected(
    trust_root: Path, version: str
) -> None:
    evidence = sav.decision_evidence(version, reason="policy.allow")
    for doc in (
        sav.document(evidence),
        sav.document(evidence, include_receipt=False),
    ):
        claim = _claim(doc, trust_root)
        assert claim.aggregate_verdict == "supported", claim.message
        assert claim.message == "permit decision canonical hash and signature are supported"
        assert not claim.does_not_establish
        assert claim.evidence == ["export.permit_decision", "trust_root"]
        assert verifier._standing_approval_permit_view(doc) is None


def test_receipt_block_without_signed_coverage_fails(trust_root: Path) -> None:
    evidence = sav.decision_evidence("v7", reason="policy.allow")
    claim = _claim(sav.document(evidence, block=sav.receipt_block()), trust_root)
    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "STANDING_APPROVAL_RECEIPT_UNSIGNED_COVERAGE"


# --- receipt block validation ------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    (
        {"per_action_review": True},
        {"per_action_review": None},
        {"per_action_review": 0},
        {"admin_review": "human_review"},
        {"facts_trust": "keel_verified"},
        {"assurance_level": "A1"},
        {"id": "not-a-uuid"},
        {"approval_version": 0},
        {"approval_version": True},
        {"approval_version": "3"},
        {"authorized_by": {"kind": "api_key", "id": "key_1"}},
        {"authorized_by": {"kind": "user", "id": ""}},
        {"authorized_by": None},
        {"co_approved_by": {"kind": "agent", "id": "agent_1"}},
        {"authorized_at": "2026-11-01"},
        {"expires_at": "2026-10-01T09:00:00+00:00"},
        {"origin": ""},
        {"usage": {"window": "rolling_24h", "used": 11, "cap": 10}},
        {"usage": {"window": "rolling_24h", "used": 1, "cap": 0}},
        {"usage": {"window": "", "used": 1, "cap": 10}},
        {"usage": None},
    ),
)
def test_malformed_receipt_block_fails(trust_root: Path, overrides: dict[str, Any]) -> None:
    doc = sav.document(sav.decision_evidence("v8"), block=sav.receipt_block(**overrides))
    claim = _claim(doc, trust_root)
    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "STANDING_APPROVAL_RECEIPT_INVALID"


def test_receipt_block_missing_fields_and_non_object_fail(trust_root: Path) -> None:
    block = sav.receipt_block()
    del block["usage"]
    for value in (block, "covered", [], False):
        doc = sav.document(sav.decision_evidence("v8"), block=value)  # type: ignore[arg-type]
        claim = _claim(doc, trust_root)
        assert claim.aggregate_verdict == "disproved"
        assert claim.reason_code == "STANDING_APPROVAL_RECEIPT_INVALID"


@pytest.mark.parametrize("version", ("v7", "v8"))
def test_null_receipt_block_means_absent(trust_root: Path, version: str) -> None:
    for reason in ("policy.allow", STANDING_APPROVAL_COVERED_REASON):
        if version == "v8" and reason != STANDING_APPROVAL_COVERED_REASON:
            continue
        doc = sav.document(sav.decision_evidence(version, reason=reason))
        doc["permit_receipt"]["standing_approval"] = None
        claim = _claim(doc, trust_root)
        assert claim.aggregate_verdict == "supported", claim.message


def test_permit_issued_outside_the_approval_window_fails(trust_root: Path) -> None:
    for block in (
        sav.receipt_block(expires_at="2026-11-13T10:00:00+00:00"),
        sav.receipt_block(authorized_at="2026-11-13T10:00:01+00:00"),
    ):
        claim = _claim(sav.document(sav.decision_evidence("v8"), block=block), trust_root)
        assert claim.aggregate_verdict == "disproved"
        assert claim.reason_code == "STANDING_APPROVAL_RECEIPT_MISMATCH"


def test_receipt_block_tolerates_unknown_keys_and_co_approver(trust_root: Path) -> None:
    block = sav.receipt_block(
        co_approved_by={"kind": "user", "id": "user_second"},
        future_field={"anything": True},
    )
    claim = _claim(sav.document(sav.decision_evidence("v8"), block=block), trust_root)
    assert claim.aggregate_verdict == "supported", claim.message


# --- human-facing projection -------------------------------------------------


def _report_for(doc: dict[str, Any], trust_root: Path) -> dict[str, Any]:
    claim = _claim(doc, trust_root)
    artifact: dict[str, Any] = {
        "kind": "export",
        "trust_source": "bundled Keel production trust root (test fixture)",
    }
    verifier._attach_permit_view(artifact, [claim], doc)
    return {
        "ok": True,
        "exit_code": 0,
        "artifact": artifact,
        "claims": [
            {
                "name": claim.name,
                "verdict": claim.aggregate_verdict,
                "required": True,
                "reason_code": claim.reason_code,
                "message": claim.message,
                "does_not_establish": list(claim.does_not_establish or []),
            }
        ],
    }


def test_permit_view_projects_coverage_only_after_verification(trust_root: Path) -> None:
    doc = sav.document(sav.decision_evidence("v8"), block=sav.receipt_block())
    report = _report_for(doc, trust_root)
    coverage = report["artifact"]["permit"]["standing_approval"]
    assert coverage["per_action_review"] is False
    assert coverage["admin_review"] == "satisfied_by_standing_approval"
    assert coverage["statement"] == _supported_statement()
    assert coverage["signed"] == {
        "reason": STANDING_APPROVAL_COVERED_REASON,
        "standing_approval_version_id": sav.STANDING_APPROVAL_VERSION_ID,
        "terms_digest": sav.TERMS_DIGEST,
    }
    assert coverage["receipt_reported"]["id"] == sav.STANDING_APPROVAL_ID

    tampered = sav.document(
        sav.decision_evidence("v8"),
        block=sav.receipt_block(terms_digest="sha256:" + "0" * 64),
    )
    assert "permit" not in _report_for(tampered, trust_root)["artifact"]


def test_human_summary_and_report_never_call_coverage_a_human_review(
    trust_root: Path,
) -> None:
    doc = sav.document(sav.decision_evidence("v8"), block=sav.receipt_block())
    report = _report_for(doc, trust_root)
    permit = report["artifact"]["permit"]
    permit.update({"agent": "agent-7", "target": "identity group commitment abc"})

    summary = derive_human_summary(
        report, evidence_state="VERIFIED", trust_mode={"label": "production"}
    )
    assert summary is not None
    assert (
        "No human reviewed this individual action: the admin review was satisfied by "
        f"standing approval {sav.STANDING_APPROVAL_ID} v3."
    ) in summary

    artifact = derive_human_artifact(
        report, evidence_state="VERIFIED", trust_mode={"label": "production"}
    )
    assert artifact is not None
    approval = artifact["authorization"]["approval"]
    assert approval["kind"] == "standing_approval"
    assert approval["per_action_review"] is False
    assert STANDING_APPROVAL_NOT_HUMAN_REVIEWED in (
        artifact["evidence_boundary"]["does_not_establish"]
    )

    lines = [line.text for line in build_report_lines(report)]
    assert (
        "  Admin review: satisfied by standing approval "
        f"{sav.STANDING_APPROVAL_ID} v3 (pre-approval); no per-action review"
    ) in lines
    rendered = render_human(report).lower()
    for phrase in HUMAN_REVIEW_WORDING:
        assert phrase not in rendered, phrase


def test_ordinary_allow_has_no_admin_review_line(trust_root: Path) -> None:
    doc = sav.document(sav.decision_evidence("v7", reason="policy.allow"))
    report = _report_for(doc, trust_root)
    assert "standing_approval" not in report["artifact"]["permit"]
    assert not any("Admin review" in line.text for line in build_report_lines(report))


def test_coverage_view_is_pure_projection() -> None:
    payload = permit_binding.canonical_binding_payload(
        binding_version="v7", **sav.builder_fields("v7")
    )
    view = coverage_view(payload, None)
    assert view["statement"] == "pre-approved by a standing approval; no per-action review"
    assert view["signed"]["standing_approval_version_id"] is None
    assert view["receipt_reported"] is None


# --- selector audit ----------------------------------------------------------


def _load_selector_audit():
    path = REPO_ROOT / "scripts" / "selector_audit.py"
    spec = importlib.util.spec_from_file_location("selector_audit_v8", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_v8_selector_audit_excludes_only_work_chains() -> None:
    """Every v7 selector also admits v8, except Work.

    Standing approvals never cover Work (spec section 1.5), so the Work v2
    root and child checks stay v7-only and fail closed on a v8 binding.
    """

    selector_audit = _load_selector_audit()
    result = selector_audit.audit_repo(REPO_ROOT, required_binding_version="v8")
    offenders = sorted(
        (failure.split(":")[0], failure.split(": ")[1].split(" uses ")[0])
        for failure in result.failures
    )
    assert offenders == [
        ("keel_verifier/work_chain_v2.py", "compare _authority_manifest_v2"),
        ("keel_verifier/work_chain_v2.py", "compare _child_containment_v2"),
    ], selector_audit.format_failures(result)


def test_decision_semantics_advertise_v8_fields() -> None:
    document = json.loads(
        (REPO_ROOT / "keel_verifier/data/semantics/permit/decision_v1.json").read_text()
    )
    body = document["body"]
    assert "v8" in body["binding_version"]["enum"]
    versioned = body["canonical_payload"]["versioned_fields"]
    assert versioned["v8"] == [*versioned["v7"], "standing_approval_version_id", "terms_digest"]
    assert STANDING_APPROVAL_COVERED_REASON in body["canonical_payload"]["standing_approval_rule"]

