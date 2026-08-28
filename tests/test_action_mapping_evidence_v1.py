"""Managed MCP Action Mapping evidence — ACTION_MAPPING_SPEC.md §8, §10.

Covers §10 tests 44, 47, and 48 for the verifier half of WP9.

The construction rule these tests obey: no test may pass through the defect it
names. Test 47 must fail when only the mapping *hash* is bound, so every
individually-required field is dropped one at a time. Test 48 must fail when
only a disclaimer string is present, so the positive statements are asserted to
be *structurally gated* — removing the supporting artifact must remove the
statement — and the banned phrasings are asserted absent from every rendered
line, not merely accompanied by a caveat.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from keel_verifier.canonical.permit_binding import (
    canonical_resource_attributes_payload,
)
from keel_verifier.permit_exact_v2 import (
    ACTION_MAPPING_ATTRIBUTE_KEY,
    ACTION_MAPPING_BINDING_STATEMENT,
    ACTION_MAPPING_CLAIMS,
    ACTION_MAPPING_INTERPRETATION_STATEMENT,
    MCP_ACTION_MAPPING_BINDING_CLAIM,
    MCP_GOVERNANCE_INTERPRETATION_CLAIM,
    MCP_STRUCTURAL_HOLD_EVIDENCE_CLAIM,
    UNIVERSAL_CLAIMS,
    adjudicate_permit_exact_v2_body,
)
from keel_verifier.report_render import build_report_lines

from tests.test_permit_exact_v2 import _body, _digest_bytes, _pin


ROOT = Path(__file__).resolve().parents[1] / "keel_verifier" / "data"

GOVERNANCE_ACTION_ID = "payment.refund"
STRUCTURAL_CLAIMS = (
    MCP_ACTION_MAPPING_BINDING_CLAIM,
    MCP_STRUCTURAL_HOLD_EVIDENCE_CLAIM,
)
EXECUTION_CLAIMS = (
    MCP_ACTION_MAPPING_BINDING_CLAIM,
    MCP_GOVERNANCE_INTERPRETATION_CLAIM,
)

# §10 test 48: phrasings the verifier must never emit. Each is banned because
# the artifact under adjudication cannot witness it.
BANNED_PHRASES = (
    "required human approval before dispatch",
    "two humans approved",
    "two-human approval",
    "verifies the WebAuthn assertion",
    "independently verifies the WebAuthn",
    "the human understood",
    "provider accepted",
    "downstream effect",
    "was dispatched",
)


def _hash(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _mapping_evidence(*, artifact_class: str) -> dict[str, Any]:
    """A complete, well-formed Action Mapping evidence block."""

    block: dict[str, Any] = {
        "version": "keel.mcp_action_mapping_evidence.v1",
        "enforcement_surface_key": "managed_mcp:action_mapping",
        "artifact_class": artifact_class,
        "permit_action_name": "mcp.tool.call",
        "source": {
            "mcp_server_id": "mcp_server_arbitrary",
            "source_tool_name": "payment.issue_refund",
            "accepted_tool_schema_hash": _hash("accepted"),
            "observed_tool_schema_hash": _hash("accepted"),
            "tool_arguments_hash": _hash("arguments"),
            "tool_contract_status": "verified",
        },
        "mapping": {
            "mapping_id": "mapping_arbitrary_refund",
            "mapping_revision": "revision_3",
            "manifest_hash": _hash("manifest"),
            "lifecycle_epoch": 7,
            "lifecycle_state": "active",
            "assurance": "human_mapped_review_only",
            "classification_provenance": "human_approved_action_mapping",
            "certified_action_contract": {"state": "absent"},
        },
        "governance_action": {
            "governance_action_id": GOVERNANCE_ACTION_ID,
            "governance_action_version": "2026.08.1",
            "catalog_entry_hash": _hash("catalog"),
        },
        "structural": {
            "challenge_class": (
                "action_review" if artifact_class == "execution" else "structural_hold"
            ),
            "challenge_basis_hash": _hash("basis"),
            "challenge_basis_version": "mcp_challenge_basis.v2",
            "reason_code": (
                "mcp.mapping_review_required"
                if artifact_class == "execution"
                else "mcp.financial_facts_incomplete"
            ),
            "typed_absence_hash": _hash("typed-absence"),
            "derivation_diagnostics_hash": _hash("diagnostics"),
        },
        "activation": {
            "activation_record_id": "activation_record_1",
            "activation_record_hash": _hash("activation"),
            "activated_lifecycle_epoch": 7,
        },
    }
    if artifact_class == "structural_decision":
        block["structural"]["unavailable_fact_paths"] = [
            "facts.refund.amount_minor",
            "facts.refund.original_payment_reference",
        ]
        return block
    block["approval"] = {
        "claim_record_id": "claim_1",
        "reviewed_permit_id": "permit_reviewed",
        "execution_permit_id": "permit_test",
        "original_trace_id": "trace_original",
        "current_trace_id": "trace_current",
        "exact_request_review_hash": _hash("exact-review"),
        "approval_requirement_hash": _hash("requirement"),
        "exact_request_binding_hash": _hash("exact-request"),
        "idempotency_binding_hash": _hash("idempotency"),
        "idempotency_binding_version": "mcp_idempotency_binding.v1",
        "consumed_at": "2026-07-30T12:15:00Z",
        "governed_request_id": "governed_request_1",
        "dispatch_claim": {
            "state": "acquired",
            "dispatch_claim_reference": "dispatch_claim_1",
            "claimed_lifecycle_epoch": 7,
        },
    }
    return block


def _mapping_body(*, artifact_class: str = "execution") -> dict[str, Any]:
    """An exact pack pinning claim registry v7 and universal recipe v6.

    The semantic binding still resolves the bundled payment_execute selector
    entry: no `mcp.tool.call` selector entry exists in any bundled keel-permit
    semantic registry, and publishing one is keel-permit's artifact, not the
    verifier's. Action Mapping adjudication is independent of the fact profile,
    and the governance-action substitution check below is asserted against the
    resolved authorized action precisely so that this stand-in cannot hide it.
    """

    body = _body()
    claim_path = ROOT / "claim_registry/v7.json"
    universal_path = ROOT / "semantics/permit/universal_verification_v6.json"
    declared = [*body["declared_claims"]]
    declared.extend(
        EXECUTION_CLAIMS if artifact_class == "execution" else STRUCTURAL_CLAIMS
    )
    body.update({"profile": "keel.permit_exact/v3", "profile_version": 3})
    body["declared_claims"] = declared
    binding = body["semantic_binding"]
    binding.update(
        {
            "claim_registry_version": "verifier-claims.v7",
            "claim_registry_digest": _digest_bytes(claim_path.read_bytes()),
            "universal_semantics_id": "keel.permit.universal_verification.v6",
            "universal_semantics_digest": _digest_bytes(universal_path.read_bytes()),
        }
    )
    body["contract_pins"]["claim_registry"] = _pin(
        claim_path,
        artifact_id="keel.verifier_claim_registry.v7",
    )
    body["contract_pins"]["universal_semantics"] = _pin(
        universal_path,
        artifact_id="keel.permit.universal_verification.v6",
    )
    attributes = body["permit_decision"]["resource_attributes_json"]
    attributes["permit_semantic_binding_v2"] = copy.deepcopy(binding)
    attributes[ACTION_MAPPING_ATTRIBUTE_KEY] = _mapping_evidence(
        artifact_class=artifact_class
    )
    if artifact_class == "structural_decision":
        body["decision_state"] = {"decision": "challenge", "status": "awaiting_review"}
        body["permit_decision"]["canonical_payload"]["decision"] = "challenge"
    _reseal(body)
    return body


def _reseal(body: dict[str, Any]) -> None:
    attributes = body["permit_decision"]["resource_attributes_json"]
    body["permit_receipt"]["action"]["resource_attributes_json"] = copy.deepcopy(
        attributes
    )
    body["permit_decision"]["canonical_payload"][
        "resource_attributes_canonical_hash"
    ] = canonical_resource_attributes_payload(attributes)


def _evidence(body: dict[str, Any]) -> dict[str, Any]:
    return body["permit_decision"]["resource_attributes_json"][
        ACTION_MAPPING_ATTRIBUTE_KEY
    ]


def _adjudicate(body: dict[str, Any]) -> dict[str, Any]:
    result = adjudicate_permit_exact_v2_body(body, decision_verdict="supported")
    return {claim.name: claim for claim in result.claims}


def _report(body: dict[str, Any]) -> dict[str, Any]:
    result = adjudicate_permit_exact_v2_body(body, decision_verdict="supported")
    return {
        "artifact": {
            "kind": "permit_exact",
            "permit": {
                "permit_id": result.permit_id,
                "decision": body["decision_state"]["decision"],
                "issued_at": "2026-07-30T12:00:00Z",
            },
        },
        "claims": [
            {
                "name": claim.name,
                "verdict": claim.verdict,
                "reason_code": claim.reason_code,
                "message": claim.message,
                "required": True,
                "does_not_establish": list(claim.does_not_establish),
            }
            for claim in result.claims
        ],
    }


def _rendered(body: dict[str, Any]) -> str:
    return "\n".join(line.text for line in build_report_lines(_report(body)))


def _positive_lines(body: dict[str, Any]) -> list[str]:
    """Rendered lines that assert something, with negations removed.

    Every disclaimer and coverage caveat renders as an em-dash bullet. Banning
    a phrase outright would be satisfied by a report that never mentions it;
    what must actually hold is that the phrase appears *only* under negation.
    """

    return [
        line.text
        for line in build_report_lines(_report(body))
        if not line.text.strip().startswith("—")
    ]


# --------------------------------------------------------------------------
# Registry and recipe wiring
# --------------------------------------------------------------------------


def test_claim_registry_v7_extends_v6_by_exact_identity_and_digest() -> None:
    v7 = json.loads((ROOT / "claim_registry/v7.json").read_text(encoding="utf-8"))
    v6_bytes = (ROOT / "claim_registry/v6.json").read_bytes()

    assert v7["version"] == "verifier-claims.v7"
    assert v7["extends"] == {
        "artifact_id": "keel.verifier_claim_registry.v6",
        "version": "verifier-claims.v6",
        "sha256": hashlib.sha256(v6_bytes).hexdigest(),
    }
    assert {claim["name"] for claim in v7["claims"]} == set(ACTION_MAPPING_CLAIMS)
    # Additive only: v7 redefines no inherited claim.
    v6 = json.loads(v6_bytes.decode("utf-8"))
    assert not {claim["name"] for claim in v7["claims"]} & {
        claim["name"] for claim in v6["claims"]
    }


def test_claim_registry_v7_rejects_a_tampered_v6_base_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from keel_verifier import verdicts

    payload = json.loads((ROOT / "claim_registry/v7.json").read_text(encoding="utf-8"))
    payload["extends"]["sha256"] = "0" * 64
    path = tmp_path / "v7.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("KEEL_CLAIM_REGISTRY", str(path))
    verdicts.load_claim_registry.cache_clear()

    with pytest.raises(ValueError, match="pins v6 digest"):
        verdicts.load_claim_registry()

    verdicts.load_claim_registry.cache_clear()


def test_universal_recipe_v6_pins_claim_registry_v7() -> None:
    recipe = json.loads(
        (ROOT / "semantics/permit/universal_verification_v6.json").read_text(
            encoding="utf-8"
        )
    )
    base_bytes = (ROOT / "semantics/permit/universal_verification_v5.json").read_bytes()

    assert recipe["body"]["claim_registry_version"] == "verifier-claims.v7"
    assert recipe["extends"]["sha256"] == hashlib.sha256(base_bytes).hexdigest()


def test_recipe_and_registry_versions_must_not_diverge() -> None:
    body = _mapping_body()
    universal_path = ROOT / "semantics/permit/universal_verification_v5.json"
    body["contract_pins"]["universal_semantics"] = _pin(
        universal_path,
        artifact_id="keel.permit.universal_verification.v5",
    )
    body["semantic_binding"]["universal_semantics_id"] = (
        "keel.permit.universal_verification.v5"
    )
    body["semantic_binding"]["universal_semantics_digest"] = _digest_bytes(
        universal_path.read_bytes()
    )
    _reseal(body)

    claims = _adjudicate(body)

    assert claims[MCP_ACTION_MAPPING_BINDING_CLAIM].verdict == "disproved"
    assert (
        claims[MCP_ACTION_MAPPING_BINDING_CLAIM].reason_code
        == "PERMIT_CONTRACT_PIN_VERSION_MISMATCH"
    )


# --------------------------------------------------------------------------
# §10 test 47 — every applicable §8 signed field is present and bound
# --------------------------------------------------------------------------


def test_47_execution_artifact_binds_every_applicable_signed_field() -> None:
    claims = _adjudicate(_mapping_body())

    assert claims[MCP_ACTION_MAPPING_BINDING_CLAIM].verdict == "supported"
    assert claims[MCP_GOVERNANCE_INTERPRETATION_CLAIM].verdict == "supported"


def test_47_structural_artifact_binds_typed_absence_and_diagnostics() -> None:
    claims = _adjudicate(_mapping_body(artifact_class="structural_decision"))

    assert claims[MCP_ACTION_MAPPING_BINDING_CLAIM].verdict == "supported"
    assert claims[MCP_STRUCTURAL_HOLD_EVIDENCE_CLAIM].verdict == "supported"
    # Execution-only fields are not required of the structural artifact, and
    # the interpretation claim is not requested for it at all.
    assert MCP_GOVERNANCE_INTERPRETATION_CLAIM not in claims


@pytest.mark.parametrize(
    ("group", "field"),
    [
        ("mapping", "mapping_id"),
        ("mapping", "mapping_revision"),
        ("mapping", "manifest_hash"),
        ("mapping", "lifecycle_epoch"),
        ("mapping", "lifecycle_state"),
        ("mapping", "assurance"),
        ("governance_action", "governance_action_id"),
        ("governance_action", "governance_action_version"),
        ("governance_action", "catalog_entry_hash"),
        ("structural", "challenge_class"),
        ("structural", "challenge_basis_hash"),
        ("structural", "challenge_basis_version"),
        ("structural", "typed_absence_hash"),
        ("structural", "derivation_diagnostics_hash"),
        ("activation", "activation_record_id"),
        ("activation", "activation_record_hash"),
    ],
)
def test_47_each_required_field_fails_closed_independently(
    group: str,
    field: str,
) -> None:
    body = _mapping_body()
    _evidence(body)[group].pop(field)
    _reseal(body)

    claims = _adjudicate(body)

    assert claims[MCP_ACTION_MAPPING_BINDING_CLAIM].verdict == "disproved"
    assert claims[MCP_GOVERNANCE_INTERPRETATION_CLAIM].verdict == "disproved"
    assert f"{group}.{field}" in claims[MCP_ACTION_MAPPING_BINDING_CLAIM].message


def test_47_manifest_hash_does_not_substitute_for_mapping_revision() -> None:
    """The mapping hash alone must not carry test 47."""

    body = _mapping_body()
    evidence = _evidence(body)
    evidence["mapping"].pop("mapping_revision")
    assert evidence["mapping"]["manifest_hash"]  # the hash is still bound
    _reseal(body)

    claims = _adjudicate(body)

    assert claims[MCP_ACTION_MAPPING_BINDING_CLAIM].verdict == "disproved"
    assert (
        claims[MCP_ACTION_MAPPING_BINDING_CLAIM].reason_code
        == "MCP_ACTION_MAPPING_FIELD_MISSING"
    )


def test_47_basis_hash_does_not_substitute_for_basis_version() -> None:
    body = _mapping_body()
    evidence = _evidence(body)
    evidence["structural"].pop("challenge_basis_version")
    assert evidence["structural"]["challenge_basis_hash"]
    _reseal(body)

    claims = _adjudicate(body)

    assert claims[MCP_ACTION_MAPPING_BINDING_CLAIM].verdict == "disproved"


def test_47_legacy_challenge_basis_version_is_non_dischargeable() -> None:
    body = _mapping_body()
    _evidence(body)["structural"]["challenge_basis_version"] = "mcp_challenge_basis.v1"
    _reseal(body)

    claims = _adjudicate(body)

    assert claims[MCP_ACTION_MAPPING_BINDING_CLAIM].verdict == "disproved"
    assert (
        claims[MCP_ACTION_MAPPING_BINDING_CLAIM].reason_code
        == "MCP_ACTION_MAPPING_BASIS_VERSION_UNSUPPORTED"
    )


def test_47_unknown_future_basis_version_is_out_of_scope_not_accepted() -> None:
    body = _mapping_body()
    _evidence(body)["structural"]["challenge_basis_version"] = "mcp_challenge_basis.v9"
    _reseal(body)

    claims = _adjudicate(body)

    assert claims[MCP_ACTION_MAPPING_BINDING_CLAIM].verdict == "unverifiable_scope"


@pytest.mark.parametrize("field", ["lifecycle_epoch", "activated_lifecycle_epoch"])
def test_47_lifecycle_epoch_is_required_on_both_surfaces(field: str) -> None:
    body = _mapping_body()
    evidence = _evidence(body)
    if field == "lifecycle_epoch":
        evidence["mapping"].pop(field)
    else:
        evidence["activation"].pop(field)
    _reseal(body)

    claims = _adjudicate(body)

    assert claims[MCP_ACTION_MAPPING_BINDING_CLAIM].verdict == "disproved"


def test_47_activation_epoch_may_not_lead_the_mapping_epoch() -> None:
    body = _mapping_body()
    _evidence(body)["activation"]["activated_lifecycle_epoch"] = 8
    _reseal(body)

    claims = _adjudicate(body)

    assert (
        claims[MCP_ACTION_MAPPING_BINDING_CLAIM].reason_code
        == "MCP_ACTION_MAPPING_ACTIVATION_EPOCH_INVALID"
    )


@pytest.mark.parametrize("field", _mapping_evidence(artifact_class="execution")["approval"])
def test_47_each_approval_field_fails_closed_independently(field: str) -> None:
    body = _mapping_body()
    _evidence(body)["approval"].pop(field)
    _reseal(body)

    claims = _adjudicate(body)

    assert claims[MCP_GOVERNANCE_INTERPRETATION_CLAIM].verdict == "disproved"
    assert (
        claims[MCP_GOVERNANCE_INTERPRETATION_CLAIM].reason_code
        == "MCP_ACTION_MAPPING_APPROVAL_FIELD_MISSING"
    )


def test_47_execution_evidence_must_name_the_permit_under_adjudication() -> None:
    body = _mapping_body()
    _evidence(body)["approval"]["execution_permit_id"] = "permit_other"
    _reseal(body)

    claims = _adjudicate(body)

    assert (
        claims[MCP_GOVERNANCE_INTERPRETATION_CLAIM].reason_code
        == "MCP_ACTION_MAPPING_APPROVAL_PERMIT_MISMATCH"
    )


def test_47_reviewed_and_execution_permits_must_be_distinct_records() -> None:
    body = _mapping_body()
    _evidence(body)["approval"]["reviewed_permit_id"] = "permit_test"
    _reseal(body)

    claims = _adjudicate(body)

    assert (
        claims[MCP_GOVERNANCE_INTERPRETATION_CLAIM].reason_code
        == "MCP_ACTION_MAPPING_APPROVAL_PERMIT_MISMATCH"
    )


def test_47_mapping_evidence_is_covered_by_the_signed_commitment() -> None:
    """Editing the block without resealing breaks the signed commitment."""

    body = _mapping_body()
    _evidence(body)["mapping"]["mapping_revision"] = "revision_forged"

    claims = _adjudicate(body)

    assert claims[MCP_ACTION_MAPPING_BINDING_CLAIM].verdict == "disproved"
    assert (
        claims[MCP_ACTION_MAPPING_BINDING_CLAIM].reason_code
        == "PERMIT_EXACT_SIGNED_ATTRIBUTES_MISMATCH"
    )


def test_47_a_pack_may_not_omit_a_claim_its_recipe_requests() -> None:
    body = _mapping_body()
    body["declared_claims"] = [
        name
        for name in body["declared_claims"]
        if name != MCP_GOVERNANCE_INTERPRETATION_CLAIM
    ]

    claims = _adjudicate(body)

    assert (
        claims[MCP_GOVERNANCE_INTERPRETATION_CLAIM].reason_code
        == "PERMIT_CONDITIONAL_CLAIM_MISSING"
    )


def test_47_a_structural_pack_may_not_omit_its_structural_claim() -> None:
    body = _mapping_body(artifact_class="structural_decision")
    body["declared_claims"] = [
        name
        for name in body["declared_claims"]
        if name != MCP_STRUCTURAL_HOLD_EVIDENCE_CLAIM
    ]

    claims = _adjudicate(body)

    assert (
        claims[MCP_STRUCTURAL_HOLD_EVIDENCE_CLAIM].reason_code
        == "PERMIT_CONDITIONAL_CLAIM_MISSING"
    )


# --------------------------------------------------------------------------
# §10 test 44 — the certified path is unreachable, the call non-approvable
# --------------------------------------------------------------------------


def test_44_arbitrary_mapping_binds_no_certified_action_contract() -> None:
    body = _mapping_body(artifact_class="structural_decision")
    evidence = _evidence(body)

    assert evidence["mapping"]["assurance"] == "human_mapped_review_only"
    assert evidence["mapping"]["certified_action_contract"] == {"state": "absent"}

    claims = _adjudicate(body)
    binding_claim = claims[MCP_ACTION_MAPPING_BINDING_CLAIM]

    assert binding_claim.verdict == "supported"
    assert any(
        "no certified_action_contract_id is bound" in value
        for value in binding_claim.does_not_establish
    )
    assert any(
        "certified action contract was bound" in value
        for value in binding_claim.does_not_establish
    )


def test_44_forged_certified_contract_on_an_arbitrary_mapping_is_rejected() -> None:
    body = _mapping_body(artifact_class="structural_decision")
    _evidence(body)["mapping"]["certified_action_contract"] = {
        "state": "present",
        "certified_action_contract_id": "keel.facts.refund_exact.v2",
        "connector_identity": "stripe",
    }
    _reseal(body)

    claims = _adjudicate(body)

    for name in STRUCTURAL_CLAIMS:
        assert claims[name].verdict == "disproved"
        assert (
            claims[name].reason_code
            == "MCP_ACTION_MAPPING_CERTIFIED_CONTRACT_FORBIDDEN"
        )


def test_44_certified_contract_state_must_be_typed_not_merely_missing() -> None:
    body = _mapping_body(artifact_class="structural_decision")
    _evidence(body)["mapping"]["certified_action_contract"] = {}
    _reseal(body)

    claims = _adjudicate(body)

    assert (
        claims[MCP_ACTION_MAPPING_BINDING_CLAIM].reason_code
        == "MCP_ACTION_MAPPING_CERTIFIED_CONTRACT_UNTYPED"
    )


def test_44_arbitrary_mapping_cannot_claim_verified_adapter_provenance() -> None:
    body = _mapping_body(artifact_class="structural_decision")
    _evidence(body)["mapping"]["classification_provenance"] = "keel_verified_adapter"
    _reseal(body)

    claims = _adjudicate(body)

    assert (
        claims[MCP_ACTION_MAPPING_BINDING_CLAIM].reason_code
        == "MCP_ACTION_MAPPING_PROVENANCE_INVALID"
    )


def test_44_structural_hold_is_non_approvable_and_has_no_execution_permit() -> None:
    body = _mapping_body(artifact_class="structural_decision")
    claims = _adjudicate(body)

    assert claims[MCP_STRUCTURAL_HOLD_EVIDENCE_CLAIM].verdict == "supported"
    assert "approval" not in _evidence(body)
    # The interpretation claim is not reachable for a structural artifact even
    # when a pack declares it anyway.
    body["declared_claims"].append(MCP_GOVERNANCE_INTERPRETATION_CLAIM)
    forced = _adjudicate(body)
    assert forced[MCP_GOVERNANCE_INTERPRETATION_CLAIM].verdict == "insufficient_evidence"


def test_44_structural_artifact_carrying_an_approval_group_is_rejected() -> None:
    body = _mapping_body(artifact_class="structural_decision")
    _evidence(body)["approval"] = _mapping_evidence(artifact_class="execution")[
        "approval"
    ]
    _reseal(body)

    claims = _adjudicate(body)

    assert (
        claims[MCP_ACTION_MAPPING_BINDING_CLAIM].reason_code
        == "MCP_ACTION_MAPPING_STRUCTURAL_APPROVAL_PRESENT"
    )


def test_44_structural_artifact_may_not_carry_an_allow_decision() -> None:
    body = _mapping_body(artifact_class="structural_decision")
    body["decision_state"] = {"decision": "allow", "status": "active"}

    claims = _adjudicate(body)

    assert (
        claims[MCP_ACTION_MAPPING_BINDING_CLAIM].reason_code
        == "MCP_ACTION_MAPPING_STRUCTURAL_DECISION_INVALID"
    )


def test_44_structural_artifact_may_not_carry_dispatch_evidence() -> None:
    body = _mapping_body(artifact_class="structural_decision")
    body["bounded_use_transitions"] = [
        {"exact_request_digest": _hash("dispatch"), "occurred_at": "2026-07-30T12:30:00Z"}
    ]

    claims = _adjudicate(body)

    assert (
        claims[MCP_ACTION_MAPPING_BINDING_CLAIM].reason_code
        == "MCP_ACTION_MAPPING_STRUCTURAL_DISPATCH_EVIDENCE"
    )


def test_44_structural_hold_never_renders_a_refund_or_payment_title() -> None:
    """§5.2: incomplete financial facts suppress refund/payment presentation.

    Checked against the asserting lines only. The word "refund" is allowed to
    appear inside "does not establish: a payment, refund, amount, or
    business-effect interpretation" -- that is the suppression, not a breach
    of it.
    """

    positive = "\n".join(_positive_lines(_mapping_body(artifact_class="structural_decision"))).lower()

    for phrase in ("refund", "payment", "amount"):
        assert phrase not in positive, phrase


# --------------------------------------------------------------------------
# Dispatch claim: absence is information
# --------------------------------------------------------------------------


def test_dispatch_claim_reference_must_be_absent_when_none_was_acquired() -> None:
    body = _mapping_body()
    _evidence(body)["approval"]["dispatch_claim"] = {
        "state": "absent",
        "dispatch_claim_reference": "dispatch_claim_1",
    }
    _reseal(body)

    claims = _adjudicate(body)

    assert (
        claims[MCP_GOVERNANCE_INTERPRETATION_CLAIM].reason_code
        == "MCP_ACTION_MAPPING_DISPATCH_CLAIM_FORBIDDEN"
    )


def test_typed_absent_dispatch_claim_is_accepted() -> None:
    body = _mapping_body()
    _evidence(body)["approval"]["dispatch_claim"] = {"state": "absent"}
    _reseal(body)

    claims = _adjudicate(body)

    assert claims[MCP_GOVERNANCE_INTERPRETATION_CLAIM].verdict == "supported"


def test_untyped_dispatch_claim_fails_closed() -> None:
    body = _mapping_body()
    _evidence(body)["approval"]["dispatch_claim"] = {"state": "maybe"}
    _reseal(body)

    claims = _adjudicate(body)

    assert (
        claims[MCP_GOVERNANCE_INTERPRETATION_CLAIM].reason_code
        == "MCP_ACTION_MAPPING_DISPATCH_CLAIM_UNTYPED"
    )


def test_dispatch_claim_epoch_must_match_the_mapping_epoch() -> None:
    body = _mapping_body()
    _evidence(body)["approval"]["dispatch_claim"]["claimed_lifecycle_epoch"] = 6
    _reseal(body)

    claims = _adjudicate(body)

    assert (
        claims[MCP_GOVERNANCE_INTERPRETATION_CLAIM].reason_code
        == "MCP_ACTION_MAPPING_DISPATCH_CLAIM_EPOCH_MISMATCH"
    )


@pytest.mark.parametrize(
    "state", ["frozen", "superseded", "permanently_revoked"]
)
def test_dispatch_claim_cannot_be_acquired_on_a_non_active_revision(
    state: str,
) -> None:
    body = _mapping_body()
    _evidence(body)["mapping"]["lifecycle_state"] = state
    _reseal(body)

    claims = _adjudicate(body)

    assert (
        claims[MCP_GOVERNANCE_INTERPRETATION_CLAIM].reason_code
        == "MCP_ACTION_MAPPING_LIFECYCLE_STATE_INVALID"
    )


# --------------------------------------------------------------------------
# The governance action never replaces Permit.action_name
# --------------------------------------------------------------------------


def test_governance_action_may_not_be_the_permit_action_name() -> None:
    body = _mapping_body()
    _evidence(body)["permit_action_name"] = GOVERNANCE_ACTION_ID
    _reseal(body)

    claims = _adjudicate(body)

    assert (
        claims[MCP_ACTION_MAPPING_BINDING_CLAIM].reason_code
        == "MCP_ACTION_MAPPING_ACTION_NAME_INVALID"
    )


def test_governance_action_may_not_appear_in_the_signed_semantic_binding() -> None:
    body = _mapping_body()
    _evidence(body)["governance_action"]["governance_action_id"] = "payment.execute"
    _reseal(body)

    claims = _adjudicate(body)

    # payment.execute is the binding's action_name and the resolved authorized
    # action, so naming it as the governance action is a substitution.
    assert (
        claims[MCP_ACTION_MAPPING_BINDING_CLAIM].reason_code
        == "MCP_ACTION_MAPPING_ACTION_NAME_MISMATCH"
    )
    assert "semantic binding" in claims[MCP_ACTION_MAPPING_BINDING_CLAIM].message


def test_wrong_enforcement_surface_key_is_not_silently_dropped() -> None:
    body = _mapping_body()
    _evidence(body)["enforcement_surface_key"] = "program:work"
    _reseal(body)

    claims = _adjudicate(body)

    for name in EXECUTION_CLAIMS:
        assert claims[name].verdict == "disproved"
        assert claims[name].reason_code == "MCP_ACTION_MAPPING_SURFACE_MISMATCH"


def test_absent_mapping_evidence_is_insufficient_not_supported() -> None:
    body = _mapping_body()
    body["permit_decision"]["resource_attributes_json"].pop(
        ACTION_MAPPING_ATTRIBUTE_KEY
    )
    _reseal(body)

    claims = _adjudicate(body)

    for name in EXECUTION_CLAIMS:
        assert claims[name].verdict == "insufficient_evidence"
        assert claims[name].reason_code == "MCP_ACTION_MAPPING_EVIDENCE_NOT_RECORDED"


def test_schema_backstop_rejects_an_unknown_evidence_field() -> None:
    body = _mapping_body()
    _evidence(body)["certified_action_contract_id"] = "keel.facts.refund_exact.v2"
    _reseal(body)

    claims = _adjudicate(body)

    assert claims[MCP_ACTION_MAPPING_BINDING_CLAIM].verdict == "disproved"
    assert (
        claims[MCP_ACTION_MAPPING_BINDING_CLAIM].reason_code
        == "MCP_ACTION_MAPPING_EVIDENCE_INVALID"
    )


# --------------------------------------------------------------------------
# §10 test 48 — bounded language, structurally gated
# --------------------------------------------------------------------------


def test_48_binding_statement_is_exactly_the_bounded_sentence() -> None:
    claims = _adjudicate(_mapping_body())

    assert (
        claims[MCP_ACTION_MAPPING_BINDING_CLAIM].message
        == "The Permit binds the mapping and activation reference used by "
        "Keel's decision."
    )
    assert ACTION_MAPPING_BINDING_STATEMENT in _rendered(_mapping_body())


def test_48_interpretation_statement_is_exactly_the_bounded_sentence() -> None:
    claims = _adjudicate(_mapping_body())

    assert (
        claims[MCP_GOVERNANCE_INTERPRETATION_CLAIM].message
        == "Keel evaluated this exact managed MCP request using the "
        "human-approved governance interpretation payment.refund under "
        "mandatory review."
    )
    assert (
        ACTION_MAPPING_INTERPRETATION_STATEMENT.format(
            governance_action_id=GOVERNANCE_ACTION_ID
        )
        in _rendered(_mapping_body())
    )


def test_48_interpretation_statement_is_gated_on_the_approval_artifacts() -> None:
    """Removing the supporting artifact must remove the statement.

    A disclaimer alone cannot carry this test: the assertion is that the
    positive sentence disappears from adjudication and from the rendered
    report when the evidence that supports it is gone.
    """

    complete = _rendered(_mapping_body())
    statement = ACTION_MAPPING_INTERPRETATION_STATEMENT.format(
        governance_action_id=GOVERNANCE_ACTION_ID
    )
    assert statement in complete

    body = _mapping_body()
    _evidence(body)["approval"].pop("exact_request_review_hash")
    _reseal(body)

    claims = _adjudicate(body)
    assert claims[MCP_GOVERNANCE_INTERPRETATION_CLAIM].verdict == "disproved"
    assert statement not in _rendered(body)


def test_48_structural_artifact_never_emits_the_interpretation_statement() -> None:
    body = _mapping_body(artifact_class="structural_decision")
    body["declared_claims"].append(MCP_GOVERNANCE_INTERPRETATION_CLAIM)

    statement = ACTION_MAPPING_INTERPRETATION_STATEMENT.format(
        governance_action_id=GOVERNANCE_ACTION_ID
    )
    assert statement not in _rendered(body)


@pytest.mark.parametrize("artifact_class", ["execution", "structural_decision"])
def test_48_no_banned_phrase_is_ever_asserted(artifact_class: str) -> None:
    """A banned phrase may appear only inside a negation, never as a claim."""

    positive = "\n".join(_positive_lines(_mapping_body(artifact_class=artifact_class))).lower()

    for phrase in BANNED_PHRASES:
        assert phrase not in positive, phrase


@pytest.mark.parametrize("artifact_class", ["execution", "structural_decision"])
def test_48_banned_phrases_are_present_but_only_as_negations(
    artifact_class: str,
) -> None:
    """The guard above must not pass by the report simply staying silent."""

    rendered = _rendered(_mapping_body(artifact_class=artifact_class)).lower()

    assert "downstream effect" in rendered
    assert "provider acceptance or completion" in rendered


def test_48_rendered_report_states_the_required_disclaimers() -> None:
    rendered = _rendered(_mapping_body()).lower()

    # §8: handler semantics, certified action facts, the deployed source
    # revision, bypass absence, and downstream completion must be disclaimed.
    assert "no certified_action_contract_id is bound" in rendered
    assert "handler semantics" in rendered
    assert "deployed one" in rendered or "source revision" in rendered
    assert "outside the governed boundary" in rendered
    assert "provider acceptance or completion" in rendered
    assert "independent verification of the webauthn activation assertion" in rendered
    assert "which approvals satisfied the frozen approval requirement" in rendered
    assert "that two humans approved" in rendered


def test_48_disclaimers_alone_do_not_appear_without_a_supported_claim() -> None:
    """The ceiling travels with a statement; it is not free-standing text."""

    body = _mapping_body()
    _evidence(body)["mapping"].pop("mapping_revision")
    _reseal(body)

    rendered = _rendered(body).lower()

    assert "action mapping" not in rendered
    assert "no certified_action_contract_id is bound" not in rendered


def test_48_four_verdict_model_is_unchanged() -> None:
    from keel_verifier.verdicts import load_claim_registry

    registry = load_claim_registry()

    assert registry.verdict_enum == (
        "supported",
        "disproved",
        "insufficient_evidence",
        "unverifiable_scope",
    )
    for name in ACTION_MAPPING_CLAIMS:
        assert registry.claim(name).verdict_enum == registry.verdict_enum


# --------------------------------------------------------------------------
# Historical compatibility
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("registry", "universal", "artifact_id", "universal_id"),
    [
        (
            "claim_registry/v2.json",
            "semantics/permit/universal_verification_v1.json",
            "keel.verifier_claim_registry.v2",
            "keel.permit.universal_verification.v1",
        ),
        (
            "claim_registry/v5.json",
            "semantics/permit/universal_verification_v4.json",
            "keel.verifier_claim_registry.v5",
            "keel.permit.universal_verification.v4",
        ),
    ],
)
def test_historical_packs_still_verify_against_their_pinned_registry(
    registry: str,
    universal: str,
    artifact_id: str,
    universal_id: str,
) -> None:
    """A pack pinning an earlier registry never sees the v7 claims."""

    body = _body()
    claim_path = ROOT / registry
    universal_path = ROOT / universal
    payload = json.loads(claim_path.read_text(encoding="utf-8"))
    binding = body["semantic_binding"]
    binding.update(
        {
            "claim_registry_version": payload["version"],
            "claim_registry_digest": _digest_bytes(claim_path.read_bytes()),
            "universal_semantics_id": universal_id,
            "universal_semantics_digest": _digest_bytes(universal_path.read_bytes()),
        }
    )
    body["contract_pins"]["claim_registry"] = _pin(claim_path, artifact_id=artifact_id)
    body["contract_pins"]["universal_semantics"] = _pin(
        universal_path, artifact_id=universal_id
    )
    body["permit_decision"]["resource_attributes_json"][
        "permit_semantic_binding_v2"
    ] = copy.deepcopy(binding)
    _reseal(body)

    result = adjudicate_permit_exact_v2_body(body, decision_verdict="supported")
    names = {claim.name for claim in result.claims}

    assert names & set(UNIVERSAL_CLAIMS)
    assert not names & set(ACTION_MAPPING_CLAIMS)
    assert all(
        claim.verdict in {"supported", "disproved", "insufficient_evidence", "unverifiable_scope"}
        for claim in result.claims
    )


def test_bundled_historical_registry_bytes_are_unchanged() -> None:
    """v7 is additive: no earlier registry byte moved."""

    expected = {
        "v5.json": "14b028e81b610c905ab923ce449c480352d56922e211023a6075e46592ce93d0",
        "v6.json": "294f3bb5c9358037d3cea1b29e80ce38b17f3ecbe42b89b710789a1f892d5378",
    }
    for name, digest in expected.items():
        raw = (ROOT / "claim_registry" / name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == digest, name


def test_action_mapping_evidence_pin_is_reachable_from_a_compact_v4_pack() -> None:
    """The compact profile resolves v7 pins by version and digest alone."""

    body = _mapping_body()
    body["profile"] = "keel.permit_exact/v4"
    body["profile_version"] = 4
    for pin in body["contract_pins"].values():
        if isinstance(pin, dict):
            pin.pop("content_base64", None)

    claims = _adjudicate(body)

    assert claims[MCP_ACTION_MAPPING_BINDING_CLAIM].verdict == "supported"
    assert claims[MCP_GOVERNANCE_INTERPRETATION_CLAIM].verdict == "supported"


def test_mapping_evidence_schema_is_bundled_for_offline_verification() -> None:
    schema_path = (
        ROOT / "permit_to_x/schemas/mcp-action-mapping-evidence-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    assert schema["properties"]["version"]["const"] == (
        "keel.mcp_action_mapping_evidence.v1"
    )
    assert schema["additionalProperties"] is False
    manifest = json.loads(
        (Path(__file__).resolve().parents[1] / "keel_verifier" / "_release_manifest.json")
        .read_text(encoding="utf-8")
    )
    relative = "keel_verifier/data/permit_to_x/schemas/mcp-action-mapping-evidence-v1.schema.json"
    assert manifest["per_file_digests"][relative] == hashlib.sha256(
        schema_path.read_bytes()
    ).hexdigest()
