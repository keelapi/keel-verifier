"""The keel-api golden vectors, adjudicated by this verifier.

The vectors and their manifest are vendored byte-identically from the producer
so the two repositories are checked against one artifact set rather than two
descriptions of one. Every vector's own ``expectation`` block is asserted. The
verifier independently derives the bounded projection, with one deliberate
narrowing: an acquired dispatch claim is not presented as proof that an
upstream request crossed a point of no return or was already dispatched.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from keel_verifier import action_mapping_evidence as ame
from keel_verifier.report_render import build_report_lines


VECTOR_DIR = Path(__file__).resolve().parent / "fixtures" / "action_mapping_evidence"
MANIFEST = json.loads((VECTOR_DIR / "MANIFEST.json").read_text(encoding="utf-8"))
SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "keel_verifier"
    / "data"
    / "permit_to_x"
    / "schemas"
    / "mcp-action-mapping-evidence-v1.schema.json"
)

POSITIVE_VECTORS = (
    "execution_before_dispatch_claim",
    "execution_after_committed_claim",
    "structural_hold_incomplete_financial_facts",
)
NEGATIVE_VECTORS = (
    "absent_unmapped_source",
    "forged_certified_contract",
    "changed_basis_version",
)
ALL_VECTORS = POSITIVE_VECTORS + NEGATIVE_VECTORS


def _vector(name: str) -> dict[str, Any]:
    return json.loads((VECTOR_DIR / f"{name}.json").read_text(encoding="utf-8"))


def _verify(name: str) -> ame.ActionMappingEvidenceResult:
    return ame.verify_action_mapping_evidence(_vector(name)["artifact"])


# ---------------------------------------------------------------------------
# The artifacts under test are the producer's, unmodified
# ---------------------------------------------------------------------------


def test_the_bundled_schema_is_the_producer_owned_artifact() -> None:
    assert (
        hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest()
        == MANIFEST["schema_sha256"]
    )
    assert MANIFEST["challenge_basis_version"] == ame.CHALLENGE_BASIS_VERSION
    assert MANIFEST["attribute_key"] == ame.ATTRIBUTE_KEY
    assert MANIFEST["enforcement_surface_key"] == ame.SURFACE_KEY
    assert MANIFEST["evidence_version"] == ame.EVIDENCE_VERSION


def test_every_vector_file_is_tracked_by_git() -> None:
    """A fresh clone must carry these, not just this working tree.

    ``.gitignore`` carries an unanchored ``manifest.json`` rule for release
    artifacts. On a case-insensitive filesystem it also matches this directory's
    ``MANIFEST.json``, which is test input. The file existed locally and the
    suite passed while a clone would have failed collection, so the tracking is
    asserted rather than assumed.
    """

    tracked = set(
        subprocess.run(
            ["git", "ls-files", "--", str(VECTOR_DIR)],
            capture_output=True,
            text=True,
            check=True,
            cwd=VECTOR_DIR.parents[2],
        ).stdout.split()
    )
    expected = {
        f"tests/fixtures/action_mapping_evidence/{path.name}"
        for path in VECTOR_DIR.iterdir()
        if path.is_file()
    }
    assert expected <= tracked, sorted(expected - tracked)


@pytest.mark.parametrize("entry", MANIFEST["vectors"], ids=lambda e: e["vector_id"])
def test_each_vector_matches_its_pinned_digest(entry: dict[str, Any]) -> None:
    payload = (VECTOR_DIR / entry["file"]).read_bytes()
    assert hashlib.sha256(payload).hexdigest() == entry["sha256"]


# ---------------------------------------------------------------------------
# Positive vectors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", POSITIVE_VECTORS)
def test_positive_vectors_are_supported(name: str) -> None:
    result = _verify(name)

    assert result.verdict == "supported", result.message
    assert result.artifact_class == _vector(name)["expectation"]["artifact_class"]


@pytest.mark.parametrize("name", POSITIVE_VECTORS)
def test_the_bounded_projection_matches_except_for_the_dispatch_overclaim(
    name: str,
) -> None:
    """Preserve the corpus while refusing its one unsafe report sentence."""

    expected = _vector(name)["bounded_projection"]
    actual = _verify(name).bounded_projection
    if name != "execution_after_committed_claim":
        assert actual == expected
        return

    assert "point of no return" in expected["in_flight_statement"]
    assert actual["in_flight_statement"] == ame.DISPATCH_CLAIM_ACQUIRED_STATEMENT
    expected_without_statement = dict(expected)
    actual_without_statement = dict(actual)
    expected_without_statement.pop("in_flight_statement")
    actual_without_statement.pop("in_flight_statement")
    assert actual_without_statement == expected_without_statement


def test_execution_before_the_claim_carries_only_pre_claim_conclusions() -> None:
    result = _verify("execution_before_dispatch_claim")
    claims = result.claims
    projection = result.bounded_projection

    assert claims[ame.BINDING_CLAIM].verdict == "supported"
    assert claims[ame.GOVERNANCE_INTERPRETATION_CLAIM].verdict == "supported"
    # The eligibility sentence names a satisfied approval. Nothing has been
    # consumed yet, so neither the claim nor the statement may appear.
    assert claims[ame.DISPATCH_ELIGIBILITY_CLAIM].verdict == "insufficient_evidence"
    assert ame.ELIGIBILITY_STATEMENT not in projection["statements"]
    assert "in_flight_statement" not in projection
    assert len(projection["statements"]) == 2


def test_post_claim_execution_adds_only_the_claims_it_carries() -> None:
    result = _verify("execution_after_committed_claim")
    claims = result.claims
    projection = result.bounded_projection

    assert claims[ame.DISPATCH_ELIGIBILITY_CLAIM].verdict == "supported"
    assert projection["statements"][-1] == ame.ELIGIBILITY_STATEMENT
    assert projection["in_flight_statement"] == (
        ame.DISPATCH_CLAIM_ACQUIRED_STATEMENT
    )
    assert "point of no return" not in projection["in_flight_statement"]
    assert "already dispatched" not in projection["in_flight_statement"]
    assert claims[ame.STRUCTURAL_HOLD_EVIDENCE_CLAIM].verdict == "insufficient_evidence"


def test_structural_hold_is_non_approvable_and_claims_no_permit_or_effect() -> None:
    vector = _vector("structural_hold_incomplete_financial_facts")
    result = _verify("structural_hold_incomplete_financial_facts")

    assert vector["expectation"]["approval_present"] is False
    assert "approval" not in vector["artifact"]
    assert result.claims[ame.STRUCTURAL_HOLD_EVIDENCE_CLAIM].verdict == "supported"
    assert result.claims[ame.GOVERNANCE_INTERPRETATION_CLAIM].verdict == (
        "insufficient_evidence"
    )
    assert result.claims[ame.DISPATCH_ELIGIBILITY_CLAIM].verdict == (
        "insufficient_evidence"
    )
    assert ame.INTERPRETATION_STATEMENT.split(" {")[0] not in " ".join(
        result.bounded_projection["statements"]
    )
    assert "in_flight_statement" not in result.bounded_projection


def test_a_structural_artifact_is_not_permit_evidence() -> None:
    """It created no Permit, so a Permit carrying it is a category error."""

    artifact = _vector("structural_hold_incomplete_financial_facts")["artifact"]

    result = ame.verify_action_mapping_evidence(artifact, permit_bound=True)

    assert result.verdict == "disproved"
    assert result.reason_code == "MCP_ACTION_MAPPING_ARTIFACT_CLASS_NOT_PERMIT_EVIDENCE"


def test_a_post_claim_artifact_is_not_permit_evidence() -> None:
    """The Permit was signed and flushed before this artifact existed."""

    artifact = _vector("execution_after_committed_claim")["artifact"]

    result = ame.verify_action_mapping_evidence(artifact, permit_bound=True)

    assert result.verdict == "disproved"
    assert result.reason_code == "MCP_ACTION_MAPPING_ARTIFACT_CLASS_NOT_PERMIT_EVIDENCE"


def test_the_execution_artifact_is_the_one_class_a_permit_may_carry() -> None:
    artifact = _vector("execution_before_dispatch_claim")["artifact"]

    result = ame.verify_action_mapping_evidence(
        artifact,
        permit_bound=True,
        permit_id=artifact["approval"]["execution_permit_id"],
    )

    assert result.verdict == "supported"


def test_the_permit_path_requires_the_named_execution_permit() -> None:
    artifact = _vector("execution_before_dispatch_claim")["artifact"]

    result = ame.verify_action_mapping_evidence(
        artifact, permit_bound=True, permit_id="some-other-permit"
    )

    assert result.reason_code == "MCP_ACTION_MAPPING_APPROVAL_PERMIT_MISMATCH"


# ---------------------------------------------------------------------------
# Negative vectors
# ---------------------------------------------------------------------------


def test_absent_unmapped_source_is_typed_absence() -> None:
    vector = _vector("absent_unmapped_source")
    result = ame.verify_action_mapping_evidence(vector["artifact"])

    assert vector["artifact"] is None
    assert result.verdict == "insufficient_evidence"
    assert result.reason_code == vector["expectation"]["verifier_reason_code"]
    assert result.artifact_class is None
    assert result.bounded_projection == vector["bounded_projection"]
    assert result.bounded_projection["statements"] == []


def test_forged_certified_contract_is_rejected() -> None:
    vector = _vector("forged_certified_contract")
    result = ame.verify_action_mapping_evidence(vector["artifact"])

    assert result.verdict == "disproved"
    assert result.reason_code == vector["expectation"]["verifier_reason_code"]
    assert vector["bounded_projection"] is None
    assert result.bounded_projection["statements"] == []


def test_changed_basis_version_is_rejected_as_unsupported_basis() -> None:
    vector = _vector("changed_basis_version")
    result = ame.verify_action_mapping_evidence(vector["artifact"])

    assert result.verdict == "disproved"
    assert result.reason_code == vector["expectation"]["verifier_reason_code"]
    assert vector["artifact"]["structural"]["challenge_basis_version"] != (
        vector["expectation"]["current_basis_version"]
    )
    assert "comparable only within an identical basis version" in result.message


@pytest.mark.parametrize("name", NEGATIVE_VECTORS)
def test_negative_vectors_emit_no_positive_statement(name: str) -> None:
    result = ame.verify_action_mapping_evidence(_vector(name)["artifact"])

    assert result.verdict != "supported"
    assert result.bounded_projection["statements"] == []
    for claim in result.claims.values():
        assert claim.verdict != "supported"


@pytest.mark.parametrize("name", NEGATIVE_VECTORS)
def test_negative_vectors_are_schema_invalid_as_the_producer_records(
    name: str,
) -> None:
    import jsonschema

    vector = _vector(name)
    assert vector["expectation"]["schema_valid"] is False
    artifact = vector["artifact"]
    validator = jsonschema.Draft202012Validator(ame.evidence_schema())
    if artifact is None:
        # Absence is the evidence: there is no instance to validate.
        assert vector["expectation"]["artifact_absent"] is True
    else:
        assert list(validator.iter_errors(artifact))


# ---------------------------------------------------------------------------
# Bounded language
# ---------------------------------------------------------------------------


def test_the_interpretation_sentence_is_the_exact_reviewed_form() -> None:
    result = _verify("execution_before_dispatch_claim")
    message = result.claims[ame.GOVERNANCE_INTERPRETATION_CLAIM].message

    assert message == (
        "Keel evaluated this exact managed MCP request using the human-approved "
        "governance interpretation keel.vector.record_note under exact review, "
        "with the consequence-critical facts bound in the review material."
    )
    assert message in _vector("execution_before_dispatch_claim")["bounded_projection"][
        "statements"
    ]


def test_under_mandatory_review_is_banned_outright() -> None:
    assert "under mandatory review" in ame.BANNED_PHRASES
    assert "under mandatory review" not in ame.INTERPRETATION_STATEMENT

    with pytest.raises(ame.BoundedLanguageError):
        ame.assert_bounded_language(
            {
                "statements": [
                    "Keel evaluated this exact managed MCP request using the "
                    "human-approved governance interpretation x under mandatory "
                    "review."
                ]
            }
        )


@pytest.mark.parametrize("phrase", ame.BANNED_PHRASES)
def test_every_banned_phrase_is_refused_rather_than_documented(phrase: str) -> None:
    with pytest.raises(ame.BoundedLanguageError):
        ame.assert_bounded_language({"statements": [f"prefix {phrase} suffix"]})


@pytest.mark.parametrize("name", POSITIVE_VECTORS)
def test_no_banned_phrase_survives_into_a_rendered_report(name: str) -> None:
    """The guard runs on the rendered lines, not only on the projection."""

    result = _verify(name)
    report = {
        "artifact": {"kind": "permit_exact", "permit": {"permit_id": "p"}},
        "claims": [
            {
                "name": claim.name,
                "verdict": claim.verdict,
                "reason_code": claim.reason_code,
                "message": claim.message,
                "required": True,
                "does_not_establish": list(claim.does_not_establish),
            }
            for claim in result.claims.values()
        ],
        "action_mapping_bounded_projection": result.bounded_projection,
    }
    rendered = "\n".join(line.text for line in build_report_lines(report))
    asserting = "\n".join(
        line for line in rendered.splitlines() if not line.strip().startswith("—")
    ).casefold()

    for phrase in ame.BANNED_PHRASES:
        assert phrase not in asserting, phrase
    for statement in result.bounded_projection["statements"]:
        assert statement in rendered


def test_the_rendered_report_states_the_two_standing_limits() -> None:
    result = _verify("execution_after_committed_claim")
    report = {
        "artifact": {"kind": "permit_exact", "permit": {"permit_id": "p"}},
        "claims": [],
        "action_mapping_bounded_projection": result.bounded_projection,
    }
    rendered = "\n".join(line.text for line in build_report_lines(report))

    assert ame.CERTIFIED_CONTRACT_NOT_BOUND_STATEMENT in rendered
    assert ame.APPROVAL_SET_NOT_ESTABLISHED_STATEMENT in rendered
    assert ame.DISPATCH_CLAIM_ACQUIRED_STATEMENT in rendered
    assert "point of no return" not in rendered
    assert "already dispatched" not in rendered
    for value in ame.DOES_NOT_ESTABLISH:
        assert value in rendered


def test_the_report_never_repeats_the_source_vectors_dispatch_overclaim() -> None:
    source_projection = _vector("execution_after_committed_claim")[
        "bounded_projection"
    ]
    report = {
        "artifact": {"kind": "permit_exact", "permit": {"permit_id": "p"}},
        "claims": [],
        "action_mapping_bounded_projection": source_projection,
    }

    rendered = "\n".join(line.text for line in build_report_lines(report))

    assert source_projection["in_flight_statement"] not in rendered
    assert ame.DISPATCH_CLAIM_ACQUIRED_STATEMENT in rendered
    assert "point of no return" not in rendered
    assert "already dispatched" not in rendered


def test_a_claim_only_report_also_removes_already_dispatched_wording() -> None:
    result = _verify("execution_after_committed_claim")
    report = {
        "artifact": {"kind": "permit_exact", "permit": {"permit_id": "p"}},
        "claims": [
            {
                "name": claim.name,
                "verdict": claim.verdict,
                "reason_code": claim.reason_code,
                "message": claim.message,
                "required": True,
                "does_not_establish": list(claim.does_not_establish),
            }
            for claim in result.claims.values()
        ],
    }

    rendered = "\n".join(line.text for line in build_report_lines(report))

    assert "point of no return" not in rendered
    assert "already dispatched" not in rendered
    assert "does not establish that one was sent" in rendered


# ---------------------------------------------------------------------------
# Standing invariants the vectors alone would not pin
# ---------------------------------------------------------------------------


def test_the_approval_set_is_never_independently_established() -> None:
    for name in POSITIVE_VECTORS:
        result = _verify(name)
        assert result.bounded_projection["approval_set_independently_established"] is (
            False
        )


def test_an_artifact_claiming_an_established_approval_set_is_rejected() -> None:
    artifact = json.loads(
        json.dumps(_vector("execution_before_dispatch_claim")["artifact"])
    )
    artifact["approval"]["approval_set_independently_established"] = True

    result = ame.verify_action_mapping_evidence(artifact)

    assert result.reason_code == "MCP_ACTION_MAPPING_APPROVAL_SET_OVERCLAIM"


def test_the_activation_ceremony_is_never_independently_verified() -> None:
    for name in POSITIVE_VECTORS:
        result = _verify(name)
        assert result.bounded_projection[
            "webauthn_assertion_independently_verified"
        ] is False


def test_an_artifact_claiming_a_verified_ceremony_is_rejected() -> None:
    artifact = json.loads(
        json.dumps(_vector("execution_before_dispatch_claim")["artifact"])
    )
    artifact["activation"]["independently_verified"] = True

    result = ame.verify_action_mapping_evidence(artifact)

    assert result.reason_code == "MCP_ACTION_MAPPING_ACTIVATION_OVERCLAIM"


def test_a_string_mapping_revision_is_rejected() -> None:
    artifact = json.loads(
        json.dumps(_vector("execution_before_dispatch_claim")["artifact"])
    )
    artifact["mapping"]["mapping_revision"] = "1"

    result = ame.verify_action_mapping_evidence(artifact)

    assert result.reason_code == "MCP_ACTION_MAPPING_REVISION_INVALID"


def test_the_manifest_hash_does_not_substitute_for_the_revision() -> None:
    artifact = json.loads(
        json.dumps(_vector("execution_before_dispatch_claim")["artifact"])
    )
    del artifact["mapping"]["mapping_revision"]
    assert artifact["mapping"]["manifest_hash"]

    result = ame.verify_action_mapping_evidence(artifact)

    assert result.reason_code == "MCP_ACTION_MAPPING_FIELD_MISSING"
    assert "mapping.mapping_revision" in result.message


def test_the_basis_hash_does_not_substitute_for_the_basis_version() -> None:
    artifact = json.loads(
        json.dumps(_vector("execution_before_dispatch_claim")["artifact"])
    )
    del artifact["structural"]["challenge_basis_version"]
    assert artifact["structural"]["challenge_basis_hash"]

    result = ame.verify_action_mapping_evidence(artifact)

    assert result.reason_code == "MCP_ACTION_MAPPING_FIELD_MISSING"
    assert "structural.challenge_basis_version" in result.message


def test_an_unrecognised_future_basis_version_is_out_of_scope() -> None:
    artifact = json.loads(
        json.dumps(_vector("execution_before_dispatch_claim")["artifact"])
    )
    artifact["structural"]["challenge_basis_version"] = "mcp_challenge_basis.v9"

    result = ame.verify_action_mapping_evidence(artifact)

    assert result.verdict == "unverifiable_scope"
    assert result.reason_code == "MCP_ACTION_MAPPING_BASIS_VERSION_UNSUPPORTED"


@pytest.mark.parametrize("group,field", ame._REQUIRED_FIELDS)
def test_each_required_field_fails_closed_independently(
    group: str, field: str
) -> None:
    artifact = json.loads(
        json.dumps(_vector("execution_before_dispatch_claim")["artifact"])
    )
    del artifact[group][field]

    result = ame.verify_action_mapping_evidence(artifact)

    assert result.verdict == "disproved"
    assert result.bounded_projection["statements"] == []


@pytest.mark.parametrize("field", ame._REQUIRED_APPROVAL_FIELDS)
def test_each_approval_field_fails_closed_independently(field: str) -> None:
    artifact = json.loads(
        json.dumps(_vector("execution_before_dispatch_claim")["artifact"])
    )
    del artifact["approval"][field]

    result = ame.verify_action_mapping_evidence(artifact)

    assert result.verdict == "disproved"


def test_an_execution_artifact_may_not_name_a_dispatch_claim() -> None:
    """The Permit is signed before the claim exists; a reference is a forgery."""

    artifact = json.loads(
        json.dumps(_vector("execution_before_dispatch_claim")["artifact"])
    )
    artifact["approval"]["dispatch_claim"] = json.loads(
        json.dumps(
            _vector("execution_after_committed_claim")["artifact"]["approval"][
                "dispatch_claim"
            ]
        )
    )

    result = ame.verify_action_mapping_evidence(artifact)

    assert result.reason_code == "MCP_ACTION_MAPPING_CLAIM_STATE_MISMATCH"


def test_an_absent_claim_must_say_why_and_carry_no_reference() -> None:
    artifact = json.loads(
        json.dumps(_vector("execution_before_dispatch_claim")["artifact"])
    )
    artifact["approval"]["dispatch_claim"] = {
        "state": "absent",
        "detail": "no_dispatch_claim_at_permit_signing_time",
        "dispatch_claim_reference": "sha256:" + "a" * 64,
    }

    result = ame.verify_action_mapping_evidence(artifact)

    assert result.reason_code == "MCP_ACTION_MAPPING_DISPATCH_CLAIM_FORBIDDEN"

    artifact["approval"]["dispatch_claim"] = {"state": "absent"}
    assert (
        ame.verify_action_mapping_evidence(artifact).reason_code
        == "MCP_ACTION_MAPPING_DISPATCH_CLAIM_FORBIDDEN"
    )


def test_a_dispatch_claim_cannot_be_acquired_at_a_stale_epoch() -> None:
    artifact = json.loads(
        json.dumps(_vector("execution_after_committed_claim")["artifact"])
    )
    artifact["approval"]["dispatch_claim"]["claimed_lifecycle_epoch"] = 0

    result = ame.verify_action_mapping_evidence(artifact)

    assert result.reason_code == "MCP_ACTION_MAPPING_DISPATCH_CLAIM_EPOCH_MISMATCH"


@pytest.mark.parametrize(
    "state", ["frozen", "superseded", "permanently_revoked"]
)
def test_a_dispatch_claim_cannot_be_acquired_on_a_non_active_revision(
    state: str,
) -> None:
    artifact = json.loads(
        json.dumps(_vector("execution_after_committed_claim")["artifact"])
    )
    artifact["mapping"]["lifecycle_state"] = state

    result = ame.verify_action_mapping_evidence(artifact)

    assert result.reason_code == "MCP_ACTION_MAPPING_LIFECYCLE_STATE_INVALID"


def test_the_governance_action_may_not_become_the_permit_action() -> None:
    artifact = json.loads(
        json.dumps(_vector("execution_before_dispatch_claim")["artifact"])
    )
    governance_action_id = artifact["governance_action"]["governance_action_id"]

    artifact["permit_action_name"] = governance_action_id
    assert (
        ame.verify_action_mapping_evidence(artifact).reason_code
        == "MCP_ACTION_MAPPING_ACTION_NAME_INVALID"
    )


def test_direct_adjudication_does_not_require_an_mcp_semantic_selector() -> None:
    artifact = _vector("execution_before_dispatch_claim")["artifact"]

    result = ame.verify_action_mapping_evidence(artifact)

    assert result.verdict == "supported"
    assert result.claims[ame.BINDING_CLAIM].verdict == "supported"


@pytest.mark.parametrize("name", POSITIVE_VECTORS)
def test_each_artifact_class_uses_recipe_v6_and_registry_v7_ceilings(
    name: str,
) -> None:
    artifact = _vector(name)["artifact"]
    result = ame.verify_action_mapping_evidence(artifact)
    expected = set(ame.expected_claims(artifact))
    supported = {
        claim.name for claim in result.claims.values() if claim.verdict == "supported"
    }

    assert ame.ACTION_MAPPING_RECIPE_VERSION == "v6"
    assert ame.ACTION_MAPPING_CLAIM_REGISTRY_VERSION == "verifier-claims.v7"
    assert supported == expected
    for claim in result.claims.values():
        assert claim.does_not_establish == ame.claim_evidence_ceiling(claim.name)


def test_a_structural_artifact_may_not_ride_alongside_dispatch_evidence() -> None:
    artifact = _vector("structural_hold_incomplete_financial_facts")["artifact"]

    assert (
        ame.verify_action_mapping_evidence(
            artifact, dispatch_evidence_present=True
        ).reason_code
        == "MCP_ACTION_MAPPING_STRUCTURAL_DISPATCH_EVIDENCE"
    )
    assert (
        ame.verify_action_mapping_evidence(artifact, decision_is_allow=True).reason_code
        == "MCP_ACTION_MAPPING_STRUCTURAL_DISPATCH_EVIDENCE"
    )


def test_the_four_verdict_model_is_unchanged() -> None:
    from keel_verifier.verdicts import load_claim_registry

    registry = load_claim_registry()

    assert registry.verdict_enum == (
        "supported",
        "disproved",
        "insufficient_evidence",
        "unverifiable_scope",
    )
    for name in ame.ACTION_MAPPING_CLAIMS:
        assert registry.claim(name).verdict_enum == registry.verdict_enum
        assert registry.claim(name).does_not_establish
