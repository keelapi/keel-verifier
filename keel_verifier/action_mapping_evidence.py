"""Managed MCP Action Mapping evidence — ACTION_MAPPING_SPEC.md §8.

Three artifact classes are established at different moments and carry different
authority, so they are verified through different paths:

``execution``
    Signed into the execution Permit *before* the reviewed-approval consumption
    claim and the dispatch claim exist. This is the only class the Permit
    adjudicator may see, and it names neither claim.

``structural_decision``
    A non-approvable hold. It created no approval action and no Permit, so it
    is **not** Permit evidence and must never be adjudicated through one. It has
    no resume and no dispatch semantics.

``post_claim_execution``
    Separate durable evidence emitted only after both relational claims have
    committed. The Permit was signed and flushed before this artifact existed,
    so it is standalone too, and it is the only class that may name a dispatch
    claim.

The schema is vendored byte-identically from the keel-api artifact the runtime
validates against, so a divergence is a byte difference rather than a judgement
call. Every positive statement below is gated on the group that carries it: no
statement is composed from prose, an artifact class, or a disclaimer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
import json
from typing import Any, Final, Mapping

import jsonschema


EVIDENCE_VERSION: Final = "keel.mcp_action_mapping_evidence.v1"
BOUNDED_PROJECTION_VERSION: Final = "keel.mcp_action_mapping_bounded_evidence.v1"
ATTRIBUTE_KEY: Final = "mcp_action_mapping_evidence_v1"
SURFACE_KEY: Final = "managed_mcp:action_mapping"
SCHEMA_ARTIFACT_ID: Final = "mcp-action-mapping-evidence-v1.schema.json"
PERMIT_ACTION_NAME: Final = "mcp.tool.call"
ACTION_MAPPING_CLAIM_REGISTRY_VERSION: Final = "verifier-claims.v7"
ACTION_MAPPING_RECIPE_ID: Final = "keel.permit.universal_verification.v7"
ACTION_MAPPING_RECIPE_VERSION: Final = "v7"

#: The live basis tuple. WP4 added the mapping lifecycle epoch and WP7 added the
#: governance action, catalog-entry hash, and assurance. A basis hash is
#: comparable only within an identical version, so an earlier version is
#: non-dischargeable with no fallback, reconstruction, or cross-version
#: comparison -- not a mismatch to be resolved.
CHALLENGE_BASIS_VERSION: Final = "mcp_challenge_basis.v4"
_SUPERSEDED_BASIS_VERSIONS: Final = frozenset(
    {"mcp_challenge_basis.v1", "mcp_challenge_basis.v2", "mcp_challenge_basis.v3"}
)

ARTIFACT_CLASS_EXECUTION: Final = "execution"
ARTIFACT_CLASS_STRUCTURAL_DECISION: Final = "structural_decision"
ARTIFACT_CLASS_POST_CLAIM_EXECUTION: Final = "post_claim_execution"

#: Only ``execution`` is bound into the signed execution Permit. The other two
#: are durable standalone evidence and a Permit carrying one is a category
#: error, not a lenient case.
PERMIT_BOUND_ARTIFACT_CLASSES: Final = frozenset({ARTIFACT_CLASS_EXECUTION})

BINDING_CLAIM: Final = "permit.mcp_action_mapping_binding.v1"
GOVERNANCE_INTERPRETATION_CLAIM: Final = "permit.mcp_governance_interpretation.v1"
STRUCTURAL_HOLD_EVIDENCE_CLAIM: Final = "permit.mcp_structural_hold_evidence.v1"
DISPATCH_ELIGIBILITY_CLAIM: Final = "permit.mcp_dispatch_eligibility.v1"
ACTION_MAPPING_CLAIMS: Final = (
    BINDING_CLAIM,
    GOVERNANCE_INTERPRETATION_CLAIM,
    STRUCTURAL_HOLD_EVIDENCE_CLAIM,
    DISPATCH_ELIGIBILITY_CLAIM,
)


# ---------------------------------------------------------------------------
# Bounded statements -- verbatim from §8, matched to the keel-api producer
# ---------------------------------------------------------------------------

BINDING_STATEMENT: Final = (
    "The Permit binds the mapping and activation reference used by Keel's "
    "decision."
)

#: The trailing clause is load-bearing. §8 withholds this form while
#: consequence-critical facts are incomplete, so a sentence that stopped at
#: "under mandatory review" would be emittable in exactly the case §8 refuses
#: it. That phrasing is banned outright below.
INTERPRETATION_STATEMENT: Final = (
    "Keel evaluated this exact managed MCP request using the human-approved "
    "governance interpretation {governance_action_id} under exact review, with "
    "the consequence-critical facts bound in the review material."
)

ELIGIBILITY_STATEMENT: Final = (
    "Keel's managed MCP decision made this exact request eligible for dispatch "
    "only after the bound action approval was satisfied."
)

STRUCTURAL_STATEMENT: Final = (
    "The signed evidence binds the structural challenge basis, typed absence, "
    "and derivation diagnostics for a managed MCP request that created no "
    "approval action and no execution Permit."
)

INCOMPLETE_FACTS_STATEMENT: Final = (
    "Keel held this opaque mapped invocation because required trusted financial "
    "facts were unavailable; no approval action or execution Permit was created."
)

CERTIFIED_CONTRACT_NOT_BOUND_STATEMENT: Final = (
    "No certified action contract was bound. The governance action is an "
    "interpretation, not a certification."
)

APPROVAL_SET_NOT_ESTABLISHED_STATEMENT: Final = (
    "The unique consumption claim establishes single consumption, not which "
    "approvals satisfied the requirement. The approval set is not "
    "independently established without a bundle containing and validating the "
    "canonical qualifying attestations."
)

DISPATCH_CLAIM_ACQUIRED_STATEMENT: Final = (
    "Keel recorded an acquired dispatch claim at the mapping lifecycle epoch. "
    "That claim does not establish that an upstream request was sent, accepted, "
    "or completed."
)

#: A floor, not a ceiling.
DOES_NOT_ESTABLISH: Final[tuple[str, ...]] = (
    "that upstream dispatch occurred",
    "that upstream dispatch occurred at most once",
    "that upstream dispatch did not occur before approval",
    "which approvals satisfied the frozen requirement",
    "provider acceptance",
    "downstream completion or effect",
    "handler semantics",
    "certified action facts or certified adapter semantics",
    "deployment of the mapped source revision",
    "absence of bypass",
    "independent verification of the WebAuthn activation ceremony",
    "that the human understood the mapping or its handler semantics",
)

#: §10 test 48, enforced rather than documented. Casefolded substrings, so a
#: paraphrase in different capitalisation still fails.
BANNED_PHRASES: Final[tuple[str, ...]] = (
    "required human approval before dispatch",
    "requires human approval before dispatch",
    "two humans approved",
    "two people approved",
    "independently verifies the webauthn",
    "independently verified the webauthn",
    "verifies the webauthn assertion",
    "keel verified what this handler does",
    "inherits stripe certification",
    "certified refund contract",
    "trusted connector",
    "fully protected",
    "freeze cancels in-flight",
    "freeze recalled",
    "point of no return",
    "already dispatched",
    "dispatched upstream",
    "may still complete",
    "under mandatory review",
    "refund of",
    "refunded",
)


class BoundedLanguageError(RuntimeError):
    """A projection carried phrasing the artifact cannot support."""


# ---------------------------------------------------------------------------
# Required field inventory
# ---------------------------------------------------------------------------

#: Fields §8 requires in their own right, checked before schema validation so
#: the missing field is named rather than folded into one schema error. The
#: manifest hash never stands in for the revision -- it is invariant across a
#: lifecycle transition that moves the epoch -- and the basis hash never stands
#: in for the basis version.
_REQUIRED_FIELDS: Final[tuple[tuple[str, str], ...]] = (
    ("source", "project_id"),
    ("source", "mcp_server_id"),
    ("source", "server_boundary_hash"),
    ("source", "source_tool_name"),
    ("source", "accepted_tool_schema_hash"),
    ("source", "observed_tool_schema_hash"),
    ("source", "tool_contract_status"),
    ("source", "tool_arguments_hash"),
    ("source", "tool_arguments_hash_version"),
    ("source", "decision_trace_id"),
    ("source", "decision_trace_hash"),
    ("mapping", "mapping_id"),
    ("mapping", "mapping_revision"),
    ("mapping", "manifest_hash"),
    ("mapping", "lifecycle_epoch"),
    ("mapping", "lifecycle_state"),
    ("mapping", "assurance"),
    ("mapping", "classification_provenance"),
    ("governance_action", "governance_action_id"),
    ("governance_action", "governance_action_version"),
    ("governance_action", "catalog_entry_hash"),
    ("structural", "challenge_class"),
    ("structural", "challenge_basis_hash"),
    ("structural", "challenge_basis_version"),
    ("structural", "reason_code"),
    ("structural", "typed_absence_hash"),
    ("structural", "derivation_diagnostics_hash"),
    ("activation", "activation_record_id"),
    ("activation", "activation_record_hash"),
    ("activation", "activated_lifecycle_epoch"),
)

_REQUIRED_APPROVAL_FIELDS: Final[tuple[str, ...]] = (
    "reviewed_permit_id",
    "execution_permit_id",
    "original_trace_id",
    "current_trace_id",
    "exact_request_review_hash",
    "approval_requirement_hash",
    "exact_request_binding_hash",
    "idempotency_binding_hash",
    "idempotency_binding_version",
    "reviewed_authorizer_input_hash",
    "reviewed_authorizer_input_contract_version",
    "claim_record",
    "dispatch_claim",
    "approval_set_independently_established",
)


@dataclass(frozen=True)
class ClaimResult:
    """One adjudicated Action Mapping claim."""

    name: str
    verdict: str
    reason_code: str
    message: str
    does_not_establish: tuple[str, ...] = ()


@dataclass(frozen=True)
class ActionMappingEvidenceResult:
    verdict: str
    reason_code: str
    message: str
    artifact_class: str | None
    claims: dict[str, ClaimResult] = field(default_factory=dict)
    bounded_projection: dict[str, Any] = field(default_factory=dict)

    @property
    def supported(self) -> bool:
        return self.verdict == "supported"


@lru_cache(maxsize=1)
def evidence_schema() -> dict[str, Any]:
    """The bundled copy of the keel-api-owned canonical schema."""

    resource = resources.files("keel_verifier").joinpath(
        f"data/permit_to_x/schemas/{SCHEMA_ARTIFACT_ID}"
    )
    return json.loads(resource.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _action_mapping_claim_definitions() -> dict[str, dict[str, Any]]:
    """Load the Action Mapping claims directly from bundled registry v7."""

    resource = resources.files("keel_verifier").joinpath(
        "data/claim_registry/v7.json"
    )
    payload = json.loads(resource.read_text(encoding="utf-8"))
    if payload.get("version") != ACTION_MAPPING_CLAIM_REGISTRY_VERSION:
        raise RuntimeError("the bundled Action Mapping claim registry is not v7")
    claims = {
        str(item["name"]): dict(item)
        for item in payload.get("claims", [])
        if isinstance(item, Mapping) and isinstance(item.get("name"), str)
    }
    if set(claims) != set(ACTION_MAPPING_CLAIMS):
        raise RuntimeError(
            "the bundled Action Mapping claim registry does not define exactly "
            "the four v7 claims"
        )
    return claims


@lru_cache(maxsize=1)
def action_mapping_recipe() -> dict[str, tuple[str, ...]]:
    """Load the class-to-claim routing directly from universal recipe v7."""

    resource = resources.files("keel_verifier").joinpath(
        "data/semantics/permit/universal_verification_v7.json"
    )
    payload = json.loads(resource.read_text(encoding="utf-8"))
    if (
        payload.get("id") != ACTION_MAPPING_RECIPE_ID
        or payload.get("version") != ACTION_MAPPING_RECIPE_VERSION
    ):
        raise RuntimeError("the bundled Action Mapping recipe is not v7")
    body = payload.get("body")
    if not isinstance(body, Mapping) or body.get("claim_registry_version") != (
        ACTION_MAPPING_CLAIM_REGISTRY_VERSION
    ):
        raise RuntimeError("the bundled Action Mapping recipe does not pin registry v7")
    conditional = body.get("conditional_evidence_claims")
    recipe = (
        conditional.get(SURFACE_KEY) if isinstance(conditional, Mapping) else None
    )
    if not isinstance(recipe, Mapping):
        raise RuntimeError("the bundled Action Mapping recipe is missing its surface")
    normalized = {
        phase: tuple(name for name in recipe.get(phase, []) if isinstance(name, str))
        for phase in ("binding", "execution", "structural", "post_claim")
    }
    routed = {name for names in normalized.values() for name in names}
    if routed != set(_action_mapping_claim_definitions()):
        raise RuntimeError(
            "the bundled Action Mapping recipe and registry disagree on claims"
        )
    return normalized


def claim_evidence_ceiling(name: str) -> tuple[str, ...]:
    """Return one claim's exact v7 ``does_not_establish`` ceiling."""

    try:
        definition = _action_mapping_claim_definitions()[name]
    except KeyError as exc:
        raise ValueError(f"unknown Action Mapping claim {name!r}") from exc
    ceiling = definition.get("does_not_establish")
    if not isinstance(ceiling, list) or not all(
        isinstance(value, str) and value for value in ceiling
    ):
        raise RuntimeError(f"Action Mapping claim {name!r} has no valid ceiling")
    return tuple(ceiling)


def _section(artifact: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    section = artifact.get(name)
    return section if isinstance(section, Mapping) else {}


def assert_bounded_language(projection: Mapping[str, Any]) -> None:
    """Refuse to emit a projection carrying banned phrasing.

    Checked over the serialised projection so a phrase cannot slip in through a
    statement, a disclaimer, or a field name.
    """

    haystack = json.dumps(projection, sort_keys=True).casefold()
    for phrase in BANNED_PHRASES:
        if phrase in haystack:
            raise BoundedLanguageError(
                f"bounded Action Mapping evidence carried the forbidden phrase "
                f"{phrase!r}"
            )


def build_bounded_projection(
    artifact: Mapping[str, Any] | None,
    *,
    approval_set_bundle_verified: bool = False,
) -> dict[str, Any]:
    """Turn one artifact into the statements it actually supports.

    ``approval_set_bundle_verified`` exists so the one condition §8 names is
    expressed rather than assumed. No caller can currently set it: establishing
    it requires a bundle containing and validating the canonical qualifying
    attestations, and no such bundle format is defined. Until one is, the answer
    is false and the verifier says so.
    """

    statements: list[str] = []
    artifact_class = ""
    governance_action_id = ""
    if artifact is not None:
        artifact_class = str(artifact.get("artifact_class") or "")
        governance_action_id = str(
            _section(artifact, "governance_action").get("governance_action_id") or ""
        )

    approval = artifact.get("approval") if artifact is not None else None
    claim_record = (
        approval.get("claim_record") if isinstance(approval, Mapping) else None
    )
    claim_recorded = (
        isinstance(claim_record, Mapping) and claim_record.get("state") == "recorded"
    )

    if artifact_class in {
        ARTIFACT_CLASS_EXECUTION,
        ARTIFACT_CLASS_POST_CLAIM_EXECUTION,
    }:
        statements.append(BINDING_STATEMENT)
        if governance_action_id:
            statements.append(
                INTERPRETATION_STATEMENT.format(
                    governance_action_id=governance_action_id
                )
            )
        if claim_recorded:
            statements.append(ELIGIBILITY_STATEMENT)
    elif artifact_class == ARTIFACT_CLASS_STRUCTURAL_DECISION:
        statements.append(BINDING_STATEMENT)
        statements.append(STRUCTURAL_STATEMENT)
        statements.append(INCOMPLETE_FACTS_STATEMENT)

    certified = _section(artifact or {}, "mapping").get("certified_action_contract")
    certified_bound = (
        isinstance(certified, Mapping) and certified.get("state") == "present"
    )

    projection: dict[str, Any] = {
        "version": BOUNDED_PROJECTION_VERSION,
        "artifact_class": artifact_class or None,
        "permit_action_name": PERMIT_ACTION_NAME,
        "statements": statements,
        "certified_action_contract_bound": certified_bound,
        "certified_action_contract_statement": CERTIFIED_CONTRACT_NOT_BOUND_STATEMENT,
        "approval_set_independently_established": bool(approval_set_bundle_verified),
        "approval_set_statement": APPROVAL_SET_NOT_ESTABLISHED_STATEMENT,
        # No branch sets this true. §8 requires a bundle carrying the canonical
        # activation record and sufficient supporting evidence before the claim
        # may be made, and no such bundle reaches this verifier.
        "webauthn_assertion_independently_verified": False,
        "does_not_establish": list(DOES_NOT_ESTABLISH),
    }
    if claim_recorded and isinstance(approval, Mapping):
        dispatch = approval.get("dispatch_claim")
        if isinstance(dispatch, Mapping) and dispatch.get("state") == "acquired":
            projection["in_flight_statement"] = DISPATCH_CLAIM_ACQUIRED_STATEMENT
    assert_bounded_language(projection)
    return projection


def _failure(
    verdict: str,
    reason_code: str,
    message: str,
    *,
    artifact_class: str | None,
    requested: tuple[str, ...],
) -> ActionMappingEvidenceResult:
    return ActionMappingEvidenceResult(
        verdict=verdict,
        reason_code=reason_code,
        message=message,
        artifact_class=artifact_class,
        claims={
            name: ClaimResult(
                name=name,
                verdict=verdict,
                reason_code=reason_code,
                message=message,
                does_not_establish=claim_evidence_ceiling(name),
            )
            for name in requested
        },
        bounded_projection=build_bounded_projection(None),
    )


def expected_claims(artifact: Mapping[str, Any] | None) -> tuple[str, ...]:
    """Claims the pinned recipe requests for one artifact class.

    The binding claim is always requested. Exactly one of the interpretation and
    structural claims follows from the class, so an emitter cannot drop the
    stricter claim by omitting it, and the eligibility claim is requested only
    where a committed consumption claim can carry it.
    """

    if artifact is None:
        return ()
    artifact_class = str(artifact.get("artifact_class") or "")
    phases_by_class = {
        ARTIFACT_CLASS_STRUCTURAL_DECISION: ("binding", "structural"),
        ARTIFACT_CLASS_EXECUTION: ("binding", "execution"),
        ARTIFACT_CLASS_POST_CLAIM_EXECUTION: (
            "binding",
            "execution",
            "post_claim",
        ),
    }
    phases = phases_by_class.get(artifact_class, ())
    recipe = action_mapping_recipe()
    return tuple(name for phase in phases for name in recipe[phase])


def verify_action_mapping_evidence(
    artifact: Mapping[str, Any] | None,
    *,
    permit_bound: bool = False,
    permit_id: str | None = None,
    dispatch_evidence_present: bool = False,
    decision_is_allow: bool | None = None,
    requested_claims: tuple[str, ...] | None = None,
) -> ActionMappingEvidenceResult:
    """Adjudicate one Action Mapping evidence artifact, fail-closed.

    ``permit_bound`` marks the Permit adjudication path, which may only see the
    ``execution`` class. The other two classes are durable standalone evidence;
    a Permit carrying one is a category error, not a lenient case.
    """

    requested = requested_claims if requested_claims is not None else ACTION_MAPPING_CLAIMS

    def fail(verdict: str, code: str, message: str) -> ActionMappingEvidenceResult:
        artifact_class = (
            str(artifact.get("artifact_class") or "") or None
            if isinstance(artifact, Mapping)
            else None
        )
        return _failure(
            verdict,
            code,
            message,
            artifact_class=artifact_class,
            requested=requested,
        )

    # Absence of the attribute is the evidence: an unmapped managed MCP call
    # keeps exactly the signed shape it had before WP9.
    if artifact is None:
        return _failure(
            "insufficient_evidence",
            "MCP_ACTION_MAPPING_EVIDENCE_NOT_RECORDED",
            "no mapping governs this managed MCP source, so no Action Mapping "
            "evidence was recorded",
            artifact_class=None,
            requested=requested,
        )
    if not isinstance(artifact, Mapping):
        return fail(
            "disproved",
            "MCP_ACTION_MAPPING_EVIDENCE_INVALID",
            "the mapping evidence is not an object",
        )
    if artifact.get("version") != EVIDENCE_VERSION:
        return fail(
            "unverifiable_scope",
            "MCP_ACTION_MAPPING_VERSION_UNSUPPORTED",
            "the mapping evidence version is not supported",
        )
    if artifact.get("enforcement_surface_key") != SURFACE_KEY:
        return fail(
            "disproved",
            "MCP_ACTION_MAPPING_SURFACE_MISMATCH",
            "the mapping evidence does not name the managed-MCP Action Mapping "
            "surface",
        )

    for group, name in _REQUIRED_FIELDS:
        value = _section(artifact, group).get(name)
        if value is None or (isinstance(value, str) and not value):
            return fail(
                "disproved",
                "MCP_ACTION_MAPPING_FIELD_MISSING",
                f"the mapping evidence does not bind {group}.{name}",
            )

    mapping = _section(artifact, "mapping")
    structural = _section(artifact, "structural")
    activation = _section(artifact, "activation")
    governance_action = _section(artifact, "governance_action")
    governance_action_id = str(governance_action.get("governance_action_id") or "")

    # A monotonic integer, not a label. A string revision cannot be ordered and
    # cannot distinguish "any revision of M" from "this exact revision".
    revision = mapping.get("mapping_revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        return fail(
            "disproved",
            "MCP_ACTION_MAPPING_REVISION_INVALID",
            "mapping.mapping_revision is not a positive integer",
        )

    basis_version = str(structural.get("challenge_basis_version") or "")
    if basis_version != CHALLENGE_BASIS_VERSION:
        return fail(
            "disproved"
            if basis_version in _SUPERSEDED_BASIS_VERSIONS
            else "unverifiable_scope",
            "MCP_ACTION_MAPPING_BASIS_VERSION_UNSUPPORTED",
            f"the challenge basis version is not the admitted "
            f"{CHALLENGE_BASIS_VERSION}; a basis hash is comparable only within "
            "an identical basis version, with no fallback, reconstruction, or "
            "cross-version comparison",
        )

    if "unavailable_fact_paths" not in structural or not isinstance(
        structural.get("unavailable_fact_paths"), list
    ):
        return fail(
            "disproved",
            "MCP_ACTION_MAPPING_FIELD_MISSING",
            "the mapping evidence does not bind structural.unavailable_fact_paths",
        )

    # The governance action is an interpretation, while the artifact itself
    # binds the managed-MCP Permit action. No semantic-selector entry for
    # mcp.tool.call is required (or currently published) to adjudicate this
    # separate evidence contract.
    permit_action_name = str(artifact.get("permit_action_name") or "")
    if permit_action_name != PERMIT_ACTION_NAME:
        return fail(
            "disproved",
            "MCP_ACTION_MAPPING_ACTION_NAME_INVALID",
            "the top-level Permit action is not mcp.tool.call",
        )
    if permit_action_name == governance_action_id:
        return fail(
            "disproved",
            "MCP_ACTION_MAPPING_ACTION_NAME_MISMATCH",
            "the target governance action replaced the Permit action name in "
            "the mapping evidence",
        )

    assurance = str(mapping.get("assurance") or "")
    certified = mapping.get("certified_action_contract")
    if not isinstance(certified, Mapping) or certified.get("state") not in (
        "absent",
        "present",
    ):
        return fail(
            "disproved",
            "MCP_ACTION_MAPPING_CERTIFIED_CONTRACT_UNTYPED",
            "the certified-action-contract state is not typed present or absent",
        )
    arbitrary_mapping = assurance == "human_mapped_review_only"
    if arbitrary_mapping and certified.get("state") != "absent":
        return fail(
            "disproved",
            "MCP_ACTION_MAPPING_CERTIFIED_CONTRACT_FORBIDDEN",
            "an arbitrary human mapping binds no certified_action_contract_id, "
            "but the evidence names one",
        )
    if arbitrary_mapping and mapping.get("classification_provenance") != (
        "human_approved_action_mapping"
    ):
        return fail(
            "disproved",
            "MCP_ACTION_MAPPING_PROVENANCE_INVALID",
            "an arbitrary human mapping cannot claim curated or verified-adapter "
            "classification provenance",
        )

    lifecycle_epoch = mapping.get("lifecycle_epoch")
    activated_epoch = activation.get("activated_lifecycle_epoch")
    if (
        not isinstance(lifecycle_epoch, int)
        or isinstance(lifecycle_epoch, bool)
        or not isinstance(activated_epoch, int)
        or isinstance(activated_epoch, bool)
    ):
        return fail(
            "disproved",
            "MCP_ACTION_MAPPING_FIELD_MISSING",
            "the mapping evidence does not bind an integer lifecycle epoch",
        )
    if activated_epoch > lifecycle_epoch:
        return fail(
            "disproved",
            "MCP_ACTION_MAPPING_ACTIVATION_EPOCH_INVALID",
            "the activation record names a later lifecycle epoch than the mapping",
        )
    # Binding a reference to an activation record is not verifying the ceremony
    # that produced it, and the artifact may not assert otherwise.
    if activation.get("independently_verified") is not False:
        return fail(
            "disproved",
            "MCP_ACTION_MAPPING_ACTIVATION_OVERCLAIM",
            "the evidence claims the activation ceremony was independently "
            "verified; binding a reference is not verifying the assertion",
        )

    artifact_class = str(artifact.get("artifact_class") or "")
    if artifact_class not in {
        ARTIFACT_CLASS_EXECUTION,
        ARTIFACT_CLASS_STRUCTURAL_DECISION,
        ARTIFACT_CLASS_POST_CLAIM_EXECUTION,
    }:
        return fail(
            "unverifiable_scope",
            "MCP_ACTION_MAPPING_ARTIFACT_CLASS_UNSUPPORTED",
            "the mapping evidence artifact class is not supported",
        )
    if permit_bound and artifact_class not in PERMIT_BOUND_ARTIFACT_CLASSES:
        return fail(
            "disproved",
            "MCP_ACTION_MAPPING_ARTIFACT_CLASS_NOT_PERMIT_EVIDENCE",
            f"{artifact_class} is durable standalone evidence and is not bound "
            "into an execution Permit",
        )

    challenge_class = str(structural.get("challenge_class") or "")
    approval = artifact.get("approval")

    if artifact_class == ARTIFACT_CLASS_STRUCTURAL_DECISION:
        if challenge_class != "structural_hold":
            return fail(
                "disproved",
                "MCP_ACTION_MAPPING_CHALLENGE_CLASS_MISMATCH",
                "a structural decision artifact must carry challenge_class "
                "structural_hold",
            )
        if approval is not None:
            return fail(
                "disproved",
                "MCP_ACTION_MAPPING_STRUCTURAL_APPROVAL_PRESENT",
                "a structural hold creates no approval action and no execution "
                "Permit, but the evidence carries an approval group",
            )
        if dispatch_evidence_present or decision_is_allow:
            return fail(
                "disproved",
                "MCP_ACTION_MAPPING_STRUCTURAL_DISPATCH_EVIDENCE",
                "a structural hold has no resume or dispatch semantics, but the "
                "bundle supplies dispatch evidence or an allow decision",
            )
    else:
        if challenge_class != "action_review":
            return fail(
                "disproved",
                "MCP_ACTION_MAPPING_CHALLENGE_CLASS_MISMATCH",
                "an execution artifact must carry challenge_class action_review",
            )
        if not isinstance(approval, Mapping):
            return fail(
                "disproved",
                "MCP_ACTION_MAPPING_APPROVAL_MISSING",
                "the execution evidence carries no approval group",
            )
        for name in _REQUIRED_APPROVAL_FIELDS:
            value = approval.get(name)
            if value is None or (isinstance(value, str) and not value):
                return fail(
                    "disproved",
                    "MCP_ACTION_MAPPING_APPROVAL_FIELD_MISSING",
                    f"the approval group does not bind {name}",
                )
        # Single consumption is not approval-set satisfaction. The artifact may
        # not assert otherwise, and no bundle format exists that would let a
        # verifier establish it.
        if approval.get("approval_set_independently_established") is not False:
            return fail(
                "disproved",
                "MCP_ACTION_MAPPING_APPROVAL_SET_OVERCLAIM",
                "the evidence claims the approval set is independently "
                "established; the unique consumption claim establishes single "
                "consumption, not which approvals satisfied the requirement",
            )
        result = _verify_relational_claims(
            approval=approval,
            artifact_class=artifact_class,
            lifecycle_epoch=lifecycle_epoch,
            lifecycle_state=str(mapping.get("lifecycle_state") or ""),
            permit_id=permit_id,
            fail=fail,
        )
        if result is not None:
            return result

    try:
        jsonschema.Draft202012Validator(
            evidence_schema(),
            format_checker=jsonschema.FormatChecker(),
        ).validate(dict(artifact))
    except jsonschema.ValidationError as exc:
        return fail(
            "disproved",
            "MCP_ACTION_MAPPING_EVIDENCE_INVALID",
            f"the signed mapping evidence is invalid: {exc.message}",
        )

    projection = build_bounded_projection(artifact)
    carried = expected_claims(artifact)
    claims: dict[str, ClaimResult] = {}
    for name in requested:
        if name in carried:
            claims[name] = ClaimResult(
                name=name,
                verdict="supported",
                reason_code=_SUPPORTED_REASON_CODES[name],
                message=_supported_message(name, governance_action_id),
                does_not_establish=claim_evidence_ceiling(name),
            )
        else:
            claims[name] = ClaimResult(
                name=name,
                verdict="insufficient_evidence",
                reason_code=_UNCARRIED_REASON_CODES[name],
                message=_UNCARRIED_MESSAGES[name],
                does_not_establish=claim_evidence_ceiling(name),
            )
    return ActionMappingEvidenceResult(
        verdict="supported",
        reason_code="MCP_ACTION_MAPPING_EVIDENCE_VERIFIED",
        message=BINDING_STATEMENT,
        artifact_class=artifact_class,
        claims=claims,
        bounded_projection=projection,
    )


def _verify_relational_claims(
    *,
    approval: Mapping[str, Any],
    artifact_class: str,
    lifecycle_epoch: int,
    lifecycle_state: str,
    permit_id: str | None,
    fail: Any,
) -> ActionMappingEvidenceResult | None:
    """Check the two typed relational-claim objects against the class.

    An ``execution`` artifact is signed and flushed before either row exists, so
    both must be typed absent with a reason. A ``post_claim_execution`` artifact
    exists only because both committed, so both must be recorded.
    """

    claim_record = approval.get("claim_record")
    dispatch_claim = approval.get("dispatch_claim")
    if not isinstance(claim_record, Mapping) or claim_record.get("state") not in (
        "absent",
        "recorded",
    ):
        return fail(
            "disproved",
            "MCP_ACTION_MAPPING_CLAIM_RECORD_UNTYPED",
            "the consumption claim record state is not typed absent or recorded",
        )
    if not isinstance(dispatch_claim, Mapping) or dispatch_claim.get("state") not in (
        "absent",
        "acquired",
    ):
        return fail(
            "disproved",
            "MCP_ACTION_MAPPING_DISPATCH_CLAIM_UNTYPED",
            "the dispatch-claim state is not typed absent or acquired",
        )

    # Absence is information, not a missing field: it must say why, and it must
    # not smuggle a reference alongside.
    for label, typed, code in (
        ("consumption claim", claim_record, "MCP_ACTION_MAPPING_CLAIM_RECORD_FORBIDDEN"),
        ("dispatch claim", dispatch_claim, "MCP_ACTION_MAPPING_DISPATCH_CLAIM_FORBIDDEN"),
    ):
        if typed.get("state") == "absent":
            if not str(typed.get("detail") or ""):
                return fail(
                    "disproved",
                    code,
                    f"the absent {label} does not say why it is absent",
                )
            if len(typed) != 2:
                return fail(
                    "disproved",
                    code,
                    f"an absent {label} must carry no reference",
                )

    expected_states = (
        ("absent", "absent")
        if artifact_class == ARTIFACT_CLASS_EXECUTION
        else ("recorded", "acquired")
    )
    if (claim_record.get("state"), dispatch_claim.get("state")) != expected_states:
        return fail(
            "disproved",
            "MCP_ACTION_MAPPING_CLAIM_STATE_MISMATCH",
            f"{artifact_class} requires claim_record={expected_states[0]} and "
            f"dispatch_claim={expected_states[1]}",
        )

    if dispatch_claim.get("state") == "acquired":
        if dispatch_claim.get("claimed_lifecycle_epoch") != lifecycle_epoch:
            return fail(
                "disproved",
                "MCP_ACTION_MAPPING_DISPATCH_CLAIM_EPOCH_MISMATCH",
                "the dispatch claim names a different lifecycle epoch than the "
                "mapping",
            )
        if lifecycle_state != "active":
            return fail(
                "disproved",
                "MCP_ACTION_MAPPING_LIFECYCLE_STATE_INVALID",
                "a dispatch claim cannot be acquired at an epoch whose mapping "
                "revision is not active",
            )
        if claim_record.get("governed_request_id") != dispatch_claim.get(
            "governed_request_id"
        ):
            return fail(
                "disproved",
                "MCP_ACTION_MAPPING_GOVERNED_REQUEST_MISMATCH",
                "the consumption claim and the dispatch claim name different "
                "governed requests",
            )

    if approval.get("reviewed_permit_id") == approval.get("execution_permit_id"):
        return fail(
            "disproved",
            "MCP_ACTION_MAPPING_APPROVAL_PERMIT_MISMATCH",
            "the reviewed Permit and the execution Permit are the same record",
        )
    if permit_id is not None and approval.get("execution_permit_id") != permit_id:
        return fail(
            "disproved",
            "MCP_ACTION_MAPPING_APPROVAL_PERMIT_MISMATCH",
            "the approval group names a different execution Permit",
        )
    return None


_SUPPORTED_REASON_CODES: Final[dict[str, str]] = {
    BINDING_CLAIM: "MCP_ACTION_MAPPING_BINDING_VERIFIED",
    GOVERNANCE_INTERPRETATION_CLAIM: "MCP_GOVERNANCE_INTERPRETATION_VERIFIED",
    STRUCTURAL_HOLD_EVIDENCE_CLAIM: "MCP_STRUCTURAL_HOLD_EVIDENCE_VERIFIED",
    DISPATCH_ELIGIBILITY_CLAIM: "MCP_DISPATCH_ELIGIBILITY_VERIFIED",
}

_UNCARRIED_REASON_CODES: Final[dict[str, str]] = {
    BINDING_CLAIM: "MCP_ACTION_MAPPING_BINDING_NOT_CARRIED",
    GOVERNANCE_INTERPRETATION_CLAIM: "MCP_GOVERNANCE_INTERPRETATION_NOT_ESTABLISHED",
    STRUCTURAL_HOLD_EVIDENCE_CLAIM: "MCP_STRUCTURAL_HOLD_EVIDENCE_NOT_RECORDED",
    DISPATCH_ELIGIBILITY_CLAIM: "MCP_DISPATCH_ELIGIBILITY_NOT_ESTABLISHED",
}

_UNCARRIED_MESSAGES: Final[dict[str, str]] = {
    BINDING_CLAIM: (
        "this artifact class carries no mapping and activation binding"
    ),
    GOVERNANCE_INTERPRETATION_CLAIM: (
        "the evidence records a non-approvable structural hold, so no exact "
        "reviewed managed MCP request is established"
    ),
    STRUCTURAL_HOLD_EVIDENCE_CLAIM: (
        "the evidence records a reviewed managed MCP execution, not a "
        "non-approvable structural hold"
    ),
    DISPATCH_ELIGIBILITY_CLAIM: (
        "no committed reviewed-approval consumption claim is recorded, so "
        "eligibility after a satisfied approval is not established"
    ),
}


def _supported_message(name: str, governance_action_id: str) -> str:
    if name == BINDING_CLAIM:
        return BINDING_STATEMENT
    if name == GOVERNANCE_INTERPRETATION_CLAIM:
        return INTERPRETATION_STATEMENT.format(
            governance_action_id=governance_action_id
        )
    if name == STRUCTURAL_HOLD_EVIDENCE_CLAIM:
        return STRUCTURAL_STATEMENT
    return ELIGIBILITY_STATEMENT


__all__ = [
    "ACTION_MAPPING_CLAIMS",
    "ACTION_MAPPING_CLAIM_REGISTRY_VERSION",
    "ACTION_MAPPING_RECIPE_ID",
    "ACTION_MAPPING_RECIPE_VERSION",
    "ARTIFACT_CLASS_EXECUTION",
    "ARTIFACT_CLASS_POST_CLAIM_EXECUTION",
    "ARTIFACT_CLASS_STRUCTURAL_DECISION",
    "ATTRIBUTE_KEY",
    "BANNED_PHRASES",
    "BINDING_CLAIM",
    "BINDING_STATEMENT",
    "BOUNDED_PROJECTION_VERSION",
    "CHALLENGE_BASIS_VERSION",
    "DISPATCH_ELIGIBILITY_CLAIM",
    "DISPATCH_CLAIM_ACQUIRED_STATEMENT",
    "DOES_NOT_ESTABLISH",
    "ELIGIBILITY_STATEMENT",
    "EVIDENCE_VERSION",
    "GOVERNANCE_INTERPRETATION_CLAIM",
    "INCOMPLETE_FACTS_STATEMENT",
    "INTERPRETATION_STATEMENT",
    "PERMIT_ACTION_NAME",
    "PERMIT_BOUND_ARTIFACT_CLASSES",
    "STRUCTURAL_HOLD_EVIDENCE_CLAIM",
    "STRUCTURAL_STATEMENT",
    "SURFACE_KEY",
    "ActionMappingEvidenceResult",
    "BoundedLanguageError",
    "ClaimResult",
    "assert_bounded_language",
    "action_mapping_recipe",
    "build_bounded_projection",
    "claim_evidence_ceiling",
    "evidence_schema",
    "expected_claims",
    "verify_action_mapping_evidence",
]
