"""Native action evidence checks (NAE M1, ``nae-m1-interface`` §4.3, §7).

A native action pack (``export.json`` schema ``keel.native_action_pack.v1``)
wraps one Permit's proof-pack ``export.json`` object (``permit_audit_bundle``)
together with the exact review v2 object, the approval linkage, the native
closure governance events and the projected handle state.

This module is the verifier's independent implementation of the seven checks
in §7.2. It is pure: it never reads keys or the network. The caller is
responsible for the outer export integrity (manifest content hash and
signature) and for the signed Permit decision; these checks only adjudicate
what the signed content says about the native action.

Verdicts and reason codes match keel-api's reference
``app/services/native_actions/evidence.py::check_native_action_pack`` on
every input the reference can evaluate. Where this module checks more than
the reference (listed in ``ADDITIONAL_CHECKS``), the extra checks run after
the reference's own check for the same concern, so an input the reference
refuses is refused here with the same verdict and reason code.

A native pack never supports more than evidence level D (Keel's record of an
upstream-reported result). Nothing here establishes provider execution,
external state change or exclusive mediation.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import rfc8785

NATIVE_ACTION_PACK_SCHEMA = "keel.native_action_pack.v1"
NATIVE_ACTION_EXPORT_TYPE = "native_action"

ACTION_SCHEMA_V1 = "keel.canonical_action/v1"
SURFACE_MANAGED_MCP = "managed_mcp"
OPERATION_PR_CREATE = "repository.pull_request.create"
CONNECTOR_GITHUB = "github"
FACT_PROFILE_PR_CREATE = "keel.facts.repository_pull_request_create_exact.v1"
NATIVE_INPUT_PR_CREATE_V1 = "keel.native_input.repository_pull_request_create.v1"
COMMITMENT_METHOD = "keel.salted_sha256_jcs.v1"
NATIVE_DECISION_INPUTS_VERSION = "keel.native_decision_inputs.v1"
EXACT_REVIEW_V2_SCHEMA = "keel.exact_request_review.v2"

#: Upper bound on the action lifetime, whatever the approval window says.
MAX_ACTION_LIFETIME = timedelta(hours=24)

#: Evidence levels a native pack can never support (§7.2 item 7).
LEVEL_CEILING = "D"
LEVELS_ABOVE_CEILING = frozenset({"E", "F"})

EVENT_PROPOSED = "native.action.proposed"
EVENT_REVIEW_DECIDED = "native.action.review_decided"
EVENT_DISPATCH_STARTED = "native.action.dispatch_started"
EVENT_UPSTREAM_RESULT = "native.action.upstream_result"
EVENT_CLOSED = "native.action.closed"
EVENT_RECONCILED = "native.action.reconciled"
NATIVE_CLOSURE_EVENT_TYPES = frozenset(
    {
        EVENT_PROPOSED,
        EVENT_REVIEW_DECIDED,
        EVENT_DISPATCH_STARTED,
        EVENT_UPSTREAM_RESULT,
        EVENT_CLOSED,
        EVENT_RECONCILED,
    }
)
UPSTREAM_OUTCOMES = frozenset(
    {"upstream_reported_success", "provider_rejected", "outcome_unknown"}
)

# Reason codes (stable; keel-api's reference uses the same strings).
REASON_PACK_SCHEMA = "native.pack_schema"
REASON_EVIDENCE_INCOMPLETE = "native.evidence_incomplete"
REASON_ACTION_SCHEMA = "native.action_schema"
REASON_CANONICAL_ACTION_SHAPE = "native.canonical_action_shape"
REASON_BINDING_HASH_MISMATCH = "native.action_binding_hash_mismatch"
REASON_CROSS_FIELD_MISMATCH = "native.cross_field_mismatch"
REASON_REVIEW_BINDING = "native.review_binding"
REASON_SINGLE_DISPATCH = "native.single_dispatch"
REASON_LEVEL_CEILING = "native.level_ceiling"
REASON_DECISION_INPUTS_VERSION = "native.decision_inputs_version"

VERDICT_SUPPORTED = "supported"
VERDICT_DISPROVED = "disproved"
VERDICT_UNVERIFIABLE_SCOPE = "unverifiable_scope"
VERDICT_NOT_SUPPORTED = "not_supported"

#: Checks this verifier makes beyond keel-api's reference implementation.
#: Each one is an equality or shape rule stated in the interface (§4.3, §7.2,
#: §7.3, §7.4, changelog 1.3.0) that every real issuance satisfies.
ADDITIONAL_CHECKS = (
    "decision inputs version and action_schema are the v1 constants (§7.1)",
    "canonical_action.project_id equals the signed Permit project_id (§7.2 item 4)",
    "canonical_action.principal_id equals the signed Permit subject_id (§7.2 item 4)",
    "exact review v2 has exactly the §7.3 key set at every level and no null (§7.3)",
    "exact review v2 permit_id, project_id, action_id and action_schema equal the Permit's (§7.3)",
    "approval v1_review_hash equals exact_review_v2.v1_review_hash (§7.5)",
    "a review_decided event's exact_review_v2_hash equals the approval's (§7.4)",
    "dispatch_started carries the action's action_id and booleans that are exactly true (§7.4)",
    "dispatch_started precedes upstream_result in the event chain (§7.2 item 6)",
    "an upstream_result without dispatch_started is outcome_unknown (changelog 1.3.0)",
    "at most one upstream_result per action (§7.2 item 6)",
)

CANONICAL_ACTION_V1_KEYS: frozenset[str] = frozenset(
    {
        "action_schema",
        "action_id",
        "project_id",
        "principal_id",
        "installation_id",
        "surface",
        "connector_identity",
        "connector_contract_version",
        "tool_schema_hash",
        "operation",
        "target",
        "canonical_input",
        "credential_reference",
        "workflow_binding",
        "policy_epoch",
        "created_at",
        "expires_at",
    }
)
TARGET_V1_KEYS: frozenset[str] = frozenset(
    {"repository_reference_commitment", "base_branch", "head_branch"}
)
CANONICAL_INPUT_V1_KEYS: frozenset[str] = frozenset(
    {
        "fact_profile_id",
        "native_input_version",
        "base_commit_sha",
        "head_commit_sha",
        "compare_state_digest",
        "changed_paths_digest",
        "title_commitment",
        "body_commitment",
        "draft",
    }
)
COMMITMENT_KEYS: frozenset[str] = frozenset({"method", "digest"})
NATIVE_ACTION_ATTRIBUTE_KEYS: frozenset[str] = frozenset(
    {"action_schema", "canonical_action", "action_binding_hash"}
)

EXACT_REVIEW_V2_KEYS: frozenset[str] = frozenset(
    {
        "schema_version",
        "permit_id",
        "project_id",
        "action_id",
        "action_binding_hash",
        "action_schema",
        "trusted_facts",
        "policy",
        "approval",
        "connector",
        "principal",
        "coverage",
        "v1_review_hash",
        "review_expires_at",
        "created_at",
    }
)
EXACT_REVIEW_V2_NESTED_KEYS: dict[str, frozenset[str]] = {
    "trusted_facts": frozenset(
        {
            "base_branch",
            "head_branch",
            "base_commit_sha",
            "head_commit_sha",
            "compare_status",
            "ahead_by",
            "behind_by",
            "changed_files_count",
            "additions_count",
            "deletions_count",
            "changed_paths_digest",
            "compare_state_digest",
            "protected_path_change_count",
            "base_branch_protected",
            "same_repository",
            "existing_open_pull_request_count",
            "merge_authorized",
            "draft",
            "repository_reference_commitment",
            "title_commitment",
            "body_commitment",
            "preflight_observed_at",
            "fact_snapshot_digest",
        }
    ),
    "policy": frozenset(
        {"id", "version", "snapshot_hash", "condition_semantics", "policy_epoch"}
    ),
    "approval": frozenset({"requirement_type", "approval_requirement_hash"}),
    "connector": frozenset(
        {
            "connector_identity",
            "credential_reference",
            "connector_contract_version",
            "tool_schema_hash",
        }
    ),
    "principal": frozenset(
        {
            "agent_principal_id",
            "credential_family_id",
            "installation_id",
            "client_claims_digest",
        }
    ),
    "coverage": frozenset(
        {
            "dispatch",
            "exclusivity_basis",
            "exclusivity_attestation_digest",
            "independently_confirmable",
        }
    ),
}

_HEX64 = re.compile(r"[0-9a-f]{64}")
_SHA40 = re.compile(r"[0-9a-f]{40}")
_RFC3339_Z = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_MAX_SAFE_INT = 2**53 - 1


class CanonicalActionShapeError(ValueError):
    """The canonical action is not exactly the v1 shape."""

    code = REASON_CANONICAL_ACTION_SHAPE


class ActionBindingHashMismatch(ValueError):
    """The stored ``action_binding_hash`` does not match the canonical action."""

    code = REASON_BINDING_HASH_MISMATCH

    def __init__(self) -> None:
        super().__init__("action_binding_hash does not match the canonical action")


# ---------------------------------------------------------------------------
# JCS and the canonical action (§4.3)
# ---------------------------------------------------------------------------


def _refuse_unsafe_numbers(value: Any) -> None:
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, bool) or item is None or isinstance(item, str):
            continue
        if isinstance(item, int):
            if abs(item) > _MAX_SAFE_INT:
                raise CanonicalActionShapeError("integer outside the interoperable range")
            continue
        if isinstance(item, float):
            raise CanonicalActionShapeError("floats are not permitted")
        if isinstance(item, Mapping):
            stack.extend(item.values())
            continue
        if isinstance(item, (list, tuple)):
            stack.extend(item)
            continue
        raise CanonicalActionShapeError(f"unsupported value type {type(item).__name__}")


def jcs(value: Any) -> bytes:
    """RFC 8785 bytes; refuses floats and integers outside ±(2^53-1)."""

    _refuse_unsafe_numbers(value)
    return rfc8785.dumps(value)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_rfc3339_seconds(value: Any) -> datetime:
    if not isinstance(value, str) or not _RFC3339_Z.fullmatch(value):
        raise CanonicalActionShapeError("timestamp is not RFC 3339 UTC seconds")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise CanonicalActionShapeError("timestamp is not a valid date-time") from exc


def _require_exact_keys(value: Any, expected: frozenset[str], where: str) -> None:
    if not isinstance(value, Mapping):
        raise CanonicalActionShapeError(f"{where} must be an object")
    keys = set(value.keys())
    if keys != expected:
        extra = sorted(str(key) for key in keys - expected)
        missing = sorted(expected - keys)
        raise CanonicalActionShapeError(
            f"{where} key set mismatch (extra={extra}, missing={missing})"
        )


def _require_str(value: Any, where: str, *, max_len: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise CanonicalActionShapeError(f"{where} must be a non-empty string")
    return value


def _require_uuid(value: Any, where: str) -> str:
    text = _require_str(value, where, max_len=36)
    try:
        parsed = uuid.UUID(text)
    except ValueError as exc:
        raise CanonicalActionShapeError(f"{where} must be a UUID") from exc
    if str(parsed) != text:
        raise CanonicalActionShapeError(f"{where} must be a canonical lowercase UUID")
    return text


def _require_commitment(value: Any, where: str) -> None:
    _require_exact_keys(value, COMMITMENT_KEYS, where)
    if value["method"] != COMMITMENT_METHOD:
        raise CanonicalActionShapeError(f"{where}.method is not {COMMITMENT_METHOD}")
    _require_str(value["digest"], f"{where}.digest", max_len=128)


def validate_canonical_action_shape(canonical_action: Any) -> None:
    """Refuse anything that is not exactly a v1 canonical action.

    No extra and no missing key at any level; ``workflow_binding`` is the only
    ``null``; no floats; integers inside ±(2^53-1);
    ``created_at < expires_at <= created_at + 24h``.
    """

    _require_exact_keys(canonical_action, CANONICAL_ACTION_V1_KEYS, "canonical_action")
    ca = canonical_action
    if ca["action_schema"] != ACTION_SCHEMA_V1:
        raise CanonicalActionShapeError("unsupported action_schema")
    for key in ("action_id", "project_id", "principal_id", "installation_id"):
        _require_uuid(ca[key], key)
    if ca["surface"] != SURFACE_MANAGED_MCP:
        raise CanonicalActionShapeError("surface must be managed_mcp")
    if ca["operation"] != OPERATION_PR_CREATE:
        raise CanonicalActionShapeError("unsupported operation")
    if ca["connector_identity"] != CONNECTOR_GITHUB:
        raise CanonicalActionShapeError("unsupported connector_identity")
    _require_str(ca["connector_contract_version"], "connector_contract_version")
    _require_str(ca["tool_schema_hash"], "tool_schema_hash", max_len=128)
    credential_reference = _require_str(ca["credential_reference"], "credential_reference")
    if not credential_reference.startswith("connector-credential:"):
        raise CanonicalActionShapeError("credential_reference must be connector-credential:<uuid>")
    _require_uuid(credential_reference.split(":", 1)[1], "credential_reference")
    if ca["workflow_binding"] is not None:
        raise CanonicalActionShapeError("workflow_binding must be null in v1")
    policy_epoch = ca["policy_epoch"]
    if isinstance(policy_epoch, bool) or not isinstance(policy_epoch, int) or policy_epoch < 0:
        raise CanonicalActionShapeError("policy_epoch must be a non-negative integer")
    created_at = _parse_rfc3339_seconds(ca["created_at"])
    expires_at = _parse_rfc3339_seconds(ca["expires_at"])
    if not created_at < expires_at <= created_at + MAX_ACTION_LIFETIME:
        raise CanonicalActionShapeError(
            "expires_at must be within (created_at, created_at + 24h]"
        )

    target = ca["target"]
    _require_exact_keys(target, TARGET_V1_KEYS, "target")
    _require_commitment(
        target["repository_reference_commitment"], "target.repository_reference_commitment"
    )
    _require_str(target["base_branch"], "target.base_branch", max_len=255)
    _require_str(target["head_branch"], "target.head_branch", max_len=255)

    ci = ca["canonical_input"]
    _require_exact_keys(ci, CANONICAL_INPUT_V1_KEYS, "canonical_input")
    if ci["fact_profile_id"] != FACT_PROFILE_PR_CREATE:
        raise CanonicalActionShapeError("unsupported fact_profile_id")
    if ci["native_input_version"] != NATIVE_INPUT_PR_CREATE_V1:
        raise CanonicalActionShapeError("unsupported native_input_version")
    for key in ("base_commit_sha", "head_commit_sha"):
        if not isinstance(ci[key], str) or not _SHA40.fullmatch(ci[key]):
            raise CanonicalActionShapeError(f"canonical_input.{key} must be a 40-hex SHA")
    _require_str(ci["compare_state_digest"], "canonical_input.compare_state_digest", max_len=128)
    _require_str(ci["changed_paths_digest"], "canonical_input.changed_paths_digest", max_len=128)
    _require_commitment(ci["title_commitment"], "canonical_input.title_commitment")
    _require_commitment(ci["body_commitment"], "canonical_input.body_commitment")
    if not isinstance(ci["draft"], bool):
        raise CanonicalActionShapeError("canonical_input.draft must be a boolean")
    _refuse_unsafe_numbers(dict(ca))


def compute_action_binding_hash(canonical_action: Any) -> str:
    """``lowercase_hex(sha256(JCS(canonical_action)))`` after the strict shape check.

    Computed over the exact object. It is never derived from the generic
    Permit fingerprint, which drops time and request-id keys.
    """

    validate_canonical_action_shape(canonical_action)
    return sha256_hex(jcs(dict(canonical_action)))


def verify_native_action_attribute(value: Any) -> str:
    """Check the ``native_action`` resource attribute; return its binding hash.

    Raises ``CanonicalActionShapeError`` or ``ActionBindingHashMismatch``.
    """

    if not isinstance(value, Mapping):
        raise CanonicalActionShapeError("native_action must be an object")
    if set(value.keys()) != NATIVE_ACTION_ATTRIBUTE_KEYS:
        raise CanonicalActionShapeError("native_action key set mismatch")
    if value["action_schema"] != ACTION_SCHEMA_V1:
        raise CanonicalActionShapeError("unsupported action_schema")
    recomputed = compute_action_binding_hash(value["canonical_action"])
    stored = value["action_binding_hash"]
    if not isinstance(stored, str) or not _HEX64.fullmatch(stored):
        raise CanonicalActionShapeError("action_binding_hash must be 64 lowercase hex")
    if not hmac.compare_digest(recomputed, stored):
        raise ActionBindingHashMismatch()
    return recomputed


def evaluate_native_action_attribute(value: Any) -> tuple[str, str | None, str | None]:
    """``(verdict, reason_code, action_binding_hash)`` for one ``native_action`` value."""

    if not isinstance(value, Mapping) or value.get("action_schema") != ACTION_SCHEMA_V1:
        return VERDICT_UNVERIFIABLE_SCOPE, REASON_ACTION_SCHEMA, None
    try:
        binding_hash = verify_native_action_attribute(value)
    except ActionBindingHashMismatch:
        return VERDICT_DISPROVED, REASON_BINDING_HASH_MISMATCH, None
    except CanonicalActionShapeError:
        return VERDICT_DISPROVED, REASON_CANONICAL_ACTION_SHAPE, None
    return VERDICT_SUPPORTED, None, binding_hash


# ---------------------------------------------------------------------------
# Exact review v2 (§7.3)
# ---------------------------------------------------------------------------


def exact_review_v2_hash(obj: Any) -> str:
    """``lowercase_hex(sha256(JCS(obj)))``; raises ``CanonicalActionShapeError`` on floats."""

    return sha256_hex(jcs(obj))


def validate_exact_review_v2_shape(review: Any) -> None:
    """The §7.3 object: all keys required at every level, no extra key, no null."""

    _require_exact_keys(review, EXACT_REVIEW_V2_KEYS, "exact_review_v2")
    if review["schema_version"] != EXACT_REVIEW_V2_SCHEMA:
        raise CanonicalActionShapeError("exact_review_v2.schema_version is not v2")
    for key, expected in EXACT_REVIEW_V2_NESTED_KEYS.items():
        _require_exact_keys(review[key], expected, f"exact_review_v2.{key}")
    if any(item is None for item in _leaf_values(review)):
        raise CanonicalActionShapeError("exact_review_v2 carries a null")


# ---------------------------------------------------------------------------
# The pack (§7.2)
# ---------------------------------------------------------------------------


def _leaf_values(value: Any) -> Iterable[Any]:
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, Mapping):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
        else:
            yield item


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _event_payload(event: Mapping[str, Any]) -> Mapping[str, Any]:
    payload = event.get("payload_json") or event.get("payload") or {}
    return payload if isinstance(payload, Mapping) else {}


def _event_precedes(first: Mapping[str, Any], second: Mapping[str, Any]) -> bool:
    """True when ``first`` is earlier than ``second`` in the project event chain.

    The pack lists events by second-resolution ``created_at``, so list order is
    not the chain order. Use ``sequence_number`` when both carry one; else
    the microsecond ``occurred_at``.
    """

    first_seq = first.get("sequence_number")
    second_seq = second.get("sequence_number")
    if (
        isinstance(first_seq, int)
        and not isinstance(first_seq, bool)
        and isinstance(second_seq, int)
        and not isinstance(second_seq, bool)
        and first.get("chain_scope") == second.get("chain_scope")
    ):
        return first_seq < second_seq
    first_at = first.get("occurred_at")
    second_at = second.get("occurred_at")
    if isinstance(first_at, str) and isinstance(second_at, str):
        try:
            return datetime.fromisoformat(first_at) <= datetime.fromisoformat(second_at)
        except ValueError:
            return False
    return False


@dataclass(frozen=True)
class NativeActionCheckResult:
    """The adjudication of one native action pack."""

    verdict: str
    reason_code: str | None = None
    message: str | None = None
    action_id: str | None = None
    action_binding_hash: str | None = None
    permit_id: str | None = None
    state: str | None = None
    upstream_outcome: str | None = None
    dispatch_started_count: int = 0
    review_present: bool = False
    requested_levels: tuple[str, ...] = ()
    checks: tuple[str, ...] = field(default_factory=tuple)

    @property
    def supported(self) -> bool:
        return self.verdict == VERDICT_SUPPORTED

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema": NATIVE_ACTION_PACK_SCHEMA,
            "verdict": self.verdict,
            "reason_code": self.reason_code,
            "message": self.message,
            "level_ceiling": LEVEL_CEILING,
            "action_id": self.action_id,
            "action_binding_hash": self.action_binding_hash,
            "permit_id": self.permit_id,
            "state": self.state,
            "upstream_outcome": self.upstream_outcome,
            "dispatch_started_count": self.dispatch_started_count,
            "review_present": self.review_present,
            "requested_levels": list(self.requested_levels),
            "checks_passed": list(self.checks),
            "does_not_establish": [
                "provider execution",
                "external state change",
                "exclusive mediation",
            ],
        }
        return {key: value for key, value in payload.items() if value is not None}


class _Refused(Exception):
    def __init__(self, verdict: str, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.verdict = verdict
        self.reason_code = reason_code
        self.message = message


def _disproved(reason_code: str, message: str) -> _Refused:
    return _Refused(VERDICT_DISPROVED, reason_code, message)


def check_native_action_pack(
    export: Any,
    *,
    requested_levels: Iterable[str] = (),
) -> NativeActionCheckResult:
    """Adjudicate one native action pack ``export.json`` object (§7.2).

    ``requested_levels`` are the evidence levels (A–F) of the claims the
    caller requests; any level above D makes the pack ``not_supported``.
    """

    levels = tuple(str(level).strip().upper() for level in requested_levels)
    context: dict[str, Any] = {"requested_levels": levels}
    passed: list[str] = []
    try:
        _check_pack(export, levels=levels, context=context, passed=passed)
    except _Refused as refused:
        return NativeActionCheckResult(
            verdict=refused.verdict,
            reason_code=refused.reason_code,
            message=refused.message,
            checks=tuple(passed),
            **context,
        )
    return NativeActionCheckResult(
        verdict=VERDICT_SUPPORTED,
        message="native action pack checks passed (level ceiling D)",
        checks=tuple(passed),
        **context,
    )


def _check_pack(
    export: Any,
    *,
    levels: tuple[str, ...],
    context: dict[str, Any],
    passed: list[str],
) -> None:
    if not isinstance(export, Mapping) or export.get("schema") != NATIVE_ACTION_PACK_SCHEMA:
        raise _Refused(
            VERDICT_UNVERIFIABLE_SCOPE,
            REASON_PACK_SCHEMA,
            f"export.json schema is not {NATIVE_ACTION_PACK_SCHEMA}",
        )
    if isinstance(export.get("state"), str):
        context["state"] = export["state"]

    # §7.1: the authoritative signed locations are the decision capability's
    # v7 resource attributes (covered by resource_attributes_canonical_hash)
    # and its signed canonical constraints.
    bundle = _mapping(export.get("permit_audit_bundle"))
    decision = _mapping(bundle.get("permit_decision"))
    attributes = _mapping(decision.get("resource_attributes_json"))
    canonical_payload = _mapping(decision.get("canonical_payload"))
    signed_constraints = _mapping(canonical_payload.get("constraints"))
    native = attributes.get("native_action")
    inputs = signed_constraints.get("native_decision_inputs_v1")
    if isinstance(canonical_payload.get("permit_id"), str):
        context["permit_id"] = canonical_payload["permit_id"]

    # (1) native_action present <=> native_decision_inputs_v1 present.
    if (native is None) != (inputs is None) or native is None:
        raise _disproved(
            REASON_EVIDENCE_INCOMPLETE,
            "native_action and native_decision_inputs_v1 must both be present in "
            "the signed Permit decision",
        )
    # The unsigned record copies must equal the signed originals.
    record_holder = bundle.get("record")
    record = (
        _mapping(record_holder.get("permit")) if isinstance(record_holder, Mapping) else {}
    )
    if record:
        record_attributes = record.get("resource_attributes_json") or {}
        record_constraints = record.get("constraints_json") or {}
        if (
            not isinstance(record_attributes, Mapping)
            or record_attributes.get("native_action") != native
        ):
            raise _disproved(
                REASON_EVIDENCE_INCOMPLETE,
                "record.permit.resource_attributes_json.native_action differs from "
                "the signed Permit decision",
            )
        if (
            not isinstance(record_constraints, Mapping)
            or record_constraints.get("native_decision_inputs_v1") != inputs
        ):
            raise _disproved(
                REASON_EVIDENCE_INCOMPLETE,
                "record.permit.constraints_json.native_decision_inputs_v1 differs "
                "from the signed Permit decision",
            )
    passed.append("evidence_present")

    # (2) action schema and exact canonical action shape; (3) binding hash.
    if not isinstance(native, Mapping) or native.get("action_schema") != ACTION_SCHEMA_V1:
        raise _Refused(
            VERDICT_UNVERIFIABLE_SCOPE,
            REASON_ACTION_SCHEMA,
            f"native_action.action_schema is not {ACTION_SCHEMA_V1}",
        )
    try:
        binding_hash = verify_native_action_attribute(native)
    except ActionBindingHashMismatch as exc:
        raise _disproved(REASON_BINDING_HASH_MISMATCH, str(exc)) from exc
    except CanonicalActionShapeError as exc:
        raise _disproved(REASON_CANONICAL_ACTION_SHAPE, str(exc)) from exc
    canonical = native["canonical_action"]
    context["action_binding_hash"] = binding_hash
    context["action_id"] = canonical["action_id"]
    passed.append("canonical_action_shape")
    if not isinstance(inputs, Mapping) or inputs.get("action_binding_hash") != binding_hash:
        raise _disproved(
            REASON_BINDING_HASH_MISMATCH,
            "native_decision_inputs_v1.action_binding_hash does not equal the "
            "recomputed action_binding_hash",
        )
    passed.append("action_binding_hash")

    # (4) cross-field equalities; no null anywhere in the constraint.
    if any(item is None for item in _leaf_values(inputs)):
        raise _disproved(
            REASON_CANONICAL_ACTION_SHAPE, "native_decision_inputs_v1 carries a null"
        )
    if (
        inputs.get("version") != NATIVE_DECISION_INPUTS_VERSION
        or inputs.get("action_schema") != ACTION_SCHEMA_V1
    ):
        raise _Refused(
            VERDICT_UNVERIFIABLE_SCOPE,
            REASON_DECISION_INPUTS_VERSION,
            f"native_decision_inputs_v1 is not {NATIVE_DECISION_INPUTS_VERSION} "
            f"for {ACTION_SCHEMA_V1}",
        )
    if inputs.get("installation_id") != canonical.get("installation_id"):
        raise _disproved(
            REASON_CROSS_FIELD_MISMATCH,
            "canonical_action.installation_id does not equal the constraint's",
        )
    if canonical.get("project_id") != canonical_payload.get("project_id"):
        raise _disproved(
            REASON_CROSS_FIELD_MISMATCH,
            "canonical_action.project_id does not equal the signed Permit project_id",
        )
    if canonical.get("principal_id") != canonical_payload.get("subject_id"):
        raise _disproved(
            REASON_CROSS_FIELD_MISMATCH,
            "canonical_action.principal_id does not equal the signed Permit initiator",
        )
    passed.append("cross_field")

    # (5) exact review v2 binding.
    review = export.get("exact_review_v2")
    approval = export.get("approval")
    events_raw = export.get("closure_events") or []
    if not isinstance(events_raw, list) or not all(
        isinstance(event, Mapping) for event in events_raw
    ):
        raise _disproved(REASON_EVIDENCE_INCOMPLETE, "closure_events must be a list of events")
    events: list[Mapping[str, Any]] = list(events_raw)
    if review is not None:
        context["review_present"] = True
        approval_map = _mapping(approval)
        try:
            review_hash = exact_review_v2_hash(review)
        except CanonicalActionShapeError as exc:
            raise _disproved(REASON_REVIEW_BINDING, f"exact_review_v2: {exc}") from exc
        if review_hash != approval_map.get("exact_review_v2_hash"):
            raise _disproved(
                REASON_REVIEW_BINDING,
                "recomputed exact_review_v2 hash does not equal the approval's "
                "exact_review_v2_hash",
            )
        if not isinstance(review, Mapping) or review.get("action_binding_hash") != binding_hash:
            raise _disproved(
                REASON_REVIEW_BINDING,
                "exact_review_v2.action_binding_hash does not equal the action_binding_hash",
            )
        if _mapping(review.get("policy")).get("condition_semantics") != inputs.get(
            "condition_semantics"
        ):
            raise _disproved(
                REASON_REVIEW_BINDING,
                "exact_review_v2.policy.condition_semantics does not equal the constraint's",
            )
        try:
            validate_exact_review_v2_shape(review)
        except CanonicalActionShapeError as exc:
            raise _disproved(REASON_REVIEW_BINDING, str(exc)) from exc
        for key, expected in (
            ("permit_id", canonical_payload.get("permit_id")),
            ("project_id", canonical_payload.get("project_id")),
            ("action_id", canonical.get("action_id")),
            ("action_schema", ACTION_SCHEMA_V1),
        ):
            if review.get(key) != expected:
                raise _disproved(
                    REASON_REVIEW_BINDING,
                    f"exact_review_v2.{key} does not equal the Permit's",
                )
        if approval_map.get("v1_review_hash") != review.get("v1_review_hash"):
            raise _disproved(
                REASON_REVIEW_BINDING,
                "approval.v1_review_hash does not equal exact_review_v2.v1_review_hash",
            )
        for event in events:
            if event.get("event_type") != EVENT_REVIEW_DECIDED:
                continue
            decided_hash = _event_payload(event).get("exact_review_v2_hash")
            if decided_hash != approval_map.get("exact_review_v2_hash"):
                raise _disproved(
                    REASON_REVIEW_BINDING,
                    "review_decided exact_review_v2_hash does not equal the approval's",
                )
        passed.append("review_binding")

    # (6) closure events: one dispatch, bound to this action, in chain order.
    started = [event for event in events if event.get("event_type") == EVENT_DISPATCH_STARTED]
    context["dispatch_started_count"] = len(started)
    if len(started) > 1:
        raise _disproved(
            REASON_SINGLE_DISPATCH,
            f"{len(started)} native.action.dispatch_started events; at most one is allowed",
        )
    for event in started:
        payload = _event_payload(event)
        if (
            payload.get("action_binding_hash") != binding_hash
            or not payload.get("frozen_arguments_equal")
            or not payload.get("preflight_facts_equal")
        ):
            raise _disproved(
                REASON_SINGLE_DISPATCH,
                "dispatch_started is not bound to this action with equal frozen "
                "arguments and preflight facts",
            )
        if (
            payload.get("action_id") != canonical.get("action_id")
            or payload.get("frozen_arguments_equal") is not True
            or payload.get("preflight_facts_equal") is not True
        ):
            raise _disproved(
                REASON_SINGLE_DISPATCH,
                "dispatch_started action_id or equality flags are not exact",
            )
    results = [event for event in events if event.get("event_type") == EVENT_UPSTREAM_RESULT]
    if len(results) > 1:
        raise _disproved(
            REASON_SINGLE_DISPATCH,
            f"{len(results)} native.action.upstream_result events; at most one is allowed",
        )
    for event in results:
        payload = _event_payload(event)
        outcome = payload.get("outcome")
        if payload.get("action_id") != canonical.get("action_id") or outcome not in UPSTREAM_OUTCOMES:
            raise _disproved(
                REASON_SINGLE_DISPATCH,
                "upstream_result is not bound to this action with a known outcome",
            )
        context["upstream_outcome"] = outcome
        if started:
            if not _event_precedes(started[0], event):
                raise _disproved(
                    REASON_SINGLE_DISPATCH,
                    "dispatch_started does not precede upstream_result",
                )
        elif outcome != "outcome_unknown":
            raise _disproved(
                REASON_SINGLE_DISPATCH,
                "upstream_result reports an outcome without a dispatch_started record",
            )
    passed.append("closure_events")

    # (7) level ceiling: nothing above D.
    above = sorted(level for level in levels if level in LEVELS_ABOVE_CEILING)
    if above:
        raise _Refused(
            VERDICT_NOT_SUPPORTED,
            REASON_LEVEL_CEILING,
            f"requested level {', '.join(above)} is above the native pack ceiling "
            f"({LEVEL_CEILING})",
        )
    passed.append("level_ceiling")


def is_native_action_pack_document(document: Any) -> bool:
    return isinstance(document, Mapping) and document.get("schema") == NATIVE_ACTION_PACK_SCHEMA


__all__ = [
    "ACTION_SCHEMA_V1",
    "ADDITIONAL_CHECKS",
    "ActionBindingHashMismatch",
    "CanonicalActionShapeError",
    "LEVEL_CEILING",
    "NATIVE_ACTION_EXPORT_TYPE",
    "NATIVE_ACTION_PACK_SCHEMA",
    "NativeActionCheckResult",
    "check_native_action_pack",
    "compute_action_binding_hash",
    "evaluate_native_action_attribute",
    "exact_review_v2_hash",
    "is_native_action_pack_document",
    "jcs",
    "validate_canonical_action_shape",
    "validate_exact_review_v2_shape",
    "verify_native_action_attribute",
]
