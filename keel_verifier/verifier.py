#!/usr/bin/env python3
"""Standalone Keel trust artifact verifier.

This is a self-contained verifier you can run WITHOUT cloning keel-api.
It depends only on:
    pip install cryptography

Three modes:

  1. Compliance export (manifest + payload):
       keel_verify.py export --export-file export.jsonl.gz --manifest manifest.json \\
           [--key-manifest keys.json]
           [--key-manifest-url https://api.keelapi.com/v1/compliance/keys]
           [--expected-public-key ed25519:...]

  2. Integrity checkpoint (raw JSON downloaded from external anchor):
       keel_verify.py checkpoint \\
           --checkpoint-file checkpoint.json \\
           [--key-manifest keys.json]
           [--key-manifest-url https://api.keelapi.com/v1/compliance/keys]
           [--expected-public-key ed25519:...] \\
           [--public-key-url https://api.keelapi.com/v1/integrity/checkpoint-public-key]

     If no explicit trust-root flag is given, the verifier uses the cached
     trust-root manifest when present, otherwise the bundled production trust
     root. Embedded public keys are used only in explicit self-attested mode.

  3. TSA receipt embedded in a checkpoint:
     Performed automatically inside ``checkpoint`` mode whenever the
     checkpoint includes a ``tsa.receipt_b64`` field. The verifier checks
     that the receipt's MessageImprint equals the checkpoint's
     composite_hash (RFC 3161 §2.4.2). For full trust-chain verification
     against the TSA's CA bundle, see --tsa-ca-bundle.

Key resolution order (when verifying signatures):

  1. ``--expected-public-key`` (explicit pin) — highest priority.
  2. ``--public-key-url`` (single-key fetch, checkpoint mode only).
  3. ``--key-manifest`` / ``--key-manifest-url`` resolved by ``key_id``.
  4. Cached ``~/.keel-verifier/trust-root.json`` when available.
  5. Bundled ``keel_verifier/data/trust_root.json``.
  6. Embedded ``public_key`` in the artifact only in explicit self-attested mode.

If the artifact carries a ``key_id`` and a key manifest is supplied, the
verifier requires the manifest to contain a matching entry with the correct
purpose. If the artifact has no ``key_id`` (legacy artifact), the manifest
must contain a single matching legacy public key for the relevant purpose;
otherwise verification fails with a clear message.

Exit codes: 0 = verified, 1 = failed, 2 = bad usage.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import gzip
import hashlib
import io
import json
import re
import subprocess
import sys
import tempfile
import urllib.request
import uuid
import zipfile
from collections.abc import Mapping
from datetime import datetime, timezone
from dataclasses import dataclass, field as dataclass_field, replace
from importlib import resources
from pathlib import Path
from typing import Any

import rfc8785

from keel_verifier.canonical.permit_binding import (
    CLOSURE_RFC8785_BINDING_VERSION,
    SUPPORTED_BINDING_VERSIONS as SUPPORTED_PERMIT_BINDING_VERSIONS,
    binding_request_canonical_version_for_binding,
    canonical_delegation_policy_payload,
    canonical_provider_wire_body_hash,
    canonical_resource_attributes_payload,
    canonical_spend_scope_payload,
    compute_canonical_binding_hash as _canonical_permit_binding_hash,
)
from keel_verifier.verdicts import (
    ClaimVerdict,
    VERDICT_SCHEMA_ID,
    VerificationReport,
    VerdictSubject,
    legacy_semantics,
    verdict_value,
)
from keel_verifier.semantics import (
    CLAIM_SEMANTICS,
    SemanticsDispatch,
    ResolvedSemantics,
    SCOPE_STATE_MERKLE_ID,
    SCOPE_STATE_MERKLE_HASH,
    make_permanent_allowlist,
    resolve_pack_semantics,
)
from keel_verifier.schemas.artifact_ref import ArtifactRef, parse_artifact_ref

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:
    print(
        "ERROR: 'cryptography' is required.  Install with: pip install cryptography",
        file=sys.stderr,
    )
    sys.exit(2)


DEFAULT_TRUST_ROOT_PATH = Path(__file__).resolve().parent / "data" / "trust_root.json"
CACHED_TRUST_ROOT_PATH = Path.home() / ".keel-verifier" / "trust-root.json"
VOICE_ATTESTATION_ARTIFACT_SCHEMA = "keel.voice.attestation.phase_a"
VOICE_ATTESTATION_ARTIFACT_VERSION_BY_SCHEMA = {
    1: "1.0.0",
    3: "1.2.0",
}
SUPPORTED_VOICE_ATTESTATION_SCHEMA_VERSIONS = frozenset(
    VOICE_ATTESTATION_ARTIFACT_VERSION_BY_SCHEMA
)
VOICE_ATTESTATION_CANONICALIZATION_PROFILE = (
    "keel.canonical_json.attestation_artifact.v1"
)
VOICE_ATTESTATION_CHAIN_GENESIS_HASH = (
    "sha256:"
    + hashlib.sha256(b"keel-voice-session-artifact-chain-genesis-v1").hexdigest()
)
KEELAPI_COMPLIANCE_KEYS_URL = "https://api.keelapi.com/v1/compliance/keys"
KEELAPI_CHECKPOINT_PUBLIC_KEY_URL = (
    "https://api.keelapi.com/v1/integrity/checkpoint-public-key"
)
GITHUB_TRUST_ROOT_URL = (
    "https://raw.githubusercontent.com/keelapi/keel-verifier/main/"
    "keel_verifier/data/trust_root.json"
)
REFRESH_KEYS_SOURCES: tuple[tuple[str, str, str], ...] = (
    # (slug, display_name, url)
    ("api", "Keel API", KEELAPI_COMPLIANCE_KEYS_URL),
    ("github", "GitHub", GITHUB_TRUST_ROOT_URL),
)
LEGACY_ARTIFACT_REF_WARNING = (
    "Bundle uses legacy schema without artifact_ref. New bundles include stable URN "
    "identity; legacy bundles remain verifiable but lose the URN identity layer."
)
LEGACY_VANTA_SCHEMA_WARNING = (
    "Bundle uses legacy Vanta-prefixed evidence schema names. "
    "Use keel.evidence/v1 and keel.workflow_evidence/v1; legacy names remain "
    "verifiable during the 3.x transition and will be removed in keel-verifier 4.0."
)
_legacy_artifact_ref_warning_printed = False
_legacy_vanta_schema_warning_printed = False
SELF_ATTESTING_BUNDLE_SCHEMA_VERSION = "keel.evidence_bundle/v1"
_LEGACY_SPLIT_EXPORT_WARNING_EMITTED = False


def _content_hash(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _artifact_ref_to_dict(artifact_ref: ArtifactRef) -> dict[str, Any]:
    return artifact_ref.model_dump()


def _emit_legacy_artifact_ref_warning_once() -> None:
    global _legacy_artifact_ref_warning_printed
    if _legacy_artifact_ref_warning_printed:
        return
    print(f"WARNING: {LEGACY_ARTIFACT_REF_WARNING}", file=sys.stderr)
    _legacy_artifact_ref_warning_printed = True


def _emit_legacy_vanta_schema_warning_once() -> None:
    global _legacy_vanta_schema_warning_printed
    if _legacy_vanta_schema_warning_printed:
        return
    print(f"WARNING: {LEGACY_VANTA_SCHEMA_WARNING}", file=sys.stderr)
    _legacy_vanta_schema_warning_printed = True


def _artifact_ref_from_bundle(bundle: Mapping[str, Any]) -> ArtifactRef | None:
    return parse_artifact_ref(bundle)


def _artifact_ref_from_export_data(export_data: bytes) -> ArtifactRef | None:
    try:
        bundle = _load_export_json_document(export_data)
    except Exception:
        return None
    if not isinstance(bundle, Mapping):
        return None
    return _artifact_ref_from_bundle(bundle)


def _emit_legacy_artifact_ref_warning_for_path(path: str | Path) -> None:
    try:
        data = Path(path).read_bytes()
        artifact_ref = _artifact_ref_from_export_data(data)
    except Exception:
        return
    if artifact_ref is None:
        _emit_legacy_artifact_ref_warning_once()


def _subject(
    *,
    subject_type: str,
    subject_id: str | None,
    verdict: str,
    reason_code: str | None,
    message: str,
    evidence: list[str] | None = None,
) -> VerdictSubject:
    return VerdictSubject(
        type=subject_type,
        id=subject_id,
        verdict=verdict_value(verdict),
        reason_code=reason_code,
        message=message,
        evidence=list(evidence or []),
    )


def _single_subject_claim(
    name: str,
    *,
    subject_type: str,
    subject_id: str | None,
    verdict: str,
    reason_code: str | None,
    message: str,
    evidence: list[str] | None = None,
    required: bool = True,
) -> ClaimVerdict:
    return ClaimVerdict(
        name=name,
        required=required,
        subjects=[
            _subject(
                subject_type=subject_type,
                subject_id=subject_id,
                verdict=verdict,
                reason_code=reason_code,
                message=message,
                evidence=evidence,
            )
        ],
        reason_code=reason_code,
        message=message,
        evidence=list(evidence or []),
    )


def _merge_claims(claims: list[ClaimVerdict]) -> list[ClaimVerdict]:
    merged: dict[str, ClaimVerdict] = {}
    order: list[str] = []
    for claim in claims:
        existing = merged.get(claim.name)
        if existing is None:
            merged[claim.name] = claim
            order.append(claim.name)
            continue
        merged[claim.name] = ClaimVerdict(
            name=claim.name,
            subjects=[*existing.subjects, *claim.subjects],
            required=existing.required or claim.required,
            semantics=existing.semantics if existing.semantics is not None else claim.semantics,
            evidence=[*existing.evidence, *claim.evidence],
            epistemic_state={
                **(existing.epistemic_state or {}),
                **(claim.epistemic_state or {}),
            }
            or None,
            reason_code=existing.reason_code or claim.reason_code,
            message=existing.message or claim.message,
            diagnostics=[*existing.diagnostics, *claim.diagnostics],
        )
    return [merged[name] for name in order]


def _apply_semantics_to_claims(
    claims: list[ClaimVerdict],
    semantics: ResolvedSemantics,
) -> list[ClaimVerdict]:
    applied: list[ClaimVerdict] = []
    requested = semantics.requested_names()
    for claim in claims:
        required = (
            semantics.required_for(claim.name)
            if semantics.mode == "pinned" and claim.name in requested
            else claim.required
        )
        applied.append(
            replace(
                claim,
                required=required,
                semantics=semantics.semantics_for_claim(claim.name),
            )
        )
    return applied


def _semantic_failure_claims(
    semantics: ResolvedSemantics,
    *,
    default_claim_names: tuple[str, ...],
    subject_type: str,
    subject_id: str | None,
    evidence: list[str],
) -> list[ClaimVerdict]:
    failure = semantics.failure
    if failure is None:
        return []
    claim_names = failure.claim_names or default_claim_names
    return _apply_semantics_to_claims(
        [
            _single_subject_claim(
                name,
                subject_type=subject_type,
                subject_id=subject_id,
                verdict=failure.verdict,
                reason_code=failure.reason_code,
                message=failure.message,
                evidence=evidence,
                required=semantics.required_for(name),
            )
            for name in claim_names
            if name in CLAIM_SEMANTICS
        ],
        semantics,
    )


def _report_diagnostics(
    diagnostics: list[str] | None,
    semantics: ResolvedSemantics | None,
) -> list[str]:
    merged = list(diagnostics or [])
    if semantics is not None:
        for diagnostic in semantics.diagnostics:
            if diagnostic not in merged:
                merged.append(diagnostic)
    return merged


def _missing_required_claim(
    name: str,
    *,
    semantics: ResolvedSemantics,
    subject_type: str,
    subject_id: str | None,
    evidence: list[str],
) -> ClaimVerdict:
    if name in CLAIM_SEMANTICS:
        verdict = "insufficient_evidence"
        reason_code = "REQUIRED_CLAIM_NOT_ADJUDICATED"
        message = (
            "claim_set declared this claim required, but no evidence or verifier "
            "path produced an adjudication"
        )
    else:
        verdict = "unverifiable_scope"
        reason_code = "REQUIRED_CLAIM_UNVERIFIABLE_SCOPE"
        message = (
            "claim_set declared this claim required, but this verifier cannot "
            "resolve an adjudication path for the claim"
        )
    return ClaimVerdict(
        name=name,
        required=True,
        verdict=verdict,
        semantics=semantics.semantics_for_claim(name),
        subjects=[
            _subject(
                subject_type=subject_type,
                subject_id=subject_id,
                verdict=verdict,
                reason_code=reason_code,
                message=message,
                evidence=evidence,
            )
        ],
        reason_code=reason_code,
        message=message,
        evidence=evidence,
    )


def _enforce_required_claims(
    *,
    claims: list[ClaimVerdict],
    semantics: ResolvedSemantics | None,
    ok: bool,
    exit_code: int | None,
    error: str | None,
    subject_type: str,
    subject_id: str | None,
    evidence: list[str],
) -> tuple[list[ClaimVerdict], bool, int | None, str | None]:
    if semantics is not None:
        claims = _apply_semantics_to_claims(claims, semantics)
    merged = _merge_claims(claims)
    if semantics is None or semantics.mode != "pinned":
        return merged, ok, exit_code, error

    required_names = [
        request.name for request in semantics.requested_claims if request.required
    ]
    if not required_names:
        return merged, ok, exit_code, error

    emitted = {claim.name for claim in merged}
    missing = [
        _missing_required_claim(
            name,
            semantics=semantics,
            subject_type=subject_type,
            subject_id=subject_id,
            evidence=evidence,
        )
        for name in required_names
        if name not in emitted
    ]
    if missing:
        merged = _merge_claims([*merged, *missing])

    unsupported = [
        claim.name
        for claim in merged
        if claim.name in required_names
        and claim.required
        and claim.aggregate_verdict != verdict_value("supported")
    ]
    if unsupported:
        ok = False
        if exit_code in (None, 0):
            exit_code = 1
        if error is None:
            error = "required claims not supported: " + ", ".join(sorted(unsupported))
    return merged, ok, exit_code, error


WALK_RECORD_HASH_MISMATCH = "WALK_RECORD_HASH_MISMATCH"
WALK_PREV_HASH_DISCONTINUITY = "WALK_PREV_HASH_DISCONTINUITY"
WALK_SEQUENCE_INVERSION = "WALK_SEQUENCE_INVERSION"
WALK_UNKNOWN_CHAIN_FORMAT = "WALK_UNKNOWN_CHAIN_FORMAT"
WALK_CLOSURE_SIGNATURE_INVALID = "WALK_CLOSURE_SIGNATURE_INVALID"
WALK_CLOSURE_DIGEST_MISMATCH = "WALK_CLOSURE_DIGEST_MISMATCH"
WALK_CLOSURE_DIGEST_MISSING = "WALK_CLOSURE_DIGEST_MISSING"
WALK_CLOSURE_DISPATCH_DIGEST_MISMATCH = "WALK_CLOSURE_DISPATCH_DIGEST_MISMATCH"
WALK_UNKNOWN_CLOSURE_FORMAT = "WALK_UNKNOWN_CLOSURE_FORMAT"
WORKFLOW_EVIDENCE_SCHEMA_INVALID = "WORKFLOW_EVIDENCE_SCHEMA_INVALID"
WORKFLOW_SIGNATURE_INVALID = "WORKFLOW_SIGNATURE_INVALID"
WORKFLOW_AMENDMENT_ORDER_INVALID = "WORKFLOW_AMENDMENT_ORDER_INVALID"
WORKFLOW_EFFECTIVE_INTENT_HASH_MISMATCH = "WORKFLOW_EFFECTIVE_INTENT_HASH_MISMATCH"
INCIDENT_MANIFEST_SCHEMA_INVALID = "INCIDENT_MANIFEST_SCHEMA_INVALID"
INCIDENT_UNKNOWN_MANIFEST_VERSION = "INCIDENT_UNKNOWN_MANIFEST_VERSION"

PERMIT_BINDING_SIGNING_PURPOSE = "permit_binding_signing"
WORKFLOW_DECLARATION_BINDING_VERSION = "workflow_declaration.v1"
WORKFLOW_AMENDMENT_BINDING_VERSION = "workflow_amendment.v1"
EVIDENCE_SCHEMA = "keel.evidence/v1"
LEGACY_VANTA_EVIDENCE_SCHEMA = "keel.vanta.evidence/v1"
WORKFLOW_EVIDENCE_SCHEMA = "keel.workflow_evidence/v1"
LEGACY_VANTA_WORKFLOW_EVIDENCE_SCHEMA = "keel.vanta.workflow_evidence/v1"
WORKFLOW_EVIDENCE_SCHEMAS = frozenset(
    {WORKFLOW_EVIDENCE_SCHEMA, LEGACY_VANTA_WORKFLOW_EVIDENCE_SCHEMA}
)
INCIDENT_WORKFLOW_DECLARATIONS_SCHEMA = "keel.workflow_declarations/v1"
INCIDENT_WORKFLOW_AMENDMENTS_SCHEMA = "keel.workflow_amendments/v1"
INCIDENT_V2_REQUIRED_FILES = {
    "admin_actions.jsonl": "keel.admin_actions/v1",
    "bracket_checkpoints.json": "keel.bracket_checkpoints/v1",
    "governance_events.jsonl": "keel.governance_events/v1",
    "incident_metadata.json": "keel.incident_metadata/v1",
    "permits.jsonl": "keel.permits/v1",
    "workflow_declarations.jsonl": "keel.workflow_declarations/v1",
    "workflow_amendments.jsonl": "keel.workflow_amendments/v1",
    "mcp_tool_decisions.jsonl": "keel.mcp_tool_decisions/v1",
}
DISPATCH_REQUEST_DIGEST_SEMANTICS = "approved_request_body_bytes_at_dispatch_time"
PROVIDER_RESPONSE_DIGEST_SEMANTICS = "provider_bytes_received_by_keel"
CLIENT_RESPONSE_DIGEST_SEMANTICS = "response_bytes_handed_to_asgi_not_tcp_receipt"
CLOSURE_STATUS_CLOSED = "closed"
CLOSURE_STATUS_MISSING_CLOSURE = "missing_closure"


def _warn_if_legacy_evidence_schema(schema: Any) -> None:
    if schema in {
        LEGACY_VANTA_EVIDENCE_SCHEMA,
        LEGACY_VANTA_WORKFLOW_EVIDENCE_SCHEMA,
    }:
        _emit_legacy_vanta_schema_warning_once()


def _is_workflow_evidence_schema(schema: Any) -> bool:
    if schema == LEGACY_VANTA_WORKFLOW_EVIDENCE_SCHEMA:
        _emit_legacy_vanta_schema_warning_once()
        return True
    return schema == WORKFLOW_EVIDENCE_SCHEMA

_SIGNED_CLOSURE_V1_REQUIRED_KEYS = (
    "binding_version",
    "permit_id",
    "execution_id",
    "correlation_id",
    "provider",
    "model",
    "provider_response_digest_v1",
    "client_response_digest_v1",
    "closure_status",
    "status_code",
    "provider_response_id",
    "provider_response_digest_semantics",
    "client_response_digest_semantics",
    "request_created_at",
    "started_at",
    "completed_at",
    "provider_response_received_at",
    "client_response_delivered_at",
    "closure_signed_at",
    "binding_key_id",
)
_SIGNED_CLOSURE_V1_OPTIONAL_KEYS = ("usage_reported_at",)
_SIGNED_CLOSURE_V2_REQUIRED_KEYS = (
    "binding_version",
    "permit_id",
    "execution_id",
    "correlation_id",
    "provider",
    "model",
    "dispatch_request_digest_v1",
    "provider_response_digest_v1",
    "client_response_digest_v1",
    "closure_status",
    "status_code",
    "provider_response_id",
    "dispatch_request_digest_semantics",
    "provider_response_digest_semantics",
    "client_response_digest_semantics",
    "request_created_at",
    "started_at",
    "completed_at",
    "provider_response_received_at",
    "client_response_delivered_at",
    "closure_signed_at",
    "binding_key_id",
)
_SIGNED_CLOSURE_V2_OPTIONAL_KEYS = ("usage_reported_at",)
PERMIT_DECISION_CLAIM_NAME = "permit.decision.v1"
PERMIT_REVOKED_CLAIM_NAME = "permit.revoked.v1"
PERMIT_DISPATCH_ABSENCE_CLAIM_NAME = (
    "permit.dispatch_absence_after_revocation.v1"
)
PERMIT_AUTHORITY_CHAIN_CLAIM_NAME = "permit.authority_chain.v1"
AUTHORITY_REVOCATION_TEMPORAL_CLAIM_NAME = "authority.revocation_temporal.v1"
PERMIT_OPERATOR_APPROVAL_CLAIM_NAME = "permit.operator_approval.v1"
PERMIT_COUNTER_SIGNATURE_CLAIM_NAME = "permit.counter_signature.v1"
PERMIT_AUDIT_ATTESTATION_CLAIM_NAME = "permit.audit_attestation.v1"
PERMIT_OPERATOR_APPROVED_CLAIM_NAME = "permit.operator_approved.v1"
PERMIT_COUNTER_SIGNED_CLAIM_NAME = "permit.counter_signed.v1"
PERMIT_AUDIT_ATTESTED_CLAIM_NAME = "permit.audit_attested.v1"
PERMIT_DECISION_ARTIFACT_TYPE = "permit_decision_binding"
PERMIT_DECISION_ARTIFACT_VERSION = "permit.decision.v1"
PERMIT_REVOKED_EVENT_TYPE = "permit.revoked"
DISPATCH_EGRESS_BOUND_EVENT_TYPE = "dispatch.egress_bound"
PERMIT_V2_FORMAT_VERSION = "v2"
PERMIT_OPERATOR_APPROVAL_SLOT = "operator_approval"
PERMIT_COUNTER_SIGNATURE_SLOT = "counter_signature"
PERMIT_AUDIT_ATTESTATION_SLOT = "audit_attestation"
PERMIT_V2_SIGNATURE_SLOTS = (
    "signature",
    PERMIT_OPERATOR_APPROVAL_SLOT,
    PERMIT_COUNTER_SIGNATURE_SLOT,
    PERMIT_AUDIT_ATTESTATION_SLOT,
    "provider_attestation",
)
PERMIT_OPERATOR_APPROVAL_PAYLOAD_TYPE = "permit.operator_approval.v1"
PERMIT_COUNTER_SIGNATURE_PAYLOAD_TYPE = "permit.counter_signature.v1"
PERMIT_COUNTER_SIGNATURE_EXECUTION_INTENT_PAYLOAD_TYPE = (
    "permit.counter_signature.execution_intent.v1"
)
PERMIT_AUDIT_ATTESTATION_PAYLOAD_TYPE = "permit.audit_attestation.v1"
PERMIT_V2_OPERATOR_KEY_PURPOSES = frozenset(
    {"permit_v2_operator", "operator", "operator_approval"}
)
PERMIT_V2_BUYER_KEY_PURPOSES = frozenset(
    {
        "permit_v2_buyer_principal",
        "buyer_principal",
        "counter_signature",
        "audit_attestation",
    }
)
AUTHORITY_CHAIN_VERSION = "authority_chain.v1"
AUTHORITY_EDGE_VERSION = "authority_edge.v1"
AUTHORITY_CHAIN_SUPPORTED_CODE = "AUTHORITY_CHAIN_SUPPORTED"
AUTHORITY_REVOCATION_TEMPORAL_SUPPORTED_CODE = "AUTHORITY_REVOCATION_TEMPORAL_SUPPORTED"
AUTHORITY_CHAIN_CONSTRAINT_KEYS = frozenset(
    {
        "requires_human_approval",
        "max_recipients",
        "max_item_amount_usd_micros",
        "allow_domains",
        "deny_external_domains",
        "allowed_hours",
        "purpose",
    }
)
AUTHORITY_CHAIN_DIRECT_SUBJECT_TYPES = frozenset(
    {"user", "service_principal", "system"}
)
AUTHORITY_CHAIN_AGENT_SUBJECT_TYPE = "agent"
AUTHORITY_CHAIN_CODE_VERDICTS = {
    "authority_chain.typed_absence": "unverifiable_scope",
    "authority_chain.evidence_incomplete": "insufficient_evidence",
    "authority_chain.edge_digest_mismatch": "disproved",
    "authority_chain.edge_signature_invalid": "disproved",
    "authority_chain.signing_key_not_valid_at_signed_at": "disproved",
    "authority_chain.unknown_constraint_key": "disproved",
    "authority_chain.chain_digest_mismatch": "disproved",
    "authority_chain.leaf_subject_mismatch": "disproved",
    "authority_chain.root_anchor_invalid": "disproved",
    "authority_chain.parent_edge_digest_broken": "disproved",
    "authority_chain.cycle_detected": "disproved",
    "authority_chain.broadened_verbs": "disproved",
    "authority_chain.broadened_classes": "disproved",
    "authority_chain.broadened_resources": "disproved",
    "authority_chain.broadened_data_classes": "disproved",
    "authority_chain.constraint_not_stricter": "disproved",
    "authority_chain.budget_parent_envelope_mismatch": "disproved",
    "authority_chain.budget_exceeds_parent": "disproved",
    "authority_chain.remaining_depth_not_strict": "disproved",
    "authority_chain.max_children_exceeds_parent": "disproved",
    "authority_chain.validity_not_subset": "disproved",
    "authority_chain.expired_at_resolution": "disproved",
    "authority_chain.unmapped_action_kind": "unverifiable_scope",
    "authority_chain.action_outside_chain_scope": "disproved",
    "authority_chain.agent_without_chain": "insufficient_evidence",
}
AUTHORITY_REVOCATION_TEMPORAL_CODE_VERDICTS = {
    "authority_revocation.signed_at_at_or_after_revoked_at": "disproved",
    "authority_revocation.compromised_key_retroactive_taint": "disproved",
}
_PERMIT_DECISION_REQUIRED_CANONICAL_FIELDS = (
    "binding_version",
    "permit_id",
    "project_id",
    "parent_permit_id",
    "decision",
    "reason",
    "provider",
    "model",
    "operation",
    "action_name",
    "request_fingerprint",
    "constraints",
    "routing",
    "policy_id",
    "policy_version",
    "policy_snapshot_hash",
    "issued_at",
    "expires_at",
    "is_dry_run",
    "binding_key_id",
    "final_request_hash",
)
_PERMIT_DECISION_V2_CANONICAL_FIELDS = (
    *_PERMIT_DECISION_REQUIRED_CANONICAL_FIELDS,
    "binding_session_id",
    "binding_session_event_hash",
    "binding_project_anchor_hash",
    "permit_chain_role",
    "inherits_from",
    "authority_delta",
)
_PERMIT_DECISION_V3_CANONICAL_FIELDS = (
    *_PERMIT_DECISION_V2_CANONICAL_FIELDS,
    "spend_scope_hash",
)
_PERMIT_DECISION_V4_CANONICAL_FIELDS = (
    *_PERMIT_DECISION_V3_CANONICAL_FIELDS,
    "delegation_policy_hash",
)
_PERMIT_DECISION_V6_CANONICAL_FIELDS = (
    *_PERMIT_DECISION_V4_CANONICAL_FIELDS,
    "resource_attributes_canonical_hash",
)
_PERMIT_DECISION_CANONICAL_FIELDS_BY_VERSION = {
    "v1": _PERMIT_DECISION_REQUIRED_CANONICAL_FIELDS,
    "v2": _PERMIT_DECISION_V2_CANONICAL_FIELDS,
    "v3": _PERMIT_DECISION_V3_CANONICAL_FIELDS,
    "v4": _PERMIT_DECISION_V4_CANONICAL_FIELDS,
    "v5": _PERMIT_DECISION_V4_CANONICAL_FIELDS,
    "v6": _PERMIT_DECISION_V6_CANONICAL_FIELDS,
}
_PERMIT_REVOKED_REQUIRED_FIELDS = (
    "permit_id",
    "project_id",
    "actor_id",
    "actor_kind",
    "reason_code",
    "revoked_at",
    "effective_at",
    "signature",
)
_PERMIT_REVOKED_ACTOR_KINDS = {"user", "service_account", "system", "api_key"}
_REASON_CODE_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_SHA256_HEX_RE = re.compile(r"^[a-f0-9]{64}$")
_PERMIT_V2_UTC_MICROSECOND_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"
)


@dataclass(frozen=True)
class PermitV2SlotSpec:
    slot_name: str
    claim_name: str
    payload_type: str
    subject_type: str
    signer_payload_field: str
    key_purposes: frozenset[str]
    invalid_code: str
    key_not_trusted_code: str
    signer_mismatch_code: str
    supported_code: str
    extra_field: str | None = None
    extra_mismatch_code: str | None = None


PERMIT_V2_OPERATOR_APPROVAL_SPEC = PermitV2SlotSpec(
    slot_name=PERMIT_OPERATOR_APPROVAL_SLOT,
    claim_name=PERMIT_OPERATOR_APPROVAL_CLAIM_NAME,
    payload_type=PERMIT_OPERATOR_APPROVAL_PAYLOAD_TYPE,
    subject_type="permit_operator_approval",
    signer_payload_field="operator_id",
    key_purposes=PERMIT_V2_OPERATOR_KEY_PURPOSES,
    invalid_code="PERMIT_OPERATOR_APPROVAL_INVALID",
    key_not_trusted_code="PERMIT_OPERATOR_APPROVAL_KEY_NOT_TRUSTED",
    signer_mismatch_code="PERMIT_OPERATOR_APPROVAL_SIGNER_MISMATCH",
    supported_code="PERMIT_OPERATOR_APPROVAL_SUPPORTED",
)
PERMIT_V2_COUNTER_SIGNATURE_SPEC = PermitV2SlotSpec(
    slot_name=PERMIT_COUNTER_SIGNATURE_SLOT,
    claim_name=PERMIT_COUNTER_SIGNATURE_CLAIM_NAME,
    payload_type=PERMIT_COUNTER_SIGNATURE_PAYLOAD_TYPE,
    subject_type="permit_counter_signature",
    signer_payload_field="buyer_principal_id",
    key_purposes=PERMIT_V2_BUYER_KEY_PURPOSES,
    invalid_code="PERMIT_COUNTER_SIGNATURE_INVALID",
    key_not_trusted_code="PERMIT_COUNTER_SIGNATURE_KEY_NOT_TRUSTED",
    signer_mismatch_code="PERMIT_COUNTER_SIGNATURE_SIGNER_MISMATCH",
    supported_code="PERMIT_COUNTER_SIGNATURE_SUPPORTED",
    extra_field="execution_intent_hash",
    extra_mismatch_code="counter_signature.execution_intent_mismatch",
)
PERMIT_V2_AUDIT_ATTESTATION_SPEC = PermitV2SlotSpec(
    slot_name=PERMIT_AUDIT_ATTESTATION_SLOT,
    claim_name=PERMIT_AUDIT_ATTESTATION_CLAIM_NAME,
    payload_type=PERMIT_AUDIT_ATTESTATION_PAYLOAD_TYPE,
    subject_type="permit_audit_attestation",
    signer_payload_field="buyer_principal_id",
    key_purposes=PERMIT_V2_BUYER_KEY_PURPOSES,
    invalid_code="PERMIT_AUDIT_ATTESTATION_INVALID",
    key_not_trusted_code="PERMIT_AUDIT_ATTESTATION_KEY_NOT_TRUSTED",
    signer_mismatch_code="PERMIT_AUDIT_ATTESTATION_SIGNER_MISMATCH",
    supported_code="PERMIT_AUDIT_ATTESTATION_SUPPORTED",
    extra_field="batch_id",
    extra_mismatch_code="PERMIT_AUDIT_ATTESTATION_BATCH_MISMATCH",
)
PERMIT_V2_LEGACY_OPERATOR_APPROVED_SPEC = replace(
    PERMIT_V2_OPERATOR_APPROVAL_SPEC,
    claim_name=PERMIT_OPERATOR_APPROVED_CLAIM_NAME,
)
PERMIT_V2_LEGACY_COUNTER_SIGNED_SPEC = replace(
    PERMIT_V2_COUNTER_SIGNATURE_SPEC,
    claim_name=PERMIT_COUNTER_SIGNED_CLAIM_NAME,
)
PERMIT_V2_LEGACY_AUDIT_ATTESTED_SPEC = replace(
    PERMIT_V2_AUDIT_ATTESTATION_SPEC,
    claim_name=PERMIT_AUDIT_ATTESTED_CLAIM_NAME,
)
PERMIT_V2_SLOT_SPECS = {
    PERMIT_OPERATOR_APPROVAL_SLOT: PERMIT_V2_OPERATOR_APPROVAL_SPEC,
    PERMIT_COUNTER_SIGNATURE_SLOT: PERMIT_V2_COUNTER_SIGNATURE_SPEC,
    PERMIT_AUDIT_ATTESTATION_SLOT: PERMIT_V2_AUDIT_ATTESTATION_SPEC,
}


def _verify_ed25519(pub_b64: str, signed_message: bytes, sig_b64: str) -> bool:
    try:
        pub_bytes = base64.b64decode(pub_b64.removeprefix("ed25519:"))
        sig_bytes = base64.b64decode(sig_b64.removeprefix("ed25519:"))
        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub_key.verify(sig_bytes, signed_message)
        return True
    except Exception:
        return False


def _public_key_fingerprint(pub_b64: str) -> str:
    raw = base64.b64decode(pub_b64.removeprefix("ed25519:"))
    return f"sha256:{hashlib.sha256(raw).hexdigest()[:32]}"


def _parse_record_hash_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        raise TypeError("created_at must be an ISO-8601 string")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


def _compute_record_hash_v1(
    *,
    event_id: str,
    event_type: str,
    resource_type: str | None,
    resource_id: str | None,
    outcome: str | None,
    severity: str,
    created_at: Any,
    prev_hash: str,
    sequence_number: int,
) -> str:
    normalized_ts = _parse_record_hash_timestamp(created_at)
    normalized_ts = (
        normalized_ts.replace(tzinfo=None)
        if normalized_ts.tzinfo
        else normalized_ts
    )
    ts_str = normalized_ts.strftime("%Y-%m-%dT%H:%M:%S.%f")
    parts = "|".join(
        [
            event_id,
            event_type,
            resource_type or "",
            resource_id or "",
            outcome or "",
            severity,
            ts_str,
            prev_hash,
            str(sequence_number),
        ]
    )
    return hashlib.sha256(parts.encode("utf-8")).hexdigest()


_GENESIS_HASH = hashlib.sha256(b"keel-audit-chain-genesis-v1").hexdigest()
DELEGATION_DENIED_CLAIM_NAME = "permit_chain.delegation_denied_correctly.v1"

AUTHORITY_ENVELOPE_VERSION = "authority-envelope.v0"
AUTHORITY_ENVELOPE_SET_FIELDS = (
    "actions",
    "tools",
    "providers",
    "models",
    "data_classes",
    "regions",
)
AUTHORITY_ENVELOPE_FIELDS = (*AUTHORITY_ENVELOPE_SET_FIELDS, "expires_at")


class AuthorityEnvelopeError(ValueError):
    """Raised when an authority envelope cannot be interpreted under v0."""


class UnsupportedAuthorityEnvelopeVersion(AuthorityEnvelopeError):
    """Raised when a caller asks for unsupported envelope semantics."""


class AuthorityEnvelopeComparison:
    __slots__ = ("allowed", "child", "details", "failed_fields", "parent")

    def __init__(
        self,
        *,
        allowed: bool,
        failed_fields: tuple[str, ...],
        parent: dict[str, Any],
        child: dict[str, Any],
        details: dict[str, Any],
    ) -> None:
        self.allowed = allowed
        self.failed_fields = failed_fields
        self.parent = parent
        self.child = child
        self.details = details


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _canonical_json_bytes(value: Any) -> bytes:
    return _canonical_json(value).encode("utf-8")


def _bundle_canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _is_self_attesting_bundle(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and value.get("schema_version") == SELF_ATTESTING_BUNDLE_SCHEMA_VERSION
        and isinstance(value.get("body"), dict)
        and isinstance(value.get("signature_envelope"), dict)
    )


def _artifact_ref_digest_for_body(value: Any) -> str:
    return f"sha256:{hashlib.sha256(_bundle_canonical_json_bytes(value)).hexdigest()}"


def _bundle_artifact_ref_material(body: Mapping[str, Any]) -> dict[str, Any]:
    material = dict(body)
    material.pop("artifact_ref", None)
    # Bundles resolve anchors after artifact_ref issuance. The signature
    # envelope content_hash covers the final body including anchor.
    material.pop("anchor", None)
    return material


def _bundle_anchor_hash(body: Mapping[str, Any]) -> str | None:
    anchor = body.get("anchor")
    if isinstance(anchor, Mapping):
        kind = anchor.get("kind")
        if kind == "published_checkpoint":
            value = anchor.get("composite_hash")
        elif kind == "chain_head_timestamp":
            value = anchor.get("chain_head_hash")
        else:
            value = None
        return value if isinstance(value, str) and value.startswith("sha256:") else None
    composite = body.get("composite_hash")
    if isinstance(composite, str) and composite.startswith("sha256:"):
        return composite
    return None


def _bundle_receipt_b64(receipt: Mapping[str, Any]) -> str | None:
    for field in ("receipt_b64", "tsa_response_base64"):
        value = receipt.get(field)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _bundle_receipt_label(receipt: Mapping[str, Any], index: int) -> str:
    for field in ("provider", "url", "tsa"):
        value = receipt.get(field)
        if isinstance(value, str) and value.strip():
            return value
    return f"receipt {index}"


def _self_attesting_bundle_claim(
    *,
    subject_type: str,
    subject_id: str | None,
    verdict: str,
    reason_code: str,
    message: str,
) -> ClaimVerdict:
    return _single_subject_claim(
        "evidence_bundle.self_attesting.v1",
        subject_type=subject_type,
        subject_id=subject_id,
        verdict=verdict,
        reason_code=reason_code,
        message=message,
        evidence=[
            "bundle.body",
            "bundle.body.artifact_ref",
            "bundle.signature_envelope",
        ],
    )


def _verify_self_attesting_bundle_payload(
    bundle: Mapping[str, Any],
    *,
    artifact_id: str | None = None,
    check_tsa: bool = True,
) -> tuple[bool, str | None, dict[str, Any] | None, list[ClaimVerdict], list[str]]:
    diagnostics: list[str] = []
    if bundle.get("schema_version") != SELF_ATTESTING_BUNDLE_SCHEMA_VERSION:
        message = "unsupported evidence bundle schema_version"
        return (
            False,
            message,
            None,
            [
                _self_attesting_bundle_claim(
                    subject_type="bundle_schema",
                    subject_id=artifact_id,
                    verdict="unverifiable_scope",
                    reason_code="BUNDLE_SCHEMA_UNSUPPORTED",
                    message=message,
                )
            ],
            diagnostics,
        )

    body = bundle.get("body")
    envelope = bundle.get("signature_envelope")
    if not isinstance(body, dict) or not isinstance(envelope, dict):
        message = "bundle must contain object body and signature_envelope"
        return (
            False,
            message,
            None,
            [
                _self_attesting_bundle_claim(
                    subject_type="bundle_shape",
                    subject_id=artifact_id,
                    verdict="insufficient_evidence",
                    reason_code="BUNDLE_SHAPE_INVALID",
                    message=message,
                )
            ],
            diagnostics,
        )

    artifact_ref = body.get("artifact_ref")
    if not isinstance(artifact_ref, dict) or not isinstance(
        artifact_ref.get("digest"), str
    ):
        message = "body.artifact_ref.digest is missing"
        return (
            False,
            message,
            body,
            [
                _self_attesting_bundle_claim(
                    subject_type="artifact_ref",
                    subject_id=artifact_id,
                    verdict="insufficient_evidence",
                    reason_code="ARTIFACT_REF_MISSING",
                    message=message,
                )
            ],
            diagnostics,
        )
    expected_artifact_digest = artifact_ref.get("digest")
    actual_artifact_digest = _artifact_ref_digest_for_body(
        _bundle_artifact_ref_material(body)
    )
    if expected_artifact_digest != actual_artifact_digest:
        message = (
            "artifact_ref.digest mismatch: "
            f"expected={expected_artifact_digest} actual={actual_artifact_digest}"
        )
        return (
            False,
            message,
            body,
            [
                _self_attesting_bundle_claim(
                    subject_type="artifact_ref",
                    subject_id=str(artifact_ref.get("id") or artifact_id or ""),
                    verdict="disproved",
                    reason_code="ARTIFACT_REF_DIGEST_MISMATCH",
                    message=message,
                )
            ],
            diagnostics,
        )

    expected_content_hash = envelope.get("content_hash")
    actual_content_hash = _content_hash(_bundle_canonical_json_bytes(body))
    if expected_content_hash != actual_content_hash:
        message = (
            "content_hash mismatch: "
            f"expected={expected_content_hash} actual={actual_content_hash}"
        )
        return (
            False,
            message,
            body,
            [
                _self_attesting_bundle_claim(
                    subject_type="signature_envelope",
                    subject_id=artifact_id,
                    verdict="disproved",
                    reason_code="BUNDLE_CONTENT_HASH_MISMATCH",
                    message=message,
                )
            ],
            diagnostics,
        )

    public_key = envelope.get("public_key")
    signature = envelope.get("signature")
    if not isinstance(public_key, str) or not isinstance(signature, str):
        message = "signature_envelope public_key/signature missing"
        return (
            False,
            message,
            body,
            [
                _self_attesting_bundle_claim(
                    subject_type="signature_envelope",
                    subject_id=artifact_id,
                    verdict="insufficient_evidence",
                    reason_code="BUNDLE_SIGNATURE_MISSING",
                    message=message,
                )
            ],
            diagnostics,
        )
    if not _verify_ed25519(public_key, actual_content_hash.encode("utf-8"), signature):
        message = "bundle signature verification failed"
        return (
            False,
            message,
            body,
            [
                _self_attesting_bundle_claim(
                    subject_type="signature_envelope",
                    subject_id=str(envelope.get("public_key_id") or artifact_id or ""),
                    verdict="disproved",
                    reason_code="BUNDLE_SIGNATURE_INVALID",
                    message=message,
                )
            ],
            diagnostics,
        )

    receipts = envelope.get("tsa_receipts")
    receipt_list = [r for r in receipts if isinstance(r, dict)] if isinstance(receipts, list) else []
    anchor_hash = _bundle_anchor_hash(body)
    if anchor_hash is None:
        diagnostics.append(
            "INFO: bundle has no anchor; verified as self-attesting without external chain anchoring"
        )
    if not receipt_list:
        diagnostics.append("WARNING: bundle has no TSA receipts; TSA is plan-tiered")
    elif check_tsa:
        if anchor_hash is None:
            diagnostics.append(
                "WARNING: bundle TSA receipts present but no anchor hash is available; "
                "skipping TSA imprint verification"
            )
        else:
            for index, receipt in enumerate(receipt_list, start=1):
                receipt_b64 = _bundle_receipt_b64(receipt)
                label = _bundle_receipt_label(receipt, index)
                if receipt_b64 is None:
                    message = f"TSA receipt {index} is missing receipt bytes"
                    return (
                        False,
                        message,
                        body,
                        [
                            _self_attesting_bundle_claim(
                                subject_type="tsa_receipts",
                                subject_id=label,
                                verdict="insufficient_evidence",
                                reason_code="BUNDLE_TSA_RECEIPT_MISSING",
                                message=message,
                            )
                        ],
                        diagnostics,
                    )
                ok, reason = _verify_tsa_receipt(
                    receipt_b64,
                    anchor_hash.removeprefix("sha256:"),
                )
                if not ok:
                    message = f"TSA: {label}: {reason}"
                    return (
                        False,
                        message,
                        body,
                        [
                            _self_attesting_bundle_claim(
                                subject_type="tsa_receipts",
                                subject_id=label,
                                verdict="disproved",
                                reason_code="BUNDLE_TSA_IMPRINT_MISMATCH",
                                message=message,
                            )
                        ],
                        diagnostics,
                    )

    return (
        True,
        None,
        body,
        [
            _self_attesting_bundle_claim(
                subject_type="evidence_bundle",
                subject_id=str(artifact_ref.get("id") or artifact_id or ""),
                verdict="supported",
                reason_code="EVIDENCE_BUNDLE_SUPPORTED",
                message=(
                    "self-attesting bundle content hash, signature, artifact_ref, "
                    "and available TSA receipt checks completed"
                ),
            )
        ],
        diagnostics,
    )


def _compute_record_hash(
    *,
    event_id: str,
    event_type: str,
    resource_type: str | None,
    resource_id: str | None,
    outcome: str | None,
    severity: str,
    occurred_at: Any,
    prev_hash: str,
    sequence_number: int,
) -> str:
    return _compute_record_hash_v1(
        event_id=event_id,
        event_type=event_type,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        severity=severity,
        created_at=occurred_at,
        prev_hash=prev_hash,
        sequence_number=sequence_number,
    )


def _event_payload(event: dict[str, Any]) -> dict[str, Any]:
    payload = event.get("payload_json")
    if payload is None:
        payload = event.get("payload")
    return payload if isinstance(payload, dict) else {}


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _governance_event_integrity_material(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_id": event.get("event_id"),
        "project_id": _string_or_none(event.get("project_id")),
        "project_name": event.get("project_name"),
        "request_id": event.get("request_id"),
        "permit_id": _string_or_none(event.get("permit_id")),
        "category": event.get("category"),
        "event_type": event.get("event_type"),
        "severity": event.get("severity"),
        "payload_json": _event_payload(event),
        "source_stage": event.get("source_stage"),
        "lineage_type": event.get("lineage_type"),
        "provider": event.get("provider"),
        "model": event.get("model"),
        "operation": event.get("operation"),
        "decision": event.get("decision"),
        "surface": event.get("surface"),
        "trace_id": event.get("trace_id"),
        "span_id": event.get("span_id"),
        "occurred_at": event.get("occurred_at"),
        "schema_version": event.get("schema_version"),
        "actor_id": event.get("actor_id"),
        "actor_type": event.get("actor_type"),
        "outcome": event.get("outcome"),
        "resource_type": event.get("resource_type"),
        "resource_id": event.get("resource_id"),
    }


def _compute_governance_event_integrity_hash(event: dict[str, Any]) -> str:
    return hashlib.sha256(
        _canonical_json_bytes(_governance_event_integrity_material(event))
    ).hexdigest()


def _compute_integrity_batch_hash(covered_events: list[dict[str, str]]) -> str:
    return hashlib.sha256(_canonical_json_bytes(covered_events)).hexdigest()


def _normalize_authority_envelope_version(version: str | None) -> str:
    normalized = str(version or "").strip()
    return normalized or AUTHORITY_ENVELOPE_VERSION


def _ensure_supported_authority_envelope_version(version: str | None) -> str:
    normalized = _normalize_authority_envelope_version(version)
    if normalized != AUTHORITY_ENVELOPE_VERSION:
        raise UnsupportedAuthorityEnvelopeVersion(
            f"Unsupported authority envelope version: {normalized}"
        )
    return normalized


def _plain_authority_mapping(value: Any) -> dict[str, Any]:
    if value is None:
        raise AuthorityEnvelopeError("authority_envelope is required")
    if not isinstance(value, dict):
        raise AuthorityEnvelopeError("authority_envelope must be an object")
    return dict(value)


def _canonical_authority_set(raw: Any, *, field: str) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, (list, tuple, set, frozenset)):
        raise AuthorityEnvelopeError(f"{field} must be a list of strings")
    values: set[str] = set()
    for item in raw:
        if not isinstance(item, str):
            raise AuthorityEnvelopeError(f"{field} members must be strings")
        values.add(item)
    return sorted(values)


def _parse_authority_datetime(raw: Any, *, field: str) -> datetime | None:
    if raw is None:
        return None
    if isinstance(raw, datetime):
        parsed = raw
    elif isinstance(raw, str):
        normalized = raw.strip()
        if not normalized:
            return None
        try:
            parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
        except ValueError as exc:
            raise AuthorityEnvelopeError(
                f"{field} must be an RFC 3339 timestamp"
            ) from exc
    else:
        raise AuthorityEnvelopeError(f"{field} must be an RFC 3339 timestamp")
    if parsed.tzinfo is None:
        raise AuthorityEnvelopeError(f"{field} must include a timezone offset")
    return parsed.astimezone(timezone.utc)


def _rfc3339_utc(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        raise AuthorityEnvelopeError("timestamp must include a timezone offset")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_authority_envelope(value: Any) -> dict[str, Any]:
    raw = _plain_authority_mapping(value)
    unknown_fields = sorted(set(raw) - set(AUTHORITY_ENVELOPE_FIELDS))
    if unknown_fields:
        raise AuthorityEnvelopeError(
            "authority_envelope contains unsupported fields: "
            + ", ".join(unknown_fields)
        )
    canonical: dict[str, Any] = {
        field: _canonical_authority_set(raw.get(field), field=field)
        for field in AUTHORITY_ENVELOPE_SET_FIELDS
    }
    canonical["expires_at"] = _rfc3339_utc(
        _parse_authority_datetime(raw.get("expires_at"), field="expires_at")
    )
    return canonical


def compare_authority_envelopes(
    *,
    parent: Any,
    child: Any,
    version: str | None,
) -> AuthorityEnvelopeComparison:
    _ensure_supported_authority_envelope_version(version)
    parent_canonical = canonical_authority_envelope(parent)
    child_canonical = canonical_authority_envelope(child)

    failed: list[str] = []
    details: dict[str, Any] = {}
    for field in AUTHORITY_ENVELOPE_SET_FIELDS:
        parent_set = set(parent_canonical[field])
        child_set = set(child_canonical[field])
        extra = sorted(child_set - parent_set)
        if extra:
            failed.append(field)
            details[field] = {
                "extra_child_members": extra,
                "parent": parent_canonical[field],
                "child": child_canonical[field],
            }

    parent_expires = _parse_authority_datetime(
        parent_canonical["expires_at"], field="expires_at"
    )
    child_expires = _parse_authority_datetime(
        child_canonical["expires_at"], field="expires_at"
    )
    if parent_expires is None or child_expires is None:
        if parent_expires != child_expires:
            failed.append("expires_at")
            details["expires_at"] = {
                "parent": parent_canonical["expires_at"],
                "child": child_canonical["expires_at"],
                "violation": "missing_comparable_timestamp",
            }
    elif child_expires > parent_expires:
        failed.append("expires_at")
        details["expires_at"] = {
            "parent": parent_canonical["expires_at"],
            "child": child_canonical["expires_at"],
            "violation": "child_expires_after_parent",
        }

    return AuthorityEnvelopeComparison(
        allowed=not failed,
        failed_fields=tuple(failed),
        parent=parent_canonical,
        child=child_canonical,
        details=details,
    )


def _json_result(
    *,
    status: str,
    supported_checks: list[str] | None = None,
    missing_requirements: list[str] | None = None,
    errors: list[str] | None = None,
    semantics: ResolvedSemantics | None = None,
    include_semantics: bool = False,
    **extra: Any,
) -> dict[str, Any]:
    result = {
        "claim_type": "delegation_denied_correctly",
        "status": status,
        "supported_checks": supported_checks or [],
        "missing_requirements": missing_requirements or [],
        "errors": errors or [],
        "supported_envelope_versions": [AUTHORITY_ENVELOPE_VERSION],
        **extra,
    }
    if include_semantics and semantics is not None:
        result["semantics"] = semantics.report_semantics()
    return result


def _load_json_evidence(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _extract_events(evidence: Any) -> list[dict[str, Any]]:
    if isinstance(evidence, list):
        return [item for item in evidence if isinstance(item, dict)]
    if not isinstance(evidence, dict):
        return []
    if isinstance(evidence.get("event_type"), str):
        return [evidence]
    for key in ("events", "records", "governance_events", "chain_entries"):
        value = evidence.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    event = evidence.get("event")
    if isinstance(event, dict):
        return [event]
    return []


def _verify_supplied_chain(
    events: list[dict[str, Any]],
    semantics_dispatch: SemanticsDispatch,
) -> tuple[str, str | None]:
    if not events:
        return "insufficient_evidence", "chain_events"

    record_hash_v1 = semantics_dispatch.record_hashers.get("v1")
    if record_hash_v1 is None:
        return "insufficient_evidence", "record_hash_semantics"

    required = {
        "event_id",
        "event_type",
        "severity",
        "occurred_at",
        "sequence_number",
        "record_hash",
        "prev_hash",
    }
    for event in events:
        missing = sorted(field for field in required if event.get(field) is None)
        if missing:
            return "insufficient_evidence", f"chain_field:{missing[0]}"

    by_scope: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        scope = str(event.get("chain_scope") or "project")
        by_scope.setdefault(scope, []).append(event)

    for scope_events in by_scope.values():
        ordered = sorted(scope_events, key=lambda item: int(item["sequence_number"]))
        expected_prev = _GENESIS_HASH
        expected_sequence = 1
        for event in ordered:
            sequence = int(event["sequence_number"])
            if sequence != expected_sequence:
                return "insufficient_evidence", "contiguous_chain_prefix"
            if event.get("prev_hash") != expected_prev:
                return "disproved", "prev_hash_mismatch"
            recomputed = record_hash_v1(
                event_id=str(event["event_id"]),
                event_type=str(event["event_type"]),
                resource_type=event.get("resource_type"),
                resource_id=event.get("resource_id"),
                outcome=event.get("outcome"),
                severity=str(event["severity"]),
                created_at=event["occurred_at"],
                prev_hash=str(event["prev_hash"]),
                sequence_number=sequence,
            )
            if event.get("record_hash") != recomputed:
                return "disproved", "record_hash_mismatch"
            expected_prev = str(event["record_hash"])
            expected_sequence += 1
    return "supported", None


def _verify_target_payload_integrity(
    events: list[dict[str, Any]],
    target: dict[str, Any],
    semantics_dispatch: SemanticsDispatch,
) -> tuple[str, str | None]:
    target_event_id = str(target.get("event_id") or "").strip()
    target_event_type = str(target.get("event_type") or "").strip()
    if not target_event_id or not target_event_type:
        return "insufficient_evidence", "payload_integrity_target"

    event_integrity_hash = semantics_dispatch.governance_event_integrity_hash
    integrity_batch_hash = semantics_dispatch.integrity_batch_hash
    if event_integrity_hash is None or integrity_batch_hash is None:
        return "insufficient_evidence", "governance_event_integrity_digest_semantics"

    target_integrity_hash = event_integrity_hash(target)
    for event in events:
        if event.get("event_type") != "audit.integrity_digest":
            continue

        payload = _event_payload(event)
        covered_raw = payload.get("covered_events")
        if not isinstance(covered_raw, list):
            continue

        covered_events: list[dict[str, str]] = []
        matching: list[dict[str, str]] = []
        for covered in covered_raw:
            if not isinstance(covered, dict):
                return "insufficient_evidence", "integrity_digest_payload"
            event_id = str(covered.get("event_id") or "").strip()
            event_type = str(covered.get("event_type") or "").strip()
            event_hash = str(covered.get("event_hash") or "").strip()
            if not event_id or not event_type or not event_hash:
                return "insufficient_evidence", "integrity_digest_payload"
            entry = {
                "event_id": event_id,
                "event_type": event_type,
                "event_hash": event_hash,
            }
            covered_events.append(entry)
            if event_id == target_event_id:
                matching.append(entry)

        if not matching:
            continue

        expected_batch_hash = integrity_batch_hash(covered_events)
        actual_batch_hash = str(payload.get("batch_hash") or "").strip()
        if actual_batch_hash != expected_batch_hash:
            return "disproved", "integrity_digest_batch_hash_mismatch"
        resource_id = str(event.get("resource_id") or "").strip()
        if resource_id and resource_id != expected_batch_hash[:32]:
            return "disproved", "integrity_digest_resource_mismatch"
        covered_event_count = payload.get("covered_event_count")
        if covered_event_count is not None:
            try:
                count = int(covered_event_count)
            except (TypeError, ValueError):
                return "insufficient_evidence", "integrity_digest_payload"
            if count != len(covered_events):
                return "disproved", "integrity_digest_count_mismatch"

        for entry in matching:
            if entry["event_type"] != target_event_type:
                return "disproved", "payload_integrity_event_type_mismatch"
            if entry["event_hash"] != target_integrity_hash:
                return "disproved", "payload_integrity_mismatch"
        return "supported", None

    return "insufficient_evidence", "payload_integrity_digest"


def _resolve_delegation_denied_semantics(
    evidence: Any,
    *,
    pack_root: Path | None,
) -> ResolvedSemantics:
    pack = evidence if isinstance(evidence, dict) else {}
    return resolve_pack_semantics(
        pack,
        pack_root=pack_root,
        default_claim_names=(DELEGATION_DENIED_CLAIM_NAME,),
        allowlist=PERMANENT_ALLOWLIST,
    )


def _semantic_failure_json_result(
    semantics: ResolvedSemantics,
    *,
    include_semantics: bool,
) -> dict[str, Any]:
    failure = semantics.failure
    assert failure is not None
    missing = [failure.reason_code] if failure.verdict == "insufficient_evidence" else []
    errors = [failure.reason_code] if failure.verdict != "insufficient_evidence" else []
    return _json_result(
        status=failure.verdict,
        missing_requirements=missing,
        errors=errors,
        reason_code=failure.reason_code,
        message=failure.message,
        semantics=semantics,
        include_semantics=include_semantics,
    )


def verify_delegation_denied_correctly(
    evidence: Any,
    *,
    event_id: str | None = None,
    pack_root: Path | None = None,
    include_semantics: bool = False,
) -> dict[str, Any]:
    semantics = _resolve_delegation_denied_semantics(evidence, pack_root=pack_root)
    if not semantics.ok:
        return _semantic_failure_json_result(
            semantics,
            include_semantics=include_semantics,
        )
    semantics_dispatch = semantics.dispatch()

    def result(**kwargs: Any) -> dict[str, Any]:
        return _json_result(
            **kwargs,
            semantics=semantics,
            include_semantics=include_semantics,
        )

    events = _extract_events(evidence)
    if not events:
        return result(
            status="insufficient_evidence",
            missing_requirements=["governance_events"],
        )

    denied_events = [
        event
        for event in events
        if event.get("event_type") == "permit.delegated_denied"
        and (event_id is None or event.get("event_id") == event_id)
    ]
    if not denied_events:
        return result(
            status="insufficient_evidence",
            missing_requirements=["permit.delegated_denied"],
        )
    if len(denied_events) > 1 and event_id is None:
        return result(
            status="insufficient_evidence",
            missing_requirements=["event_id_for_ambiguous_claim"],
        )

    target = denied_events[0]
    chain_status, chain_detail = _verify_supplied_chain(events, semantics_dispatch)
    if chain_status != "supported":
        missing = [chain_detail] if chain_status == "insufficient_evidence" else []
        errors = [chain_detail] if chain_status == "disproved" else []
        return result(
            status=chain_status,
            missing_requirements=missing,
            errors=errors,
        )

    integrity_status, integrity_detail = _verify_target_payload_integrity(
        events,
        target,
        semantics_dispatch,
    )
    if integrity_status != "supported":
        missing = [integrity_detail] if integrity_status == "insufficient_evidence" else []
        errors = [integrity_detail] if integrity_status == "disproved" else []
        return result(
            status=integrity_status,
            supported_checks=["hash_chain_integrity"],
            missing_requirements=missing,
            errors=errors,
        )

    payload = _event_payload(target)
    version = payload.get("authority_envelope_version")
    if not isinstance(version, str) or not version.strip():
        return result(
            status="insufficient_evidence",
            supported_checks=["hash_chain_integrity", "payload_integrity_digest"],
            missing_requirements=["authority_envelope_version"],
        )
    version = version.strip()
    try:
        _ensure_supported_authority_envelope_version(version)
    except UnsupportedAuthorityEnvelopeVersion:
        return result(
            status="unverifiable_scope",
            supported_checks=["hash_chain_integrity", "payload_integrity_digest"],
            errors=["unsupported_authority_envelope_version"],
        )

    authority_comparator = semantics_dispatch.authority_envelope_comparators.get(version)
    if authority_comparator is None:
        return result(
            status="unverifiable_scope",
            supported_checks=["hash_chain_integrity", "payload_integrity_digest"],
            errors=["unsupported_authority_envelope_version"],
        )

    child = payload.get("child_requested_authority_envelope")
    parent = payload.get("parent_authority_envelope")
    failed_fields = payload.get("failed_fields")
    reason_code = payload.get("reason_code")
    missing_requirements: list[str] = []
    if child is None:
        missing_requirements.append("child_requested_authority_envelope")
    if failed_fields is None:
        missing_requirements.append("failed_fields")
    if not reason_code:
        missing_requirements.append("reason_code")
    if missing_requirements:
        return result(
            status="insufficient_evidence",
            supported_checks=["hash_chain_integrity", "payload_integrity_digest"],
            missing_requirements=missing_requirements,
        )

    event_failed = {str(field) for field in failed_fields or []}
    if parent is None:
        if reason_code == "authority_envelope.parent_missing" and (
            "authority_envelope" in event_failed
        ):
            try:
                canonical_authority_envelope(child)
            except Exception as exc:
                return result(
                    status="insufficient_evidence",
                    supported_checks=["hash_chain_integrity", "payload_integrity_digest"],
                    missing_requirements=["child_requested_authority_envelope"],
                    errors=[str(exc)],
                    event_id=target.get("event_id"),
                )
            return result(
                status="supported",
                supported_checks=[
                    "hash_chain_integrity",
                    "payload_integrity_digest",
                    "child_requested_authority_envelope_present",
                    "parent_authority_envelope_absent",
                    "denial_reason_matches_parent_missing",
                ],
                event_id=target.get("event_id"),
                failed_fields=sorted(event_failed),
            )
        return result(
            status="insufficient_evidence",
            supported_checks=["hash_chain_integrity", "payload_integrity_digest"],
            missing_requirements=["parent_authority_envelope"],
        )

    try:
        comparison = authority_comparator(
            parent=parent,
            child=child,
            version=version,
        )
    except UnsupportedAuthorityEnvelopeVersion:
        return result(
            status="unverifiable_scope",
            supported_checks=["hash_chain_integrity", "payload_integrity_digest"],
            errors=["unsupported_authority_envelope_version"],
        )
    except Exception as exc:
        return result(
            status="insufficient_evidence",
            supported_checks=["hash_chain_integrity", "payload_integrity_digest"],
            missing_requirements=["comparable_authority_envelopes"],
            errors=[str(exc)],
        )

    if comparison.allowed:
        return result(
            status="disproved",
            supported_checks=["hash_chain_integrity", "payload_integrity_digest"],
            errors=["comparator_allows_child_authority"],
            event_id=target.get("event_id"),
        )

    expected_failed = set(comparison.failed_fields)
    if event_failed != expected_failed:
        return result(
            status="disproved",
            supported_checks=[
                "hash_chain_integrity",
                "payload_integrity_digest",
                "comparator_reran",
            ],
            errors=["failed_fields_mismatch"],
            expected_failed_fields=sorted(expected_failed),
            event_failed_fields=sorted(event_failed),
            event_id=target.get("event_id"),
        )

    return result(
        status="supported",
        supported_checks=[
            "hash_chain_integrity",
            "payload_integrity_digest",
            "parent_authority_envelope_present",
            "child_requested_authority_envelope_present",
            "comparator_reran",
            "denial_was_correct",
        ],
        event_id=target.get("event_id"),
        failed_fields=sorted(expected_failed),
        comparison_details=comparison.details,
    )


def _compute_canonical_binding_hash(payload: dict[str, Any]) -> str:
    return _canonical_permit_binding_hash(payload)


def _binding_key_id_from_public_key(public_key: str) -> str:
    raw = base64.b64decode(public_key.removeprefix("ed25519:"))
    return hashlib.sha256(raw).hexdigest()[:16]


# ─── Key manifest loading ──────────────────────────────────────────


def _parse_iso_or_none(value: Any) -> datetime | None:
    """Parse an ISO-8601 timestamp. Returns None if missing or unparseable.

    Accepts ``Z`` and ``+00:00`` suffixes; bare strings without an
    explicit zone are assumed UTC. Used for both artifact signing times
    (``signed_at`` / ``computed_at``) and manifest entry windows
    (``valid_from`` / ``valid_to``).
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _filter_by_active_window(
    entries: list[dict[str, Any]],
    signing_time: datetime,
) -> list[dict[str, Any]]:
    """Keep entries whose [valid_from, valid_to] window covers signing_time.

    An absent bound or explicit JSON null means "open-ended" on that
    side. A present non-null bound that fails to parse makes the entry
    malformed, so the entry is excluded conservatively.
    """
    matches: list[dict[str, Any]] = []
    for entry in entries:
        valid_from = None
        valid_to = None
        malformed_window = False

        for field in ("valid_from", "valid_to"):
            if field not in entry or entry[field] is None:
                continue
            parsed = _parse_iso_or_none(entry[field])
            if parsed is None:
                malformed_window = True
                break
            if field == "valid_from":
                valid_from = parsed
            else:
                valid_to = parsed

        if malformed_window:
            continue
        if valid_from is not None and signing_time < valid_from:
            continue
        if valid_to is not None and signing_time > valid_to:
            continue
        matches.append(entry)
    return matches


def _load_key_manifest(source: str) -> list[dict[str, Any]]:
    """Load a Keel public key manifest from a local file path or URL."""
    if source.startswith(("http://", "https://")):
        with urllib.request.urlopen(source, timeout=10) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    else:
        body = json.loads(Path(source).read_text(encoding="utf-8"))

    if not isinstance(body, dict) or not isinstance(body.get("keys"), list):
        raise ValueError(
            f"Key manifest at {source!r} must be a JSON object with a 'keys' list"
        )

    default_purpose = (
        body.get("purpose") if isinstance(body.get("purpose"), str) else None
    )
    entries: list[dict[str, Any]] = []
    for entry in body["keys"]:
        if not isinstance(entry, dict):
            continue
        normalized = dict(entry)
        if default_purpose is not None and not isinstance(
            normalized.get("purpose"), str
        ):
            normalized["purpose"] = default_purpose
        public_key_b64 = normalized.get("public_key_b64")
        if not isinstance(normalized.get("public_key"), str) and isinstance(
            public_key_b64, str
        ):
            public_key_material = public_key_b64.removeprefix("ed25519:")
            normalized["public_key"] = f"ed25519:{public_key_material}"
        if "valid_from" not in normalized and "active_from" in normalized:
            normalized["valid_from"] = normalized.get("active_from")
        if "valid_to" not in normalized and "active_to" in normalized:
            normalized["valid_to"] = normalized.get("active_to")
        if "status" not in normalized and (
            "active_to" in normalized or "valid_to" in normalized
        ):
            normalized["status"] = (
                "active" if normalized.get("valid_to") is None else "retired"
            )
        entries.append(normalized)

    return entries


def _resolve_from_manifest(
    manifest_entries: list[dict[str, Any]],
    *,
    key_id: str | None,
    purpose: str,
    signing_time: datetime | None = None,
) -> tuple[str | None, dict[str, Any] | None, str | None]:
    """Pick the right entry from the manifest.

    Returns ``(public_key, entry, error)``.  Error is a human-readable string
    if no resolution is possible; ``public_key`` and ``entry`` are None in
    that case.

    When the artifact has no ``key_id`` and the manifest has multiple
    candidates for the purpose, ``signing_time`` (parsed from the artifact's
    ``signed_at`` or ``computed_at`` field) filters candidates to those
    whose ``[valid_from, valid_to]`` window covers it. If signing_time is
    None, the verifier falls back to the legacy "single candidate" rule
    so older artifacts without a signing timestamp remain verifiable.
    """
    purpose_entries = [e for e in manifest_entries if e.get("purpose") == purpose]
    if not purpose_entries:
        return (
            None,
            None,
            f"key manifest contains no entry with purpose={purpose!r}",
        )

    if key_id is not None:
        matches = [e for e in purpose_entries if e.get("key_id") == key_id]
        if not matches:
            return (
                None,
                None,
                f"key_id {key_id!r} not found in key manifest for purpose={purpose!r}",
            )
        # Prefer an exact unique match
        entry = matches[0]
        pub = entry.get("public_key")
        if not isinstance(pub, str):
            return None, None, "matched manifest entry has no public_key"
        return pub, entry, None

    # Legacy artifact (no key_id). When the artifact carries no parseable
    # signing timestamp, retain the single-candidate rule for back-compat
    # with older artifacts.
    if signing_time is None:
        if len(purpose_entries) != 1:
            return (
                None,
                None,
                (
                    "artifact has no key_id and the key manifest does not contain a "
                    "single legacy fallback for purpose="
                    + repr(purpose)
                    + f" ({len(purpose_entries)} candidates)"
                ),
            )
        entry = purpose_entries[0]
        pub = entry.get("public_key")
        if not isinstance(pub, str):
            return None, None, "legacy fallback manifest entry has no public_key"
        return pub, entry, None

    # Filter manifest candidates by their active window vs. signing_time.
    active = _filter_by_active_window(purpose_entries, signing_time)
    if len(active) == 1:
        entry = active[0]
        pub = entry.get("public_key")
        if not isinstance(pub, str):
            return None, None, "matching manifest entry has no public_key"
        return pub, entry, None

    if len(active) == 0:
        return (
            None,
            None,
            (
                f"no manifest entries for purpose={purpose!r} were active at "
                f"signing time {signing_time.isoformat()} "
                f"({len(purpose_entries)} candidates evaluated); manifest may "
                "be missing key history"
            ),
        )

    return (
        None,
        None,
        (
            f"multiple manifest entries for purpose={purpose!r} were active at "
            f"signing time {signing_time.isoformat()} "
            f"({len(active)} candidates); manifest is ambiguous within active window"
        ),
    )


def _resolve_trust_key(
    *,
    artifact_pub: str | None,
    artifact_key_id: str | None,
    purpose: str,
    expected_public_key: str | None,
    public_key_url: str | None,
    key_manifest_source: str | None,
    signing_time: datetime | None = None,
) -> tuple[str | None, str, str | None]:
    """Resolve which public key to trust for verifying an artifact.

    Returns ``(trusted_public_key, trust_source, error)``.  When ``error`` is
    not None, the trusted key is None and verification must abort.

    ``signing_time`` (parsed from the artifact) lets the manifest path
    filter retired candidates by their active window. None falls back to
    the legacy single-candidate rule.
    """
    if expected_public_key is not None:
        return expected_public_key, "user-supplied", None

    if public_key_url is not None:
        try:
            with urllib.request.urlopen(public_key_url, timeout=10) as resp:
                body = json.loads(resp.read().decode("utf-8"))
            pub = body.get("public_key")
            if not isinstance(pub, str) or not pub.startswith("ed25519:"):
                return None, "", f"unexpected response shape from {public_key_url}"
            return pub, f"fetched from {public_key_url}", None
        except Exception as exc:
            return None, "", f"could not fetch public key: {exc}"

    if key_manifest_source is not None:
        try:
            entries = _load_key_manifest(key_manifest_source)
        except Exception as exc:
            return None, "", f"could not load key manifest: {exc}"
        pub, entry, err = _resolve_from_manifest(
            entries,
            key_id=artifact_key_id,
            purpose=purpose,
            signing_time=signing_time,
        )
        if err is not None:
            return None, "", err
        assert pub is not None and entry is not None
        return pub, (
            f"key manifest ({key_manifest_source}) "
            f"key_id={entry.get('key_id')} status={entry.get('status')}"
        ), None

    if artifact_pub is not None:
        return artifact_pub, "embedded", None

    return None, "", "no trust key available (artifact is unsigned)"


def _bundled_key_manifest_source() -> str | None:
    return str(DEFAULT_TRUST_ROOT_PATH) if DEFAULT_TRUST_ROOT_PATH.exists() else None


def _cached_key_manifest_source() -> str | None:
    """Path to the user-refreshed manifest at ``~/.keel-verifier/trust-root.json`` if present."""
    return str(CACHED_TRUST_ROOT_PATH) if CACHED_TRUST_ROOT_PATH.exists() else None


def _key_manifest_source_for_args(args: argparse.Namespace) -> str | None:
    """Resolve which trust-root source to use for a verification run.

    Resolution order:
      1. Explicit ``--key-manifest`` / ``--key-manifest-url`` argument.
      2. Self-attested mode short-circuits to no manifest.
      3. Cached manifest at ``~/.keel-verifier/trust-root.json`` (populated by
         ``keel-verify refresh-keys``).
      4. Bundled trust root shipped with the wheel.
    """
    explicit = getattr(args, "key_manifest", None) or getattr(args, "key_manifest_url", None)
    if explicit:
        return explicit
    if getattr(args, "self_attested", False):
        return None
    cached = _cached_key_manifest_source()
    if cached is not None:
        return cached
    return _bundled_key_manifest_source()


def _composite_hash(chain_heads: dict[str, dict[str, Any]]) -> str:
    parts: list[str] = []
    for scope_key in sorted(chain_heads.keys()):
        head = chain_heads[scope_key]
        parts.append(
            f"{scope_key}:{head['sequence_number']}:{head['last_record_hash']}"
        )
    combined = "\n".join(parts)
    return f"sha256:{hashlib.sha256(combined.encode('utf-8')).hexdigest()}"


# ─── Mode 1: export ────────────────────────────────────────────────


def _walk_fail(code: str, message: str) -> int:
    print(f"FAILED: {code}: {message}", file=sys.stderr)
    return 1


def _walk_structure_fail(message: str) -> int:
    print(f"FAILED: {message}", file=sys.stderr)
    return 1


def _scope_label(chain_scope: Any) -> str:
    return "<none>" if chain_scope is None else str(chain_scope)


def _entry_id(entry: dict[str, Any]) -> str:
    event_id = entry.get("event_id")
    return event_id if isinstance(event_id, str) and event_id else "<unknown>"


def _required_str(entry: dict[str, Any], field: str) -> str:
    value = entry.get(field)
    if not isinstance(value, str) or value == "":
        raise TypeError(f"{field} must be a non-empty string")
    return value


def _optional_str(entry: dict[str, Any], field: str) -> str | None:
    value = entry.get(field)
    if value is None or isinstance(value, str):
        return value
    raise TypeError(f"{field} must be a string or null")


def _required_int(entry: dict[str, Any], field: str) -> int:
    value = entry.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field} must be an integer")
    return value


def _optional_sequence_number(entry: dict[str, Any]) -> int | None:
    if entry.get("sequence_number") is None:
        return None
    return _required_int(entry, "sequence_number")


def _sequence_sort_key(entry: dict[str, Any]) -> tuple[bool, int]:
    sequence_number = _optional_sequence_number(entry)
    return (
        sequence_number is None,
        sequence_number if sequence_number is not None else 0,
    )


def _walk_array_order_fail(
    chain_scope: Any,
    entries: list[dict[str, Any]],
) -> int | None:
    for index in range(1, len(entries)):
        previous = entries[index - 1]
        current = entries[index]
        try:
            previous_sequence = _optional_sequence_number(previous)
            current_sequence = _optional_sequence_number(current)
        except (TypeError, ValueError) as exc:
            return _walk_fail(
                WALK_SEQUENCE_INVERSION,
                f"event_id={_entry_id(current)} {exc}",
            )
        if previous_sequence is None or current_sequence is None:
            continue
        if current_sequence < previous_sequence:
            return _walk_fail(
                WALK_SEQUENCE_INVERSION,
                (
                    f"chain_scope={_scope_label(chain_scope)} "
                    f"prev_event_id={_entry_id(previous)} "
                    f"prev_sequence_number={previous_sequence} "
                    f"event_id={_entry_id(current)} "
                    f"sequence_number={current_sequence}"
                ),
            )
    return None


def _walk_duplicate_sequence_fail(
    chain_scope: Any,
    entries: list[dict[str, Any]],
) -> int | None:
    seen: dict[int, dict[str, Any]] = {}
    for entry in entries:
        try:
            sequence_number = _optional_sequence_number(entry)
        except (TypeError, ValueError) as exc:
            return _walk_fail(
                WALK_SEQUENCE_INVERSION,
                f"event_id={_entry_id(entry)} {exc}",
            )
        if sequence_number is None:
            continue
        if sequence_number in seen:
            return _walk_fail(
                WALK_SEQUENCE_INVERSION,
                (
                    f"chain_scope={_scope_label(chain_scope)} "
                    f"event_id={_entry_id(entry)} "
                    f"previous_event_id={_entry_id(seen[sequence_number])} "
                    f"duplicate_sequence_number={sequence_number}"
                ),
            )
        seen[sequence_number] = entry
    return None


def _decode_export_json_payload(export_data: bytes) -> bytes:
    if export_data.startswith(b"\x1f\x8b"):
        try:
            return gzip.decompress(export_data)
        except OSError as exc:
            raise ValueError(f"gzip decompression failed: {exc}") from exc
    return export_data


def _load_export_json_document(export_data: bytes) -> Any:
    decoded = _decode_export_json_payload(export_data).decode("utf-8")
    try:
        return json.loads(decoded)
    except json.JSONDecodeError as exc:
        records: list[dict[str, Any]] = []
        for line_number, line in enumerate(decoded.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as line_exc:
                raise ValueError(
                    f"JSONL line {line_number} is not valid JSON: {line_exc}"
                ) from line_exc
            if not isinstance(record, dict):
                raise ValueError(f"JSONL line {line_number} must be a JSON object")
            records.append(record)
        if not records:
            raise exc
        project_id = next(
            (
                record.get("project_id")
                for record in records
                if isinstance(record.get("project_id"), str)
                and record.get("project_id")
            ),
            None,
        )
        return {
            "schema": "keel.governance_events/v1",
            "project_id": project_id,
            "record_count": len(records),
            "records": records,
        }


def _load_audit_export_bundle_for_optional_check(
    export_data: bytes,
    *,
    label: str,
) -> tuple[dict[str, Any] | None, int | None]:
    try:
        bundle = _load_export_json_document(export_data)
    except Exception as exc:
        return None, _walk_structure_fail(f"export is not JSON: {exc}")

    if not isinstance(bundle, dict):
        return None, _walk_structure_fail("bundle must be a JSON object")
    if bundle.get("bundle_type") != "audit_export_bundle":
        return None, _walk_structure_fail(
            "bundle_type must be 'audit_export_bundle'",
        )

    schema_version = bundle.get("schema_version")
    if schema_version not in {1, 2}:
        return None, _walk_structure_fail(
            "schema_version must be 1 or 2",
        )
    if schema_version == 1:
        print(
            f"{label}: bundle has no chain entries (schema_version=1, "
            "request with ?include_chain_entries=true to enable verification)"
        )
        return None, 0
    if bundle.get("include_chain_entries") is not True:
        return None, _walk_structure_fail(
            "schema_version=2 requires include_chain_entries=true",
        )
    return bundle, None


def _record_permit_id(record: dict[str, Any]) -> str | None:
    permit = record.get("permit")
    if not isinstance(permit, dict):
        return None
    permit_id = permit.get("id")
    return permit_id if isinstance(permit_id, str) and permit_id else None


def _record_permit_binding_request_hash(record: dict[str, Any]) -> str | None:
    permit = record.get("permit")
    if not isinstance(permit, dict):
        return None
    value = permit.get("binding_request_hash")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _entry_inline_permit_id(entry: dict[str, Any]) -> str | None:
    value = entry.get("permit_id")
    if isinstance(value, str) and value:
        return value
    payload = _entry_payload(entry)
    value = payload.get("permit_id")
    if isinstance(value, str) and value:
        return value
    if entry.get("resource_type") == "permit":
        value = entry.get("resource_id")
        if isinstance(value, str) and value:
            return value
    return None


def _entry_payload(entry: dict[str, Any]) -> dict[str, Any]:
    payload = entry.get("payload_json")
    if isinstance(payload, dict):
        return payload
    return {}


def _flatten_chain_entries(
    bundle: dict[str, Any],
) -> tuple[list[dict[str, Any]] | None, int | None]:
    records = bundle.get("records")
    if not isinstance(records, list):
        return None, _walk_structure_fail("records must be a list")

    record_binding_by_permit: dict[str, str] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        record_permit_id = _record_permit_id(record)
        record_binding_request_hash = _record_permit_binding_request_hash(record)
        if record_permit_id is not None and record_binding_request_hash is not None:
            record_binding_by_permit[record_permit_id] = record_binding_request_hash

    bundle_chain_entries = bundle.get("chain_entries")
    if bundle_chain_entries is not None:
        if not isinstance(bundle_chain_entries, list):
            return None, _walk_structure_fail("chain_entries must be a list")
        flattened: list[dict[str, Any]] = []
        for entry_index, entry in enumerate(bundle_chain_entries):
            if not isinstance(entry, dict):
                return None, _walk_structure_fail(
                    f"chain_entries[{entry_index}] must be an object",
                )
            permit_id = _entry_inline_permit_id(entry)
            flattened.append(
                {
                    "entry": entry,
                    "record_index": None,
                    "entry_index": entry_index,
                    "record_permit_id": permit_id,
                    "record_binding_request_hash": record_binding_by_permit.get(
                        permit_id or "",
                    ),
                }
            )
        return flattened, None

    flattened: list[dict[str, Any]] = []
    for record_index, record in enumerate(records):
        if not isinstance(record, dict):
            return None, _walk_structure_fail(
                f"records[{record_index}] must be an object",
            )
        record_permit_id = _record_permit_id(record)
        record_binding_request_hash = _record_permit_binding_request_hash(record)
        chain_entries = record.get("chain_entries")
        if chain_entries is None:
            return None, _walk_structure_fail(
                f"records[{record_index}].chain_entries missing",
            )
        if not isinstance(chain_entries, list):
            return None, _walk_structure_fail(
                f"records[{record_index}].chain_entries must be a list",
            )
        for entry_index, entry in enumerate(chain_entries):
            if not isinstance(entry, dict):
                return None, _walk_structure_fail(
                    f"records[{record_index}].chain_entries[{entry_index}] "
                    "must be an object",
                )
            flattened.append(
                {
                    "entry": entry,
                    "record_index": record_index,
                    "entry_index": entry_index,
                    "record_permit_id": record_permit_id,
                    "record_binding_request_hash": record_binding_request_hash,
                }
            )
    return flattened, None


def _governance_events_export_as_walk_bundle(
    bundle: dict[str, Any],
) -> tuple[dict[str, Any] | None, int | None]:
    records = bundle.get("records")
    if not isinstance(records, list):
        return None, _walk_structure_fail("records must be a list")

    chain_entries: list[dict[str, Any]] = []
    project_id = bundle.get("project_id")
    derived_chain_scope = (
        f"project:{project_id}" if isinstance(project_id, str) and project_id else None
    )
    for record_index, record in enumerate(records):
        if not isinstance(record, dict):
            return None, _walk_structure_fail(
                f"records[{record_index}] must be an object",
            )
        entry = dict(record)
        entry["chain_format_version"] = str(record.get("chain_format_version") or "v1")
        entry["created_at"] = record.get("occurred_at") or record.get("created_at")
        if "payload_json" not in entry and isinstance(record.get("payload"), dict):
            entry["payload_json"] = record["payload"]
        if not entry.get("chain_scope") and derived_chain_scope is not None:
            entry["chain_scope"] = derived_chain_scope
        chain_entries.append(entry)

    return {
        "bundle_type": "audit_export_bundle",
        "schema_version": 2,
        "include_chain_entries": True,
        "chain_entries": chain_entries,
        "records": [],
    }, None


def _walk_export_events(
    export_data: bytes,
    semantics_dispatch: SemanticsDispatch | None = None,
) -> int:
    if semantics_dispatch is None:
        semantics_dispatch = _legacy_dispatch()
    record_hashers = semantics_dispatch.record_hashers
    try:
        bundle = _load_export_json_document(export_data)
    except Exception as exc:
        return _walk_structure_fail(f"export is not JSON: {exc}")

    if not isinstance(bundle, dict):
        return _walk_structure_fail("bundle must be a JSON object")
    if bundle.get("schema") == "keel.governance_events/v1":
        bundle, conversion_result = _governance_events_export_as_walk_bundle(bundle)
        if conversion_result is not None:
            return conversion_result
        if bundle is None:
            return _walk_structure_fail("could not load governance events export")
    elif bundle.get("bundle_type") != "audit_export_bundle":
        return _walk_structure_fail(
            "bundle_type must be 'audit_export_bundle'",
        )

    schema_version = bundle.get("schema_version")
    if schema_version not in {1, 2}:
        return _walk_structure_fail(
            "schema_version must be 1 or 2",
        )
    if schema_version == 1:
        print(
            "WALK-EVENTS: bundle has no chain entries (schema_version=1, "
            "request with ?include_chain_entries=true to enable walk)"
        )
        return 0
    if bundle.get("include_chain_entries") is not True:
        return _walk_structure_fail(
            "schema_version=2 requires include_chain_entries=true",
        )

    by_scope: dict[Any, list[dict[str, Any]]] = {}
    entries_walked = 0

    bundle_chain_entries = bundle.get("chain_entries")
    if bundle_chain_entries is not None:
        if not isinstance(bundle_chain_entries, list):
            return _walk_structure_fail("chain_entries must be a list")
        bundle_entries_by_scope: dict[Any, list[dict[str, Any]]] = {}
        for entry_index, entry in enumerate(bundle_chain_entries):
            if not isinstance(entry, dict):
                return _walk_structure_fail(
                    f"chain_entries[{entry_index}] must be an object",
                )
            version = entry.get("chain_format_version")
            if version not in record_hashers:
                return _walk_fail(
                    WALK_UNKNOWN_CHAIN_FORMAT,
                    (
                        f"event_id={_entry_id(entry)} "
                        f"chain_format_version={version!r}"
                    ),
                )
            try:
                _optional_sequence_number(entry)
            except (TypeError, ValueError) as exc:
                return _walk_fail(
                    WALK_SEQUENCE_INVERSION,
                    f"event_id={_entry_id(entry)} {exc}",
                )
            chain_scope = entry.get("chain_scope")
            by_scope.setdefault(chain_scope, []).append(entry)
            bundle_entries_by_scope.setdefault(chain_scope, []).append(entry)
            entries_walked += 1
        for chain_scope, scope_entries in bundle_entries_by_scope.items():
            sequence_failure = _walk_array_order_fail(chain_scope, scope_entries)
            if sequence_failure is not None:
                return sequence_failure
    else:
        records = bundle.get("records")
        if not isinstance(records, list):
            return _walk_structure_fail("records must be a list")

        for record_index, record in enumerate(records):
            if not isinstance(record, dict):
                return _walk_structure_fail(
                    f"records[{record_index}] must be an object",
                )
            chain_entries = record.get("chain_entries")
            if chain_entries is None:
                return _walk_structure_fail(
                    f"records[{record_index}].chain_entries missing",
                )
            if not isinstance(chain_entries, list):
                return _walk_structure_fail(
                    f"records[{record_index}].chain_entries must be a list",
                )
            record_entries_by_scope: dict[Any, list[dict[str, Any]]] = {}
            for entry_index, entry in enumerate(chain_entries):
                if not isinstance(entry, dict):
                    return _walk_structure_fail(
                        f"records[{record_index}].chain_entries[{entry_index}] "
                        "must be an object",
                    )
                version = entry.get("chain_format_version")
                if version not in record_hashers:
                    return _walk_fail(
                        WALK_UNKNOWN_CHAIN_FORMAT,
                        (
                            f"event_id={_entry_id(entry)} "
                            f"chain_format_version={version!r}"
                        ),
                    )
                try:
                    _optional_sequence_number(entry)
                except (TypeError, ValueError) as exc:
                    return _walk_fail(
                        WALK_SEQUENCE_INVERSION,
                        f"event_id={_entry_id(entry)} {exc}",
                    )
                chain_scope = entry.get("chain_scope")
                by_scope.setdefault(chain_scope, []).append(entry)
                record_entries_by_scope.setdefault(chain_scope, []).append(entry)
                entries_walked += 1
            for chain_scope, scope_entries in record_entries_by_scope.items():
                sequence_failure = _walk_array_order_fail(chain_scope, scope_entries)
                if sequence_failure is not None:
                    return sequence_failure

    record_hash_checks = 0
    prev_hash_checks = 0
    sequence_checks = 0
    for chain_scope, entries in sorted(
        by_scope.items(),
        key=lambda item: _scope_label(item[0]),
    ):
        sequence_failure = _walk_duplicate_sequence_fail(chain_scope, entries)
        if sequence_failure is not None:
            return sequence_failure
        entries.sort(key=_sequence_sort_key)
        first = entries[0]
        print(
            "WALK-EVENTS: "
            f"chain_scope={_scope_label(chain_scope)} "
            f"first sequence_number={first['sequence_number']}, "
            "prev_hash unverifiable from this bundle "
            "(continuity prior to window requires server-side "
            "verify_chain_integrity)"
        )

        previous: dict[str, Any] | None = None
        for entry in entries:
            event_id = _entry_id(entry)
            try:
                sequence_number = _required_int(entry, "sequence_number")
                record_hash = _required_str(entry, "record_hash")
                prev_hash = _required_str(entry, "prev_hash")
                hasher = record_hashers[entry["chain_format_version"]]
                expected_hash = hasher(
                    event_id=_required_str(entry, "event_id"),
                    event_type=_required_str(entry, "event_type"),
                    resource_type=_optional_str(entry, "resource_type"),
                    resource_id=_optional_str(entry, "resource_id"),
                    outcome=_optional_str(entry, "outcome"),
                    severity=_required_str(entry, "severity"),
                    created_at=entry.get("created_at"),
                    prev_hash=prev_hash,
                    sequence_number=sequence_number,
                )
            except (TypeError, ValueError) as exc:
                return _walk_fail(
                    WALK_RECORD_HASH_MISMATCH,
                    f"event_id={event_id} could not recompute hash: {exc}",
                )

            record_hash_checks += 1
            if record_hash != expected_hash:
                return _walk_fail(
                    WALK_RECORD_HASH_MISMATCH,
                    (
                        f"event_id={event_id} "
                        f"expected={expected_hash} actual={record_hash}"
                    ),
                )

            if previous is not None:
                prev_hash_checks += 1
                expected_prev = _required_str(previous, "record_hash")
                if prev_hash != expected_prev:
                    return _walk_fail(
                        WALK_PREV_HASH_DISCONTINUITY,
                        (
                            f"chain_scope={_scope_label(chain_scope)} "
                            f"event_id={event_id} "
                            f"sequence_number={sequence_number} "
                            f"expected_prev={expected_prev} actual_prev={prev_hash}"
                        ),
                    )

                sequence_checks += 1
                previous_sequence = _required_int(previous, "sequence_number")
                if sequence_number <= previous_sequence:
                    return _walk_fail(
                        WALK_SEQUENCE_INVERSION,
                        (
                            f"chain_scope={_scope_label(chain_scope)} "
                            f"event_id={event_id} "
                            f"previous_sequence_number={previous_sequence} "
                            f"sequence_number={sequence_number}"
                        ),
                    )

            previous = entry

    print("WALK-EVENTS: VERIFIED")
    print(f"  chain_scopes:        {len(by_scope)}")
    print(f"  entries_walked:      {entries_walked}")
    print(f"  record_hash_checks:  {record_hash_checks} PASS")
    print(
        f"  prev_hash_checks:    {prev_hash_checks} PASS "
        "(excludes window-edge entries)"
    )
    print(f"  sequence_checks:     {sequence_checks} PASS")
    return 0


def _closure_signature_value(payload: dict[str, Any]) -> str | None:
    value = payload.get("closure_signature_b64")
    if isinstance(value, str) and value.strip():
        return value.strip()
    value = payload.get("binding_signature")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _closure_canonical_hash_value(payload: dict[str, Any]) -> str | None:
    value = payload.get("closure_canonical_hash")
    if isinstance(value, str) and value.strip():
        return value.strip()
    value = payload.get("binding_canonical_hash")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _closure_v1_signed_payload(payload: dict[str, Any]) -> dict[str, Any]:
    missing = [key for key in _SIGNED_CLOSURE_V1_REQUIRED_KEYS if key not in payload]
    if missing:
        raise ValueError(f"closure payload missing signed field(s): {', '.join(missing)}")
    signed = {key: payload.get(key) for key in _SIGNED_CLOSURE_V1_REQUIRED_KEYS}
    for key in _SIGNED_CLOSURE_V1_OPTIONAL_KEYS:
        if key in payload:
            signed[key] = payload.get(key)
    return signed


def _closure_v2_signed_payload(payload: dict[str, Any]) -> dict[str, Any]:
    missing = [key for key in _SIGNED_CLOSURE_V2_REQUIRED_KEYS if key not in payload]
    if missing:
        raise ValueError(f"closure payload missing signed field(s): {', '.join(missing)}")
    signed = {key: payload.get(key) for key in _SIGNED_CLOSURE_V2_REQUIRED_KEYS}
    for key in _SIGNED_CLOSURE_V2_OPTIONAL_KEYS:
        if key in payload:
            signed[key] = payload.get(key)
    return signed


def _verify_closure_v1_signature(
    *,
    payload: dict[str, Any],
    args: argparse.Namespace,
) -> tuple[bool, str]:
    try:
        signed_payload = _closure_v1_signed_payload(payload)
    except ValueError as exc:
        return False, str(exc)

    canonical_hash = _closure_canonical_hash_value(payload)
    signature = _closure_signature_value(payload)
    permit_id = signed_payload.get("permit_id")
    if not isinstance(canonical_hash, str) or not canonical_hash:
        return False, f"permit_id={permit_id} closure_canonical_hash missing"
    if not isinstance(signature, str) or not signature:
        return False, f"permit_id={permit_id} closure_signature_b64 missing"

    recomputed = _compute_canonical_binding_hash(signed_payload)
    if recomputed != canonical_hash:
        return (
            False,
            (
                f"permit_id={permit_id} canonical_hash mismatch "
                f"expected={recomputed} actual={canonical_hash}"
            ),
        )

    closure_signed_at = _parse_iso_or_none(signed_payload.get("closure_signed_at"))
    trusted_pub, trust_source, err = _resolve_trust_key(
        artifact_pub=None,
        artifact_key_id=None,
        purpose=PERMIT_BINDING_SIGNING_PURPOSE,
        expected_public_key=None,
        public_key_url=None,
        key_manifest_source=_key_manifest_source_for_args(args),
        signing_time=closure_signed_at,
    )
    if err is not None or trusted_pub is None:
        return False, f"permit_id={permit_id} {err}"

    binding_key_id = signed_payload.get("binding_key_id")
    if isinstance(binding_key_id, str) and binding_key_id:
        try:
            actual_key_id = _binding_key_id_from_public_key(trusted_pub)
        except Exception as exc:
            return False, f"permit_id={permit_id} invalid trusted public key: {exc}"
        if actual_key_id != binding_key_id:
            return (
                False,
                (
                    f"permit_id={permit_id} binding_key_id mismatch "
                    f"expected={binding_key_id} actual={actual_key_id}"
                ),
            )

    if not _verify_ed25519(trusted_pub, canonical_hash.encode("utf-8"), signature):
        return (
            False,
            f"permit_id={permit_id} Ed25519 signature invalid ({trust_source})",
        )
    return True, trust_source


def _verify_closure_v2_signature(
    *,
    payload: dict[str, Any],
    args: argparse.Namespace,
) -> tuple[bool, str]:
    try:
        signed_payload = _closure_v2_signed_payload(payload)
    except ValueError as exc:
        return False, str(exc)

    canonical_hash = _closure_canonical_hash_value(payload)
    signature = _closure_signature_value(payload)
    permit_id = signed_payload.get("permit_id")
    if not isinstance(canonical_hash, str) or not canonical_hash:
        return False, f"permit_id={permit_id} closure_canonical_hash missing"
    if not isinstance(signature, str) or not signature:
        return False, f"permit_id={permit_id} closure_signature_b64 missing"

    recomputed = _compute_canonical_binding_hash(signed_payload)
    if recomputed != canonical_hash:
        return (
            False,
            (
                f"permit_id={permit_id} canonical_hash mismatch "
                f"expected={recomputed} actual={canonical_hash}"
            ),
        )

    closure_signed_at = _parse_iso_or_none(signed_payload.get("closure_signed_at"))
    trusted_pub, trust_source, err = _resolve_trust_key(
        artifact_pub=None,
        artifact_key_id=None,
        purpose=PERMIT_BINDING_SIGNING_PURPOSE,
        expected_public_key=None,
        public_key_url=None,
        key_manifest_source=_key_manifest_source_for_args(args),
        signing_time=closure_signed_at,
    )
    if err is not None or trusted_pub is None:
        return False, f"permit_id={permit_id} {err}"

    binding_key_id = signed_payload.get("binding_key_id")
    if isinstance(binding_key_id, str) and binding_key_id:
        try:
            actual_key_id = _binding_key_id_from_public_key(trusted_pub)
        except Exception as exc:
            return False, f"permit_id={permit_id} invalid trusted public key: {exc}"
        if actual_key_id != binding_key_id:
            return (
                False,
                (
                    f"permit_id={permit_id} binding_key_id mismatch "
                    f"expected={binding_key_id} actual={actual_key_id}"
                ),
            )

    if not _verify_ed25519(trusted_pub, canonical_hash.encode("utf-8"), signature):
        return (
            False,
            f"permit_id={permit_id} Ed25519 signature invalid ({trust_source})",
        )
    return True, trust_source


def _permit_claim(
    name: str,
    *,
    subject_type: str,
    subject_id: str | None,
    verdict: str,
    reason_code: str | None,
    message: str,
    evidence: list[str] | None = None,
    epistemic_state: dict[str, str] | None = None,
) -> ClaimVerdict:
    claim = _single_subject_claim(
        name,
        subject_type=subject_type,
        subject_id=subject_id,
        verdict=verdict,
        reason_code=reason_code,
        message=message,
        evidence=evidence or ["export"],
    )
    if epistemic_state is None:
        return claim
    return replace(claim, epistemic_state=epistemic_state)


def _authority_rfc8785_bytes(value: Any) -> bytes:
    encoded = rfc8785.dumps(value)
    return encoded if isinstance(encoded, bytes) else encoded.encode("utf-8")


def _authority_sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _authority_claim(
    claim_name: str,
    *,
    input_doc: dict[str, Any],
    verdict: str,
    reason_code: str | None,
    message: str,
    evidence: list[str] | None = None,
    epistemic_state: dict[str, str] | None = None,
) -> ClaimVerdict:
    permit = input_doc.get("permit") if isinstance(input_doc.get("permit"), dict) else {}
    permit_id = _string_field(permit.get("permit_id"), permit.get("id"))
    return _permit_claim(
        claim_name,
        subject_type=(
            "authority_chain"
            if claim_name == PERMIT_AUTHORITY_CHAIN_CLAIM_NAME
            else "authority_revocation_temporal"
        ),
        subject_id=permit_id,
        verdict=verdict,
        reason_code=reason_code,
        message=message,
        evidence=evidence or ["permit", "authority_chain", "authority_edges", "trust_root"],
        epistemic_state=epistemic_state,
    )


def _authority_chain_claim(
    *,
    input_doc: dict[str, Any],
    verdict: str,
    reason_code: str | None,
    message: str,
    evidence: list[str] | None = None,
) -> ClaimVerdict:
    return _authority_claim(
        PERMIT_AUTHORITY_CHAIN_CLAIM_NAME,
        input_doc=input_doc,
        verdict=verdict,
        reason_code=reason_code,
        message=message,
        evidence=evidence,
        epistemic_state={"authority_chain": "verified" if verdict == "supported" else "observed"},
    )


def _authority_revocation_temporal_claim(
    *,
    input_doc: dict[str, Any],
    verdict: str,
    reason_code: str | None,
    message: str,
    evidence: list[str] | None = None,
) -> ClaimVerdict:
    return _authority_claim(
        AUTHORITY_REVOCATION_TEMPORAL_CLAIM_NAME,
        input_doc=input_doc,
        verdict=verdict,
        reason_code=reason_code,
        message=message,
        evidence=evidence,
        epistemic_state={
            "authority_revocation_temporal": "verified"
            if verdict == "supported"
            else "observed"
        },
    )


def _authority_code_verdict(code: str, *, revocation_temporal: bool = False) -> str:
    table = (
        AUTHORITY_REVOCATION_TEMPORAL_CODE_VERDICTS
        if revocation_temporal
        else AUTHORITY_CHAIN_CODE_VERDICTS
    )
    return table[code]


def _authority_key_records(
    *,
    trust_root: dict[str, Any] | None,
    key_manifest_source: str | None,
) -> dict[str, dict[str, Any]]:
    if trust_root is not None and isinstance(trust_root.get("keys"), list):
        entries = [entry for entry in trust_root["keys"] if isinstance(entry, dict)]
    elif key_manifest_source is not None:
        try:
            entries = _load_key_manifest(key_manifest_source)
        except Exception:
            entries = []
    else:
        entries = []
    records: dict[str, dict[str, Any]] = {}
    for entry in entries:
        key_id = entry.get("key_id")
        if isinstance(key_id, str) and key_id:
            records[key_id] = entry
    return records


def _authority_public_key(record: dict[str, Any]) -> str | None:
    for key in ("public_key_bytes", "public_key"):
        value = record.get(key)
        if isinstance(value, str) and value.startswith("ed25519:"):
            return value
    return None


def _authority_edge_payload_bytes(edge: dict[str, Any]) -> bytes:
    return _authority_rfc8785_bytes(edge["payload"])


def _authority_chain_payload_for_edges(edges: list[dict[str, Any]]) -> dict[str, Any]:
    payloads = [edge["payload"] for edge in edges]
    return {
        "chain_version": AUTHORITY_CHAIN_VERSION,
        "org_id": payloads[0]["org_id"],
        "project_id": payloads[0]["project_id"],
        "edge_digests": [edge["edge_digest"] for edge in edges],
        "leaf_principal_id": payloads[-1]["delegate"]["principal_id"],
        "effective_not_before": max(payload["validity"]["not_before"] for payload in payloads),
        "effective_not_after": min(payload["validity"]["not_after"] for payload in payloads),
        "policy_version": payloads[-1]["policy_version"],
    }


def _authority_set_subset(child: Any, parent: Any) -> bool:
    return isinstance(child, list) and isinstance(parent, list) and set(child).issubset(set(parent))


def _authority_resource_subset(child: Any, parent: Any) -> bool:
    if not isinstance(child, dict) or not isinstance(parent, dict):
        return False
    for key, child_value in child.items():
        if not isinstance(child_value, str) or key not in parent:
            return False
        parent_value = parent[key]
        if not isinstance(parent_value, str):
            return False
        if parent_value.endswith("*"):
            if not child_value.startswith(parent_value[:-1]):
                return False
        elif child_value != parent_value:
            return False
    return True


def _authority_constraints_subset(child: Any, parent: Any) -> bool:
    if not isinstance(child, dict) or not isinstance(parent, dict):
        return False
    if any(key not in AUTHORITY_CHAIN_CONSTRAINT_KEYS for key in child):
        return False
    if any(key not in AUTHORITY_CHAIN_CONSTRAINT_KEYS for key in parent):
        return False
    if parent.get("requires_human_approval") is True and child.get("requires_human_approval") is not True:
        return False
    if (
        "max_recipients" in child
        and "max_recipients" in parent
        and child["max_recipients"] > parent["max_recipients"]
    ):
        return False
    if (
        "max_item_amount_usd_micros" in child
        and "max_item_amount_usd_micros" in parent
        and child["max_item_amount_usd_micros"] > parent["max_item_amount_usd_micros"]
    ):
        return False
    if (
        "allow_domains" in child
        and "allow_domains" in parent
        and not set(child["allow_domains"]).issubset(set(parent["allow_domains"]))
    ):
        return False
    if (
        "deny_external_domains" in child
        and "deny_external_domains" in parent
        and not set(child["deny_external_domains"]).issuperset(set(parent["deny_external_domains"]))
    ):
        return False
    if "allowed_hours" in child and "allowed_hours" in parent:
        child_hours = child["allowed_hours"]
        parent_hours = parent["allowed_hours"]
        if not isinstance(child_hours, dict) or not isinstance(parent_hours, dict):
            return False
        if (
            child_hours.get("tz") != parent_hours.get("tz")
            or child_hours.get("start") < parent_hours.get("start")
            or child_hours.get("end") > parent_hours.get("end")
        ):
            return False
    if parent.get("purpose") is not None and child.get("purpose") != parent.get("purpose"):
        return False
    return True


def _authority_chain_edges_in_order(
    input_doc: dict[str, Any],
    records: dict[str, dict[str, Any]],
) -> list[dict[str, Any]] | None:
    chain = input_doc.get("authority_chain")
    if not isinstance(chain, dict) or not isinstance(chain.get("payload"), dict):
        return None
    edge_digests = chain["payload"].get("edge_digests")
    if not isinstance(edge_digests, list):
        return None
    supplied_edges = input_doc.get("authority_edges")
    if not isinstance(supplied_edges, list):
        return None
    edge_by_digest = {
        edge.get("edge_digest"): edge
        for edge in supplied_edges
        if isinstance(edge, dict) and isinstance(edge.get("edge_digest"), str)
    }
    ordered: list[dict[str, Any]] = []
    for digest in edge_digests:
        if not isinstance(digest, str):
            return None
        edge = edge_by_digest.get(digest)
        if edge is None or not isinstance(edge.get("payload"), dict):
            return None
        signing_key = edge["payload"].get("signing_key")
        key_id = signing_key.get("key_id") if isinstance(signing_key, dict) else None
        if not isinstance(key_id, str) or key_id not in records:
            return None
        ordered.append(edge)
    return ordered


def _authority_signing_key_validity_code(
    payload: dict[str, Any],
    record: dict[str, Any],
) -> str | None:
    signed_at = _parse_iso_or_none(payload.get("signed_at"))
    valid_from = _parse_iso_or_none(record.get("valid_from") or record.get("active_from"))
    valid_until = _parse_iso_or_none(
        record.get("valid_until") if "valid_until" in record else record.get("valid_to")
    )
    if signed_at is None or valid_from is None:
        return "authority_chain.signing_key_not_valid_at_signed_at"
    if signed_at < valid_from:
        return "authority_chain.signing_key_not_valid_at_signed_at"
    if valid_until is not None and signed_at >= valid_until:
        return "authority_chain.signing_key_not_valid_at_signed_at"
    signing_key = payload.get("signing_key")
    custody_tier = signing_key.get("custody_tier") if isinstance(signing_key, dict) else None
    if custody_tier != record.get("custody_tier"):
        return "authority_chain.signing_key_not_valid_at_signed_at"
    return None


def _authority_revocation_temporal_code(
    payload: dict[str, Any],
    record: dict[str, Any],
) -> str | None:
    signed_at = _parse_iso_or_none(payload.get("signed_at"))
    if signed_at is None:
        return None
    revoked_at = _parse_iso_or_none(record.get("revoked_at"))
    if revoked_at is not None and signed_at >= revoked_at:
        return "authority_revocation.signed_at_at_or_after_revoked_at"
    compromised_at = _parse_iso_or_none(record.get("compromised_at"))
    if compromised_at is not None and signed_at >= compromised_at:
        return "authority_revocation.compromised_key_retroactive_taint"
    return None


def _authority_subject_type(permit: dict[str, Any]) -> str | None:
    value = permit.get("subject_type")
    return value.strip().lower() if isinstance(value, str) and value.strip() else None


def _authority_digest(permit: dict[str, Any]) -> str | None:
    value = permit.get("authority_chain_digest")
    return value if isinstance(value, str) and _SHA256_HEX_RE.fullmatch(value) else None


def _adjudicate_permit_authority_chain_v1(
    *,
    export_document: dict[str, Any],
    key_manifest_source: str | None = None,
    trust_root: dict[str, Any] | None = None,
) -> ClaimVerdict:
    input_doc = export_document
    permit = input_doc.get("permit")
    if not isinstance(permit, dict):
        return _authority_chain_claim(
            input_doc=input_doc,
            verdict="insufficient_evidence",
            reason_code="authority_chain.evidence_incomplete",
            message="permit authority-chain evidence is missing",
            evidence=["permit"],
        )

    binding_version = _permit_v2_envelope_version(permit)
    chain_digest = _authority_digest(permit)
    if binding_version != "v7":
        return _authority_chain_claim(
            input_doc=input_doc,
            verdict=_authority_code_verdict("authority_chain.typed_absence"),
            reason_code="authority_chain.typed_absence",
            message="binding version does not carry v7 authority-chain subject fields",
            evidence=["permit.binding_version"],
        )
    if chain_digest is None:
        if _authority_subject_type(permit) == AUTHORITY_CHAIN_AGENT_SUBJECT_TYPE:
            return _authority_chain_claim(
                input_doc=input_doc,
                verdict=_authority_code_verdict("authority_chain.agent_without_chain"),
                reason_code="authority_chain.agent_without_chain",
                message="v7 agent permit carries no authority-chain evidence",
                evidence=["permit.subject_type", "permit.authority_chain_digest"],
            )
        return _authority_chain_claim(
            input_doc=input_doc,
            verdict=_authority_code_verdict("authority_chain.typed_absence"),
            reason_code="authority_chain.typed_absence",
            message="non-agent v7 permit claims no delegation chain",
            evidence=["permit.subject_type", "permit.authority_chain_digest"],
        )

    records = _authority_key_records(
        trust_root=trust_root,
        key_manifest_source=key_manifest_source,
    )
    chain = input_doc.get("authority_chain")
    edges = _authority_chain_edges_in_order(input_doc, records)
    if not isinstance(chain, dict) or edges is None:
        return _authority_chain_claim(
            input_doc=input_doc,
            verdict=_authority_code_verdict("authority_chain.evidence_incomplete"),
            reason_code="authority_chain.evidence_incomplete",
            message="authority chain, edge, or signing-key evidence is incomplete",
            evidence=["authority_chain", "authority_edges", "trust_root"],
        )

    for edge in edges:
        payload = edge["payload"]
        payload_bytes = _authority_edge_payload_bytes(edge)
        if _authority_sha256_hex(payload_bytes) != edge.get("edge_digest"):
            return _authority_chain_claim(
                input_doc=input_doc,
                verdict=_authority_code_verdict("authority_chain.edge_digest_mismatch"),
                reason_code="authority_chain.edge_digest_mismatch",
                message="edge digest does not match RFC 8785 payload bytes",
                evidence=["authority_edges.edge_digest", "authority_edges.payload"],
            )
        signing_key = payload["signing_key"]
        record = records[signing_key["key_id"]]
        if record.get("signer_id") != payload.get("delegator", {}).get("principal_id"):
            return _authority_chain_claim(
                input_doc=input_doc,
                verdict=_authority_code_verdict("authority_chain.edge_signature_invalid"),
                reason_code="authority_chain.edge_signature_invalid",
                message="edge signing key is not bound to the delegator principal",
                evidence=["authority_edges.payload.delegator", "trust_root.keys"],
            )
        public_key = _authority_public_key(record)
        if public_key is None or not _verify_ed25519(public_key, payload_bytes, str(edge.get("signature"))):
            return _authority_chain_claim(
                input_doc=input_doc,
                verdict=_authority_code_verdict("authority_chain.edge_signature_invalid"),
                reason_code="authority_chain.edge_signature_invalid",
                message="edge signature does not verify over RFC 8785 payload bytes",
                evidence=["authority_edges.signature", "trust_root.keys"],
            )
        validity_code = _authority_signing_key_validity_code(payload, record)
        if validity_code is not None:
            return _authority_chain_claim(
                input_doc=input_doc,
                verdict=_authority_code_verdict(validity_code),
                reason_code=validity_code,
                message="edge signing key was not valid at signed_at",
                evidence=["authority_edges.payload.signed_at", "trust_root.keys"],
            )
        constraints = payload.get("scope", {}).get("constraints")
        if not isinstance(constraints, dict) or any(
            key not in AUTHORITY_CHAIN_CONSTRAINT_KEYS for key in constraints
        ):
            return _authority_chain_claim(
                input_doc=input_doc,
                verdict=_authority_code_verdict("authority_chain.unknown_constraint_key"),
                reason_code="authority_chain.unknown_constraint_key",
                message="edge scope contains a constraint key outside the v1 vocabulary",
                evidence=["authority_edges.payload.scope.constraints"],
            )

    chain_payload = chain.get("payload")
    if not isinstance(chain_payload, dict):
        return _authority_chain_claim(
            input_doc=input_doc,
            verdict=_authority_code_verdict("authority_chain.evidence_incomplete"),
            reason_code="authority_chain.evidence_incomplete",
            message="authority_chain.payload is missing",
            evidence=["authority_chain.payload"],
        )
    if _authority_sha256_hex(_authority_rfc8785_bytes(chain_payload)) != chain_digest:
        return _authority_chain_claim(
            input_doc=input_doc,
            verdict=_authority_code_verdict("authority_chain.chain_digest_mismatch"),
            reason_code="authority_chain.chain_digest_mismatch",
            message="authority_chain_digest does not match chain payload bytes",
            evidence=["permit.authority_chain_digest", "authority_chain.payload"],
        )
    if chain_payload != _authority_chain_payload_for_edges(edges):
        return _authority_chain_claim(
            input_doc=input_doc,
            verdict=_authority_code_verdict("authority_chain.chain_digest_mismatch"),
            reason_code="authority_chain.chain_digest_mismatch",
            message="authority_chain.payload does not match the ordered edge payloads",
            evidence=["authority_chain.payload", "authority_edges"],
        )

    if chain_payload.get("leaf_principal_id") != permit.get("subject_id"):
        return _authority_chain_claim(
            input_doc=input_doc,
            verdict=_authority_code_verdict("authority_chain.leaf_subject_mismatch"),
            reason_code="authority_chain.leaf_subject_mismatch",
            message="authority-chain leaf principal does not match permit subject_id",
            evidence=["authority_chain.payload.leaf_principal_id", "permit.subject_id"],
        )

    root_payload = edges[0]["payload"]
    if root_payload.get("parent_edge_digest") is not None or root_payload.get("delegator", {}).get(
        "principal_type"
    ) not in {"user", "service_principal"}:
        return _authority_chain_claim(
            input_doc=input_doc,
            verdict=_authority_code_verdict("authority_chain.root_anchor_invalid"),
            reason_code="authority_chain.root_anchor_invalid",
            message="root edge is not anchored by a user or service-principal delegator",
            evidence=["authority_edges[0].payload.delegator", "authority_edges[0].payload.parent_edge_digest"],
        )

    seen_principals = {root_payload["delegator"]["principal_id"]}
    for index, edge in enumerate(edges):
        payload = edge["payload"]
        if index > 0:
            previous_edge = edges[index - 1]
            previous = previous_edge["payload"]
            if payload.get("delegator") != previous.get("delegate"):
                return _authority_chain_claim(
                    input_doc=input_doc,
                    verdict=_authority_code_verdict("authority_chain.parent_edge_digest_broken"),
                    reason_code="authority_chain.parent_edge_digest_broken",
                    message="edge delegator does not equal the previous edge delegate",
                    evidence=["authority_edges.payload.delegator"],
                )
            if payload.get("parent_edge_digest") != previous_edge.get("edge_digest"):
                return _authority_chain_claim(
                    input_doc=input_doc,
                    verdict=_authority_code_verdict("authority_chain.parent_edge_digest_broken"),
                    reason_code="authority_chain.parent_edge_digest_broken",
                    message="edge parent_edge_digest does not equal the previous edge digest",
                    evidence=["authority_edges.payload.parent_edge_digest"],
                )
        delegate_id = payload.get("delegate", {}).get("principal_id")
        if delegate_id in seen_principals:
            return _authority_chain_claim(
                input_doc=input_doc,
                verdict=_authority_code_verdict("authority_chain.cycle_detected"),
                reason_code="authority_chain.cycle_detected",
                message="authority chain delegates back to an upstream principal",
                evidence=["authority_edges.payload.delegate"],
            )
        seen_principals.add(delegate_id)
        if index == 0:
            continue

        previous = edges[index - 1]["payload"]
        parent_scope = previous["scope"]
        child_scope = payload["scope"]
        if not _authority_set_subset(child_scope.get("action_verbs"), parent_scope.get("action_verbs")):
            return _authority_chain_claim(
                input_doc=input_doc,
                verdict=_authority_code_verdict("authority_chain.broadened_verbs"),
                reason_code="authority_chain.broadened_verbs",
                message="child edge broadens action verbs beyond the parent",
                evidence=["authority_edges.payload.scope.action_verbs"],
            )
        if not _authority_set_subset(child_scope.get("action_classes"), parent_scope.get("action_classes")):
            return _authority_chain_claim(
                input_doc=input_doc,
                verdict=_authority_code_verdict("authority_chain.broadened_classes"),
                reason_code="authority_chain.broadened_classes",
                message="child edge broadens action classes beyond the parent",
                evidence=["authority_edges.payload.scope.action_classes"],
            )
        if not _authority_resource_subset(child_scope.get("resources"), parent_scope.get("resources")):
            return _authority_chain_claim(
                input_doc=input_doc,
                verdict=_authority_code_verdict("authority_chain.broadened_resources"),
                reason_code="authority_chain.broadened_resources",
                message="child edge broadens resources beyond the parent",
                evidence=["authority_edges.payload.scope.resources"],
            )
        if not _authority_set_subset(child_scope.get("data_classes"), parent_scope.get("data_classes")):
            return _authority_chain_claim(
                input_doc=input_doc,
                verdict=_authority_code_verdict("authority_chain.broadened_data_classes"),
                reason_code="authority_chain.broadened_data_classes",
                message="child edge broadens data classes beyond the parent",
                evidence=["authority_edges.payload.scope.data_classes"],
            )
        if not _authority_constraints_subset(child_scope.get("constraints"), parent_scope.get("constraints")):
            return _authority_chain_claim(
                input_doc=input_doc,
                verdict=_authority_code_verdict("authority_chain.constraint_not_stricter"),
                reason_code="authority_chain.constraint_not_stricter",
                message="child edge constraints are not stricter than the parent",
                evidence=["authority_edges.payload.scope.constraints"],
            )

        parent_budget = previous.get("budget_partition")
        child_budget = payload.get("budget_partition")
        if isinstance(parent_budget, dict) and isinstance(child_budget, dict):
            if child_budget.get("parent_budget_envelope_id") != parent_budget.get("budget_envelope_id"):
                return _authority_chain_claim(
                    input_doc=input_doc,
                    verdict=_authority_code_verdict("authority_chain.budget_parent_envelope_mismatch"),
                    reason_code="authority_chain.budget_parent_envelope_mismatch",
                    message="child budget parent envelope does not match parent budget envelope",
                    evidence=["authority_edges.payload.budget_partition"],
                )
        if parent_budget is None and child_budget is not None:
            return _authority_chain_claim(
                input_doc=input_doc,
                verdict=_authority_code_verdict("authority_chain.budget_parent_envelope_mismatch"),
                reason_code="authority_chain.budget_parent_envelope_mismatch",
                message="child carries a budget partition when parent has none",
                evidence=["authority_edges.payload.budget_partition"],
            )
        if isinstance(parent_budget, dict) and isinstance(child_budget, dict):
            if child_budget.get("allocated_usd_micros") > parent_budget.get("allocated_usd_micros"):
                return _authority_chain_claim(
                    input_doc=input_doc,
                    verdict=_authority_code_verdict("authority_chain.budget_exceeds_parent"),
                    reason_code="authority_chain.budget_exceeds_parent",
                    message="child budget allocation exceeds the parent allocation",
                    evidence=["authority_edges.payload.budget_partition.allocated_usd_micros"],
                )

        if payload["creation_policy"]["remaining_depth"] >= previous["creation_policy"]["remaining_depth"]:
            return _authority_chain_claim(
                input_doc=input_doc,
                verdict=_authority_code_verdict("authority_chain.remaining_depth_not_strict"),
                reason_code="authority_chain.remaining_depth_not_strict",
                message="child remaining_depth is not strictly less than parent remaining_depth",
                evidence=["authority_edges.payload.creation_policy.remaining_depth"],
            )
        parent_max = previous["creation_policy"]["max_children"]
        child_max = payload["creation_policy"]["max_children"]
        if parent_max is not None and child_max is not None and child_max > parent_max:
            return _authority_chain_claim(
                input_doc=input_doc,
                verdict=_authority_code_verdict("authority_chain.max_children_exceeds_parent"),
                reason_code="authority_chain.max_children_exceeds_parent",
                message="child max_children exceeds parent max_children",
                evidence=["authority_edges.payload.creation_policy.max_children"],
            )
        if (
            _parse_iso_or_none(payload["validity"]["not_before"])
            < _parse_iso_or_none(previous["validity"]["not_before"])
            or _parse_iso_or_none(payload["validity"]["not_after"])
            > _parse_iso_or_none(previous["validity"]["not_after"])
        ):
            return _authority_chain_claim(
                input_doc=input_doc,
                verdict=_authority_code_verdict("authority_chain.validity_not_subset"),
                reason_code="authority_chain.validity_not_subset",
                message="child validity window is not contained in parent validity window",
                evidence=["authority_edges.payload.validity"],
            )

    resolution_time = _parse_iso_or_none(input_doc.get("resolution_time"))
    effective_not_before = _parse_iso_or_none(chain_payload.get("effective_not_before"))
    effective_not_after = _parse_iso_or_none(chain_payload.get("effective_not_after"))
    if (
        resolution_time is None
        or effective_not_before is None
        or effective_not_after is None
        or resolution_time < effective_not_before
        or resolution_time > effective_not_after
    ):
        return _authority_chain_claim(
            input_doc=input_doc,
            verdict=_authority_code_verdict("authority_chain.expired_at_resolution"),
            reason_code="authority_chain.expired_at_resolution",
            message="resolution time is outside the effective chain validity window",
            evidence=["resolution_time", "authority_chain.payload.effective_not_before", "authority_chain.payload.effective_not_after"],
        )

    requested_action = input_doc.get("requested_action")
    action_class_map = input_doc.get("action_class_map")
    requested_kind = requested_action.get("kind") if isinstance(requested_action, dict) else None
    if not isinstance(action_class_map, dict) or not isinstance(requested_kind, str) or requested_kind not in action_class_map:
        return _authority_chain_claim(
            input_doc=input_doc,
            verdict=_authority_code_verdict("authority_chain.unmapped_action_kind"),
            reason_code="authority_chain.unmapped_action_kind",
            message="requested action kind is absent from the action-class map",
            evidence=["requested_action.kind", "action_class_map"],
        )
    leaf_scope = edges[-1]["payload"]["scope"]
    requested_classes = action_class_map[requested_kind]
    if (
        not _authority_set_subset(requested_classes, leaf_scope.get("action_classes"))
        or requested_kind not in leaf_scope.get("action_verbs", [])
    ):
        return _authority_chain_claim(
            input_doc=input_doc,
            verdict=_authority_code_verdict("authority_chain.action_outside_chain_scope"),
            reason_code="authority_chain.action_outside_chain_scope",
            message="requested action is outside the leaf edge scope",
            evidence=["requested_action", "authority_edges[-1].payload.scope"],
        )

    return _authority_chain_claim(
        input_doc=input_doc,
        verdict="supported",
        reason_code=AUTHORITY_CHAIN_SUPPORTED_CODE,
        message="authority chain structure, signatures, attenuation, liveness, and action scope are supported",
    )


def _adjudicate_authority_revocation_temporal_v1(
    *,
    export_document: dict[str, Any],
    key_manifest_source: str | None = None,
    trust_root: dict[str, Any] | None = None,
) -> ClaimVerdict:
    input_doc = export_document
    records = _authority_key_records(
        trust_root=trust_root,
        key_manifest_source=key_manifest_source,
    )
    edges = _authority_chain_edges_in_order(input_doc, records)
    if edges is None:
        return _authority_revocation_temporal_claim(
            input_doc=input_doc,
            verdict="insufficient_evidence",
            reason_code=None,
            message="authority chain, edge, or signing-key evidence is incomplete",
            evidence=["authority_chain", "authority_edges", "trust_root"],
        )

    for edge in edges:
        payload = edge["payload"]
        record = records[payload["signing_key"]["key_id"]]
        temporal_code = _authority_revocation_temporal_code(payload, record)
        if temporal_code is not None:
            return _authority_revocation_temporal_claim(
                input_doc=input_doc,
                verdict=_authority_code_verdict(temporal_code, revocation_temporal=True),
                reason_code=temporal_code,
                message="edge signed_at is at or after signing-key revocation or compromise",
                evidence=["authority_edges.payload.signed_at", "trust_root.keys"],
            )

    return _authority_revocation_temporal_claim(
        input_doc=input_doc,
        verdict="supported",
        reason_code=AUTHORITY_REVOCATION_TEMPORAL_SUPPORTED_CODE,
        message="authority edge signatures predate signing-key revocation and compromise instants",
    )


def _entry_payload_any(entry: dict[str, Any]) -> dict[str, Any]:
    payload = entry.get("payload_json")
    if isinstance(payload, dict):
        return payload
    payload = entry.get("payload")
    if isinstance(payload, dict):
        return payload
    return {}


def _iter_export_entries(document: dict[str, Any]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    bundle_entries = document.get("chain_entries")
    if isinstance(bundle_entries, list):
        entries.extend(entry for entry in bundle_entries if isinstance(entry, dict))
    records = document.get("records")
    if isinstance(records, list):
        for record in records:
            if not isinstance(record, dict):
                continue
            chain_entries = record.get("chain_entries")
            if isinstance(chain_entries, list):
                entries.extend(
                    entry for entry in chain_entries if isinstance(entry, dict)
                )
            else:
                entries.append(record)
    return entries


def _string_field(*values: Any) -> str | None:
    for value in values:
        if isinstance(value, str) and value:
            return value
    return None


def _is_uuid_text(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        uuid.UUID(value)
    except (TypeError, ValueError):
        return False
    return True


def _actor_id_has_pii_shape(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip()
    if not text:
        return False
    return (
        _EMAIL_RE.fullmatch(text) is not None
        or "@" in text
        or bool(re.search(r"\s", text))
    )


def _raw_ed25519_signature_b64(value: Any) -> bool:
    if not isinstance(value, str) or value.startswith("ed25519:"):
        return False
    try:
        return len(base64.b64decode(value, validate=True)) == 64
    except Exception:
        return False


def _permit_v2_slot_claim(
    spec: PermitV2SlotSpec,
    *,
    permit_id: str | None,
    verdict: str,
    reason_code: str,
    message: str,
    evidence: list[str] | None = None,
    epistemic_state: str | None = None,
) -> ClaimVerdict:
    slot_state = epistemic_state
    if slot_state is None:
        slot_state = "verified" if verdict == "supported" else "observed"
    return _permit_claim(
        spec.claim_name,
        subject_type=spec.subject_type,
        subject_id=permit_id,
        verdict=verdict,
        reason_code=reason_code,
        message=message,
        evidence=evidence or [f"permit.{spec.slot_name}"],
        epistemic_state={spec.slot_name: slot_state},
    )


def _permit_v2_required_envelope_fields(spec: PermitV2SlotSpec) -> set[str]:
    fields = {
        "payload_type",
        "signer_id",
        "key_id",
        "signed_at",
        "signed_payload_hash",
        "signature",
    }
    if spec.extra_field is not None:
        fields.add(spec.extra_field)
    return fields


def _permit_v2_sha256_hex(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text if _SHA256_HEX_RE.fullmatch(text) else None


def _permit_v2_sha256_hexish(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if text.startswith("sha256:"):
        text = text.removeprefix("sha256:")
    return text if _SHA256_HEX_RE.fullmatch(text) else None


def _permit_v2_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _permit_v2_parse_signed_at(value: Any) -> datetime | None:
    if not isinstance(value, str) or _PERMIT_V2_UTC_MICROSECOND_RE.fullmatch(value) is None:
        return None
    return _parse_iso_or_none(value)


def _permit_v2_key_id_from_public_key(public_key: str) -> str:
    raw = base64.b64decode(public_key.removeprefix("ed25519:"))
    return hashlib.sha256(raw).hexdigest()


def _permit_v2_public_key_b64(public_key: str) -> str | None:
    try:
        raw = base64.b64decode(public_key.removeprefix("ed25519:"), validate=True)
        if len(raw) != 32:
            return None
        return base64.b64encode(raw).decode("ascii")
    except Exception:
        return None


def _permit_v2_payload_hash(payload_bytes: bytes) -> str:
    return hashlib.sha256(payload_bytes).hexdigest()


def _permit_v2_envelope_version(permit: dict[str, Any]) -> str | None:
    value = permit.get("binding_version")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _permit_v2_canonical_bytes(
    envelope_version: str | None,
    payload: Mapping[str, Any],
) -> bytes:
    if str(envelope_version or "").strip() in {"v5", "v6"}:
        return rfc8785.dumps(dict(payload))
    return _canonical_json_bytes(dict(payload))


def _permit_v2_permit_id(permit: dict[str, Any]) -> str | None:
    value = _string_field(permit.get("id"), permit.get("permit_id"))
    return value if _is_uuid_text(value) else None


def _permit_v2_account_id(
    *,
    permit: dict[str, Any],
    manifest: dict[str, Any],
) -> str | None:
    fields = ("account_id", "organization_id", "org_id", "tenant_id", "project_id")
    for source in (permit, manifest):
        for field in fields:
            value = source.get(field)
            if _is_uuid_text(value):
                return str(value)
    return None


def _iter_permit_v2_candidates(
    document: dict[str, Any],
) -> list[tuple[dict[str, Any], str]]:
    candidates: list[tuple[dict[str, Any], str]] = []
    if document.get("permit_format_version") == PERMIT_V2_FORMAT_VERSION:
        candidates.append((document, "export"))
    for key in ("permit", "permit_v2", "permit_record"):
        nested = document.get(key)
        if isinstance(nested, dict) and nested.get("permit_format_version") == PERMIT_V2_FORMAT_VERSION:
            candidates.append((nested, f"export.{key}"))
    for entry_index, entry in enumerate(_iter_export_entries(document)):
        if entry.get("permit_format_version") == PERMIT_V2_FORMAT_VERSION:
            candidates.append((entry, f"chain_entries[{entry_index}]"))
        payload = _entry_payload_any(entry)
        if payload.get("permit_format_version") == PERMIT_V2_FORMAT_VERSION:
            candidates.append((payload, f"chain_entries[{entry_index}].payload_json"))
        for key in ("permit", "permit_v2", "permit_record"):
            nested = payload.get(key)
            if isinstance(nested, dict) and nested.get("permit_format_version") == PERMIT_V2_FORMAT_VERSION:
                candidates.append((nested, f"chain_entries[{entry_index}].payload_json.{key}"))
    return candidates


def _find_permit_v2_slot(
    document: dict[str, Any],
    slot_name: str,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, str]:
    fallback = f"permit.{slot_name}"
    for permit, path in _iter_permit_v2_candidates(document):
        slot = permit.get(slot_name)
        if isinstance(slot, dict):
            return permit, slot, f"{path}.{slot_name}"
        fallback = f"{path}.{slot_name}"
    return None, None, fallback


def _permit_v2_auto_required_claims(document: dict[str, Any] | None) -> set[str]:
    if document is None:
        return set()
    claims: set[str] = set()
    for permit, _path in _iter_permit_v2_candidates(document):
        for slot_name, spec in PERMIT_V2_SLOT_SPECS.items():
            if isinstance(permit.get(slot_name), dict):
                claims.add(spec.claim_name)
    return claims


def _permit_v2_slot_schema_error(
    slot: dict[str, Any],
    spec: PermitV2SlotSpec,
) -> tuple[str, str] | None:
    if slot.get("payload_type") != spec.payload_type:
        return (
            "PAYLOAD_TYPE_MISMATCH",
            f"{spec.slot_name}.payload_type must be {spec.payload_type}",
        )
    expected = _permit_v2_required_envelope_fields(spec)
    actual = set(slot.keys())
    missing = sorted(expected - actual)
    if missing:
        return (
            spec.invalid_code,
            f"{spec.slot_name} missing required field(s): " + ", ".join(missing),
        )
    extra = sorted(actual - expected)
    if extra:
        return (
            spec.invalid_code,
            f"{spec.slot_name} has unsupported field(s): " + ", ".join(extra),
        )
    if not _is_uuid_text(slot.get("signer_id")):
        return spec.invalid_code, f"{spec.slot_name}.signer_id must be a UUID string"
    if _permit_v2_sha256_hex(slot.get("key_id")) is None:
        return spec.invalid_code, f"{spec.slot_name}.key_id must be lowercase SHA-256 hex"
    if _permit_v2_parse_signed_at(slot.get("signed_at")) is None:
        return (
            spec.invalid_code,
            f"{spec.slot_name}.signed_at must be UTC ISO 8601 with microsecond precision",
        )
    if _permit_v2_sha256_hex(slot.get("signed_payload_hash")) is None:
        return (
            spec.invalid_code,
            f"{spec.slot_name}.signed_payload_hash must be lowercase SHA-256 hex",
        )
    if not _raw_ed25519_signature_b64(slot.get("signature")):
        return spec.invalid_code, f"{spec.slot_name}.signature must be base64 Ed25519 bytes"
    if spec.extra_field == "execution_intent_hash" and _permit_v2_sha256_hex(
        slot.get("execution_intent_hash")
    ) is None:
        return (
            spec.invalid_code,
            f"{spec.slot_name}.execution_intent_hash must be lowercase SHA-256 hex",
        )
    if spec.extra_field == "batch_id" and not _is_nonempty_str(slot.get("batch_id")):
        return spec.invalid_code, f"{spec.slot_name}.batch_id must be a non-empty string"
    return None


def _explicit_permit_v2_signed_payload(
    *,
    export_document: dict[str, Any],
    permit: dict[str, Any],
    spec: PermitV2SlotSpec,
) -> dict[str, Any] | None:
    for source in (permit, export_document):
        for key in ("permit_v2_signed_payloads", "signature_payloads"):
            payloads = source.get(key)
            if isinstance(payloads, dict):
                payload = payloads.get(spec.slot_name)
                if isinstance(payload, dict):
                    return payload
    return None


def _permit_v2_issuer_signature_hash(permit: dict[str, Any]) -> str | None:
    explicit = _permit_v2_sha256_hex(permit.get("issuer_signature_hash"))
    if explicit is not None:
        return explicit
    signature = permit.get("signature")
    if isinstance(signature, dict):
        return _permit_v2_payload_hash(
            _permit_v2_canonical_bytes(
                _permit_v2_envelope_version(permit),
                signature,
            )
        )
    if isinstance(signature, str) and signature.strip():
        return _permit_v2_payload_hash(signature.strip().encode("utf-8"))
    return None


def _permit_v2_canonical_permit_hash(permit: dict[str, Any]) -> str | None:
    explicit = _permit_v2_sha256_hex(
        permit.get("permit_canonical_hash") or permit.get("canonical_hash")
    )
    if explicit is not None:
        return explicit
    excluded = {
        *PERMIT_V2_SIGNATURE_SLOTS,
        "permit_format_version",
        "issuer_signature_hash",
        "permit_canonical_hash",
        "permit_v2_signed_payloads",
        "signature_payloads",
        "revocation",
        "audit_batch",
        "audit_batches",
        "known_audit_batches",
        "batches",
        "counter_signature_execution_intent",
        "counter_signature_execution_intent_v1",
        "execution_intent",
        "dispatch_facts",
    }
    canonical_payload = {key: value for key, value in permit.items() if key not in excluded}
    if not canonical_payload:
        return None
    return _permit_v2_payload_hash(
        _permit_v2_canonical_bytes(
            _permit_v2_envelope_version(permit),
            canonical_payload,
        )
    )


def _permit_v2_signed_payload(
    *,
    export_document: dict[str, Any],
    permit: dict[str, Any],
    slot: dict[str, Any],
    spec: PermitV2SlotSpec,
) -> tuple[dict[str, Any] | None, str | None, str | None]:
    explicit = _explicit_permit_v2_signed_payload(
        export_document=export_document,
        permit=permit,
        spec=spec,
    )
    if explicit is not None:
        return explicit, None, None

    permit_id = _permit_v2_permit_id(permit)
    issuer_signature_hash = _permit_v2_issuer_signature_hash(permit)
    permit_canonical_hash = _permit_v2_canonical_permit_hash(permit)
    missing = [
        field
        for field, value in (
            ("permit_id", permit_id),
            ("issuer_signature_hash", issuer_signature_hash),
            ("permit_canonical_hash", permit_canonical_hash),
        )
        if value is None
    ]
    if missing:
        return (
            None,
            spec.invalid_code,
            "cannot reconstruct canonical signed payload; missing " + ", ".join(missing),
        )
    payload: dict[str, Any] = {
        "payload_type": spec.payload_type,
        "permit_id": permit_id,
        "issuer_signature_hash": issuer_signature_hash,
        "permit_canonical_hash": permit_canonical_hash,
        spec.signer_payload_field: slot["signer_id"],
        "signed_at": slot["signed_at"],
    }
    if spec.extra_field is not None:
        payload[spec.extra_field] = slot[spec.extra_field]
    return payload, None, None


def _permit_v2_signed_payload_error(
    *,
    payload: dict[str, Any],
    permit: dict[str, Any],
    slot: dict[str, Any],
    spec: PermitV2SlotSpec,
) -> tuple[str, str] | None:
    expected = {
        "payload_type",
        "permit_id",
        "issuer_signature_hash",
        "permit_canonical_hash",
        spec.signer_payload_field,
        "signed_at",
    }
    if spec.extra_field is not None:
        expected.add(spec.extra_field)
    actual = set(payload.keys())
    missing = sorted(expected - actual)
    if missing:
        return spec.invalid_code, "signed payload missing field(s): " + ", ".join(missing)
    extra = sorted(actual - expected)
    if extra:
        return spec.invalid_code, "signed payload has unsupported field(s): " + ", ".join(extra)
    if payload.get("payload_type") != spec.payload_type:
        return (
            "PAYLOAD_TYPE_MISMATCH",
            f"signed payload payload_type must be {spec.payload_type}",
        )
    permit_id = _permit_v2_permit_id(permit)
    if payload.get("permit_id") != permit_id:
        return spec.invalid_code, "signed payload permit_id does not match the permit"
    if _permit_v2_sha256_hex(payload.get("issuer_signature_hash")) is None:
        return spec.invalid_code, "signed payload issuer_signature_hash must be lowercase SHA-256 hex"
    if _permit_v2_sha256_hex(payload.get("permit_canonical_hash")) is None:
        return spec.invalid_code, "signed payload permit_canonical_hash must be lowercase SHA-256 hex"
    if not _is_uuid_text(payload.get(spec.signer_payload_field)):
        return spec.invalid_code, f"signed payload {spec.signer_payload_field} must be a UUID string"
    if payload.get(spec.signer_payload_field) != slot.get("signer_id"):
        return (
            spec.signer_mismatch_code,
            f"{spec.slot_name}.signer_id does not match signed payload {spec.signer_payload_field}",
        )
    if payload.get("signed_at") != slot.get("signed_at"):
        return spec.invalid_code, "signed payload signed_at does not match the envelope"
    if spec.extra_field is not None and payload.get(spec.extra_field) != slot.get(spec.extra_field):
        return (
            spec.extra_mismatch_code or spec.invalid_code,
            f"{spec.slot_name}.{spec.extra_field} does not match signed payload {spec.extra_field}",
        )
    return None


def _permit_v2_window_bounds(permit: dict[str, Any]) -> tuple[datetime | None, datetime | None]:
    valid_from = _parse_iso_or_none(
        permit.get("valid_from") or permit.get("issued_at") or permit.get("created_at")
    )
    valid_until = _parse_iso_or_none(
        permit.get("valid_until")
        or permit.get("valid_to")
        or permit.get("expires_at")
    )
    return valid_from, valid_until


def _permit_v2_slot_window_error(
    *,
    permit: dict[str, Any],
    signing_time: datetime,
    spec: PermitV2SlotSpec,
) -> tuple[str, str] | None:
    valid_from, valid_until = _permit_v2_window_bounds(permit)
    if valid_from is None:
        return spec.invalid_code, "permit valid_from/issued_at/created_at is missing or malformed"
    if spec.slot_name in {PERMIT_OPERATOR_APPROVAL_SLOT, PERMIT_COUNTER_SIGNATURE_SLOT}:
        if valid_until is None:
            return spec.invalid_code, "permit valid_until/expires_at is missing or malformed"
        if signing_time < valid_from or signing_time > valid_until:
            return spec.invalid_code, f"{spec.slot_name}.signed_at is outside the permit validity window"
    elif spec.slot_name == PERMIT_AUDIT_ATTESTATION_SLOT and signing_time < valid_from:
        return spec.invalid_code, "audit_attestation.signed_at is before permit valid_from"
    return None


def _permit_v2_revocation_effective_at(
    *,
    export_document: dict[str, Any],
    permit: dict[str, Any],
) -> datetime | None:
    for source in (permit.get("revocation"), export_document.get("revocation")):
        if isinstance(source, dict):
            effective_at = _parse_iso_or_none(source.get("effective_at"))
            if effective_at is not None:
                return effective_at
    event, _declared_hash, _path = _find_revocation_evidence(export_document)
    if event is None:
        return None
    permit_id = _permit_v2_permit_id(permit)
    if permit_id is not None and event.get("permit_id") != permit_id:
        return None
    return _parse_iso_or_none(event.get("effective_at"))


def _permit_v2_counter_signature_intent_candidates(
    *,
    export_document: dict[str, Any],
    permit: dict[str, Any],
) -> list[tuple[dict[str, Any], str]]:
    candidates: list[tuple[dict[str, Any], str]] = []

    def add(value: Any, path: str) -> None:
        if isinstance(value, dict):
            candidates.append((value, path))

    for source, source_path in (
        (permit, "permit"),
        (export_document, "export"),
    ):
        for key in (
            "counter_signature_execution_intent",
            "counter_signature_execution_intent_v1",
            "execution_intent",
            "dispatch_facts",
            "dispatch",
        ):
            add(source.get(key), f"{source_path}.{key}")

    for entry_index, entry in enumerate(_iter_export_entries(export_document)):
        payload = _entry_payload_any(entry)
        event_type = _permit_v2_text(entry.get("event_type")) or _permit_v2_text(
            payload.get("event_type")
        )
        merged = {**entry, **payload}
        if (
            event_type in {"dispatch.egress_bound", "execution.completed"}
            or any(
                field in merged
                for field in (
                    "dispatch_request_hash",
                    "dispatch_request_digest_v1",
                    "binding_request_hash",
                )
            )
        ):
            candidates.append((merged, f"chain_entries[{entry_index}]"))

    candidates.append((permit, "permit"))
    return candidates


def _permit_v2_nested_mapping(value: Any, *keys: str) -> dict[str, Any] | None:
    current = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current if isinstance(current, dict) else None


def _permit_v2_counter_signature_intent_hashes(
    *,
    export_document: dict[str, Any],
    permit: dict[str, Any],
) -> tuple[list[tuple[str, str]], str | None]:
    permit_id = _permit_v2_permit_id(permit)
    permit_canonical_hash = _permit_v2_canonical_permit_hash(permit)
    if permit_id is None or permit_canonical_hash is None:
        return [], "cannot reconstruct execution intent; missing permit_id or permit_canonical_hash"

    hashes: list[tuple[str, str]] = []
    for candidate, path in _permit_v2_counter_signature_intent_candidates(
        export_document=export_document,
        permit=permit,
    ):
        target = _permit_v2_nested_mapping(candidate, "target") or {}
        resource_attributes = (
            _permit_v2_nested_mapping(candidate, "resource_attributes")
            or _permit_v2_nested_mapping(candidate, "resource_attributes_json")
            or {}
        )
        dispatch_request_hash = _permit_v2_sha256_hexish(
            candidate.get("dispatch_request_hash")
            or candidate.get("dispatch_request_digest_v1")
            or candidate.get("binding_request_hash")
            or candidate.get("final_request_hash")
            or permit.get("binding_request_hash")
            or permit.get("final_request_hash")
        )
        resource_provider = _permit_v2_text(
            candidate.get("resource_provider")
            or candidate.get("provider")
            or target.get("provider")
            or permit.get("resource_provider")
            or permit.get("provider")
        )
        resource_model = _permit_v2_text(
            candidate.get("resource_model")
            or candidate.get("model")
            or target.get("model")
            or permit.get("resource_model")
            or permit.get("model")
        )
        resource_operation = _permit_v2_text(
            candidate.get("resource_operation")
            or candidate.get("operation")
            or target.get("operation")
            or resource_attributes.get("operation")
            or permit.get("resource_operation")
            or permit.get("operation")
        )
        if resource_operation is None:
            permit_attributes = (
                _permit_v2_nested_mapping(permit, "resource_attributes")
                or _permit_v2_nested_mapping(permit, "resource_attributes_json")
                or {}
            )
            resource_operation = _permit_v2_text(
                permit_attributes.get("operation") or permit.get("action_name")
            )
        if (
            dispatch_request_hash is None
            or resource_provider is None
            or resource_model is None
        ):
            continue
        payload = {
            "payload_type": PERMIT_COUNTER_SIGNATURE_EXECUTION_INTENT_PAYLOAD_TYPE,
            "permit_id": permit_id,
            "permit_canonical_hash": permit_canonical_hash,
            "dispatch_request_hash": dispatch_request_hash,
            "resource_provider": resource_provider,
            "resource_model": resource_model,
            "resource_operation": resource_operation,
        }
        hashes.append(
            (
                _permit_v2_payload_hash(
                    _permit_v2_canonical_bytes(
                        _permit_v2_envelope_version(permit),
                        payload,
                    )
                ),
                path,
            )
        )
    if not hashes:
        return [], "counter_signature execution-intent dispatch facts are absent"
    return hashes, None


def _known_audit_batch_ids(*sources: dict[str, Any]) -> set[str]:
    ids: set[str] = set()

    def collect(value: Any) -> None:
        if isinstance(value, str) and value.strip():
            ids.add(value.strip())
        elif isinstance(value, dict):
            for field in ("batch_id", "id", "audit_batch_id"):
                raw = value.get(field)
                if isinstance(raw, str) and raw.strip():
                    ids.add(raw.strip())
            for field in ("audit_batches", "known_audit_batches", "batches"):
                collect(value.get(field))
        elif isinstance(value, list):
            for item in value:
                collect(item)

    for source in sources:
        for field in ("audit_batch", "audit_batches", "known_audit_batches", "batches"):
            collect(source.get(field))
    return ids


def _permit_v2_entry_identity(entry: dict[str, Any], *fields: str) -> str | None:
    for field in fields:
        value = entry.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _permit_v2_key_entry_active_at(entry: dict[str, Any], signing_time: datetime) -> bool:
    valid_from = _parse_iso_or_none(entry.get("valid_from") or entry.get("active_from"))
    if valid_from is not None and signing_time < valid_from:
        return False
    valid_until = _parse_iso_or_none(
        entry.get("valid_until") or entry.get("valid_to") or entry.get("active_to")
    )
    if valid_until is not None and signing_time >= valid_until:
        return False
    revoked_at = _parse_iso_or_none(entry.get("revoked_at"))
    if revoked_at is not None and signing_time >= revoked_at:
        return False
    compromised_at = _parse_iso_or_none(entry.get("compromised_at"))
    return not (compromised_at is not None and signing_time >= compromised_at)


def _permit_v2_key_entry_matches(
    entry: dict[str, Any],
    *,
    spec: PermitV2SlotSpec,
    account_id: str,
    signer_id: str,
    key_id: str,
    signing_time: datetime,
) -> bool:
    purpose = entry.get("purpose")
    signer_role = entry.get("signer_role")
    expected_role = (
        "operator"
        if spec.slot_name == PERMIT_OPERATOR_APPROVAL_SLOT
        else "buyer_principal"
    )
    if (
        purpose not in spec.key_purposes
        and signer_role != expected_role
    ):
        return False
    if entry.get("key_id") != key_id:
        return False
    entry_account_id = _permit_v2_entry_identity(
        entry,
        "account_id",
        "organization_id",
        "org_id",
        "tenant_id",
        "project_id",
    )
    if entry_account_id != account_id:
        return False
    entry_signer_id = _permit_v2_entry_identity(
        entry,
        "signer_id",
        "operator_id",
        "buyer_principal_id",
    )
    if entry_signer_id != signer_id:
        return False
    return _permit_v2_key_entry_active_at(entry, signing_time)


def _resolve_permit_v2_slot_key(
    *,
    slot: dict[str, Any],
    spec: PermitV2SlotSpec,
    account_id: str,
    signing_time: datetime,
    key_manifest_source: str | None,
) -> tuple[str | None, str | None]:
    source = key_manifest_source or _cached_key_manifest_source() or _bundled_key_manifest_source()
    if source is None:
        return None, "no permit v2 key registry evidence available"
    try:
        entries = _load_key_manifest(source)
    except Exception as exc:
        return None, f"could not load key registry evidence: {exc}"

    matches = [
        entry
        for entry in entries
        if _permit_v2_key_entry_matches(
            entry,
            spec=spec,
            account_id=account_id,
            signer_id=str(slot["signer_id"]),
            key_id=str(slot["key_id"]),
            signing_time=signing_time,
        )
    ]
    if len(matches) != 1:
        return None, "no unique trusted permit v2 signer key resolved at signing time"
    public_key = matches[0].get("public_key")
    if not isinstance(public_key, str):
        return None, "resolved permit v2 key has no public_key"
    if _permit_v2_public_key_b64(public_key) is None:
        return None, "resolved permit v2 key is not a valid Ed25519 public key"
    return public_key, None


def _adjudicate_permit_v2_signature_slot(
    *,
    export_document: dict[str, Any],
    manifest: dict[str, Any],
    key_manifest_source: str | None,
    spec: PermitV2SlotSpec,
) -> ClaimVerdict:
    permit, slot, evidence_path = _find_permit_v2_slot(export_document, spec.slot_name)
    if permit is None or slot is None:
        return _permit_v2_slot_claim(
            spec,
            permit_id=None,
            verdict="insufficient_evidence",
            reason_code=spec.invalid_code,
            message=f"Permit v2 {spec.slot_name} evidence is absent",
            evidence=[evidence_path],
            epistemic_state="unverifiable",
        )

    permit_id = _permit_v2_permit_id(permit)
    if permit_id is None:
        return _permit_v2_slot_claim(
            spec,
            permit_id=None,
            verdict="insufficient_evidence",
            reason_code=spec.invalid_code,
            message="Permit v2 permit_id/id is missing or malformed",
            evidence=[evidence_path, "permit.id"],
            epistemic_state="unverifiable",
        )

    schema_error = _permit_v2_slot_schema_error(slot, spec)
    if schema_error is not None:
        reason, message = schema_error
        return _permit_v2_slot_claim(
            spec,
            permit_id=permit_id,
            verdict="disproved",
            reason_code=reason,
            message=message,
            evidence=[evidence_path],
        )

    signed_at = _permit_v2_parse_signed_at(slot["signed_at"])
    assert signed_at is not None
    payload, payload_reason, payload_message = _permit_v2_signed_payload(
        export_document=export_document,
        permit=permit,
        slot=slot,
        spec=spec,
    )
    if payload is None:
        return _permit_v2_slot_claim(
            spec,
            permit_id=permit_id,
            verdict="insufficient_evidence",
            reason_code=payload_reason or spec.invalid_code,
            message=payload_message or "canonical signed payload evidence is absent",
            evidence=[evidence_path, "canonical_payload"],
            epistemic_state="unverifiable",
        )

    payload_error = _permit_v2_signed_payload_error(
        payload=payload,
        permit=permit,
        slot=slot,
        spec=spec,
    )
    if payload_error is not None:
        reason, message = payload_error
        return _permit_v2_slot_claim(
            spec,
            permit_id=permit_id,
            verdict="disproved",
            reason_code=reason,
            message=message,
            evidence=[evidence_path, "canonical_payload"],
        )

    payload_bytes = _permit_v2_canonical_bytes(
        _permit_v2_envelope_version(permit),
        payload,
    )
    if _permit_v2_payload_hash(payload_bytes) != slot["signed_payload_hash"]:
        return _permit_v2_slot_claim(
            spec,
            permit_id=permit_id,
            verdict="disproved",
            reason_code=spec.invalid_code,
            message=f"{spec.slot_name}.signed_payload_hash does not match canonical signed payload bytes",
            evidence=[evidence_path, "signed_payload_hash"],
        )

    window_error = _permit_v2_slot_window_error(
        permit=permit,
        signing_time=signed_at,
        spec=spec,
    )
    if window_error is not None:
        reason, message = window_error
        return _permit_v2_slot_claim(
            spec,
            permit_id=permit_id,
            verdict="disproved",
            reason_code=reason,
            message=message,
            evidence=[evidence_path, "signed_at"],
        )

    if spec.slot_name == PERMIT_COUNTER_SIGNATURE_SLOT:
        intent_hashes, intent_error = _permit_v2_counter_signature_intent_hashes(
            export_document=export_document,
            permit=permit,
        )
        if not intent_hashes:
            return _permit_v2_slot_claim(
                spec,
                permit_id=permit_id,
                verdict="insufficient_evidence",
                reason_code="PERMIT_COUNTER_SIGNATURE_EXECUTION_INTENT_MISSING",
                message=intent_error or "counter_signature execution intent is absent",
                evidence=[evidence_path, "execution_intent"],
                epistemic_state="unverifiable",
            )
        if slot["execution_intent_hash"] not in {
            intent_hash for intent_hash, _path in intent_hashes
        }:
            return _permit_v2_slot_claim(
                spec,
                permit_id=permit_id,
                verdict="disproved",
                reason_code="counter_signature.execution_intent_mismatch",
                message=(
                    "counter_signature.execution_intent_hash does not match "
                    "canonical permit.counter_signature.execution_intent.v1 bytes"
                ),
                evidence=[
                    evidence_path,
                    *(path for _intent_hash, path in intent_hashes),
                ],
            )

        effective_at = _permit_v2_revocation_effective_at(
            export_document=export_document,
            permit=permit,
        )
        if effective_at is not None and signed_at >= effective_at:
            return _permit_v2_slot_claim(
                spec,
                permit_id=permit_id,
                verdict="disproved",
                reason_code=spec.invalid_code,
                message="counter_signature.signed_at is not before revocation.effective_at",
                evidence=[evidence_path, "revocation.effective_at"],
            )

    if spec.slot_name == PERMIT_AUDIT_ATTESTATION_SLOT:
        known_batches = _known_audit_batch_ids(permit, export_document, manifest)
        if slot["batch_id"] not in known_batches:
            return _permit_v2_slot_claim(
                spec,
                permit_id=permit_id,
                verdict="disproved",
                reason_code="PERMIT_AUDIT_ATTESTATION_BATCH_MISMATCH",
                message="audit_attestation.batch_id does not resolve to a known audit batch",
                evidence=[evidence_path, "audit_batches"],
            )

    account_id = _permit_v2_account_id(permit=permit, manifest=manifest)
    if account_id is None:
        return _permit_v2_slot_claim(
            spec,
            permit_id=permit_id,
            verdict="insufficient_evidence",
            reason_code=spec.key_not_trusted_code,
            message="account_id is required to resolve permit v2 signer keys",
            evidence=[evidence_path, "key_registry"],
            epistemic_state="unverifiable",
        )
    public_key, key_error = _resolve_permit_v2_slot_key(
        slot=slot,
        spec=spec,
        account_id=account_id,
        signing_time=signed_at,
        key_manifest_source=key_manifest_source,
    )
    if public_key is None:
        return _permit_v2_slot_claim(
            spec,
            permit_id=permit_id,
            verdict="insufficient_evidence",
            reason_code=spec.key_not_trusted_code,
            message=key_error or "permit v2 signer key could not be resolved",
            evidence=[evidence_path, "key_registry"],
            epistemic_state="unverifiable",
        )

    if not _verify_ed25519(public_key, payload_bytes, str(slot["signature"])):
        return _permit_v2_slot_claim(
            spec,
            permit_id=permit_id,
            verdict="disproved",
            reason_code=spec.invalid_code,
            message=f"{spec.slot_name} signature does not verify over canonical signed payload bytes",
            evidence=[evidence_path, "signature", "key_registry"],
        )

    return _permit_v2_slot_claim(
        spec,
        permit_id=permit_id,
        verdict="supported",
        reason_code=spec.supported_code,
        message=f"Permit v2 {spec.slot_name} payload hash, signer key, timing, and signature are supported",
        evidence=[evidence_path, "key_registry"],
    )


def _adjudicate_permit_operator_approval_v1(
    *,
    export_document: dict[str, Any],
    manifest: dict[str, Any],
    key_manifest_source: str | None,
) -> ClaimVerdict:
    return _adjudicate_permit_v2_signature_slot(
        export_document=export_document,
        manifest=manifest,
        key_manifest_source=key_manifest_source,
        spec=PERMIT_V2_OPERATOR_APPROVAL_SPEC,
    )


def _adjudicate_permit_counter_signature_v1(
    *,
    export_document: dict[str, Any],
    manifest: dict[str, Any],
    key_manifest_source: str | None,
) -> ClaimVerdict:
    return _adjudicate_permit_v2_signature_slot(
        export_document=export_document,
        manifest=manifest,
        key_manifest_source=key_manifest_source,
        spec=PERMIT_V2_COUNTER_SIGNATURE_SPEC,
    )


def _adjudicate_permit_audit_attestation_v1(
    *,
    export_document: dict[str, Any],
    manifest: dict[str, Any],
    key_manifest_source: str | None,
) -> ClaimVerdict:
    return _adjudicate_permit_v2_signature_slot(
        export_document=export_document,
        manifest=manifest,
        key_manifest_source=key_manifest_source,
        spec=PERMIT_V2_AUDIT_ATTESTATION_SPEC,
    )


def _adjudicate_operator_approved_v1(
    *,
    export_document: dict[str, Any],
    manifest: dict[str, Any],
    key_manifest_source: str | None,
) -> ClaimVerdict:
    return _adjudicate_permit_v2_signature_slot(
        export_document=export_document,
        manifest=manifest,
        key_manifest_source=key_manifest_source,
        spec=PERMIT_V2_LEGACY_OPERATOR_APPROVED_SPEC,
    )


def _adjudicate_pre_dispatch_counter_signed_v1(
    *,
    export_document: dict[str, Any],
    manifest: dict[str, Any],
    key_manifest_source: str | None,
) -> ClaimVerdict:
    return _adjudicate_permit_v2_signature_slot(
        export_document=export_document,
        manifest=manifest,
        key_manifest_source=key_manifest_source,
        spec=PERMIT_V2_LEGACY_COUNTER_SIGNED_SPEC,
    )


def _adjudicate_audit_attested_v1(
    *,
    export_document: dict[str, Any],
    manifest: dict[str, Any],
    key_manifest_source: str | None,
) -> ClaimVerdict:
    return _adjudicate_permit_v2_signature_slot(
        export_document=export_document,
        manifest=manifest,
        key_manifest_source=key_manifest_source,
        spec=PERMIT_V2_LEGACY_AUDIT_ATTESTED_SPEC,
    )


def _permit_binding_key_candidates(
    *,
    key_manifest_source: str | None,
    signing_time: datetime | None,
) -> tuple[list[dict[str, Any]], str | None]:
    source = key_manifest_source or _cached_key_manifest_source() or _bundled_key_manifest_source()
    if source is None:
        return [], "no permit-binding trust root available"
    try:
        entries = _load_key_manifest(source)
    except Exception as exc:
        return [], f"could not load key manifest: {exc}"
    candidates = [
        entry
        for entry in entries
        if entry.get("purpose") == PERMIT_BINDING_SIGNING_PURPOSE
        and isinstance(entry.get("public_key"), str)
    ]
    if signing_time is not None:
        candidates = _filter_by_active_window(candidates, signing_time)
    if not candidates:
        return [], "no active permit-binding key found in trust root"
    return candidates, None


def _find_permit_decision_evidence(
    document: dict[str, Any],
) -> tuple[dict[str, Any] | None, str]:
    top_level = document.get("permit_decision")
    if isinstance(top_level, dict):
        return top_level, "export.permit_decision"
    top_level = document.get("permit_decision_binding")
    if isinstance(top_level, dict):
        return top_level, "export.permit_decision_binding"
    if document.get("artifact_type") == PERMIT_DECISION_ARTIFACT_TYPE:
        return document, "export"

    for entry in _iter_export_entries(document):
        payload = _entry_payload_any(entry)
        for key in (
            "permit_decision",
            "permit_decision_binding",
            "decision_binding",
        ):
            nested = payload.get(key)
            if isinstance(nested, dict):
                return nested, f"payload_json.{key}"
        if payload.get("artifact_type") == PERMIT_DECISION_ARTIFACT_TYPE:
            return payload, "payload_json"
        if entry.get("artifact_type") == PERMIT_DECISION_ARTIFACT_TYPE:
            return entry, "chain_entry"
    return None, "export.permit_decision"


def _permit_decision_schema_error(evidence: dict[str, Any]) -> str | None:
    if evidence.get("artifact_type") != PERMIT_DECISION_ARTIFACT_TYPE:
        return "artifact_type must be permit_decision_binding"
    if evidence.get("artifact_version") != PERMIT_DECISION_ARTIFACT_VERSION:
        return "artifact_version must be permit.decision.v1"
    canonical_payload = evidence.get("canonical_payload")
    if not isinstance(canonical_payload, dict):
        return "canonical_payload must be an object"
    binding_version = canonical_payload.get("binding_version")
    if binding_version not in SUPPORTED_PERMIT_BINDING_VERSIONS:
        return "binding_version must be one of v1, v2, v3, v4, v5, or v6"
    required = set(_PERMIT_DECISION_CANONICAL_FIELDS_BY_VERSION[str(binding_version)])
    if set(canonical_payload.keys()) != required:
        missing = sorted(required - set(canonical_payload.keys()))
        extra = sorted(set(canonical_payload.keys()) - required)
        if missing:
            if (
                binding_version == "v6"
                and missing == ["resource_attributes_canonical_hash"]
                and not extra
            ):
                return None
            return "canonical_payload missing signed field(s): " + ", ".join(missing)
        return "canonical_payload has unsupported signed field(s): " + ", ".join(extra)
    if canonical_payload.get("decision") not in {"allow", "deny", "challenge"}:
        return "decision must be allow, deny, or challenge"
    for field in ("permit_id", "project_id", "issued_at", "binding_key_id"):
        if not _is_nonempty_str(canonical_payload.get(field)):
            return f"canonical_payload.{field} must be a non-empty string"
    if not _is_nonempty_str(evidence.get("binding_canonical_hash")):
        return "binding_canonical_hash must be a non-empty string"
    signature = evidence.get("binding_signature")
    if not _is_nonempty_str(signature) or not str(signature).startswith("ed25519:"):
        return "binding_signature must be ed25519:<base64>"
    if not _is_nonempty_str(evidence.get("binding_issued_at")):
        return "binding_issued_at must be a non-empty string"
    return None


@dataclass(frozen=True)
class _PermitDecisionBindingFailure:
    verdict: str
    reason_code: str
    message: str
    evidence: list[str]


def _permit_decision_resource_attributes(
    evidence: dict[str, Any],
) -> tuple[Mapping[str, Any] | None, _PermitDecisionBindingFailure | None]:
    raw = evidence.get("resource_attributes_json")
    evidence_path = "resource_attributes_json"
    if raw is None:
        raw = evidence.get("resource_attributes")
        evidence_path = "resource_attributes"
    if isinstance(raw, Mapping):
        return raw, None
    if isinstance(raw, str):
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError as exc:
            return None, _PermitDecisionBindingFailure(
                verdict="insufficient_evidence",
                reason_code="permit.binding.resource_attributes_json_invalid",
                message=f"resource_attributes_json is not valid JSON: {exc}",
                evidence=[evidence_path],
            )
        if isinstance(decoded, Mapping):
            return decoded, None
        return None, _PermitDecisionBindingFailure(
            verdict="insufficient_evidence",
            reason_code="permit.binding.resource_attributes_json_invalid",
            message="resource_attributes_json must decode to an object",
            evidence=[evidence_path],
        )
    return None, _PermitDecisionBindingFailure(
        verdict="insufficient_evidence",
        reason_code="permit.binding.resource_attributes_json_missing",
        message="resource_attributes_json is required to recompute binding sub-hashes",
        evidence=[evidence_path],
    )


_PERMIT_DECISION_WIRE_BODY_FIELDS = (
    "binding_request_body",
    "binding_request_body_json",
    "provider_wire_body",
    "provider_request_body",
    "provider_request_json",
    "dispatch_request_body",
)


def _permit_decision_wire_body(
    evidence: dict[str, Any],
) -> tuple[Mapping[str, Any] | None, str | None, _PermitDecisionBindingFailure | None]:
    for field in _PERMIT_DECISION_WIRE_BODY_FIELDS:
        raw = evidence.get(field)
        if raw is None:
            continue
        if isinstance(raw, Mapping):
            return raw, field, None
        if isinstance(raw, str):
            try:
                decoded = json.loads(raw)
            except json.JSONDecodeError as exc:
                return None, field, _PermitDecisionBindingFailure(
                    verdict="insufficient_evidence",
                    reason_code="permit.binding.wire_body_json_invalid",
                    message=f"{field} is not valid JSON: {exc}",
                    evidence=[field],
                )
            if isinstance(decoded, Mapping):
                return decoded, field, None
        return None, field, _PermitDecisionBindingFailure(
            verdict="insufficient_evidence",
            reason_code="permit.binding.wire_body_json_invalid",
            message=f"{field} must be a JSON object",
            evidence=[field],
        )
    return None, None, None


def _permit_decision_binding_request_hash(
    evidence: dict[str, Any],
    canonical_payload: dict[str, Any],
) -> tuple[str | None, str | None]:
    for source, prefix in ((evidence, ""), (canonical_payload, "canonical_payload.")):
        for field in (
            "binding_request_hash",
            "final_request_hash",
            "dispatch_request_hash",
            "dispatch_request_digest_v1",
        ):
            value = _permit_v2_sha256_hexish(source.get(field))
            if value is not None:
                return value, prefix + field
    return None, None


def _permit_decision_binding_request_canonical_version(
    evidence: dict[str, Any],
    canonical_payload: dict[str, Any],
) -> str:
    for source in (evidence, canonical_payload):
        value = source.get("binding_request_canonical_version")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return binding_request_canonical_version_for_binding(
        str(canonical_payload.get("binding_version") or "")
    )


def _permit_decision_binding_recompute_failure(
    *,
    evidence: dict[str, Any],
    canonical_payload: dict[str, Any],
    evidence_path: str,
) -> _PermitDecisionBindingFailure | None:
    version = canonical_payload.get("binding_version")
    wire_body, wire_field, wire_failure = _permit_decision_wire_body(evidence)
    if wire_failure is not None:
        return wire_failure
    if wire_body is not None:
        expected_hash, hash_field = _permit_decision_binding_request_hash(
            evidence,
            canonical_payload,
        )
        if expected_hash is None:
            return _PermitDecisionBindingFailure(
                verdict="insufficient_evidence",
                reason_code="permit.binding.wire_body_hash_missing",
                message="wire-body evidence is present but binding_request_hash is absent",
                evidence=[wire_field or "binding_request_body"],
            )
        canonical_version = _permit_decision_binding_request_canonical_version(
            evidence,
            canonical_payload,
        )
        actual_hash = canonical_provider_wire_body_hash(
            wire_body,
            binding_request_canonical_version=canonical_version,
        )
        if actual_hash != expected_hash:
            reason = (
                f"permit.binding.{version}.wire_body_hash_mismatch"
                if version in {"v5", "v6"}
                else "permit.binding.wire_body_hash_mismatch"
            )
            return _PermitDecisionBindingFailure(
                verdict="disproved",
                reason_code=reason,
                message="binding_request_hash does not match provider wire-body bytes",
                evidence=[
                    evidence_path,
                    wire_field or "binding_request_body",
                    hash_field or "binding_request_hash",
                ],
            )

    if version not in {"v3", "v4", "v5", "v6"}:
        return None

    resource_attributes, resource_failure = _permit_decision_resource_attributes(evidence)

    if version == "v6":
        resource_attributes_canonical_hash = canonical_payload.get(
            "resource_attributes_canonical_hash"
        )
        if resource_attributes_canonical_hash is None:
            return _PermitDecisionBindingFailure(
                verdict="disproved",
                reason_code=(
                    "permit.binding.v6.resource_attributes_canonical_hash_missing"
                ),
                message=(
                    "v6 canonical_payload is missing "
                    "resource_attributes_canonical_hash"
                ),
                evidence=[evidence_path, "canonical_payload.resource_attributes_canonical_hash"],
            )
        if resource_failure is not None:
            return resource_failure
        assert resource_attributes is not None
        recomputed_resource_attributes_hash = canonical_resource_attributes_payload(
            resource_attributes
        )
        if recomputed_resource_attributes_hash != resource_attributes_canonical_hash:
            return _PermitDecisionBindingFailure(
                verdict="disproved",
                reason_code=(
                    "permit.binding.v6.resource_attributes_canonical_hash_mismatch"
                ),
                message=(
                    "canonical_payload.resource_attributes_canonical_hash does not "
                    "match resource_attributes_json"
                ),
                evidence=[
                    evidence_path,
                    "canonical_payload.resource_attributes_canonical_hash",
                    "resource_attributes_json",
                ],
            )

    spend_scope_hash = canonical_payload.get("spend_scope_hash")
    if spend_scope_hash is not None:
        if resource_failure is not None:
            return resource_failure
        assert resource_attributes is not None
        recomputed_spend_scope_hash = canonical_spend_scope_payload(
            resource_attributes.get("spend_scope")
        )
        if recomputed_spend_scope_hash != spend_scope_hash:
            spend_reason_version = str(version) if version in {"v5", "v6"} else "v3"
            return _PermitDecisionBindingFailure(
                verdict="disproved",
                reason_code=(
                    f"permit.binding.{spend_reason_version}.spend_scope_hash_mismatch"
                ),
                message=(
                    "canonical_payload.spend_scope_hash does not match "
                    "resource_attributes_json.spend_scope"
                ),
                evidence=[
                    evidence_path,
                    "canonical_payload.spend_scope_hash",
                    "resource_attributes_json.spend_scope",
                ],
            )

    if version not in {"v4", "v5", "v6"}:
        return None

    delegation_policy_hash = canonical_payload.get("delegation_policy_hash")
    if delegation_policy_hash is None:
        return None
    if resource_failure is not None:
        return resource_failure
    assert resource_attributes is not None
    recomputed_delegation_policy_hash = canonical_delegation_policy_payload(
        resource_attributes.get("delegation_policy")
    )
    if recomputed_delegation_policy_hash != delegation_policy_hash:
        delegation_reason_version = str(version) if version in {"v5", "v6"} else "v4"
        return _PermitDecisionBindingFailure(
            verdict="disproved",
            reason_code=(
                "permit.binding."
                f"{delegation_reason_version}.delegation_policy_hash_mismatch"
            ),
            message=(
                "canonical_payload.delegation_policy_hash does not match "
                "resource_attributes_json.delegation_policy"
            ),
            evidence=[
                evidence_path,
                "canonical_payload.delegation_policy_hash",
                "resource_attributes_json.delegation_policy",
            ],
        )
    return None


def _adjudicate_permit_decision_v1(
    *,
    export_document: dict[str, Any],
    key_manifest_source: str | None,
) -> ClaimVerdict:
    evidence, evidence_path = _find_permit_decision_evidence(export_document)
    if evidence is None:
        return _permit_claim(
            PERMIT_DECISION_CLAIM_NAME,
            subject_type="permit_decision",
            subject_id=None,
            verdict="insufficient_evidence",
            reason_code="PERMIT_DECISION_EVIDENCE_MISSING",
            message="permit decision binding evidence is absent",
            evidence=[evidence_path],
        )

    canonical_payload = evidence.get("canonical_payload")
    permit_id = (
        canonical_payload.get("permit_id")
        if isinstance(canonical_payload, dict)
        and isinstance(canonical_payload.get("permit_id"), str)
        else None
    )
    schema_error = _permit_decision_schema_error(evidence)
    if schema_error is not None:
        verdict = (
            "unverifiable_scope"
            if "binding_version" in schema_error
            else "insufficient_evidence"
            if "missing" in schema_error or "must be a non-empty" in schema_error
            else "disproved"
        )
        reason = (
            "PERMIT_DECISION_UNSUPPORTED_BINDING_VERSION"
            if "binding_version" in schema_error
            else "PERMIT_DECISION_EVIDENCE_MISSING"
            if verdict == "insufficient_evidence"
            else "PERMIT_DECISION_SCHEMA_INVALID"
        )
        return _permit_claim(
            PERMIT_DECISION_CLAIM_NAME,
            subject_type="permit_decision",
            subject_id=permit_id,
            verdict=verdict,
            reason_code=reason,
            message=schema_error,
            evidence=[evidence_path],
        )
    assert isinstance(canonical_payload, dict)

    canonical_hash = str(evidence["binding_canonical_hash"])
    recomputed = _compute_canonical_binding_hash(canonical_payload)
    if recomputed != canonical_hash:
        return _permit_claim(
            PERMIT_DECISION_CLAIM_NAME,
            subject_type="permit_decision",
            subject_id=permit_id,
            verdict="disproved",
            reason_code="PERMIT_DECISION_CANONICAL_HASH_MISMATCH",
            message="binding_canonical_hash does not match the canonical payload",
            evidence=[evidence_path, "canonical_payload"],
        )

    binding_failure = _permit_decision_binding_recompute_failure(
        evidence=evidence,
        canonical_payload=canonical_payload,
        evidence_path=evidence_path,
    )
    if binding_failure is not None:
        return _permit_claim(
            PERMIT_DECISION_CLAIM_NAME,
            subject_type="permit_decision",
            subject_id=permit_id,
            verdict=binding_failure.verdict,
            reason_code=binding_failure.reason_code,
            message=binding_failure.message,
            evidence=binding_failure.evidence,
        )

    expected_decision = evidence.get("expected_decision")
    if isinstance(expected_decision, str) and expected_decision != canonical_payload.get("decision"):
        return _permit_claim(
            PERMIT_DECISION_CLAIM_NAME,
            subject_type="permit_decision",
            subject_id=permit_id,
            verdict="disproved",
            reason_code="PERMIT_DECISION_CANONICAL_PAYLOAD_MISMATCH",
            message="canonical_payload.decision does not match the requested decision evidence",
            evidence=[evidence_path, "canonical_payload.decision"],
        )

    signing_time = _parse_iso_or_none(evidence.get("binding_issued_at")) or _parse_iso_or_none(
        canonical_payload.get("issued_at")
    )
    trusted_pub, _trust_source, err = _resolve_trust_key(
        artifact_pub=None,
        artifact_key_id=str(canonical_payload["binding_key_id"]),
        purpose=PERMIT_BINDING_SIGNING_PURPOSE,
        expected_public_key=None,
        public_key_url=None,
        key_manifest_source=key_manifest_source,
        signing_time=signing_time,
    )
    if err is not None or trusted_pub is None:
        reason = (
            "PERMIT_DECISION_UNTRUSTED_KEY"
            if "not found" in str(err) or "contains no entry" in str(err)
            else "PERMIT_DECISION_TRUST_ROOT_UNRESOLVABLE"
        )
        return _permit_claim(
            PERMIT_DECISION_CLAIM_NAME,
            subject_type="permit_decision",
            subject_id=permit_id,
            verdict="insufficient_evidence",
            reason_code=reason,
            message=str(err or "permit-binding key could not be resolved"),
            evidence=[evidence_path, "trust_root"],
        )
    try:
        actual_key_id = _binding_key_id_from_public_key(trusted_pub)
    except Exception as exc:
        return _permit_claim(
            PERMIT_DECISION_CLAIM_NAME,
            subject_type="permit_decision",
            subject_id=permit_id,
            verdict="insufficient_evidence",
            reason_code="PERMIT_DECISION_TRUST_ROOT_UNRESOLVABLE",
            message=f"trusted permit-binding key is malformed: {exc}",
            evidence=[evidence_path, "trust_root"],
        )
    if actual_key_id != canonical_payload["binding_key_id"]:
        return _permit_claim(
            PERMIT_DECISION_CLAIM_NAME,
            subject_type="permit_decision",
            subject_id=permit_id,
            verdict="disproved",
            reason_code="PERMIT_DECISION_KEY_ID_MISMATCH",
            message="canonical payload binding_key_id does not match the trusted public key",
            evidence=[evidence_path, "trust_root"],
        )
    if not _verify_ed25519(
        trusted_pub,
        canonical_hash.encode("utf-8"),
        str(evidence["binding_signature"]),
    ):
        return _permit_claim(
            PERMIT_DECISION_CLAIM_NAME,
            subject_type="permit_decision",
            subject_id=permit_id,
            verdict="disproved",
            reason_code="PERMIT_DECISION_SIGNATURE_INVALID",
            message="permit decision signature does not verify over the canonical hash",
            evidence=[evidence_path, "binding_signature"],
        )
    return _permit_claim(
        PERMIT_DECISION_CLAIM_NAME,
        subject_type="permit_decision",
        subject_id=permit_id,
        verdict="supported",
        reason_code="PERMIT_DECISION_SUPPORTED",
        message="permit decision canonical hash and signature are supported",
        evidence=[evidence_path, "trust_root"],
    )


def _find_revocation_evidence(
    document: dict[str, Any],
) -> tuple[dict[str, Any] | None, str | None, str]:
    top_level = document.get("revocation_event")
    if isinstance(top_level, dict):
        event = top_level.get("event")
        if isinstance(event, dict):
            canonical_hash = top_level.get("canonical_hash")
            return (
                event,
                canonical_hash if isinstance(canonical_hash, str) else None,
                "export.revocation_event.event",
            )
        return top_level, None, "export.revocation_event"
    if document.get("event_type") == PERMIT_REVOKED_EVENT_TYPE and "signature" in document:
        return document, None, "export"

    for entry in _iter_export_entries(document):
        payload = _entry_payload_any(entry)
        nested = payload.get("revocation_event")
        if isinstance(nested, dict):
            wrapped_event = nested.get("event")
            canonical_hash = nested.get("canonical_hash")
            if not isinstance(canonical_hash, str):
                canonical_hash = payload.get("revocation_canonical_hash")
            if isinstance(wrapped_event, dict):
                return (
                    wrapped_event,
                    canonical_hash if isinstance(canonical_hash, str) else None,
                    "payload_json.revocation_event.event",
                )
            return (
                nested,
                canonical_hash if isinstance(canonical_hash, str) else None,
                "payload_json.revocation_event",
            )
        if (
            entry.get("event_type") == PERMIT_REVOKED_EVENT_TYPE
            and "signature" in payload
        ):
            return payload, None, "payload_json"
        if entry.get("event_type") == PERMIT_REVOKED_EVENT_TYPE and "signature" in entry:
            return entry, None, "chain_entry"
    return None, None, "export.revocation_event"


def _permit_revoked_schema_error(event: dict[str, Any]) -> tuple[str | None, str | None]:
    keys = set(event.keys())
    required = set(_PERMIT_REVOKED_REQUIRED_FIELDS)
    missing = sorted(required - keys)
    if missing:
        return "PERMIT_REVOKED_EVIDENCE_MISSING", "revocation event missing required field(s): " + ", ".join(missing)
    extra = sorted(keys - required)
    if extra:
        return "PERMIT_REVOKED_SCHEMA_INVALID", "revocation event has unsupported field(s): " + ", ".join(extra)
    for field in ("permit_id", "project_id", "actor_id"):
        if not isinstance(event.get(field), str) or not event[field]:
            return "PERMIT_REVOKED_SCHEMA_INVALID", f"{field} must be a non-empty string"
    if _actor_id_has_pii_shape(event.get("actor_id")):
        return "PERMIT_REVOKED_ACTOR_PII_DETECTED", "actor_id appears to contain PII rather than an opaque UUID"
    for field in ("permit_id", "project_id", "actor_id"):
        if not _is_uuid_text(event.get(field)):
            return "PERMIT_REVOKED_SCHEMA_INVALID", f"{field} must be a UUID string"
    if event.get("actor_kind") not in _PERMIT_REVOKED_ACTOR_KINDS:
        return "PERMIT_REVOKED_ACTOR_KIND_UNSUPPORTED", "actor_kind is outside the v1 taxonomy"
    reason_code = event.get("reason_code")
    if not isinstance(reason_code, str) or not _REASON_CODE_RE.fullmatch(reason_code):
        return "PERMIT_REVOKED_SCHEMA_INVALID", "reason_code must be a taxonomy code"
    for field in ("revoked_at", "effective_at"):
        if _parse_iso_or_none(event.get(field)) is None:
            return "PERMIT_REVOKED_SCHEMA_INVALID", f"{field} must be an RFC 3339 timestamp"
    if not _raw_ed25519_signature_b64(event.get("signature")):
        return "PERMIT_REVOKED_SCHEMA_INVALID", "signature must be raw base64 Ed25519 bytes"
    return None, None


def _adjudicate_permit_revoked_v1(
    *,
    export_document: dict[str, Any],
    manifest: dict[str, Any],
    key_manifest_source: str | None,
) -> ClaimVerdict:
    event, declared_canonical_hash, evidence_path = _find_revocation_evidence(export_document)
    if event is None:
        return _permit_claim(
            PERMIT_REVOKED_CLAIM_NAME,
            subject_type="permit_revocation",
            subject_id=None,
            verdict="insufficient_evidence",
            reason_code="PERMIT_REVOKED_EVIDENCE_MISSING",
            message="permit.revoked event evidence is absent",
            evidence=[evidence_path],
        )
    permit_id = event.get("permit_id") if isinstance(event.get("permit_id"), str) else None
    reason, schema_message = _permit_revoked_schema_error(event)
    if reason is not None:
        verdict = (
            "insufficient_evidence"
            if reason == "PERMIT_REVOKED_EVIDENCE_MISSING"
            else "unverifiable_scope"
            if reason == "PERMIT_REVOKED_ACTOR_KIND_UNSUPPORTED"
            else "disproved"
        )
        return _permit_claim(
            PERMIT_REVOKED_CLAIM_NAME,
            subject_type="permit_revocation",
            subject_id=permit_id,
            verdict=verdict,
            reason_code=reason,
            message=schema_message or "revocation event schema validation failed",
            evidence=[evidence_path],
        )

    declared_project_id = _string_field(export_document.get("project_id"), manifest.get("project_id"))
    declared_permit_id = _string_field(export_document.get("permit_id"))
    if declared_project_id is not None and event["project_id"] != declared_project_id:
        return _permit_claim(
            PERMIT_REVOKED_CLAIM_NAME,
            subject_type="permit_revocation",
            subject_id=permit_id,
            verdict="disproved",
            reason_code="PERMIT_REVOKED_PROJECT_ID_MISMATCH",
            message="revocation project_id does not match the declared project scope",
            evidence=[evidence_path, "project_id"],
        )
    if declared_permit_id is not None and event["permit_id"] != declared_permit_id:
        return _permit_claim(
            PERMIT_REVOKED_CLAIM_NAME,
            subject_type="permit_revocation",
            subject_id=permit_id,
            verdict="disproved",
            reason_code="PERMIT_REVOKED_PERMIT_ID_MISMATCH",
            message="revocation permit_id does not match the declared permit scope",
            evidence=[evidence_path, "permit_id"],
        )
    if event["effective_at"] != event["revoked_at"]:
        return _permit_claim(
            PERMIT_REVOKED_CLAIM_NAME,
            subject_type="permit_revocation",
            subject_id=permit_id,
            verdict="disproved",
            reason_code="PERMIT_REVOKED_EFFECTIVE_AT_MISMATCH",
            message="v1 revocation requires effective_at to equal revoked_at",
            evidence=[evidence_path, "effective_at", "revoked_at"],
        )

    signed_payload = {key: event[key] for key in _PERMIT_REVOKED_REQUIRED_FIELDS if key != "signature"}
    canonical_hash = _compute_canonical_binding_hash(signed_payload)
    if declared_canonical_hash is not None and declared_canonical_hash != canonical_hash:
        return _permit_claim(
            PERMIT_REVOKED_CLAIM_NAME,
            subject_type="permit_revocation",
            subject_id=permit_id,
            verdict="disproved",
            reason_code="PERMIT_REVOKED_SIGNATURE_INVALID",
            message="declared revocation canonical hash does not match the signed payload",
            evidence=[evidence_path, "revocation_canonical_hash"],
        )

    candidates, key_error = _permit_binding_key_candidates(
        key_manifest_source=key_manifest_source,
        signing_time=_parse_iso_or_none(event["revoked_at"]),
    )
    if key_error is not None:
        return _permit_claim(
            PERMIT_REVOKED_CLAIM_NAME,
            subject_type="permit_revocation",
            subject_id=permit_id,
            verdict="insufficient_evidence",
            reason_code="PERMIT_REVOKED_TRUST_ROOT_UNRESOLVABLE",
            message=key_error,
            evidence=[evidence_path, "trust_root"],
        )
    signature = str(event["signature"])
    if not any(
        _verify_ed25519(
            str(candidate["public_key"]),
            canonical_hash.encode("utf-8"),
            signature,
        )
        for candidate in candidates
    ):
        return _permit_claim(
            PERMIT_REVOKED_CLAIM_NAME,
            subject_type="permit_revocation",
            subject_id=permit_id,
            verdict="disproved",
            reason_code="PERMIT_REVOKED_SIGNATURE_INVALID",
            message="permit.revoked signature does not verify under an active permit-binding key",
            evidence=[evidence_path, "signature", "trust_root"],
        )

    return _permit_claim(
        PERMIT_REVOKED_CLAIM_NAME,
        subject_type="permit_revocation",
        subject_id=permit_id,
        verdict="supported",
        reason_code="PERMIT_REVOKED_SUPPORTED",
        message="permit.revoked event schema, identity binding, temporal rule, and signature are supported",
        evidence=[evidence_path, "trust_root"],
    )


def _revocation_event_from_supported_claim(
    export_document: dict[str, Any],
) -> dict[str, Any] | None:
    event, _declared_hash, _path = _find_revocation_evidence(export_document)
    return event


def _absence_claim(
    *,
    segment_id: str | None,
    verdict: str,
    reason_code: str,
    message: str,
    evidence: list[str] | None = None,
) -> ClaimVerdict:
    return _permit_claim(
        PERMIT_DISPATCH_ABSENCE_CLAIM_NAME,
        subject_type="permit_dispatch_absence_after_revocation",
        subject_id=segment_id,
        verdict=verdict,
        reason_code=reason_code,
        message=message,
        evidence=evidence or ["export.scope_faithfulness", "checkpoint_scope_state"],
    )


def _absence_predicate_out_of_grammar(predicate: Any) -> bool:
    if not isinstance(predicate, dict):
        return True
    if set(predicate.keys()) != {"version", "operator", "equals", "ranges"}:
        return True
    if predicate.get("version") != SCOPE_PREDICATE_VERSION or predicate.get("operator") != "and":
        return True
    equals = predicate.get("equals")
    ranges = predicate.get("ranges")
    if not isinstance(equals, dict) or not isinstance(ranges, dict):
        return True
    if set(equals.keys()) != {"project_id", "permit_id", "event_type"}:
        return True
    if any(
        not isinstance(equals.get(field), str)
        for field in ("project_id", "permit_id", "event_type")
    ):
        return True
    if set(ranges.keys()) != {"occurred_at"}:
        return True
    occurred = ranges.get("occurred_at")
    return not (
        isinstance(occurred, dict)
        and set(occurred.keys()) == {"gte", "lt"}
        and isinstance(occurred.get("gte"), str)
        and isinstance(occurred.get("lt"), str)
    )


def _absence_predicate_matches_revocation(
    *,
    predicate: dict[str, Any],
    revocation_event: dict[str, Any],
    checkpoint: dict[str, Any],
) -> bool:
    equals = predicate["equals"]
    occurred = predicate["ranges"]["occurred_at"]
    return (
        equals.get("project_id") == revocation_event.get("project_id")
        and equals.get("permit_id") == revocation_event.get("permit_id")
        and equals.get("event_type") == DISPATCH_EGRESS_BOUND_EVENT_TYPE
        and occurred.get("gte") == revocation_event.get("effective_at")
        and occurred.get("lt") == checkpoint.get("computed_at")
    )


def _absence_bridge_record_matches_predicate(
    record: dict[str, Any],
    predicate: dict[str, Any],
) -> bool:
    return _scope_predicate_matches(record, predicate)


def _pinned_claim_requested(
    semantics: ResolvedSemantics,
    requested: set[str],
    claim_name: str,
) -> bool:
    return semantics.mode == "pinned" and claim_name in requested


def _adjudicate_permit_dispatch_absence_after_revocation_v1(
    *,
    export_document: dict[str, Any],
    manifest: dict[str, Any],
    manifest_path: Path,
    key_manifest_source: str | None,
    semantics_dispatch: SemanticsDispatch | None = None,
    explicit_sidecar: str | None = None,
    explicit_checkpoint: str | None = None,
    scope_claims: list[ClaimVerdict] | None = None,
    revocation_claim: ClaimVerdict | None = None,
) -> ClaimVerdict:
    if revocation_claim is None:
        revocation_claim = _adjudicate_permit_revoked_v1(
            export_document=export_document,
            manifest=manifest,
            key_manifest_source=key_manifest_source,
        )
    if revocation_claim.aggregate_verdict != verdict_value("supported"):
        reason = revocation_claim.reason_code or "PERMIT_REVOKED_EVIDENCE_MISSING"
        return _absence_claim(
            segment_id=None,
            verdict="insufficient_evidence",
            reason_code=reason,
            message="permit.revoked.v1 evidence is required before absence can be adjudicated",
            evidence=["permit.revoked.v1"],
        )
    revocation_event = _revocation_event_from_supported_claim(export_document)
    if revocation_event is None:
        return _absence_claim(
            segment_id=None,
            verdict="insufficient_evidence",
            reason_code="PERMIT_REVOKED_EVIDENCE_MISSING",
            message="supported revocation claim did not expose revocation event evidence",
            evidence=["permit.revoked.v1"],
        )

    checkpoint = _resolve_scope_checkpoint(
        manifest_path=manifest_path,
        explicit_checkpoint=explicit_checkpoint,
    )
    if checkpoint is None:
        return _absence_claim(
            segment_id=None,
            verdict="insufficient_evidence",
            reason_code="CHECKPOINT_SCOPE_STATE_CHECKPOINT_MISSING",
            message="referenced checkpoint artifact is absent",
            evidence=["checkpoint"],
        )
    if scope_claims is None:
        scope_claims = _adjudicate_export_scope_faithfulness_v1(
            export_data=_canonical_json_bytes(export_document),
            manifest=manifest,
            manifest_path=manifest_path,
            key_manifest_source=key_manifest_source,
            semantics_dispatch=semantics_dispatch,
            explicit_sidecar=explicit_sidecar,
            explicit_checkpoint=explicit_checkpoint,
        )
    blocking_scope = [
        claim
        for claim in scope_claims
        if claim.name in {"checkpoint.scope_state.v1", "export.scope_faithfulness.v1"}
        and claim.aggregate_verdict != verdict_value("supported")
        and claim.reason_code != "EXPORT_PROOF_BRIDGE_MISCLASSIFIED"
    ]
    if blocking_scope:
        first = blocking_scope[0]
        return _absence_claim(
            segment_id=None,
            verdict="insufficient_evidence",
            reason_code=first.reason_code or "EXPORT_SCOPE_DECLARATION_MISSING",
            message=first.message or "scope dependency is not supported",
            evidence=[first.name],
        )

    block = export_document.get("scope_faithfulness")
    segments = block.get("segments") if isinstance(block, dict) else None
    if not isinstance(segments, list):
        return _absence_claim(
            segment_id=None,
            verdict="insufficient_evidence",
            reason_code="EXPORT_SCOPE_DECLARATION_MISSING",
            message="absence claim requires a scope_faithfulness segment",
            evidence=["export.scope_faithfulness"],
        )

    matching_segment: dict[str, Any] | None = None
    for raw_segment in segments:
        segment = _normalize_scope_segment(raw_segment)
        if not isinstance(segment, dict):
            continue
        declared_scope = segment.get("declared_scope")
        predicate = declared_scope.get("predicate") if isinstance(declared_scope, dict) else None
        if _absence_predicate_out_of_grammar(predicate):
            return _absence_claim(
                segment_id=segment.get("segment_id") if isinstance(segment.get("segment_id"), str) else None,
                verdict="unverifiable_scope",
                reason_code="EXPORT_SCOPE_PREDICATE_OUT_OF_GRAMMAR",
                message="absence predicate must use v1 equality on project_id, permit_id, event_type and a bounded occurred_at range",
                evidence=["export.scope_faithfulness.declared_scope.predicate"],
            )
        assert isinstance(predicate, dict)
        if _absence_predicate_matches_revocation(
            predicate=predicate,
            revocation_event=revocation_event,
            checkpoint=checkpoint,
        ):
            matching_segment = segment
            break

    if matching_segment is None:
        return _absence_claim(
            segment_id=None,
            verdict="insufficient_evidence",
            reason_code="EXPORT_SCOPE_COMMITMENT_MISSING",
            message="no scope-faithfulness segment declares the required post-revocation dispatch predicate",
            evidence=["export.scope_faithfulness.segments"],
        )

    segment_id = (
        matching_segment.get("segment_id")
        if isinstance(matching_segment.get("segment_id"), str)
        else None
    )
    reference = matching_segment.get("scope_state_reference")
    if not isinstance(reference, dict):
        return _absence_claim(
            segment_id=segment_id,
            verdict="insufficient_evidence",
            reason_code="CHECKPOINT_SCOPE_STATE_MISSING",
            message="absence segment has no scope-state reference",
            evidence=["export.scope_faithfulness.scope_state_reference"],
        )
    sidecar, _sidecar_bytes = _resolve_scope_sidecar(
        manifest_path=manifest_path,
        reference=reference,
        explicit_sidecar=explicit_sidecar,
    )
    if sidecar is None:
        return _absence_claim(
            segment_id=segment_id,
            verdict="insufficient_evidence",
            reason_code="CHECKPOINT_SCOPE_STATE_MISSING",
            message="absence segment references an absent scope-state sidecar",
            evidence=["checkpoint_scope_state"],
        )

    predicate = matching_segment["declared_scope"]["predicate"]
    predicate_value_hash = _predicate_hash(predicate)
    commitments = sidecar.get("scope_commitments")
    commitment = next(
        (
            item
            for item in commitments
            if isinstance(item, dict)
            and item.get("predicate_value_hash") == predicate_value_hash
        ),
        None,
    ) if isinstance(commitments, list) else None
    if commitment is None:
        return _absence_claim(
            segment_id=segment_id,
            verdict="insufficient_evidence",
            reason_code="EXPORT_SCOPE_COMMITMENT_MISSING",
            message="sidecar has no commitment for the absence predicate",
            evidence=["checkpoint_scope_state.scope_commitments"],
        )

    evidence = matching_segment.get("chain_evidence")
    disclosures = evidence.get("disclosure_records") if isinstance(evidence, dict) else []
    bridges = evidence.get("proof_bridge_records") if isinstance(evidence, dict) else []
    if not isinstance(disclosures, list) or not isinstance(bridges, list):
        return _absence_claim(
            segment_id=segment_id,
            verdict="insufficient_evidence",
            reason_code="EXPORT_SCOPE_DECLARATION_SCHEMA_INVALID",
            message="absence segment chain_evidence is malformed",
            evidence=["export.scope_faithfulness.chain_evidence"],
        )
    for record in disclosures:
        if isinstance(record, dict) and _scope_predicate_matches(record, predicate):
            return _absence_claim(
                segment_id=segment_id,
                verdict="disproved",
                reason_code="EXPORT_SCOPE_POST_REVOCATION_DISPATCH_PRESENT",
                message="a disclosed dispatch.egress_bound record is at or after revocation effective_at",
                evidence=["export.scope_faithfulness.chain_evidence.disclosure_records"],
            )
    for record in bridges:
        if isinstance(record, dict) and _absence_bridge_record_matches_predicate(record, predicate):
            return _absence_claim(
                segment_id=segment_id,
                verdict="disproved",
                reason_code="EXPORT_SCOPE_BRIDGE_RECORD_MATCHES_PREDICATE",
                message="a bridge or proof record satisfies the post-revocation dispatch predicate",
                evidence=["export.scope_faithfulness.chain_evidence.proof_bridge_records"],
            )

    matching_count = commitment.get("matching_count")
    if not _is_nonbool_int(matching_count):
        return _absence_claim(
            segment_id=segment_id,
            verdict="insufficient_evidence",
            reason_code="EXPORT_SCOPE_COMMITMENT_MISSING",
            message="sidecar matching_count is missing or malformed for the absence predicate",
            evidence=["checkpoint_scope_state.scope_commitments.matching_count"],
        )
    if int(matching_count) > 0:
        return _absence_claim(
            segment_id=segment_id,
            verdict="disproved",
            reason_code="EXPORT_SCOPE_POST_REVOCATION_DISPATCH_PRESENT",
            message="sidecar matching_count reports one or more post-revocation dispatch records",
            evidence=["checkpoint_scope_state.scope_commitments.matching_count"],
        )

    return _absence_claim(
        segment_id=segment_id,
        verdict="supported",
        reason_code="PERMIT_DISPATCH_ABSENCE_AFTER_REVOCATION_SUPPORTED",
        message="scope-faithful absence adjudication found no matching post-revocation dispatch initiation",
        evidence=["permit.revoked.v1", "checkpoint.scope_state.v1", "export.scope_faithfulness.v1"],
    )


def _entry_permit_id(context: dict[str, Any]) -> str | None:
    entry = context["entry"]
    payload = _entry_payload(entry)
    permit_id = payload.get("permit_id")
    if isinstance(permit_id, str) and permit_id:
        return permit_id
    return context.get("record_permit_id")


def _digest_value(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _digest_candidates(
    contexts: list[dict[str, Any]],
    *,
    permit_id: str,
    event_types: tuple[str, ...],
) -> list[dict[str, Any]]:
    accepted = set(event_types)
    return [
        context
        for context in contexts
        if _entry_permit_id(context) == permit_id
        and context["entry"].get("event_type") in accepted
    ]


def _verify_closure_digest_reference(
    *,
    closure_payload: dict[str, Any],
    contexts: list[dict[str, Any]],
    permit_id: str,
    field: str,
    event_types: tuple[str, ...],
) -> int | None:
    closure_status = str(closure_payload.get("closure_status") or "").strip().lower()
    if closure_status == CLOSURE_STATUS_MISSING_CLOSURE:
        return None

    closure_digest = _digest_value(closure_payload.get(field))
    if closure_digest is None:
        if closure_status == CLOSURE_STATUS_CLOSED:
            return _walk_fail(
                WALK_CLOSURE_DIGEST_MISSING,
                f"permit_id={permit_id} closure_status=closed missing {field}",
            )
        return None

    candidates = _digest_candidates(
        contexts,
        permit_id=permit_id,
        event_types=event_types,
    )
    if not candidates:
        return _walk_fail(
            WALK_CLOSURE_DIGEST_MISSING,
            (
                f"permit_id={permit_id} missing "
                f"{'/'.join(event_types)} evidence for {field}"
            ),
        )

    candidate_values = [
        _digest_value(_entry_payload(context["entry"]).get(field))
        for context in candidates
    ]
    present_values = [value for value in candidate_values if value is not None]
    if not present_values:
        return _walk_fail(
            WALK_CLOSURE_DIGEST_MISSING,
            (
                f"permit_id={permit_id} {'/'.join(event_types)} evidence "
                f"missing {field}"
            ),
        )
    if closure_digest not in present_values:
        return _walk_fail(
            WALK_CLOSURE_DIGEST_MISMATCH,
            (
                f"permit_id={permit_id} {field} mismatch "
                f"closure={closure_digest} events={present_values}"
            ),
        )
    return None


def _verify_closure_dispatch_digest_reference(
    *,
    closure_payload: dict[str, Any],
    closure_context: dict[str, Any],
    permit_id: str,
) -> int | None:
    closure_status = str(closure_payload.get("closure_status") or "").strip().lower()
    if closure_status == CLOSURE_STATUS_MISSING_CLOSURE:
        return None

    closure_digest = _digest_value(
        closure_payload.get("dispatch_request_digest_v1")
    )
    if closure_digest is None:
        if closure_status == CLOSURE_STATUS_CLOSED:
            return _walk_fail(
                WALK_CLOSURE_DIGEST_MISSING,
                (
                    f"permit_id={permit_id} closure_status=closed missing "
                    "dispatch_request_digest_v1"
                ),
            )
        print(
            "WARNING: "
            f"permit_id={permit_id} closure_status={closure_status or 'unknown'} "
            "missing dispatch_request_digest_v1; abnormal closures should carry "
            "the dispatch-time request digest when dispatch occurred.",
            file=sys.stderr,
        )
        return None

    record_digest = _digest_value(
        closure_context.get("record_binding_request_hash")
    )
    if record_digest is None:
        return _walk_fail(
            WALK_CLOSURE_DIGEST_MISSING,
            (
                f"permit_id={permit_id} export permit missing binding_request_hash "
                "for dispatch_request_digest_v1"
            ),
        )
    if closure_digest != record_digest:
        return _walk_fail(
            WALK_CLOSURE_DISPATCH_DIGEST_MISMATCH,
            (
                "permit_id="
                f"{permit_id} dispatch_request_digest_v1 mismatch "
                f"closure={closure_digest} binding_request_hash={record_digest}"
            ),
        )
    return None


def _verify_closure_v1(
    *,
    closure_context: dict[str, Any],
    contexts: list[dict[str, Any]],
    args: argparse.Namespace,
) -> int | None:
    closure_entry = closure_context["entry"]
    closure_payload = _entry_payload(closure_entry)
    permit_id = closure_payload.get("permit_id")
    if not isinstance(permit_id, str) or not permit_id:
        return _walk_fail(
            WALK_CLOSURE_SIGNATURE_INVALID,
            f"event_id={_entry_id(closure_entry)} permit_id missing",
        )

    ok, reason = _verify_closure_v1_signature(payload=closure_payload, args=args)
    if not ok:
        return _walk_fail(
            WALK_CLOSURE_SIGNATURE_INVALID,
            f"permit_id={permit_id} event_id={_entry_id(closure_entry)} {reason}",
        )

    if closure_payload.get("provider_response_digest_semantics") not in {
        PROVIDER_RESPONSE_DIGEST_SEMANTICS,
        None,
    }:
        return _walk_fail(
            WALK_CLOSURE_DIGEST_MISMATCH,
            f"permit_id={permit_id} provider_response_digest_semantics mismatch",
        )
    if closure_payload.get("client_response_digest_semantics") not in {
        CLIENT_RESPONSE_DIGEST_SEMANTICS,
        None,
    }:
        return _walk_fail(
            WALK_CLOSURE_DIGEST_MISMATCH,
            f"permit_id={permit_id} client_response_digest_semantics mismatch",
        )

    for field, event_types in (
        (
            "provider_response_digest_v1",
            ("provider.response.received", "execution.completed"),
        ),
        (
            "client_response_digest_v1",
            ("client.response.delivered", "execution.completed"),
        ),
    ):
        failure = _verify_closure_digest_reference(
            closure_payload=closure_payload,
            contexts=contexts,
            permit_id=permit_id,
            field=field,
            event_types=event_types,
        )
        if failure is not None:
            return failure
    return None


def _verify_closure_v2(
    *,
    closure_context: dict[str, Any],
    contexts: list[dict[str, Any]],
    args: argparse.Namespace,
) -> int | None:
    closure_entry = closure_context["entry"]
    closure_payload = _entry_payload(closure_entry)
    permit_id = closure_payload.get("permit_id")
    if not isinstance(permit_id, str) or not permit_id:
        return _walk_fail(
            WALK_CLOSURE_SIGNATURE_INVALID,
            f"event_id={_entry_id(closure_entry)} permit_id missing",
        )

    ok, reason = _verify_closure_v2_signature(payload=closure_payload, args=args)
    if not ok:
        return _walk_fail(
            WALK_CLOSURE_SIGNATURE_INVALID,
            f"permit_id={permit_id} event_id={_entry_id(closure_entry)} {reason}",
        )

    if (
        closure_payload.get("dispatch_request_digest_semantics")
        != DISPATCH_REQUEST_DIGEST_SEMANTICS
    ):
        return _walk_fail(
            WALK_CLOSURE_DIGEST_MISMATCH,
            f"permit_id={permit_id} dispatch_request_digest_semantics mismatch",
        )
    if closure_payload.get("provider_response_digest_semantics") not in {
        PROVIDER_RESPONSE_DIGEST_SEMANTICS,
        None,
    }:
        return _walk_fail(
            WALK_CLOSURE_DIGEST_MISMATCH,
            f"permit_id={permit_id} provider_response_digest_semantics mismatch",
        )
    if closure_payload.get("client_response_digest_semantics") not in {
        CLIENT_RESPONSE_DIGEST_SEMANTICS,
        None,
    }:
        return _walk_fail(
            WALK_CLOSURE_DIGEST_MISMATCH,
            f"permit_id={permit_id} client_response_digest_semantics mismatch",
        )

    failure = _verify_closure_dispatch_digest_reference(
        closure_payload=closure_payload,
        closure_context=closure_context,
        permit_id=permit_id,
    )
    if failure is not None:
        return failure

    for field, event_types in (
        (
            "provider_response_digest_v1",
            ("provider.response.received", "execution.completed"),
        ),
        (
            "client_response_digest_v1",
            ("client.response.delivered", "execution.completed"),
        ),
    ):
        failure = _verify_closure_digest_reference(
            closure_payload=closure_payload,
            contexts=contexts,
            permit_id=permit_id,
            field=field,
            event_types=event_types,
        )
        if failure is not None:
            return failure
    return None


PERMANENT_ALLOWLIST = make_permanent_allowlist(
    record_hash_v1=_compute_record_hash_v1,
    closure_v1=_verify_closure_v1,
    closure_v2=_verify_closure_v2,
    composite_hash=_composite_hash,
    governance_event_integrity_hash=_compute_governance_event_integrity_hash,
    integrity_batch_hash=_compute_integrity_batch_hash,
    authority_envelope_v0=compare_authority_envelopes,
)


def _legacy_dispatch() -> SemanticsDispatch:
    semantics = resolve_pack_semantics(
        {},
        pack_root=None,
        default_claim_names=tuple(CLAIM_SEMANTICS),
        allowlist=PERMANENT_ALLOWLIST,
    )
    if not semantics.ok:
        failure = semantics.failure
        raise RuntimeError(
            failure.message if failure is not None else "legacy semantics unresolved"
        )
    return semantics.dispatch()


def _verify_export_closures(
    export_data: bytes,
    args: argparse.Namespace,
    semantics_dispatch: SemanticsDispatch | None = None,
) -> int:
    if semantics_dispatch is None:
        semantics_dispatch = _legacy_dispatch()
    closure_verifiers = semantics_dispatch.closure_verifiers
    bundle, bundle_result = _load_audit_export_bundle_for_optional_check(
        export_data,
        label="VERIFY-CLOSURE",
    )
    if bundle_result is not None:
        return bundle_result
    assert bundle is not None

    contexts, flatten_result = _flatten_chain_entries(bundle)
    if flatten_result is not None:
        return flatten_result
    assert contexts is not None

    closures_checked = 0
    digest_checks = 0
    dispatch_digest_checks = 0
    dispatch_digest_warnings = 0
    chain_scopes: set[str] = set()
    for context in contexts:
        entry = context["entry"]
        if entry.get("event_type") != "permit.closed":
            continue
        payload = _entry_payload(entry)
        binding_version = payload.get("binding_version")
        verifier = closure_verifiers.get(binding_version)
        if verifier is None:
            return _walk_fail(
                WALK_UNKNOWN_CLOSURE_FORMAT,
                (
                    f"event_id={_entry_id(entry)} "
                    f"permit_id={payload.get('permit_id')} "
                    f"binding_version={binding_version!r}"
                ),
            )
        failure = verifier(closure_context=context, contexts=contexts, args=args)
        if failure is not None:
            return failure
        closures_checked += 1
        chain_scopes.add(_scope_label(entry.get("chain_scope")))
        closure_status = str(payload.get("closure_status") or "").strip().lower()
        if closure_status != CLOSURE_STATUS_MISSING_CLOSURE:
            if _digest_value(payload.get("provider_response_digest_v1")) is not None:
                digest_checks += 1
            if _digest_value(payload.get("client_response_digest_v1")) is not None:
                digest_checks += 1
            if binding_version in {"closure_v2", CLOSURE_RFC8785_BINDING_VERSION}:
                if _digest_value(payload.get("dispatch_request_digest_v1")) is not None:
                    dispatch_digest_checks += 1
                elif closure_status != CLOSURE_STATUS_CLOSED:
                    dispatch_digest_warnings += 1

    print("VERIFY-CLOSURE: VERIFIED")
    print(f"  chain_scopes:        {len(chain_scopes)}")
    print(f"  closures_verified:   {closures_checked}")
    print(f"  signature_checks:    {closures_checked} PASS")
    print(f"  digest_checks:       {digest_checks} PASS")
    if dispatch_digest_checks:
        print("  dispatch_digest_check: PASS")
    else:
        print("  dispatch_digest_check: SKIPPED")
    if dispatch_digest_warnings:
        print(f"  dispatch_digest_warnings: {dispatch_digest_warnings}")
    return 0


@dataclass(frozen=True)
class _WorkflowEvidenceIndex:
    declarations: dict[str, dict[str, Any]]
    amendments_by_declaration: dict[str, list[dict[str, Any]]]


def _workflow_fail(code: str, message: str) -> int:
    print(f"FAILED: {code}: {message}", file=sys.stderr)
    return 1


def _strip_none(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _strip_none(item)
            for key, item in value.items()
            if item is not None
        }
    if isinstance(value, list):
        return [_strip_none(item) for item in value]
    return value


def _canonical_workflow_json(value: Any) -> str:
    return json.dumps(
        _strip_none(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _normalize_sha256_hex(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.startswith("sha256:"):
        text = text.removeprefix("sha256:")
    return text or None


def _required_workflow_str(record: dict[str, Any], field: str) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def _optional_workflow_str(record: dict[str, Any], field: str) -> str | None:
    value = record.get(field)
    if value is None:
        return None
    if isinstance(value, str):
        return value
    raise ValueError(f"{field} must be a string or null")


def _optional_workflow_int(record: dict[str, Any], field: str) -> int | None:
    value = record.get(field)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer or null")
    if value < 0:
        raise ValueError(f"{field} must be non-negative")
    return value


def _required_workflow_int(record: dict[str, Any], field: str) -> int:
    value = _optional_workflow_int(record, field)
    if value is None:
        raise ValueError(f"{field} must be an integer")
    return value


def _workflow_declaration_id(record: dict[str, Any]) -> str:
    value = record.get("workflow_declaration_id", record.get("id"))
    if not isinstance(value, str) or not value.strip():
        raise ValueError("workflow_declaration_id must be a non-empty string")
    return value.strip()


def _workflow_amendment_id(record: dict[str, Any]) -> str:
    value = record.get("workflow_amendment_id", record.get("id"))
    if not isinstance(value, str) or not value.strip():
        raise ValueError("workflow_amendment_id must be a non-empty string")
    return value.strip()


def _workflow_project_id(record: dict[str, Any]) -> str:
    return _required_workflow_str(record, "project_id")


def _workflow_datetime_sort_key(record: dict[str, Any], field: str) -> datetime:
    parsed = _parse_iso_or_none(record.get(field))
    if parsed is None:
        raise ValueError(f"{field} must be an ISO-8601 timestamp")
    return parsed


def _workflow_issued_at_candidates(value: Any) -> list[str]:
    candidates: list[str] = []
    if isinstance(value, str) and value.strip():
        candidates.append(value.strip())
    parsed = _parse_iso_or_none(value)
    if parsed is not None:
        normalized = parsed.astimezone(timezone.utc).isoformat()
        if normalized not in candidates:
            candidates.append(normalized)
    return candidates


def _workflow_principal_payload(
    record: dict[str, Any],
    *,
    object_field: str,
    api_key_field: str,
    dashboard_session_field: str,
) -> dict[str, Any]:
    principal = record.get(object_field)
    if isinstance(principal, dict):
        principal_type = principal.get("type")
        principal_id = principal.get("id")
        if principal_type == "api_key" and isinstance(principal_id, str):
            return {"api_key_id": principal_id}
        if principal_type == "dashboard_session" and isinstance(principal_id, str):
            return {"dashboard_session_id": principal_id}

    return _strip_none(
        {
            "api_key_id": record.get(api_key_field),
            "dashboard_session_id": record.get(dashboard_session_field),
        }
    )


def _workflow_declaration_intent(record: dict[str, Any]) -> dict[str, Any]:
    for field in ("intent_json", "intent"):
        value = record.get(field)
        if isinstance(value, dict):
            return _strip_none(dict(value))

    intent = _strip_none(
        {
            "expected_calls": record.get("expected_calls"),
            "max_calls": record.get("max_calls"),
            "expected_model": record.get("expected_model"),
            "expected_input_tokens_per_call": record.get(
                "expected_input_tokens_per_call"
            ),
            "expected_output_tokens_per_call": record.get(
                "expected_output_tokens_per_call"
            ),
            "max_duration_seconds": record.get("max_duration_seconds"),
        }
    )
    if not isinstance(intent, dict):
        raise ValueError("workflow intent must be an object")
    return intent


def _validate_workflow_intent(intent: dict[str, Any]) -> None:
    expected_calls = intent.get("expected_calls")
    max_calls = intent.get("max_calls")
    for field, value in (
        ("expected_calls", expected_calls),
        ("max_calls", max_calls),
        ("expected_input_tokens_per_call", intent.get("expected_input_tokens_per_call")),
        ("expected_output_tokens_per_call", intent.get("expected_output_tokens_per_call")),
        ("max_duration_seconds", intent.get("max_duration_seconds")),
    ):
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"intent.{field} must be a non-negative integer")
    if expected_calls is None and max_calls is None:
        raise ValueError("intent requires expected_calls or max_calls")
    if expected_calls is not None and max_calls is not None and expected_calls > max_calls:
        raise ValueError("intent.expected_calls must be <= intent.max_calls")
    expected_model = intent.get("expected_model")
    if expected_model is not None and not isinstance(expected_model, str):
        raise ValueError("intent.expected_model must be a string or null")


def _workflow_projected_cost(record: dict[str, Any]) -> dict[str, Any]:
    projected = record.get("projected_cost")
    if isinstance(projected, dict):
        return _strip_none(dict(projected))
    return _strip_none(
        {
            "amount_micros": record.get("projection_amount_micros"),
            "currency": record.get("projection_currency", "USD"),
            "methodology": record.get("projection_methodology"),
        }
    )


def _workflow_declaration_payload_candidates(
    record: dict[str, Any],
    *,
    binding_key_id: str,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    signed_payload = record.get("signed_payload")
    if isinstance(signed_payload, dict):
        payload = dict(signed_payload)
        payload.setdefault("binding_key_id", binding_key_id)
        candidates.append(payload)

    intent = _workflow_declaration_intent(record)
    declared_by = _workflow_principal_payload(
        record,
        object_field="declared_by",
        api_key_field="declared_by_api_key_id",
        dashboard_session_field="declared_by_dashboard_session_id",
    )
    issued_at_values = _workflow_issued_at_candidates(
        record.get("declaration_signed_at")
        or record.get("declared_at")
        or record.get("created_at")
    )
    for issued_at in issued_at_values:
        candidates.append(
            {
                "binding_version": WORKFLOW_DECLARATION_BINDING_VERSION,
                "project_id": _workflow_project_id(record),
                "workflow_id": _required_workflow_str(record, "workflow_id"),
                "intent": intent,
                "budget_envelope_id": record.get("budget_envelope_id"),
                "declared_by": declared_by,
                "projected_cost": _workflow_projected_cost(record),
                "status": _required_workflow_str(record, "status"),
                "issued_at": issued_at,
                "binding_key_id": binding_key_id,
            }
        )
    return candidates


def _workflow_amendment_delta(record: dict[str, Any]) -> dict[str, Any]:
    delta = record.get("delta")
    if isinstance(delta, dict):
        return _strip_none(dict(delta))
    return _strip_none(
        {
            "applied_against_version": record.get("applied_against_version"),
            "previous_max_calls": record.get("previous_max_calls"),
            "new_max_calls": record.get("new_max_calls"),
            "previous_expected_calls": record.get("previous_expected_calls"),
            "new_expected_calls": record.get("new_expected_calls"),
            "reason_provided": record.get("reason_provided"),
        }
    )


def _workflow_amendment_payload_candidates(
    record: dict[str, Any],
    *,
    binding_key_id: str,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    signed_payload = record.get("signed_payload")
    if isinstance(signed_payload, dict):
        payload = dict(signed_payload)
        payload.setdefault("binding_key_id", binding_key_id)
        candidates.append(payload)

    amendment_id = _workflow_amendment_id(record)
    declaration_id = _workflow_declaration_id(record)
    project_id = _workflow_project_id(record)
    delta = _workflow_amendment_delta(record)
    amended_by = _workflow_principal_payload(
        record,
        object_field="amended_by",
        api_key_field="amended_by_api_key_id",
        dashboard_session_field="amended_by_dashboard_session_id",
    )
    issued_at_values = _workflow_issued_at_candidates(
        record.get("amendment_signed_at") or record.get("created_at")
    )
    for issued_at in issued_at_values:
        base = {
            "binding_version": WORKFLOW_AMENDMENT_BINDING_VERSION,
            "project_id": project_id,
            "workflow_declaration_id": declaration_id,
            "amended_by": amended_by,
            "issued_at": issued_at,
            "binding_key_id": binding_key_id,
        }
        candidates.append({**base, "delta": delta})
        candidates.append({**base, "workflow_amendment_id": amendment_id, "delta": delta})
        candidates.append({**base, **delta})
        candidates.append({**base, "workflow_amendment_id": amendment_id, **delta})
    return candidates


def _verify_workflow_signed_record(
    *,
    record: dict[str, Any],
    canonical_hash_field: str,
    signature_field: str,
    signing_time_field: str,
    args: argparse.Namespace,
    payload_candidates,
    record_label: str,
) -> int | None:
    canonical_hash = _normalize_sha256_hex(record.get(canonical_hash_field))
    signature = record.get(signature_field)
    if canonical_hash is None:
        return _workflow_fail(
            WORKFLOW_SIGNATURE_INVALID,
            f"{record_label} missing {canonical_hash_field}",
        )
    if not isinstance(signature, str) or not signature.strip():
        return _workflow_fail(
            WORKFLOW_SIGNATURE_INVALID,
            f"{record_label} missing {signature_field}",
        )

    artifact_key_id = (
        record.get("binding_key_id")
        if isinstance(record.get("binding_key_id"), str)
        else record.get("key_id")
        if isinstance(record.get("key_id"), str)
        else None
    )
    signing_time = _parse_iso_or_none(record.get(signing_time_field))
    trusted_pub, trust_source, err = _resolve_trust_key(
        artifact_pub=None,
        artifact_key_id=artifact_key_id,
        purpose=PERMIT_BINDING_SIGNING_PURPOSE,
        expected_public_key=None,
        public_key_url=None,
        key_manifest_source=_key_manifest_source_for_args(args),
        signing_time=signing_time,
    )
    if err is not None or trusted_pub is None:
        return _workflow_fail(
            WORKFLOW_SIGNATURE_INVALID,
            f"{record_label} {err}",
        )

    try:
        binding_key_id = _binding_key_id_from_public_key(trusted_pub)
    except Exception as exc:
        return _workflow_fail(
            WORKFLOW_SIGNATURE_INVALID,
            f"{record_label} invalid permit-binding public key: {exc}",
        )
    if artifact_key_id is not None and artifact_key_id != binding_key_id:
        return _workflow_fail(
            WORKFLOW_SIGNATURE_INVALID,
            (
                f"{record_label} binding_key_id mismatch "
                f"expected={artifact_key_id} actual={binding_key_id}"
            ),
        )

    candidates = payload_candidates(record, binding_key_id=binding_key_id)
    recomputed_hashes = [
        _compute_canonical_binding_hash(candidate) for candidate in candidates
    ]
    if canonical_hash not in recomputed_hashes:
        return _workflow_fail(
            WORKFLOW_SIGNATURE_INVALID,
            (
                f"{record_label} canonical_hash mismatch "
                f"actual={canonical_hash}"
            ),
        )

    if not _verify_ed25519(trusted_pub, canonical_hash.encode("utf-8"), signature):
        return _workflow_fail(
            WORKFLOW_SIGNATURE_INVALID,
            f"{record_label} Ed25519 signature invalid ({trust_source})",
        )
    return None


def _validate_workflow_declaration_record(
    record: dict[str, Any],
    *,
    require_effective_hash: bool,
) -> None:
    _required_workflow_str(record, "workflow_id")
    _workflow_declaration_id(record)
    _workflow_project_id(record)
    status = _required_workflow_str(record, "status")
    if status not in {"active", "completed", "expired", "rejected"}:
        raise ValueError("status must be active, completed, expired, or rejected")
    intent = _workflow_declaration_intent(record)
    _validate_workflow_intent(intent)
    _required_workflow_int(record, "version")
    _optional_workflow_int(record, "cached_actual_calls")
    _optional_workflow_int(record, "projection_amount_micros")
    _optional_workflow_str(record, "declaration_canonical_hash")
    _optional_workflow_str(record, "declaration_signature_b64")
    if _parse_iso_or_none(record.get("declaration_signed_at")) is None:
        raise ValueError("declaration_signed_at must be an ISO-8601 timestamp")
    if require_effective_hash and _normalize_sha256_hex(record.get("effective_intent_hash")) is None:
        raise ValueError("effective_intent_hash must be a non-empty string")


def _validate_workflow_amendment_record(record: dict[str, Any]) -> None:
    _workflow_amendment_id(record)
    _workflow_declaration_id(record)
    _workflow_project_id(record)
    _required_workflow_int(record, "applied_against_version")
    _optional_workflow_int(record, "previous_max_calls")
    _optional_workflow_int(record, "new_max_calls")
    _optional_workflow_int(record, "previous_expected_calls")
    _optional_workflow_int(record, "new_expected_calls")
    reason = record.get("reason_provided")
    if reason is not None and not isinstance(reason, str):
        raise ValueError("reason_provided must be a string or null")
    if _parse_iso_or_none(record.get("created_at")) is None:
        raise ValueError("created_at must be an ISO-8601 timestamp")
    _optional_workflow_str(record, "amendment_canonical_hash")
    _optional_workflow_str(record, "amendment_signature_b64")


def _compute_effective_intent_hash_from_records(
    declaration: dict[str, Any],
    amendments: list[dict[str, Any]],
    *,
    before_created_at: datetime | None = None,
) -> str:
    selected: list[dict[str, Any]] = []
    for amendment in amendments:
        created_at = _workflow_datetime_sort_key(amendment, "created_at")
        if before_created_at is not None and created_at >= before_created_at:
            continue
        selected.append(amendment)

    selected.sort(
        key=lambda item: (
            _workflow_datetime_sort_key(item, "created_at"),
            _workflow_amendment_id(item),
        )
    )
    hasher = hashlib.sha256()
    hasher.update(
        _canonical_workflow_json(_workflow_declaration_intent(declaration)).encode(
            "utf-8"
        )
    )
    for amendment in selected:
        hasher.update(
            _canonical_workflow_json(_workflow_amendment_delta(amendment)).encode(
                "utf-8"
            )
        )
    return hasher.hexdigest()


def _verify_workflow_amendment_chains(
    declarations: dict[str, dict[str, Any]],
    amendments_by_declaration: dict[str, list[dict[str, Any]]],
) -> int | None:
    for declaration_id, amendments in sorted(amendments_by_declaration.items()):
        if declaration_id not in declarations:
            return _workflow_fail(
                WORKFLOW_AMENDMENT_ORDER_INVALID,
                f"workflow_declaration_id={declaration_id} has no declaration record",
            )
        previous_sort_key: tuple[datetime, str] | None = None
        expected_version = 1
        for amendment in amendments:
            amendment_id = _workflow_amendment_id(amendment)
            sort_key = (
                _workflow_datetime_sort_key(amendment, "created_at"),
                amendment_id,
            )
            if previous_sort_key is not None and sort_key < previous_sort_key:
                return _workflow_fail(
                    WORKFLOW_AMENDMENT_ORDER_INVALID,
                    (
                        f"workflow_declaration_id={declaration_id} "
                        f"workflow_amendment_id={amendment_id} is out of order"
                    ),
                )
            applied_against_version = _required_workflow_int(
                amendment,
                "applied_against_version",
            )
            if applied_against_version != expected_version:
                return _workflow_fail(
                    WORKFLOW_AMENDMENT_ORDER_INVALID,
                    (
                        f"workflow_declaration_id={declaration_id} "
                        f"workflow_amendment_id={amendment_id} "
                        f"expected_applied_against_version={expected_version} "
                        f"actual={applied_against_version}"
                    ),
                )
            previous_sort_key = sort_key
            expected_version += 1

        declaration_version = _required_workflow_int(
            declarations[declaration_id],
            "version",
        )
        if declaration_version != expected_version:
            return _workflow_fail(
                WORKFLOW_AMENDMENT_ORDER_INVALID,
                (
                    f"workflow_declaration_id={declaration_id} "
                    f"declaration version={declaration_version} does not match "
                    f"amendment history version={expected_version}"
                ),
            )
    return None


def _verify_workflow_effective_hashes(
    declarations: dict[str, dict[str, Any]],
    amendments_by_declaration: dict[str, list[dict[str, Any]]],
) -> int | None:
    for declaration_id, declaration in sorted(declarations.items()):
        expected = _compute_effective_intent_hash_from_records(
            declaration,
            amendments_by_declaration.get(declaration_id, []),
        )
        actual = _normalize_sha256_hex(declaration.get("effective_intent_hash"))
        if actual is None:
            continue
        if actual != expected:
            return _workflow_fail(
                WORKFLOW_EFFECTIVE_INTENT_HASH_MISMATCH,
                (
                    f"workflow_declaration_id={declaration_id} "
                    f"expected={expected} actual={actual}"
                ),
            )
    return None


def _verify_workflow_records(
    *,
    declarations: list[dict[str, Any]],
    amendments: list[dict[str, Any]],
    args: argparse.Namespace,
    require_declaration_effective_hash: bool,
) -> tuple[_WorkflowEvidenceIndex | None, int | None]:
    declarations_by_id: dict[str, dict[str, Any]] = {}
    amendments_by_declaration: dict[str, list[dict[str, Any]]] = {}

    for index, declaration in enumerate(declarations):
        if not isinstance(declaration, dict):
            return None, _workflow_fail(
                WORKFLOW_EVIDENCE_SCHEMA_INVALID,
                f"declarations[{index}] must be an object",
            )
        try:
            _validate_workflow_declaration_record(
                declaration,
                require_effective_hash=require_declaration_effective_hash,
            )
            declaration_id = _workflow_declaration_id(declaration)
        except ValueError as exc:
            return None, _workflow_fail(
                WORKFLOW_EVIDENCE_SCHEMA_INVALID,
                f"declarations[{index}] {exc}",
            )
        if declaration_id in declarations_by_id:
            return None, _workflow_fail(
                WORKFLOW_EVIDENCE_SCHEMA_INVALID,
                f"duplicate workflow_declaration_id={declaration_id}",
            )
        failure = _verify_workflow_signed_record(
            record=declaration,
            canonical_hash_field="declaration_canonical_hash",
            signature_field="declaration_signature_b64",
            signing_time_field="declaration_signed_at",
            args=args,
            payload_candidates=_workflow_declaration_payload_candidates,
            record_label=f"workflow_declaration_id={declaration_id}",
        )
        if failure is not None:
            return None, failure
        declarations_by_id[declaration_id] = declaration

    for index, amendment in enumerate(amendments):
        if not isinstance(amendment, dict):
            return None, _workflow_fail(
                WORKFLOW_EVIDENCE_SCHEMA_INVALID,
                f"amendments[{index}] must be an object",
            )
        try:
            _validate_workflow_amendment_record(amendment)
            declaration_id = _workflow_declaration_id(amendment)
            amendment_id = _workflow_amendment_id(amendment)
        except ValueError as exc:
            return None, _workflow_fail(
                WORKFLOW_EVIDENCE_SCHEMA_INVALID,
                f"amendments[{index}] {exc}",
            )
        failure = _verify_workflow_signed_record(
            record=amendment,
            canonical_hash_field="amendment_canonical_hash",
            signature_field="amendment_signature_b64",
            signing_time_field="created_at",
            args=args,
            payload_candidates=_workflow_amendment_payload_candidates,
            record_label=f"workflow_amendment_id={amendment_id}",
        )
        if failure is not None:
            return None, failure
        amendments_by_declaration.setdefault(declaration_id, []).append(amendment)

    chain_failure = _verify_workflow_amendment_chains(
        declarations_by_id,
        amendments_by_declaration,
    )
    if chain_failure is not None:
        return None, chain_failure
    hash_failure = _verify_workflow_effective_hashes(
        declarations_by_id,
        amendments_by_declaration,
    )
    if hash_failure is not None:
        return None, hash_failure

    return (
        _WorkflowEvidenceIndex(
            declarations=declarations_by_id,
            amendments_by_declaration=amendments_by_declaration,
        ),
        None,
    )


def _verify_workflow_evidence_document(
    document: dict[str, Any],
    *,
    args: argparse.Namespace,
    label: str,
) -> tuple[_WorkflowEvidenceIndex | None, int | None]:
    if not _is_workflow_evidence_schema(document.get("schema")):
        return None, _workflow_fail(
            WORKFLOW_EVIDENCE_SCHEMA_INVALID,
            f"{label} schema must be {WORKFLOW_EVIDENCE_SCHEMA!r}",
        )
    declarations = document.get("declarations")
    amendments = document.get("amendments")
    if not isinstance(declarations, list):
        return None, _workflow_fail(
            WORKFLOW_EVIDENCE_SCHEMA_INVALID,
            f"{label} declarations must be a list",
        )
    if not isinstance(amendments, list):
        return None, _workflow_fail(
            WORKFLOW_EVIDENCE_SCHEMA_INVALID,
            f"{label} amendments must be a list",
        )
    if document.get("declaration_count") != len(declarations):
        return None, _workflow_fail(
            WORKFLOW_EVIDENCE_SCHEMA_INVALID,
            (
                f"{label} declaration_count={document.get('declaration_count')} "
                f"does not match declarations length={len(declarations)}"
            ),
        )
    if document.get("amendment_count") != len(amendments):
        return None, _workflow_fail(
            WORKFLOW_EVIDENCE_SCHEMA_INVALID,
            (
                f"{label} amendment_count={document.get('amendment_count')} "
                f"does not match amendments length={len(amendments)}"
            ),
        )
    index, failure = _verify_workflow_records(
        declarations=declarations,
        amendments=amendments,
        args=args,
        require_declaration_effective_hash=True,
    )
    if failure is not None:
        return None, failure
    assert index is not None
    print(f"{label}: VERIFIED")
    print(f"  declarations_verified: {len(declarations)}")
    print(f"  amendments_verified:   {len(amendments)}")
    return index, None


def _extract_permit_workflow_snapshot(record: dict[str, Any]) -> dict[str, Any] | None:
    for key in ("workflow_state_json", "workflow_state"):
        value = record.get(key)
        if isinstance(value, dict):
            return value
    permit = record.get("permit")
    if isinstance(permit, dict):
        for key in ("workflow_state_json", "workflow_state"):
            value = permit.get(key)
            if isinstance(value, dict):
                return value
    return None


def _permit_created_at(record: dict[str, Any]) -> datetime | None:
    for key in ("created_at", "timestamp", "permit_created_at"):
        parsed = _parse_iso_or_none(record.get(key))
        if parsed is not None:
            return parsed
    permit = record.get("permit")
    if isinstance(permit, dict):
        for key in ("created_at", "timestamp", "permit_created_at"):
            parsed = _parse_iso_or_none(permit.get(key))
            if parsed is not None:
                return parsed
    return None


def _verify_permit_workflow_snapshots(
    permit_records: list[dict[str, Any]],
    index: _WorkflowEvidenceIndex,
    *,
    label: str,
) -> int | None:
    checked = 0
    for record_index, record in enumerate(permit_records):
        if not isinstance(record, dict):
            return _workflow_fail(
                WORKFLOW_EVIDENCE_SCHEMA_INVALID,
                f"{label} permit_records[{record_index}] must be an object",
            )
        snapshot = _extract_permit_workflow_snapshot(record)
        if snapshot is None:
            continue
        declaration_id = snapshot.get("workflow_declaration_id") or record.get(
            "workflow_declaration_id"
        )
        if not isinstance(declaration_id, str) or not declaration_id.strip():
            if snapshot.get("admission_state") == "unknown_or_inactive":
                continue
            return _workflow_fail(
                WORKFLOW_EFFECTIVE_INTENT_HASH_MISMATCH,
                f"{label} permit_records[{record_index}] missing workflow_declaration_id",
            )
        declaration_id = declaration_id.strip()
        declaration = index.declarations.get(declaration_id)
        if declaration is None:
            return _workflow_fail(
                WORKFLOW_EFFECTIVE_INTENT_HASH_MISMATCH,
                (
                    f"{label} permit_records[{record_index}] "
                    f"workflow_declaration_id={declaration_id} missing declaration"
                ),
            )
        created_at = _permit_created_at(record)
        if created_at is None:
            return _workflow_fail(
                WORKFLOW_EFFECTIVE_INTENT_HASH_MISMATCH,
                f"{label} permit_records[{record_index}] missing permit created_at",
            )
        expected_hash = _compute_effective_intent_hash_from_records(
            declaration,
            index.amendments_by_declaration.get(declaration_id, []),
            before_created_at=created_at,
        )
        actual_hash = _normalize_sha256_hex(snapshot.get("effective_intent_hash"))
        if actual_hash != expected_hash:
            return _workflow_fail(
                WORKFLOW_EFFECTIVE_INTENT_HASH_MISMATCH,
                (
                    f"{label} permit_records[{record_index}] "
                    f"workflow_declaration_id={declaration_id} "
                    f"expected={expected_hash} actual={actual_hash}"
                ),
            )
        expected_version = (
            len(
                [
                    amendment
                    for amendment in index.amendments_by_declaration.get(
                        declaration_id,
                        [],
                    )
                    if _workflow_datetime_sort_key(amendment, "created_at")
                    < created_at
                ]
            )
            + 1
        )
        snapshot_version = snapshot.get("declaration_version_at_decision")
        if snapshot_version != expected_version:
            return _workflow_fail(
                WORKFLOW_EFFECTIVE_INTENT_HASH_MISMATCH,
                (
                    f"{label} permit_records[{record_index}] "
                    f"workflow_declaration_id={declaration_id} "
                    f"expected_version={expected_version} actual={snapshot_version}"
                ),
            )
        checked += 1
    if checked:
        print(f"{label}: workflow_state_json checks: {checked} PASS")
    return None


def _json_document_or_none(data: bytes) -> dict[str, Any] | None:
    try:
        value = json.loads(data.decode("utf-8"))
    except Exception:
        return None
    return value if isinstance(value, dict) else None


def _resolve_sibling_path(
    *,
    manifest: dict[str, Any],
    manifest_path: Path,
    export_path: Path,
    sibling: dict[str, Any],
) -> Path | None:
    descriptor = sibling.get("workflow_evidence")
    file_name = "workflow_evidence.json"
    if isinstance(descriptor, dict) and isinstance(descriptor.get("file_name"), str):
        file_name = descriptor["file_name"]

    candidates: list[Path] = []
    explicit = sibling.get("workflow_evidence_file")
    if isinstance(explicit, str) and explicit:
        explicit_path = Path(explicit)
        candidates.append(explicit_path)
        if not explicit_path.is_absolute():
            candidates.append(manifest_path.parent / explicit_path)

    bundle_dir = sibling.get("bundle_dir")
    if isinstance(bundle_dir, str) and bundle_dir:
        bundle_path = Path(bundle_dir)
        candidates.append(bundle_path / file_name)
        if not bundle_path.is_absolute():
            candidates.append(manifest_path.parent / bundle_path / file_name)

    export_id = manifest.get("export_id")
    candidates.extend(
        [
            manifest_path.parent / file_name,
            export_path.parent / file_name,
        ]
    )
    if isinstance(export_id, str) and export_id:
        candidates.extend(
            [
                manifest_path.parent / export_id / file_name,
                export_path.parent / export_id / file_name,
            ]
        )

    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.expanduser()
        if resolved in seen:
            continue
        seen.add(resolved)
        if resolved.exists():
            return resolved
    return None


def _verify_signed_workflow_sibling(
    *,
    workflow_path: Path,
    descriptor: dict[str, Any],
    args: argparse.Namespace,
) -> tuple[dict[str, Any] | None, int | None]:
    workflow_data = workflow_path.read_bytes()
    expected_hash = descriptor.get("content_hash")
    actual_hash = _content_hash(workflow_data)
    if expected_hash != actual_hash:
        return None, _workflow_fail(
            WORKFLOW_EVIDENCE_SCHEMA_INVALID,
            (
                f"workflow_evidence content_hash mismatch "
                f"expected={expected_hash} actual={actual_hash}"
            ),
        )
    signature = descriptor.get("signature")
    if not isinstance(signature, str) or not signature.strip():
        return None, _workflow_fail(
            WORKFLOW_SIGNATURE_INVALID,
            "workflow_evidence sibling manifest is unsigned",
        )
    embedded_pub = descriptor.get("public_key")
    artifact_key_id = (
        descriptor.get("key_id") if isinstance(descriptor.get("key_id"), str) else None
    )
    signing_time = _parse_iso_or_none(descriptor.get("signed_at"))
    trusted_pub, _trust_source, err = _resolve_trust_key(
        artifact_pub=embedded_pub if isinstance(embedded_pub, str) else None,
        artifact_key_id=artifact_key_id,
        purpose="export_signing",
        expected_public_key=getattr(args, "expected_public_key", None),
        public_key_url=None,
        key_manifest_source=_key_manifest_source_for_args(args),
        signing_time=signing_time,
    )
    if err is not None or trusted_pub is None:
        return None, _workflow_fail(WORKFLOW_SIGNATURE_INVALID, str(err))
    if isinstance(embedded_pub, str) and embedded_pub != trusted_pub:
        return None, _workflow_fail(
            WORKFLOW_SIGNATURE_INVALID,
            "workflow_evidence public_key does not match trusted key",
        )
    if not _verify_ed25519(trusted_pub, actual_hash.encode("utf-8"), signature):
        return None, _workflow_fail(
            WORKFLOW_SIGNATURE_INVALID,
            "workflow_evidence sibling signature invalid",
        )
    document = _json_document_or_none(workflow_data)
    if document is None:
        return None, _workflow_fail(
            WORKFLOW_EVIDENCE_SCHEMA_INVALID,
            "workflow_evidence sibling is not a JSON object",
        )
    return document, None


def _verify_vanta_workflow_extension(
    *,
    export_document: dict[str, Any] | None,
    export_path: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
    args: argparse.Namespace,
) -> int | None:
    sibling_artifacts = manifest.get("sibling_artifacts")
    if not isinstance(sibling_artifacts, dict):
        return None
    sibling = sibling_artifacts.get("workflow_evidence")
    if not isinstance(sibling, dict):
        return None
    if not _is_workflow_evidence_schema(sibling.get("schema")):
        return _workflow_fail(
            WORKFLOW_EVIDENCE_SCHEMA_INVALID,
            "workflow_evidence sibling schema is invalid",
        )
    descriptor = sibling.get("workflow_evidence")
    if not isinstance(descriptor, dict):
        return _workflow_fail(
            WORKFLOW_EVIDENCE_SCHEMA_INVALID,
            "workflow_evidence sibling descriptor missing",
        )
    workflow_path = _resolve_sibling_path(
        manifest=manifest,
        manifest_path=manifest_path,
        export_path=export_path,
        sibling=sibling,
    )
    if workflow_path is None:
        return _workflow_fail(
            WORKFLOW_EVIDENCE_SCHEMA_INVALID,
            "workflow_evidence file could not be found next to export/manifest",
        )
    workflow_document, failure = _verify_signed_workflow_sibling(
        workflow_path=workflow_path,
        descriptor=descriptor,
        args=args,
    )
    if failure is not None:
        return failure
    assert workflow_document is not None
    index, failure = _verify_workflow_evidence_document(
        workflow_document,
        args=args,
        label="WORKFLOW-EVIDENCE",
    )
    if failure is not None:
        return failure
    assert index is not None
    if isinstance(export_document, dict) and isinstance(export_document.get("records"), list):
        snapshot_failure = _verify_permit_workflow_snapshots(
            export_document["records"],
            index,
            label="WORKFLOW-EVIDENCE",
        )
        if snapshot_failure is not None:
            return snapshot_failure
    return None


def _read_jsonl_from_zip(
    zip_file: zipfile.ZipFile,
    name: str,
) -> list[dict[str, Any]]:
    raw = zip_file.read(name).decode("utf-8")
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{name}:{line_number} must be a JSON object")
        records.append(value)
    return records


def _incident_manifest_from_zip(zip_file: zipfile.ZipFile) -> dict[str, Any] | None:
    for name in ("manifest.json", "bundle_manifest.json"):
        if name not in zip_file.namelist():
            continue
        value = json.loads(zip_file.read(name).decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"{name} must be a JSON object")
        return value
    return None


def _manifest_file_schemas(bundle_manifest: dict[str, Any]) -> dict[str, str | None]:
    files = bundle_manifest.get("files")
    if not isinstance(files, list):
        raise ValueError("files must be a list")
    schemas: dict[str, str | None] = {}
    for index, entry in enumerate(files):
        if not isinstance(entry, dict):
            raise ValueError(f"files[{index}] must be an object")
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"files[{index}].name must be a non-empty string")
        schema = entry.get("schema")
        if schema is not None and not isinstance(schema, str):
            raise ValueError(f"files[{index}].schema must be a string or null")
        schemas[name] = schema
    return schemas


def _verify_incident_bundle(
    *,
    export_path: Path,
    manifest: dict[str, Any],
    args: argparse.Namespace,
) -> int | None:
    if not zipfile.is_zipfile(export_path):
        if manifest.get("export_type") == "incident_evidence":
            return _workflow_fail(
                INCIDENT_MANIFEST_SCHEMA_INVALID,
                "incident_evidence export payload must be a zip bundle",
            )
        return None

    with zipfile.ZipFile(export_path) as zip_file:
        try:
            bundle_manifest = (
                manifest
                if "manifest_version" in manifest
                else _incident_manifest_from_zip(zip_file)
            )
        except Exception as exc:
            return _workflow_fail(
                INCIDENT_MANIFEST_SCHEMA_INVALID,
                f"could not read incident bundle manifest: {exc}",
            )
        if bundle_manifest is None:
            return None

        manifest_version = bundle_manifest.get("manifest_version")
        if manifest_version == 1:
            return None
        if manifest_version != 2:
            return _workflow_fail(
                INCIDENT_UNKNOWN_MANIFEST_VERSION,
                f"unsupported incident bundle manifest_version={manifest_version!r}",
            )

        try:
            schemas = _manifest_file_schemas(bundle_manifest)
        except ValueError as exc:
            return _workflow_fail(INCIDENT_MANIFEST_SCHEMA_INVALID, str(exc))

        for name, schema in INCIDENT_V2_REQUIRED_FILES.items():
            if schemas.get(name) != schema:
                return _workflow_fail(
                    INCIDENT_MANIFEST_SCHEMA_INVALID,
                    f"{name} manifest schema must be {schema!r}",
                )
            if name not in zip_file.namelist():
                return _workflow_fail(
                    INCIDENT_MANIFEST_SCHEMA_INVALID,
                    f"{name} listed in manifest but missing from zip",
                )
        if "permits.jsonl" not in schemas or "permits.jsonl" not in zip_file.namelist():
            return _workflow_fail(
                INCIDENT_MANIFEST_SCHEMA_INVALID,
                "manifest_version=2 requires permits.jsonl",
            )

        try:
            metadata = json.loads(zip_file.read("incident_metadata.json").decode("utf-8"))
            if not isinstance(metadata, dict):
                raise ValueError("incident_metadata.json must be an object")
            if metadata.get("schema") != "keel.incident_evidence/v1":
                raise ValueError(
                    "incident_metadata.json schema must be keel.incident_evidence/v1"
                )
            declarations = _read_jsonl_from_zip(
                zip_file,
                "workflow_declarations.jsonl",
            )
            amendments = _read_jsonl_from_zip(zip_file, "workflow_amendments.jsonl")
            permits = _read_jsonl_from_zip(zip_file, "permits.jsonl")
            _read_jsonl_from_zip(zip_file, "mcp_tool_decisions.jsonl")
        except Exception as exc:
            return _workflow_fail(
                INCIDENT_MANIFEST_SCHEMA_INVALID,
                f"could not read incident bundle jsonl: {exc}",
            )

    index, failure = _verify_workflow_records(
        declarations=declarations,
        amendments=amendments,
        args=args,
        require_declaration_effective_hash=False,
    )
    if failure is not None:
        return failure
    assert index is not None
    snapshot_failure = _verify_permit_workflow_snapshots(
        permits,
        index,
        label="INCIDENT-BUNDLE",
    )
    if snapshot_failure is not None:
        return snapshot_failure
    print("INCIDENT-BUNDLE: VERIFIED")
    print("  manifest_version:    2")
    print(f"  declarations_verified: {len(declarations)}")
    print(f"  amendments_verified:   {len(amendments)}")
    return None


def _verify_export_workflow_extensions(
    *,
    export_data: bytes,
    export_path: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
    args: argparse.Namespace,
) -> int | None:
    export_document = _json_document_or_none(export_data)
    if isinstance(export_document, dict):
        _warn_if_legacy_evidence_schema(export_document.get("schema"))
    if isinstance(export_document, dict) and _is_workflow_evidence_schema(
        export_document.get("schema")
    ):
        _index, failure = _verify_workflow_evidence_document(
            export_document,
            args=args,
            label="WORKFLOW-EVIDENCE",
        )
        return failure

    sibling_failure = _verify_vanta_workflow_extension(
        export_document=export_document,
        export_path=export_path,
        manifest_path=manifest_path,
        manifest=manifest,
        args=args,
    )
    if sibling_failure is not None:
        return sibling_failure

    incident_failure = _verify_incident_bundle(
        export_path=export_path,
        manifest=manifest,
        args=args,
    )
    if incident_failure is not None:
        return incident_failure
    return None


def _fetch_manifest_bytes(url: str) -> bytes:
    """Fetch raw manifest bytes from a URL with a short timeout."""
    with urllib.request.urlopen(url, timeout=10) as resp:
        return resp.read()


def _validate_manifest_payload(payload: dict[str, Any]) -> int:
    """Validate that ``payload`` looks like a Keel public-key manifest.

    Returns the number of keys when valid; raises ``ValueError`` otherwise. A
    valid manifest is a JSON object with a non-empty ``keys`` list, where each
    entry has at minimum a ``public_key`` (or ``public_key_b64``) string.
    """
    if not isinstance(payload, dict):
        raise ValueError("manifest is not a JSON object")
    keys = payload.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ValueError("manifest has no 'keys' list or it is empty")
    for entry in keys:
        if not isinstance(entry, dict):
            raise ValueError("manifest 'keys' entries must be JSON objects")
        pub = entry.get("public_key")
        pub_b64 = entry.get("public_key_b64")
        if not (isinstance(pub, str) and pub.strip()) and not (
            isinstance(pub_b64, str) and pub_b64.strip()
        ):
            raise ValueError("manifest 'keys' entries must include 'public_key'")
    return len(keys)


def _captured_check(callable_, *args, **kwargs) -> tuple[int | None, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        result = callable_(*args, **kwargs)
    return result, stdout.getvalue(), stderr.getvalue()


def _failure_from_output(stdout: str, stderr: str) -> tuple[str, str]:
    text = f"{stderr}\n{stdout}"
    match = re.search(r"FAILED:\s+([A-Z][A-Z0-9_]+):\s*(.*)", text)
    if match:
        return match.group(1), match.group(2).strip()
    lowered = text.lower()
    if "content hash mismatch" in lowered:
        return "CONTENT_HASH_MISMATCH", "content hash mismatch"
    if "signature verification failed" in lowered:
        return "SIGNATURE_VERIFICATION_FAILED", "signature verification failed"
    if "export manifest is unsigned" in lowered:
        return "MANIFEST_SIGNATURE_MISSING", "export manifest is unsigned"
    if "export is not json" in lowered:
        return "EXPORT_STRUCTURE_INVALID", "export is not JSON"
    match = re.search(r"FAILED:\s*(.*)", text)
    return "VERIFICATION_FAILED", (match.group(1).strip() if match else text.strip())


def _export_artifact_dict(
    *,
    export_path: Path,
    manifest_path: Path,
    export_data: bytes | None = None,
    manifest_data: bytes | None = None,
    artifact_ref: ArtifactRef | None = None,
) -> dict[str, Any]:
    artifact: dict[str, Any] = {
        "kind": "export",
        "manifest_path": str(manifest_path),
        "payload_path": str(export_path),
    }
    if manifest_data is not None:
        artifact["manifest_hash"] = _content_hash(manifest_data)
    if export_data is not None:
        artifact["payload_hash"] = _content_hash(export_data)
    if artifact_ref is not None:
        artifact["artifact_ref"] = _artifact_ref_to_dict(artifact_ref)
    return artifact


def _export_report(
    *,
    ok: bool,
    exit_code: int,
    artifact: dict[str, Any],
    claims: list[ClaimVerdict],
    semantics: ResolvedSemantics | None = None,
    error: str | None = None,
    diagnostics: list[str] | None = None,
) -> VerificationReport:
    claims, ok, enforced_exit_code, error = _enforce_required_claims(
        claims=claims,
        semantics=semantics,
        ok=ok,
        exit_code=exit_code,
        error=error,
        subject_type="claim_set_requirement",
        subject_id=artifact.get("manifest_path"),
        evidence=["manifest.claim_set"],
    )
    return VerificationReport(
        ok=ok,
        exit_code=enforced_exit_code if enforced_exit_code is not None else exit_code,
        artifact=artifact,
        claims=claims,
        error=error,
        diagnostics=_report_diagnostics(diagnostics, semantics),
        semantics=semantics.report_semantics() if semantics is not None else legacy_semantics(),
    )


def _export_integrity_claim(
    *,
    export_path: Path,
    manifest_path: Path,
    content_verdict: str,
    signature_verdict: str,
    reason_code: str,
    message: str,
    signature_message: str | None = None,
) -> ClaimVerdict:
    return ClaimVerdict(
        name="export.integrity.v1",
        subjects=[
            _subject(
                subject_type="payload_content_hash",
                subject_id=export_path.name,
                verdict=content_verdict,
                reason_code=(
                    "CONTENT_HASH_MATCH"
                    if content_verdict == "supported"
                    else reason_code
                ),
                message=(
                    "export bytes match manifest content_hash"
                    if content_verdict == "supported"
                    else message
                ),
                evidence=["manifest.content_hash", str(export_path)],
            ),
            _subject(
                subject_type="manifest_signature",
                subject_id=manifest_path.name,
                verdict=signature_verdict,
                reason_code=reason_code,
                message=signature_message or message,
                evidence=["manifest.signature", "manifest.public_key", "manifest.key_id"],
            ),
        ],
        reason_code=reason_code,
        message=message,
        evidence=["manifest.content_hash", "manifest.signature", str(export_path)],
    )


def _payload_record_count(export_data: bytes) -> int | None:
    try:
        document = _load_export_json_document(export_data)
    except Exception:
        return None
    if not isinstance(document, dict):
        return None
    records = document.get("records")
    if isinstance(records, list):
        return len(records)
    return None


def _evaluate_export_scope_identity(
    *,
    manifest: dict[str, Any],
    export_data: bytes,
) -> ClaimVerdict | None:
    identity_fields = (
        "export_id",
        "project_id",
        "export_type",
        "format",
        "compressed",
        "record_count",
    )
    if not any(field in manifest for field in identity_fields):
        return None
    missing = [field for field in identity_fields if field not in manifest]
    if missing:
        return _single_subject_claim(
            "export.scope_identity.v1",
            subject_type="manifest_identity",
            subject_id=str(manifest.get("export_id") or "<unknown>"),
            verdict="insufficient_evidence",
            reason_code="EXPORT_SCOPE_IDENTITY_INCOMPLETE",
            message=f"manifest identity fields missing: {', '.join(missing)}",
            evidence=["manifest"],
            required=False,
        )

    record_count = _payload_record_count(export_data)
    if record_count is None:
        return _single_subject_claim(
            "export.scope_identity.v1",
            subject_type="manifest_identity",
            subject_id=str(manifest.get("export_id") or "<unknown>"),
            verdict="unverifiable_scope",
            reason_code="EXPORT_SCOPE_IDENTITY_UNVERIFIABLE",
            message="export payload shape does not expose a verifiable record_count",
            evidence=["manifest", "export.records"],
            required=False,
        )
    if record_count != manifest.get("record_count"):
        return _single_subject_claim(
            "export.scope_identity.v1",
            subject_type="manifest_identity",
            subject_id=str(manifest.get("export_id") or "<unknown>"),
            verdict="disproved",
            reason_code="EXPORT_SCOPE_RECORD_COUNT_MISMATCH",
            message=(
                f"manifest record_count={manifest.get('record_count')} "
                f"does not match payload records={record_count}"
            ),
            evidence=["manifest.record_count", "export.records"],
            required=False,
        )

    try:
        document = _load_export_json_document(export_data)
    except Exception:
        document = None
    project_id = document.get("project_id") if isinstance(document, dict) else None
    if (
        isinstance(manifest.get("project_id"), str)
        and isinstance(project_id, str)
        and manifest["project_id"] != project_id
    ):
        return _single_subject_claim(
            "export.scope_identity.v1",
            subject_type="manifest_identity",
            subject_id=str(manifest.get("export_id") or "<unknown>"),
            verdict="disproved",
            reason_code="EXPORT_SCOPE_PROJECT_ID_MISMATCH",
            message="manifest project_id does not match payload project_id",
            evidence=["manifest.project_id", "export.project_id"],
            required=False,
        )

    return _single_subject_claim(
        "export.scope_identity.v1",
        subject_type="manifest_identity",
        subject_id=str(manifest.get("export_id") or "<unknown>"),
        verdict="supported",
        reason_code="EXPORT_SCOPE_IDENTITY_SUPPORTED",
        message="manifest identity fields match the export payload shape",
        evidence=["manifest", "export.records"],
        required=False,
    )


SCOPE_FAITHFULNESS_VERSION = "keel.export_scope_faithfulness.v1"
SCOPE_STATE_SIDECAR_VERSION = "checkpoint_scope_state.v1"
SCOPE_PREDICATE_VERSION = "keel.scope_predicate.v1"
SCOPE_DECLARATION_VERSION = "keel.scope_declaration.v1"
PRESENTATION_POLICY_VERSION = "keel.presentation_policy.v1"
SCOPE_EMPTY_TREE_HASH = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SCOPE_STATE_SIDECAR_FILE = "checkpoint-scope-state-v1.json"
SCOPE_SUPPORTED_PREDICATE_KINDS = {
    "project_id",
    "permit_id",
    "request_id",
    "event_type",
    "category",
    "severity",
    "decision_type",
    "policy_id",
    "provider",
    "sequence_number",
    "created_at",
    "occurred_at",
    "section",
    "export_type",
}
SCOPE_RESERVED_PREDICATE_KINDS = {
    "subject_id",
    "model",
    "requested_by",
    "incident_id",
}
SCOPE_ALLOWED_RESERVED_NAMESPACES = {"non_membership_profile"}
_SCOPE_RECORD_FIELDS = {
    "event_id",
    "event_type",
    "chain_scope",
    "sequence_number",
    "record_hash",
    "prev_hash",
    "created_at",
    "chain_format_version",
}
_SCOPE_RECORD_PAYLOAD_FALLBACK_FIELDS = {
    "project_id",
    "permit_id",
    "resource_type",
    "resource_id",
    "outcome",
    "severity",
    "category",
    "occurred_at",
    "request_id",
    "policy_id",
    "provider",
    "section",
    "export_type",
}


@dataclass(frozen=True)
class ScopeClaimResult:
    claim: ClaimVerdict
    sidecar: dict[str, Any] | None = None
    sidecar_bytes: bytes | None = None


def _scope_claim(
    name: str,
    *,
    subject_type: str,
    subject_id: str | None,
    verdict: str,
    reason_code: str,
    message: str,
    evidence: list[str] | None = None,
    subjects: list[VerdictSubject] | None = None,
) -> ClaimVerdict:
    if subjects is not None:
        return ClaimVerdict(
            name=name,
            subjects=subjects,
            verdict=verdict,
            reason_code=reason_code,
            message=message,
            evidence=list(evidence or []),
        )
    return _single_subject_claim(
        name,
        subject_type=subject_type,
        subject_id=subject_id,
        verdict=verdict,
        reason_code=reason_code,
        message=message,
        evidence=evidence or [],
    )


def _scope_state_claim(
    *,
    sidecar: dict[str, Any] | None,
    verdict: str,
    reason_code: str,
    message: str,
    evidence: list[str] | None = None,
) -> ClaimVerdict:
    sidecar_id = None
    if isinstance(sidecar, dict):
        value = sidecar.get("scope_state_id")
        sidecar_id = value if isinstance(value, str) else None
    return _scope_claim(
        "checkpoint.scope_state.v1",
        subject_type="checkpoint_scope_state",
        subject_id=sidecar_id,
        verdict=verdict,
        reason_code=reason_code,
        message=message,
        evidence=evidence or ["checkpoint_scope_state"],
    )


def _export_scope_claim(
    *,
    segment_id: str | None,
    verdict: str,
    reason_code: str,
    message: str,
    evidence: list[str] | None = None,
) -> ClaimVerdict:
    return _scope_claim(
        "export.scope_faithfulness.v1",
        subject_type="scope_faithfulness_segment",
        subject_id=segment_id,
        verdict=verdict,
        reason_code=reason_code,
        message=message,
        evidence=evidence or ["export.scope_faithfulness"],
    )


def _prefixed_sha256(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _hash_bytes(value: str) -> bytes:
    text = value.removeprefix("sha256:")
    return bytes.fromhex(text)


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def _is_nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _is_nonbool_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _exact_keys(value: Any, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value.keys()) == keys


def _load_bundled_semantic(relative_path: str) -> dict[str, Any]:
    path = Path(relative_path)
    raw = resources.files("keel_verifier").joinpath("data", *path.parts).read_bytes()
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{relative_path} must be a JSON object")
    return value


def _scope_merkle_semantic() -> dict[str, Any]:
    return _load_bundled_semantic("semantics/scope_state/merkle_v1.json")


def _lookup_hierarchy_from_merkle_semantic() -> dict[str, list[tuple[str, str | None]]]:
    semantic = _scope_merkle_semantic()
    body = semantic.get("body")
    raw = body.get("predicate_field_lookup_hierarchy") if isinstance(body, dict) else None
    if not isinstance(raw, list):
        raise ValueError("keel.scope_state.merkle.v1 has no predicate lookup hierarchy")
    hierarchy: dict[str, list[tuple[str, str | None]]] = {}
    for item in raw:
        if not isinstance(item, dict):
            continue
        kind = item.get("kind")
        text = item.get("ordered_lookup_chain")
        if not isinstance(kind, str) or not isinstance(text, str):
            continue
        paths: list[tuple[str, str | None]] = []
        for segment in text.split("; "):
            match = re.match(r'\d+\. `([^`]+)`(?: when `([^`]+)`)?$', segment)
            if match is None:
                raise ValueError(f"cannot parse lookup segment {segment!r}")
            paths.append((match.group(1), match.group(2)))
        hierarchy[kind] = paths
    return hierarchy


def _get_entry_path(entry: dict[str, Any], path: str) -> Any:
    if not path.startswith("entry."):
        return None
    current: Any = entry
    for part in path.removeprefix("entry.").split("."):
        if not isinstance(current, dict):
            return None
        if part not in current:
            if part == "payload_json" and isinstance(current.get("payload"), dict):
                current = current["payload"]
                continue
            return None
        current = current[part]
    return current


def _lookup_condition_matches(entry: dict[str, Any], condition: str | None) -> bool:
    if condition is None:
        return True
    if condition == 'entry.resource_type == "permit"':
        return _get_entry_path(entry, "entry.resource_type") == "permit"
    return False


def _resolve_scope_predicate_value(entry: dict[str, Any], kind: str) -> Any:
    hierarchy = _lookup_hierarchy_from_merkle_semantic()
    for path, condition in hierarchy.get(kind, []):
        if not _lookup_condition_matches(entry, condition):
            continue
        value = _get_entry_path(entry, path)
        if isinstance(value, (str, int, float, bool)) and not isinstance(value, bool):
            return value
        if isinstance(value, bool):
            return value
    return None


def _scope_timestamp_in_half_open_range(actual: Any, range_value: dict[str, Any]) -> bool:
    actual_time = _parse_iso_or_none(str(actual))
    lower = _parse_iso_or_none(str(range_value["gte"]))
    upper = _parse_iso_or_none(str(range_value["lt"]))
    if actual_time is None or lower is None or upper is None:
        return False
    return lower <= actual_time < upper


def _predicate_hash(predicate: dict[str, Any]) -> str:
    return _prefixed_sha256(_canonical_json_bytes(predicate))


def _validate_scope_predicate(
    predicate: Any,
    *,
    sidecar_context: bool = False,
) -> tuple[str | None, str | None]:
    if not isinstance(predicate, dict):
        return "EXPORT_SCOPE_PREDICATE_MALFORMED", "predicate must be an object"
    required = {"version", "operator", "equals", "ranges"}
    if set(predicate.keys()) != required:
        return "EXPORT_SCOPE_PREDICATE_MALFORMED", "predicate must contain version, operator, equals, and ranges"
    if predicate.get("version") != SCOPE_PREDICATE_VERSION:
        return "EXPORT_SCOPE_PREDICATE_UNSUPPORTED", "predicate grammar version is unsupported"
    if predicate.get("operator") != "and":
        return "EXPORT_SCOPE_PREDICATE_UNSUPPORTED", "predicate operator is unsupported"
    equals = predicate.get("equals")
    ranges = predicate.get("ranges")
    if not isinstance(equals, dict) or not isinstance(ranges, dict):
        return "EXPORT_SCOPE_PREDICATE_MALFORMED", "predicate equals and ranges must be objects"
    for kind, value in equals.items():
        if kind in SCOPE_RESERVED_PREDICATE_KINDS or kind not in SCOPE_SUPPORTED_PREDICATE_KINDS:
            return "EXPORT_SCOPE_PREDICATE_UNSUPPORTED", f"predicate kind {kind!r} is unsupported"
        if kind in {"sequence_number", "created_at", "occurred_at"}:
            return "EXPORT_SCOPE_PREDICATE_MALFORMED", f"predicate kind {kind!r} must use ranges"
        if isinstance(value, (dict, list)):
            return "EXPORT_SCOPE_PREDICATE_MALFORMED", f"predicate equals value for {kind!r} must be scalar"
    for kind, value in ranges.items():
        if kind in SCOPE_RESERVED_PREDICATE_KINDS or kind not in SCOPE_SUPPORTED_PREDICATE_KINDS:
            return "EXPORT_SCOPE_PREDICATE_UNSUPPORTED", f"predicate range kind {kind!r} is unsupported"
        if kind not in {"sequence_number", "created_at", "occurred_at"}:
            return "EXPORT_SCOPE_PREDICATE_MALFORMED", f"predicate kind {kind!r} must use equals"
        if not isinstance(value, dict):
            return "EXPORT_SCOPE_PREDICATE_MALFORMED", f"predicate range for {kind!r} must be an object"
        if kind == "sequence_number":
            if set(value.keys()) != {"gte", "lte"} or not _is_nonbool_int(value.get("gte")) or not _is_nonbool_int(value.get("lte")):
                return "EXPORT_SCOPE_PREDICATE_MALFORMED", "sequence_number range must contain integer gte and lte"
            if int(value["gte"]) > int(value["lte"]):
                return "EXPORT_SCOPE_PREDICATE_MALFORMED", "sequence_number range has gte after lte"
        else:
            if set(value.keys()) != {"gte", "lt"} or not isinstance(value.get("gte"), str) or not isinstance(value.get("lt"), str):
                return "EXPORT_SCOPE_PREDICATE_MALFORMED", f"{kind} range must contain timestamp gte and lt"
            if _parse_iso_or_none(value["gte"]) is None or _parse_iso_or_none(value["lt"]) is None:
                return "EXPORT_SCOPE_PREDICATE_MALFORMED", f"{kind} range timestamps are invalid"
    if sidecar_context:
        return None, None
    return None, None


def _scope_predicate_matches(entry: dict[str, Any], predicate: dict[str, Any]) -> bool:
    for kind, expected in predicate["equals"].items():
        actual = _resolve_scope_predicate_value(entry, kind)
        if actual != expected:
            return False
    for kind, range_value in predicate["ranges"].items():
        actual = _resolve_scope_predicate_value(entry, kind)
        if actual is None:
            return False
        if kind == "sequence_number":
            try:
                actual_int = int(actual)
            except (TypeError, ValueError):
                return False
            if actual_int < int(range_value["gte"]) or actual_int > int(range_value["lte"]):
                return False
            continue
        if not _scope_timestamp_in_half_open_range(actual, range_value):
            return False
    return True


def _scope_merkle_root(
    disclosure_records: list[dict[str, Any]],
    predicate_value_hash: str,
) -> str:
    if not disclosure_records:
        return SCOPE_EMPTY_TREE_HASH
    leaves: list[bytes] = []
    for record in sorted(
        disclosure_records,
        key=lambda item: (
            int(item["sequence_number"]),
            str(item["event_id"]),
            str(item["record_hash"]),
        ),
    ):
        leaf_object = {
            "canonical_predicate_value_hash": predicate_value_hash,
            "event_id": record["event_id"],
            "record_hash": record["record_hash"],
            "sequence_number": record["sequence_number"],
        }
        leaves.append(hashlib.sha256(b"\x00" + _canonical_json_bytes(leaf_object)).digest())

    def merkle_hash(nodes: list[bytes]) -> bytes:
        if len(nodes) == 1:
            return nodes[0]
        split = 1 << ((len(nodes) - 1).bit_length() - 1)
        left = merkle_hash(nodes[:split])
        right = merkle_hash(nodes[split:])
        return hashlib.sha256(b"\x01" + left + right).digest()

    return f"sha256:{merkle_hash(leaves).hex()}"


def _scope_sidecar_signed_bytes(sidecar: dict[str, Any]) -> bytes:
    signed = json.loads(_canonical_json(sidecar))
    del signed["signature"]["signature"]
    return _canonical_json_bytes(signed)


def _scope_sidecar_schema_error(sidecar: Any) -> str | None:
    if not _exact_keys(
        sidecar,
        {
            "artifact_type",
            "version",
            "scope_state_id",
            "checkpoint_id",
            "chain_scope",
            "predicate_grammar_version",
            "predicate_basis",
            "commitment_profile",
            "scope_commitments",
            "tree_size",
            "signed_at",
            "signature",
            "trust_root_reference",
        },
    ):
        return "sidecar top-level fields do not match checkpoint_scope_state.v1"
    if sidecar.get("artifact_type") != "checkpoint_scope_state":
        return "artifact_type must be checkpoint_scope_state"
    if sidecar.get("version") != SCOPE_STATE_SIDECAR_VERSION:
        return "version must be checkpoint_scope_state.v1"
    for field in ("scope_state_id", "checkpoint_id", "chain_scope", "predicate_grammar_version", "commitment_profile", "signed_at"):
        if not _is_nonempty_str(sidecar.get(field)):
            return f"{field} must be a non-empty string"
    if not _is_nonbool_int(sidecar.get("tree_size")) or int(sidecar["tree_size"]) < 0:
        return "tree_size must be a non-negative integer"

    basis = sidecar.get("predicate_basis")
    if not _exact_keys(basis, {"canonicalization_profile", "supported_predicate_kinds", "reserved_namespaces"}):
        return "predicate_basis must contain canonicalization_profile, supported_predicate_kinds, and reserved_namespaces"
    if basis.get("canonicalization_profile") != "keel.canonical_json.payload.v1":
        return "predicate_basis canonicalization_profile is unsupported"
    supported = basis.get("supported_predicate_kinds")
    if not isinstance(supported, list) or len(set(supported)) != len(supported):
        return "supported_predicate_kinds must be a unique array"
    if any(not isinstance(kind, str) or kind not in SCOPE_SUPPORTED_PREDICATE_KINDS for kind in supported):
        return "supported_predicate_kinds contains an unsupported kind"
    reserved = basis.get("reserved_namespaces")
    if (
        not isinstance(reserved, list)
        or len(set(reserved)) != len(reserved)
        or any(
            not isinstance(item, str)
            or not (item.startswith("keel.") or item in SCOPE_ALLOWED_RESERVED_NAMESPACES)
            for item in reserved
        )
    ):
        return "reserved_namespaces must be unique supported namespace strings"

    signature = sidecar.get("signature")
    if not _exact_keys(signature, {"algorithm", "key_id", "signature"}):
        return "signature block must contain algorithm, key_id, and signature"
    if signature.get("algorithm") != "Ed25519":
        return "signature algorithm must be Ed25519"
    if not _is_nonempty_str(signature.get("key_id")):
        return "signature.key_id must be a non-empty string"
    if not _is_nonempty_str(signature.get("signature")) or not str(signature["signature"]).startswith("ed25519:"):
        return "signature.signature must be ed25519:<base64>"

    trust = sidecar.get("trust_root_reference")
    if not _exact_keys(trust, {"manifest_version", "purpose", "key_id"}):
        return "trust_root_reference must contain manifest_version, purpose, and key_id"
    if trust.get("manifest_version") != "keel.public_key_manifest.v1":
        return "trust_root_reference.manifest_version is unsupported"
    if trust.get("purpose") not in {"scope_state", "integrity_checkpoint"}:
        return "trust_root_reference.purpose is unsupported"
    if not _is_nonempty_str(trust.get("key_id")):
        return "trust_root_reference.key_id must be a non-empty string"

    commitments = sidecar.get("scope_commitments")
    if not isinstance(commitments, list) or not commitments:
        return "scope_commitments must be a non-empty array"
    for index, commitment in enumerate(commitments):
        if not _exact_keys(
            commitment,
            {
                "predicate_value",
                "predicate_value_hash",
                "first_matching_sequence",
                "last_matching_sequence",
                "matching_count",
                "membership_root_hash",
            },
        ):
            return f"scope_commitments[{index}] fields do not match v1"
        if not _is_hash(commitment.get("predicate_value_hash")):
            return f"scope_commitments[{index}].predicate_value_hash must be sha256:<hex>"
        if not _is_hash(commitment.get("membership_root_hash")):
            return f"scope_commitments[{index}].membership_root_hash must be sha256:<hex>"
        count = commitment.get("matching_count")
        if not _is_nonbool_int(count) or int(count) < 0:
            return f"scope_commitments[{index}].matching_count must be a non-negative integer"
        for field in ("first_matching_sequence", "last_matching_sequence"):
            value = commitment.get(field)
            if value is not None and (not _is_nonbool_int(value) or int(value) < 1):
                return f"scope_commitments[{index}].{field} must be a positive integer or null"
        predicate_error, _message = _validate_scope_predicate(
            commitment.get("predicate_value"),
            sidecar_context=True,
        )
        if predicate_error == "EXPORT_SCOPE_PREDICATE_MALFORMED":
            return f"scope_commitments[{index}].predicate_value is malformed"
    return None


def _resolve_scope_trust_key(
    *,
    key_id: str,
    purpose: str,
    signing_time: datetime | None,
    key_manifest_source: str | None,
) -> tuple[str | None, str | None, str | None]:
    source = key_manifest_source or _cached_key_manifest_source() or _bundled_key_manifest_source()
    if source is None:
        return None, None, "CHECKPOINT_SCOPE_STATE_KEY_UNRESOLVED"
    try:
        entries = _load_key_manifest(source)
    except Exception:
        return None, None, "CHECKPOINT_SCOPE_STATE_KEY_UNRESOLVED"
    purpose_entries = [entry for entry in entries if entry.get("purpose") == purpose]
    matches = [entry for entry in purpose_entries if entry.get("key_id") == key_id]
    if not matches:
        return None, None, "CHECKPOINT_SCOPE_STATE_KEY_UNRESOLVED"
    if signing_time is not None:
        active = _filter_by_active_window(matches, signing_time)
        if not active:
            return None, None, "CHECKPOINT_SCOPE_STATE_KEY_NOT_ACTIVE"
        matches = active
    if len(matches) != 1:
        return None, None, "CHECKPOINT_SCOPE_STATE_KEY_UNRESOLVED"
    pub = matches[0].get("public_key")
    if not isinstance(pub, str):
        return None, None, "CHECKPOINT_SCOPE_STATE_KEY_UNRESOLVED"
    return pub, f"key manifest ({source}) purpose={purpose!r} key_id={key_id!r}", None


def _verify_checkpoint_for_scope_state(
    *,
    sidecar: dict[str, Any],
    checkpoint: dict[str, Any] | None,
    key_manifest_source: str | None,
    semantics_dispatch: SemanticsDispatch | None,
) -> tuple[str | None, str | None]:
    if checkpoint is None:
        return "CHECKPOINT_SCOPE_STATE_CHECKPOINT_MISSING", "referenced checkpoint artifact is absent"
    if not isinstance(checkpoint, dict):
        return "CHECKPOINT_SCOPE_STATE_CHECKPOINT_MISMATCH", "checkpoint artifact must be a JSON object"
    if checkpoint.get("checkpoint_id") != sidecar.get("checkpoint_id"):
        return "CHECKPOINT_SCOPE_STATE_CHECKPOINT_MISMATCH", "sidecar checkpoint_id does not match checkpoint artifact"
    chain_heads = checkpoint.get("chain_heads")
    if not isinstance(chain_heads, dict):
        return "CHECKPOINT_SCOPE_STATE_CHECKPOINT_MISMATCH", "checkpoint chain_heads are missing or malformed"
    composite = checkpoint.get("composite_hash")
    if not isinstance(composite, str) or not composite.startswith("sha256:"):
        return "CHECKPOINT_SCOPE_STATE_CHECKPOINT_MISMATCH", "checkpoint composite_hash is missing or malformed"
    try:
        hasher = semantics_dispatch.composite_hash if semantics_dispatch else _composite_hash
        if hasher is None:
            hasher = _composite_hash
        recomputed = hasher(chain_heads)
    except Exception as exc:
        return "CHECKPOINT_SCOPE_STATE_CHECKPOINT_MISMATCH", f"could not recompute checkpoint composite_hash: {exc}"
    if recomputed != composite:
        return "CHECKPOINT_SCOPE_STATE_CHECKPOINT_MISMATCH", "checkpoint composite_hash does not match chain_heads"

    signature = checkpoint.get("signature")
    if not isinstance(signature, str):
        return "CHECKPOINT_SCOPE_STATE_CHECKPOINT_MISMATCH", "checkpoint signature is missing"
    key_id = checkpoint.get("key_id") if isinstance(checkpoint.get("key_id"), str) else None
    signing_time = _parse_iso_or_none(checkpoint.get("computed_at"))
    trusted_pub, _trust_source, err = _resolve_trust_key(
        artifact_pub=checkpoint.get("public_key") if isinstance(checkpoint.get("public_key"), str) else None,
        artifact_key_id=key_id,
        purpose="integrity_checkpoint",
        expected_public_key=None,
        public_key_url=None,
        key_manifest_source=key_manifest_source or _cached_key_manifest_source() or _bundled_key_manifest_source(),
        signing_time=signing_time,
    )
    if err is not None or trusted_pub is None:
        return "CHECKPOINT_SCOPE_STATE_CHECKPOINT_MISMATCH", err or "checkpoint trust key could not be resolved"
    if isinstance(checkpoint.get("public_key"), str) and checkpoint["public_key"] != trusted_pub:
        return "CHECKPOINT_SCOPE_STATE_CHECKPOINT_MISMATCH", "checkpoint public_key does not match trust root"
    if not _verify_ed25519(trusted_pub, composite.encode("utf-8"), signature):
        return "CHECKPOINT_SCOPE_STATE_CHECKPOINT_MISMATCH", "checkpoint signature does not verify"
    return None, None


def _adjudicate_checkpoint_scope_state_v1(
    sidecar: dict[str, Any] | None,
    *,
    checkpoint: dict[str, Any] | None,
    key_manifest_source: str | None = None,
    semantics_dispatch: SemanticsDispatch | None = None,
) -> ScopeClaimResult:
    if sidecar is None:
        claim = _scope_state_claim(
            sidecar=None,
            verdict="insufficient_evidence",
            reason_code="CHECKPOINT_SCOPE_STATE_MISSING",
            message="required scope-state sidecar artifact is absent",
        )
        return ScopeClaimResult(claim=claim)
    if not isinstance(sidecar, dict):
        claim = _scope_state_claim(
            sidecar=None,
            verdict="disproved",
            reason_code="CHECKPOINT_SCOPE_STATE_SCHEMA_INVALID",
            message="scope-state sidecar must be a JSON object",
        )
        return ScopeClaimResult(claim=claim)

    signature = sidecar.get("signature")
    signature_value = signature.get("signature") if isinstance(signature, dict) else None
    if not isinstance(signature, dict) or not _is_nonempty_str(signature_value):
        claim = _scope_state_claim(
            sidecar=sidecar,
            verdict="insufficient_evidence",
            reason_code="CHECKPOINT_SCOPE_STATE_SIGNATURE_MISSING",
            message="scope-state sidecar signature block or signature value is absent",
        )
        return ScopeClaimResult(claim=claim, sidecar=sidecar)

    schema_error = _scope_sidecar_schema_error(sidecar)
    if schema_error is not None:
        claim = _scope_state_claim(
            sidecar=sidecar,
            verdict="disproved",
            reason_code="CHECKPOINT_SCOPE_STATE_SCHEMA_INVALID",
            message=schema_error,
        )
        return ScopeClaimResult(claim=claim, sidecar=sidecar)

    signing_time = _parse_iso_or_none(sidecar.get("signed_at"))
    trust = sidecar["trust_root_reference"]
    trusted_pub, _trust_source, key_error = _resolve_scope_trust_key(
        key_id=sidecar["signature"]["key_id"],
        purpose=str(trust["purpose"]),
        signing_time=signing_time,
        key_manifest_source=key_manifest_source,
    )
    if key_error is not None or trusted_pub is None:
        verdict = "disproved" if key_error == "CHECKPOINT_SCOPE_STATE_KEY_NOT_ACTIVE" else "insufficient_evidence"
        claim = _scope_state_claim(
            sidecar=sidecar,
            verdict=verdict,
            reason_code=key_error or "CHECKPOINT_SCOPE_STATE_KEY_UNRESOLVED",
            message="scope-state signing key could not be resolved in an active trust-root window",
        )
        return ScopeClaimResult(claim=claim, sidecar=sidecar)
    if not _verify_ed25519(
        trusted_pub,
        _scope_sidecar_signed_bytes(sidecar),
        sidecar["signature"]["signature"],
    ):
        claim = _scope_state_claim(
            sidecar=sidecar,
            verdict="disproved",
            reason_code="CHECKPOINT_SCOPE_STATE_SIGNATURE_INVALID",
            message="scope-state sidecar signature does not verify over the signed v1 field set",
        )
        return ScopeClaimResult(claim=claim, sidecar=sidecar)

    checkpoint_error, checkpoint_message = _verify_checkpoint_for_scope_state(
        sidecar=sidecar,
        checkpoint=checkpoint,
        key_manifest_source=key_manifest_source,
        semantics_dispatch=semantics_dispatch,
    )
    if checkpoint_error is not None:
        verdict = "insufficient_evidence" if checkpoint_error == "CHECKPOINT_SCOPE_STATE_CHECKPOINT_MISSING" else "disproved"
        claim = _scope_state_claim(
            sidecar=sidecar,
            verdict=verdict,
            reason_code=checkpoint_error,
            message=checkpoint_message or "referenced checkpoint did not verify",
        )
        return ScopeClaimResult(claim=claim, sidecar=sidecar)

    chain_heads = checkpoint.get("chain_heads") if isinstance(checkpoint, dict) else {}
    if sidecar["chain_scope"] not in chain_heads:
        claim = _scope_state_claim(
            sidecar=sidecar,
            verdict="disproved",
            reason_code="CHECKPOINT_SCOPE_STATE_CHAIN_SCOPE_NOT_IN_CHECKPOINT",
            message="checkpoint chain_heads do not contain the sidecar chain_scope",
        )
        return ScopeClaimResult(claim=claim, sidecar=sidecar)
    head = chain_heads[sidecar["chain_scope"]]
    head_sequence = head.get("sequence_number") if isinstance(head, dict) else None
    if not _is_nonbool_int(head_sequence):
        claim = _scope_state_claim(
            sidecar=sidecar,
            verdict="disproved",
            reason_code="CHECKPOINT_SCOPE_STATE_CHECKPOINT_MISMATCH",
            message="checkpoint head sequence_number is malformed",
        )
        return ScopeClaimResult(claim=claim, sidecar=sidecar)

    for commitment in sidecar["scope_commitments"]:
        count = commitment["matching_count"]
        first = commitment["first_matching_sequence"]
        last = commitment["last_matching_sequence"]
        if count == 0:
            if first is not None or last is not None:
                claim = _scope_state_claim(
                    sidecar=sidecar,
                    verdict="disproved",
                    reason_code="CHECKPOINT_SCOPE_STATE_LAST_SEQUENCE_AFTER_CHECKPOINT",
                    message="zero-count scope commitments must have null matching range",
                )
                return ScopeClaimResult(claim=claim, sidecar=sidecar)
        elif not isinstance(last, int) or last > int(head_sequence):
            claim = _scope_state_claim(
                sidecar=sidecar,
                verdict="disproved",
                reason_code="CHECKPOINT_SCOPE_STATE_LAST_SEQUENCE_AFTER_CHECKPOINT",
                message="scope commitment range exceeds checkpoint head sequence",
            )
            return ScopeClaimResult(claim=claim, sidecar=sidecar)

    if sidecar.get("predicate_grammar_version") != SCOPE_PREDICATE_VERSION:
        claim = _scope_state_claim(
            sidecar=sidecar,
            verdict="unverifiable_scope",
            reason_code="CHECKPOINT_SCOPE_STATE_GRAMMAR_UNSUPPORTED",
            message="scope-state sidecar names an unsupported predicate grammar",
        )
        return ScopeClaimResult(claim=claim, sidecar=sidecar)

    for commitment in sidecar["scope_commitments"]:
        predicate_error, predicate_message = _validate_scope_predicate(
            commitment["predicate_value"],
            sidecar_context=True,
        )
        if predicate_error == "EXPORT_SCOPE_PREDICATE_UNSUPPORTED":
            claim = _scope_state_claim(
                sidecar=sidecar,
                verdict="unverifiable_scope",
                reason_code="CHECKPOINT_SCOPE_STATE_GRAMMAR_UNSUPPORTED",
                message=predicate_message or "scope-state sidecar names an unsupported predicate grammar",
            )
            return ScopeClaimResult(claim=claim, sidecar=sidecar)

    if (
        sidecar.get("commitment_profile") != SCOPE_STATE_MERKLE_ID
        or (SCOPE_STATE_MERKLE_ID, SCOPE_STATE_MERKLE_HASH) not in PERMANENT_ALLOWLIST
    ):
        claim = _scope_state_claim(
            sidecar=sidecar,
            verdict="unverifiable_scope",
            reason_code="CHECKPOINT_SCOPE_STATE_COMMITMENT_PROFILE_UNKNOWN",
            message="scope-state sidecar names an unknown commitment profile",
        )
        return ScopeClaimResult(claim=claim, sidecar=sidecar)

    seen_hashes: set[str] = set()
    for commitment in sidecar["scope_commitments"]:
        actual_hash = _predicate_hash(commitment["predicate_value"])
        if actual_hash != commitment["predicate_value_hash"]:
            claim = _scope_state_claim(
                sidecar=sidecar,
                verdict="disproved",
                reason_code="CHECKPOINT_SCOPE_STATE_PREDICATE_HASH_MISMATCH",
                message="scope commitment predicate_value_hash does not match predicate_value",
            )
            return ScopeClaimResult(claim=claim, sidecar=sidecar)
        if actual_hash in seen_hashes:
            claim = _scope_state_claim(
                sidecar=sidecar,
                verdict="disproved",
                reason_code="CHECKPOINT_SCOPE_STATE_COMMITMENT_PREDICATE_DUPLICATE",
                message="scope-state sidecar has duplicate predicate commitments",
            )
            return ScopeClaimResult(claim=claim, sidecar=sidecar)
        seen_hashes.add(actual_hash)

    claim = _scope_state_claim(
        sidecar=sidecar,
        verdict="supported",
        reason_code="CHECKPOINT_SCOPE_STATE_SUPPORTED",
        message="scope-state sidecar signature, checkpoint binding, predicate grammar, and commitment profile are supported",
    )
    return ScopeClaimResult(claim=claim, sidecar=sidecar)


def _load_json_file_if_present(path: Path) -> tuple[dict[str, Any] | None, bytes | None]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except Exception:
        return None, None
    return (value if isinstance(value, dict) else None), raw


def _resolve_scope_checkpoint(
    *,
    manifest_path: Path,
    explicit_checkpoint: str | None = None,
) -> dict[str, Any] | None:
    candidates: list[Path] = []
    if explicit_checkpoint:
        candidates.append(Path(explicit_checkpoint))
    candidates.extend(
        [
            manifest_path.parent / "checkpoint.json",
            manifest_path.parent.parent / "checkpoint.json",
            manifest_path.parent.parent / "pack" / "checkpoint.json",
        ]
    )
    for candidate in candidates:
        value, _raw = _load_json_file_if_present(candidate)
        if value is not None:
            return value
    return None


def _sidecar_candidate_paths(
    *,
    manifest_path: Path,
    reference: dict[str, Any],
    explicit_sidecar: str | None = None,
) -> list[Path]:
    candidates: list[Path] = []
    if explicit_sidecar:
        candidates.append(Path(explicit_sidecar))
    storage_uri = reference.get("storage_uri")
    if isinstance(storage_uri, str) and storage_uri:
        storage_path = Path(storage_uri)
        if storage_path.is_absolute():
            candidates.append(storage_path)
        else:
            candidates.append(manifest_path.parent / storage_path)
            candidates.append(manifest_path.parent.parent / storage_path)
    candidates.extend(
        [
            manifest_path.parent / "sidecars" / SCOPE_STATE_SIDECAR_FILE,
            manifest_path.parent.parent / "sidecars" / SCOPE_STATE_SIDECAR_FILE,
            manifest_path.parent / SCOPE_STATE_SIDECAR_FILE,
        ]
    )
    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate)
        if key not in seen:
            unique.append(candidate)
            seen.add(key)
    return unique


def _resolve_scope_sidecar(
    *,
    manifest_path: Path,
    reference: dict[str, Any],
    explicit_sidecar: str | None = None,
) -> tuple[dict[str, Any] | None, bytes | None]:
    for candidate in _sidecar_candidate_paths(
        manifest_path=manifest_path,
        reference=reference,
        explicit_sidecar=explicit_sidecar,
    ):
        value, raw = _load_json_file_if_present(candidate)
        if value is not None and raw is not None:
            return value, raw
    return None, None


def _scope_export_declaration_present(export_data: bytes) -> bool:
    try:
        document = _load_export_json_document(export_data)
    except Exception:
        return False
    return (
        isinstance(document, dict)
        and isinstance(document.get("scope_faithfulness"), dict)
        and document["scope_faithfulness"].get("version") == SCOPE_FAITHFULNESS_VERSION
    )


def _first_present(mapping: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def _normalize_scope_record(record: Any) -> Any:
    if not isinstance(record, dict):
        return record
    source = record.get("chain_entry_ref")
    if not isinstance(source, dict):
        source = record

    payload: dict[str, Any] = {}
    for candidate in (
        record.get("payload_json"),
        source.get("payload_json"),
        record.get("payload"),
        source.get("payload"),
    ):
        if isinstance(candidate, dict):
            payload.update(candidate)
    for field in _SCOPE_RECORD_PAYLOAD_FALLBACK_FIELDS:
        if field not in payload and field in record:
            payload[field] = record[field]
        if field not in payload and field in source:
            payload[field] = source[field]
    if "event_type" not in payload:
        event_type = _first_present(record, "event_type")
        if event_type is None:
            event_type = _first_present(source, "event_type")
        if isinstance(event_type, str):
            payload["event_type"] = event_type

    normalized: dict[str, Any] = {}
    aliases = {
        "record_hash": ("record_hash", "chain_entry_hash"),
        "prev_hash": ("prev_hash", "previous_record_hash"),
        "chain_format_version": ("chain_format_version", "format_version"),
    }
    for field in _SCOPE_RECORD_FIELDS:
        keys = aliases.get(field, (field,))
        value = _first_present(record, *keys)
        if value is None:
            value = _first_present(source, *keys)
        normalized[field] = value
    normalized["payload_json"] = payload
    return normalized


def _normalize_scope_segment(segment: Any) -> Any:
    if not isinstance(segment, dict):
        return segment
    normalized = dict(segment)
    end = normalized.get("declared_end")
    if isinstance(end, dict):
        normalized["declared_end"] = {
            key: end.get(key)
            for key in (
                "checkpoint_id",
                "chain_scope",
                "sequence_number",
                "last_record_hash",
                "boundary_policy",
            )
        }
    evidence = normalized.get("chain_evidence")
    if isinstance(evidence, dict):
        normalized_evidence = dict(evidence)
        for list_name in ("disclosure_records", "proof_bridge_records"):
            records = evidence.get(list_name)
            if isinstance(records, list):
                normalized_evidence[list_name] = [
                    _normalize_scope_record(record) for record in records
                ]
        normalized["chain_evidence"] = normalized_evidence
    return normalized


def _scope_segment_schema_error(segment: Any) -> str | None:
    if not _exact_keys(
        segment,
        {
            "segment_id",
            "declared_scope",
            "declared_start",
            "declared_end",
            "scope_state_reference",
            "canonical_filters",
            "chain_evidence",
        },
    ):
        return "scope_faithfulness segment fields do not match v1"
    if not _is_nonempty_str(segment.get("segment_id")):
        return "segment_id must be a non-empty string"
    scope = segment.get("declared_scope")
    if not _exact_keys(scope, {"version", "scope_kind", "chain_scope", "population_label", "predicate", "presentation_policy"}):
        return "declared_scope fields do not match v1"
    if scope.get("version") != SCOPE_DECLARATION_VERSION or scope.get("scope_kind") not in {"declared_population", "declared_sample"}:
        return "declared_scope version or scope_kind is unsupported"
    if not _is_nonempty_str(scope.get("chain_scope")) or not _is_nonempty_str(scope.get("population_label")):
        return "declared_scope chain_scope and population_label must be non-empty strings"
    policy = scope.get("presentation_policy")
    if not _exact_keys(policy, {"version", "policy_kind", "policy_parameters"}):
        return "presentation_policy fields do not match v1"
    if policy.get("version") != PRESENTATION_POLICY_VERSION or policy.get("policy_kind") not in {"none", "plan_tier", "section", "field_redaction"}:
        return "presentation_policy is unsupported"
    if not isinstance(policy.get("policy_parameters"), dict):
        return "presentation_policy.policy_parameters must be an object"

    start = segment.get("declared_start")
    if not isinstance(start, dict) or not _is_nonempty_str(start.get("kind")):
        return "declared_start must be an object with a kind"
    if start["kind"] == "genesis":
        if not _exact_keys(start, {"kind", "chain_scope", "sequence_number", "genesis_prev_hash"}) or start.get("sequence_number") != 1:
            return "genesis declared_start fields do not match v1"
    elif start["kind"] == "predecessor_proof":
        if not _exact_keys(start, {"kind", "chain_scope", "predecessor_sequence_number", "predecessor_record_hash", "first_evidence_sequence_number"}):
            return "predecessor_proof declared_start fields do not match v1"
    elif start["kind"] == "checkpoint_anchor":
        if not _exact_keys(start, {"kind", "checkpoint_id", "chain_scope", "sequence_number", "last_record_hash"}):
            return "checkpoint_anchor declared_start fields do not match v1"
    else:
        return "declared_start kind is unsupported"
    if not _is_nonempty_str(start.get("chain_scope")):
        return "declared_start.chain_scope must be a non-empty string"

    end = segment.get("declared_end")
    if not _exact_keys(end, {"checkpoint_id", "chain_scope", "sequence_number", "last_record_hash", "boundary_policy"}):
        return "declared_end fields do not match v1"
    if not _is_nonempty_str(end.get("checkpoint_id")) or not _is_nonempty_str(end.get("chain_scope")) or not _is_nonempty_str(end.get("last_record_hash")):
        return "declared_end checkpoint_id, chain_scope, and last_record_hash must be non-empty strings"
    if not _is_nonbool_int(end.get("sequence_number")) or end["sequence_number"] < 0:
        return "declared_end.sequence_number must be a non-negative integer"
    if end.get("boundary_policy") not in {"explicit_checkpoint", "latest_checkpoint_at_export"}:
        return "declared_end.boundary_policy is unsupported"

    reference = segment.get("scope_state_reference")
    if not _exact_keys(reference, {"artifact_type", "scope_state_id", "checkpoint_id", "chain_scope", "artifact_hash"}) and not _exact_keys(reference, {"artifact_type", "scope_state_id", "checkpoint_id", "chain_scope", "artifact_hash", "storage_uri"}):
        return "scope_state_reference fields do not match v1"
    if reference.get("artifact_type") != "checkpoint_scope_state":
        return "scope_state_reference.artifact_type must be checkpoint_scope_state"
    for field in ("scope_state_id", "checkpoint_id", "chain_scope"):
        if not _is_nonempty_str(reference.get(field)):
            return f"scope_state_reference.{field} must be a non-empty string"
    if not _is_hash(reference.get("artifact_hash")):
        return "scope_state_reference.artifact_hash must be sha256:<hex>"

    filters = segment.get("canonical_filters")
    if not _exact_keys(filters, {"canonicalization_profile", "raw_filters", "filters_hash"}):
        return "canonical_filters fields do not match v1"
    if filters.get("canonicalization_profile") != "keel.canonical_json.payload.v1":
        return "canonical_filters canonicalization_profile is unsupported"
    if not isinstance(filters.get("raw_filters"), dict) or not _is_hash(filters.get("filters_hash")):
        return "canonical_filters raw_filters and filters_hash are malformed"

    evidence = segment.get("chain_evidence")
    if not _exact_keys(evidence, {"disclosure_records", "proof_bridge_records"}):
        return "chain_evidence fields do not match v1"
    for list_name in ("disclosure_records", "proof_bridge_records"):
        records = evidence.get(list_name)
        if not isinstance(records, list):
            return f"chain_evidence.{list_name} must be an array"
        for index, record in enumerate(records):
            if not _exact_keys(record, {"event_id", "event_type", "chain_scope", "sequence_number", "record_hash", "prev_hash", "created_at", "chain_format_version", "payload_json"}):
                return f"{list_name}[{index}] fields do not match v1"
            if not _is_nonempty_str(record.get("event_id")) or not _is_nonempty_str(record.get("event_type")) or not _is_nonempty_str(record.get("chain_scope")):
                return f"{list_name}[{index}] identity fields must be non-empty strings"
            if not _is_nonbool_int(record.get("sequence_number")) or int(record["sequence_number"]) < 1:
                return f"{list_name}[{index}].sequence_number must be a positive integer"
            if not _is_nonempty_str(record.get("record_hash")) or not _is_nonempty_str(record.get("prev_hash")):
                return f"{list_name}[{index}] hash fields must be non-empty strings"
            if not _is_nonempty_str(record.get("created_at")) or not _is_nonempty_str(record.get("chain_format_version")):
                return f"{list_name}[{index}] created_at and chain_format_version must be non-empty strings"
            if not isinstance(record.get("payload_json"), dict):
                return f"{list_name}[{index}].payload_json must be an object"
    return None


def _declared_start_sequence(start: dict[str, Any]) -> int:
    if start["kind"] == "genesis":
        return 1
    if start["kind"] == "predecessor_proof":
        return int(start["first_evidence_sequence_number"])
    return int(start["sequence_number"]) + 1


def _ordered_scope_evidence(segment: dict[str, Any]) -> list[dict[str, Any]]:
    evidence = segment["chain_evidence"]
    return sorted(
        [*evidence["disclosure_records"], *evidence["proof_bridge_records"]],
        key=lambda item: (int(item["sequence_number"]), str(item["event_id"]), str(item["record_hash"])),
    )


def _check_scope_start(segment: dict[str, Any]) -> tuple[str | None, str | None]:
    start = segment["declared_start"]
    records = _ordered_scope_evidence(segment)
    if not records:
        if segment["declared_scope"]["predicate"] and not segment["chain_evidence"]["disclosure_records"]:
            return None, None
        return "EXPORT_CHAIN_PROOF_MISSING", "scope-faithfulness segment has no chain evidence"
    first = records[0]
    if start["kind"] == "genesis":
        if first["sequence_number"] != 1 or first["prev_hash"] != start["genesis_prev_hash"]:
            return "EXPORT_BOUNDARY_START_MISMATCH", "first supplied evidence does not match declared genesis start"
        return None, None
    if start["kind"] == "predecessor_proof":
        if first["sequence_number"] != start["first_evidence_sequence_number"] or first["prev_hash"] != start["predecessor_record_hash"]:
            return "EXPORT_BOUNDARY_START_MISMATCH", "first supplied evidence does not chain from declared predecessor proof"
        for bridge in segment["chain_evidence"]["proof_bridge_records"]:
            if bridge["sequence_number"] == start["predecessor_sequence_number"] and bridge["record_hash"] != start["predecessor_record_hash"]:
                return "EXPORT_BOUNDARY_START_MISMATCH", "supplied predecessor bridge record hash does not match declared predecessor"
        return None, None
    if start["kind"] == "checkpoint_anchor":
        if first["sequence_number"] != start["sequence_number"] + 1 or first["prev_hash"] != start["last_record_hash"]:
            return "EXPORT_BOUNDARY_START_MISMATCH", "first supplied evidence does not extend declared checkpoint anchor"
        return None, None
    return "EXPORT_BOUNDARY_START_MISMATCH", "declared_start kind is unsupported"


def _check_scope_continuity(segment: dict[str, Any]) -> tuple[str | None, str | None]:
    records = _ordered_scope_evidence(segment)
    seen_sequences: set[int] = set()
    previous: dict[str, Any] | None = None
    for record in records:
        seq = int(record["sequence_number"])
        if seq in seen_sequences:
            return "EXPORT_CHAIN_PROOF_DISCONTINUITY", "duplicate sequence_number in chain evidence"
        seen_sequences.add(seq)
        if previous is not None:
            if seq <= int(previous["sequence_number"]):
                return "EXPORT_CHAIN_PROOF_DISCONTINUITY", "chain evidence sequence numbers are not increasing"
            if record["prev_hash"] != previous["record_hash"]:
                return "EXPORT_CHAIN_PROOF_DISCONTINUITY", "chain evidence prev_hash does not match previous record_hash"
        previous = record
    return None, None


def _latest_freshness_evidence(export_document: dict[str, Any], manifest: dict[str, Any], segment: dict[str, Any]) -> Any:
    segment_id = segment.get("segment_id")
    for source in (
        export_document.get("scope_faithfulness_freshness"),
        manifest.get("scope_faithfulness_freshness"),
        export_document.get("checkpoint_selection_evidence"),
        manifest.get("checkpoint_selection_evidence"),
    ):
        if isinstance(source, dict):
            if isinstance(source.get(str(segment_id)), dict):
                return source[str(segment_id)]
            return source
    return None


def _check_latest_checkpoint_policy(
    export_document: dict[str, Any],
    manifest: dict[str, Any],
    segment: dict[str, Any],
) -> tuple[str | None, str | None]:
    end = segment["declared_end"]
    if end.get("boundary_policy") != "latest_checkpoint_at_export":
        return None, None
    evidence = _latest_freshness_evidence(export_document, manifest, segment)
    if evidence is None:
        return "EXPORT_BOUNDARY_FRESHNESS_EVIDENCE_MISSING", "latest-at-export boundary policy lacks signed freshness evidence"
    later_items: list[Any] = []
    if isinstance(evidence, dict):
        if isinstance(evidence.get("later_checkpoints"), list):
            later_items.extend(evidence["later_checkpoints"])
        if isinstance(evidence.get("observed_checkpoints"), list):
            later_items.extend(evidence["observed_checkpoints"])
        if "sequence_number" in evidence:
            later_items.append(evidence)
    elif isinstance(evidence, list):
        later_items.extend(evidence)
    for item in later_items:
        if not isinstance(item, dict):
            continue
        if item.get("chain_scope") not in {None, end["chain_scope"]}:
            continue
        sequence = item.get("sequence_number")
        if _is_nonbool_int(sequence) and int(sequence) > int(end["sequence_number"]):
            return "EXPORT_BOUNDARY_STALE_CHECKPOINT", "freshness evidence shows a later checkpoint was available at export time"
        checkpoint_id = item.get("checkpoint_id")
        if isinstance(checkpoint_id, str) and checkpoint_id and checkpoint_id != end["checkpoint_id"] and _is_nonbool_int(sequence):
            return "EXPORT_BOUNDARY_STALE_CHECKPOINT", "freshness evidence names a later checkpoint"
    return None, None


def _adjudicate_export_scope_faithfulness_v1(
    *,
    export_data: bytes,
    manifest: dict[str, Any],
    manifest_path: Path,
    key_manifest_source: str | None,
    semantics_dispatch: SemanticsDispatch | None = None,
    explicit_sidecar: str | None = None,
    explicit_checkpoint: str | None = None,
) -> list[ClaimVerdict]:
    try:
        export_document = _load_export_json_document(export_data)
    except Exception as exc:
        return [
            _export_scope_claim(
                segment_id=None,
                verdict="disproved",
                reason_code="EXPORT_SCOPE_DECLARATION_SCHEMA_INVALID",
                message=f"export payload is not JSON: {exc}",
            )
        ]
    if not isinstance(export_document, dict):
        return [
            _export_scope_claim(
                segment_id=None,
                verdict="disproved",
                reason_code="EXPORT_SCOPE_DECLARATION_SCHEMA_INVALID",
                message="export payload must be a JSON object",
            )
        ]
    block = export_document.get("scope_faithfulness")
    if not isinstance(block, dict):
        return [
            _export_scope_claim(
                segment_id=None,
                verdict="insufficient_evidence",
                reason_code="EXPORT_SCOPE_DECLARATION_MISSING",
                message="signed export payload has no scope_faithfulness block",
            )
        ]
    if set(block.keys()) != {"version", "segments"} or block.get("version") != SCOPE_FAITHFULNESS_VERSION or not isinstance(block.get("segments"), list) or not block["segments"]:
        return [
            _export_scope_claim(
                segment_id=None,
                verdict="disproved",
                reason_code="EXPORT_SCOPE_DECLARATION_SCHEMA_INVALID",
                message="scope_faithfulness block violates v1 schema",
            )
        ]

    checkpoint = _resolve_scope_checkpoint(
        manifest_path=manifest_path,
        explicit_checkpoint=explicit_checkpoint,
    )
    sidecar_claims: list[ClaimVerdict] = []
    export_subjects: list[VerdictSubject] = []
    export_failure: tuple[str, str, str] | None = None
    for raw_segment in block["segments"]:
        segment = _normalize_scope_segment(raw_segment)
        segment_id = segment.get("segment_id") if isinstance(segment, dict) and isinstance(segment.get("segment_id"), str) else None
        schema_error = _scope_segment_schema_error(segment)
        if schema_error is not None:
            export_failure = ("disproved", "EXPORT_SCOPE_DECLARATION_SCHEMA_INVALID", schema_error)
            export_subjects.append(
                _subject(
                    subject_type="scope_faithfulness_segment",
                    subject_id=segment_id,
                    verdict="disproved",
                    reason_code="EXPORT_SCOPE_DECLARATION_SCHEMA_INVALID",
                    message=schema_error,
                    evidence=["export.scope_faithfulness.segments"],
                )
            )
            break

        predicate_error, predicate_message = _validate_scope_predicate(segment["declared_scope"]["predicate"])
        if predicate_error is not None:
            verdict = "unverifiable_scope" if predicate_error == "EXPORT_SCOPE_PREDICATE_UNSUPPORTED" else "disproved"
            export_failure = (verdict, predicate_error, predicate_message or "declared predicate is unsupported or malformed")
            export_subjects.append(
                _subject(
                    subject_type="scope_faithfulness_segment",
                    subject_id=segment_id,
                    verdict=verdict,
                    reason_code=predicate_error,
                    message=predicate_message,
                    evidence=["export.scope_faithfulness.declared_scope.predicate"],
                )
            )
            break

        start_sequence = _declared_start_sequence(segment["declared_start"])
        if start_sequence > int(segment["declared_end"]["sequence_number"]):
            export_failure = ("disproved", "EXPORT_BOUNDARY_START_AFTER_END", "declared_start sequence is after declared_end sequence")
            export_subjects.append(
                _subject(
                    subject_type="scope_faithfulness_segment",
                    subject_id=segment_id,
                    verdict="disproved",
                    reason_code="EXPORT_BOUNDARY_START_AFTER_END",
                    message="declared_start sequence is after declared_end sequence",
                    evidence=["export.scope_faithfulness.declared_start", "export.scope_faithfulness.declared_end"],
                )
            )
            break

        filters = segment["canonical_filters"]
        actual_filters_hash = _prefixed_sha256(_canonical_json_bytes(filters["raw_filters"]))
        if actual_filters_hash != filters["filters_hash"]:
            export_failure = ("disproved", "EXPORT_RAW_FILTERS_HASH_MISMATCH", "canonical_filters.raw_filters do not hash to filters_hash")
            export_subjects.append(
                _subject(
                    subject_type="scope_faithfulness_segment",
                    subject_id=segment_id,
                    verdict="disproved",
                    reason_code="EXPORT_RAW_FILTERS_HASH_MISMATCH",
                    message="canonical_filters.raw_filters do not hash to filters_hash",
                    evidence=["export.scope_faithfulness.canonical_filters"],
                )
            )
            break

        reference = segment["scope_state_reference"]
        sidecar, sidecar_bytes = _resolve_scope_sidecar(
            manifest_path=manifest_path,
            reference=reference,
            explicit_sidecar=explicit_sidecar,
        )
        if sidecar is None or sidecar_bytes is None:
            scope_state_claim = _scope_state_claim(
                sidecar=None,
                verdict="insufficient_evidence",
                reason_code="CHECKPOINT_SCOPE_STATE_MISSING",
                message="export references an absent scope-state sidecar",
            )
            sidecar_claims.append(scope_state_claim)
            export_failure = ("insufficient_evidence", "CHECKPOINT_SCOPE_STATE_MISSING", "export references an absent scope-state sidecar")
            export_subjects.append(
                _subject(
                    subject_type="scope_faithfulness_segment",
                    subject_id=segment_id,
                    verdict="insufficient_evidence",
                    reason_code="CHECKPOINT_SCOPE_STATE_MISSING",
                    message="export references an absent scope-state sidecar",
                    evidence=["export.scope_faithfulness.scope_state_reference"],
                )
            )
            break
        if _prefixed_sha256(sidecar_bytes) != reference["artifact_hash"]:
            export_failure = ("disproved", "EXPORT_SCOPE_STATE_REFERENCE_MISMATCH", "scope_state_reference artifact_hash does not match resolved sidecar bytes")
            export_subjects.append(
                _subject(
                    subject_type="scope_faithfulness_segment",
                    subject_id=segment_id,
                    verdict="disproved",
                    reason_code="EXPORT_SCOPE_STATE_REFERENCE_MISMATCH",
                    message="scope_state_reference artifact_hash does not match resolved sidecar bytes",
                    evidence=["export.scope_faithfulness.scope_state_reference"],
                )
            )
            break
        for field in ("artifact_type", "scope_state_id", "checkpoint_id", "chain_scope"):
            if sidecar.get(field) != reference.get(field):
                export_failure = ("disproved", "EXPORT_SCOPE_STATE_REFERENCE_MISMATCH", f"scope_state_reference.{field} does not match resolved sidecar")
                export_subjects.append(
                    _subject(
                        subject_type="scope_faithfulness_segment",
                        subject_id=segment_id,
                        verdict="disproved",
                        reason_code="EXPORT_SCOPE_STATE_REFERENCE_MISMATCH",
                        message=f"scope_state_reference.{field} does not match resolved sidecar",
                        evidence=["export.scope_faithfulness.scope_state_reference"],
                    )
                )
                break
        if export_failure is not None:
            break

        scope_state_result = _adjudicate_checkpoint_scope_state_v1(
            sidecar,
            checkpoint=checkpoint,
            key_manifest_source=key_manifest_source,
            semantics_dispatch=semantics_dispatch,
        )
        sidecar_claims.append(scope_state_result.claim)
        if scope_state_result.claim.aggregate_verdict != verdict_value("supported"):
            verdict = scope_state_result.claim.aggregate_verdict
            reason = scope_state_result.claim.reason_code or "CHECKPOINT_SCOPE_STATE_MISSING"
            message = scope_state_result.claim.message or "scope-state sidecar did not support this segment"
            export_failure = (verdict, reason, message)
            export_subjects.append(
                _subject(
                    subject_type="scope_faithfulness_segment",
                    subject_id=segment_id,
                    verdict=verdict,
                    reason_code=reason,
                    message=message,
                    evidence=["export.scope_faithfulness.scope_state_reference", "checkpoint_scope_state"],
                )
            )
            break

        chain_scope_fields = {
            segment["declared_scope"]["chain_scope"],
            segment["declared_start"]["chain_scope"],
            segment["declared_end"]["chain_scope"],
            reference["chain_scope"],
            sidecar["chain_scope"],
        }
        for record in _ordered_scope_evidence(segment):
            chain_scope_fields.add(record["chain_scope"])
        if len(chain_scope_fields) != 1:
            export_failure = ("disproved", "EXPORT_SCOPE_CHAIN_SCOPE_MISMATCH", "segment fields or records disagree on chain_scope")
            export_subjects.append(
                _subject(
                    subject_type="scope_faithfulness_segment",
                    subject_id=segment_id,
                    verdict="disproved",
                    reason_code="EXPORT_SCOPE_CHAIN_SCOPE_MISMATCH",
                    message="segment fields or records disagree on chain_scope",
                    evidence=["export.scope_faithfulness.segments[].chain_scope"],
                )
            )
            break

        if checkpoint is None or not isinstance(checkpoint.get("chain_heads"), dict):
            export_failure = ("insufficient_evidence", "CHECKPOINT_SCOPE_STATE_CHECKPOINT_MISSING", "referenced checkpoint artifact is absent")
            export_subjects.append(
                _subject(
                    subject_type="scope_faithfulness_segment",
                    subject_id=segment_id,
                    verdict="insufficient_evidence",
                    reason_code="CHECKPOINT_SCOPE_STATE_CHECKPOINT_MISSING",
                    message="referenced checkpoint artifact is absent",
                    evidence=["checkpoint"],
                )
            )
            break
        head = checkpoint["chain_heads"].get(sidecar["chain_scope"])
        end = segment["declared_end"]
        if not isinstance(head, dict):
            export_failure = ("disproved", "EXPORT_BOUNDARY_END_NOT_CHECKPOINT", "declared_end does not name a checkpoint chain head")
            export_subjects.append(
                _subject(
                    subject_type="scope_faithfulness_segment",
                    subject_id=segment_id,
                    verdict="disproved",
                    reason_code="EXPORT_BOUNDARY_END_NOT_CHECKPOINT",
                    message="declared_end does not name a checkpoint chain head",
                    evidence=["export.scope_faithfulness.declared_end", "checkpoint.chain_heads"],
                )
            )
            break
        if (
            end["checkpoint_id"] != sidecar["checkpoint_id"]
            or end["chain_scope"] != sidecar["chain_scope"]
            or end["sequence_number"] != head.get("sequence_number")
            or end["last_record_hash"] != head.get("last_record_hash")
        ):
            export_failure = ("disproved", "EXPORT_BOUNDARY_CHECKPOINT_MISMATCH", "declared_end differs from the sidecar checkpoint head")
            export_subjects.append(
                _subject(
                    subject_type="scope_faithfulness_segment",
                    subject_id=segment_id,
                    verdict="disproved",
                    reason_code="EXPORT_BOUNDARY_CHECKPOINT_MISMATCH",
                    message="declared_end differs from the sidecar checkpoint head",
                    evidence=["export.scope_faithfulness.declared_end", "checkpoint.chain_heads"],
                )
            )
            break

        boundary_error, boundary_message = _check_latest_checkpoint_policy(export_document, manifest, segment)
        if boundary_error is not None:
            verdict = "insufficient_evidence" if boundary_error == "EXPORT_BOUNDARY_FRESHNESS_EVIDENCE_MISSING" else "disproved"
            export_failure = (verdict, boundary_error, boundary_message or "latest checkpoint policy failed")
            export_subjects.append(
                _subject(
                    subject_type="scope_faithfulness_segment",
                    subject_id=segment_id,
                    verdict=verdict,
                    reason_code=boundary_error,
                    message=boundary_message,
                    evidence=["export.scope_faithfulness.declared_end.boundary_policy"],
                )
            )
            break

        start_error, start_message = _check_scope_start(segment)
        if start_error is not None:
            verdict = "insufficient_evidence" if start_error == "EXPORT_CHAIN_PROOF_MISSING" else "disproved"
            export_failure = (verdict, start_error, start_message or "declared_start does not match supplied evidence")
            export_subjects.append(
                _subject(
                    subject_type="scope_faithfulness_segment",
                    subject_id=segment_id,
                    verdict=verdict,
                    reason_code=start_error,
                    message=start_message,
                    evidence=["export.scope_faithfulness.declared_start", "export.scope_faithfulness.chain_evidence"],
                )
            )
            break

        continuity_error, continuity_message = _check_scope_continuity(segment)
        if continuity_error is not None:
            export_failure = ("disproved", continuity_error, continuity_message or "chain evidence is discontinuous")
            export_subjects.append(
                _subject(
                    subject_type="scope_faithfulness_segment",
                    subject_id=segment_id,
                    verdict="disproved",
                    reason_code=continuity_error,
                    message=continuity_message,
                    evidence=["export.scope_faithfulness.chain_evidence"],
                )
            )
            break

        predicate = segment["declared_scope"]["predicate"]
        disclosures = segment["chain_evidence"]["disclosure_records"]
        bridges = segment["chain_evidence"]["proof_bridge_records"]
        for record in disclosures:
            if not _scope_predicate_matches(record, predicate):
                export_failure = ("disproved", "EXPORT_SCOPE_PREDICATE_VIOLATED", "a disclosure record does not satisfy the declared predicate")
                export_subjects.append(
                    _subject(
                        subject_type="scope_faithfulness_segment",
                        subject_id=segment_id,
                        verdict="disproved",
                        reason_code="EXPORT_SCOPE_PREDICATE_VIOLATED",
                        message="a disclosure record does not satisfy the declared predicate",
                        evidence=["export.scope_faithfulness.chain_evidence.disclosure_records"],
                    )
                )
                break
        if export_failure is not None:
            break
        for record in bridges:
            if _scope_predicate_matches(record, predicate):
                export_failure = ("disproved", "EXPORT_PROOF_BRIDGE_MISCLASSIFIED", "a proof bridge record satisfies the declared predicate and is misclassified")
                export_subjects.append(
                    _subject(
                        subject_type="scope_faithfulness_segment",
                        subject_id=segment_id,
                        verdict="disproved",
                        reason_code="EXPORT_PROOF_BRIDGE_MISCLASSIFIED",
                        message="a proof bridge record satisfies the declared predicate and is misclassified",
                        evidence=["export.scope_faithfulness.chain_evidence.proof_bridge_records"],
                    )
                )
                break
        if export_failure is not None:
            break

        predicate_value_hash = _predicate_hash(predicate)
        commitment = next(
            (
                item
                for item in sidecar["scope_commitments"]
                if item.get("predicate_value_hash") == predicate_value_hash
            ),
            None,
        )
        if commitment is None:
            export_failure = ("insufficient_evidence", "EXPORT_SCOPE_COMMITMENT_MISSING", "sidecar has no commitment for the declared predicate")
            export_subjects.append(
                _subject(
                    subject_type="scope_faithfulness_segment",
                    subject_id=segment_id,
                    verdict="insufficient_evidence",
                    reason_code="EXPORT_SCOPE_COMMITMENT_MISSING",
                    message="sidecar has no commitment for the declared predicate",
                    evidence=["checkpoint_scope_state.scope_commitments"],
                )
            )
            break

        if commitment["matching_count"] != len(disclosures):
            export_failure = ("disproved", "EXPORT_SCOPE_CARDINALITY_MISMATCH", "signed matching_count differs from disclosure record count")
            export_subjects.append(
                _subject(
                    subject_type="scope_faithfulness_segment",
                    subject_id=segment_id,
                    verdict="disproved",
                    reason_code="EXPORT_SCOPE_CARDINALITY_MISMATCH",
                    message="signed matching_count differs from disclosure record count",
                    evidence=["checkpoint_scope_state.scope_commitments.matching_count", "export.scope_faithfulness.chain_evidence.disclosure_records"],
                )
            )
            break

        recomputed_root = _scope_merkle_root(disclosures, predicate_value_hash)
        if recomputed_root != commitment["membership_root_hash"]:
            export_failure = ("disproved", "EXPORT_SCOPE_MEMBERSHIP_ROOT_MISMATCH", "recomputed membership root differs from signed sidecar root")
            export_subjects.append(
                _subject(
                    subject_type="scope_faithfulness_segment",
                    subject_id=segment_id,
                    verdict="disproved",
                    reason_code="EXPORT_SCOPE_MEMBERSHIP_ROOT_MISMATCH",
                    message="recomputed membership root differs from signed sidecar root",
                    evidence=["checkpoint_scope_state.scope_commitments.membership_root_hash", "export.scope_faithfulness.chain_evidence.disclosure_records"],
                )
            )
            break

        if not disclosures:
            first = last = None
        else:
            sequences = [int(record["sequence_number"]) for record in disclosures]
            first = min(sequences)
            last = max(sequences)
        if commitment["first_matching_sequence"] != first or commitment["last_matching_sequence"] != last:
            export_failure = ("disproved", "EXPORT_SCOPE_RANGE_MISMATCH", "signed matching range differs from disclosure record sequence range")
            export_subjects.append(
                _subject(
                    subject_type="scope_faithfulness_segment",
                    subject_id=segment_id,
                    verdict="disproved",
                    reason_code="EXPORT_SCOPE_RANGE_MISMATCH",
                    message="signed matching range differs from disclosure record sequence range",
                    evidence=["checkpoint_scope_state.scope_commitments.matching_range", "export.scope_faithfulness.chain_evidence.disclosure_records"],
                )
            )
            break

        export_subjects.append(
            _subject(
                subject_type="scope_faithfulness_segment",
                subject_id=segment_id,
                verdict="supported",
                reason_code="EXPORT_SCOPE_FAITHFULNESS_SUPPORTED",
                message="scope-faithfulness segment reconciles against the signed scope-state sidecar",
                evidence=["export.scope_faithfulness", "checkpoint_scope_state"],
            )
        )

    if export_failure is None:
        export_claim = ClaimVerdict(
            name="export.scope_faithfulness.v1",
            subjects=export_subjects,
            verdict="supported",
            reason_code="EXPORT_SCOPE_FAITHFULNESS_SUPPORTED",
            message="all scope-faithfulness segments are supported",
            evidence=["export.scope_faithfulness", "checkpoint_scope_state"],
        )
    else:
        verdict, reason_code, message = export_failure
        export_claim = ClaimVerdict(
            name="export.scope_faithfulness.v1",
            subjects=export_subjects,
            verdict=verdict,
            reason_code=reason_code,
            message=message,
            evidence=["export.scope_faithfulness", "checkpoint_scope_state"],
        )
    return [*sidecar_claims, export_claim]


def _count_from_output(stdout: str, label: str) -> int | None:
    match = re.search(rf"{re.escape(label)}:\s+(\d+)", stdout)
    if not match:
        return None
    return int(match.group(1))


def _workflow_claims_from_output(
    *,
    manifest: dict[str, Any],
    stdout: str,
    stderr: str,
    result: int | None,
) -> list[ClaimVerdict]:
    claims: list[ClaimVerdict] = []
    sibling_artifacts = manifest.get("sibling_artifacts")
    sibling_present = (
        isinstance(sibling_artifacts, dict)
        and isinstance(sibling_artifacts.get("workflow_evidence"), dict)
    )
    if sibling_present and "WORKFLOW-EVIDENCE: VERIFIED" in stdout:
        claims.append(
            _single_subject_claim(
                "workflow_evidence.sibling_integrity.v1",
                subject_type="workflow_evidence_sibling",
                subject_id="workflow_evidence",
                verdict="supported",
                reason_code="WORKFLOW_SIBLING_INTEGRITY_SUPPORTED",
                message="workflow evidence sibling content hash and signature are valid",
                evidence=["manifest.sibling_artifacts.workflow_evidence"],
            )
        )

    declarations = _count_from_output(stdout, "declarations_verified")
    amendments = _count_from_output(stdout, "amendments_verified")
    if declarations is not None and declarations > 0:
        claims.extend(
            [
                _single_subject_claim(
                    "workflow.declaration_signature.v1",
                    subject_type="workflow_declarations",
                    subject_id="declarations",
                    verdict="supported",
                    reason_code="WORKFLOW_DECLARATION_SIGNATURE_SUPPORTED",
                    message=f"{declarations} workflow declaration signature(s) verified",
                    evidence=["workflow_evidence.declarations"],
                ),
                _single_subject_claim(
                    "workflow.effective_intent_hash.v1",
                    subject_type="workflow_declarations",
                    subject_id="declarations",
                    verdict="supported",
                    reason_code="WORKFLOW_EFFECTIVE_INTENT_HASH_SUPPORTED",
                    message="workflow effective intent hash checks verified",
                    evidence=["workflow_evidence.declarations", "workflow_evidence.amendments"],
                ),
            ]
        )
    if amendments is not None and amendments > 0:
        claims.append(
            _single_subject_claim(
                "workflow.amendment_signature.v1",
                subject_type="workflow_amendments",
                subject_id="amendments",
                verdict="supported",
                reason_code="WORKFLOW_AMENDMENT_SIGNATURE_SUPPORTED",
                message=f"{amendments} workflow amendment signature(s) verified",
                evidence=["workflow_evidence.amendments"],
            )
        )
    snapshot_checks = _count_from_output(stdout, "workflow_state_json checks")
    if snapshot_checks is not None and snapshot_checks > 0:
        claims.append(
            _single_subject_claim(
                "workflow.permit_snapshot.v1",
                subject_type="permit_workflow_snapshot",
                subject_id="workflow_state_json",
                verdict="supported",
                reason_code="WORKFLOW_PERMIT_SNAPSHOT_SUPPORTED",
                message=f"{snapshot_checks} permit workflow snapshot(s) verified",
                evidence=["export.records.workflow_state_json"],
            )
        )
    if "INCIDENT-BUNDLE: VERIFIED" in stdout:
        claims.append(
            _single_subject_claim(
                "incident.bundle_manifest.v1",
                subject_type="incident_bundle",
                subject_id="incident.zip",
                verdict="supported",
                reason_code="INCIDENT_BUNDLE_MANIFEST_SUPPORTED",
                message="incident bundle manifest v2 file set and schemas verified",
                evidence=["incident.zip", "manifest"],
            )
        )

    if result is None:
        return claims
    if result == 0:
        return claims

    reason_code, message = _failure_from_output(stdout, stderr)
    lowered = message.lower()
    if reason_code == WORKFLOW_EVIDENCE_SCHEMA_INVALID:
        if "workflow_evidence content_hash mismatch" in lowered:
            claim_name = "workflow_evidence.sibling_integrity.v1"
            verdict = "disproved"
        elif "declaration_signed_at" in lowered or "declarations[" in lowered:
            claim_name = "workflow.declaration_signature.v1"
            verdict = "insufficient_evidence"
        else:
            claim_name = "workflow.effective_intent_hash.v1"
            verdict = "insufficient_evidence"
    elif reason_code == WORKFLOW_SIGNATURE_INVALID:
        if "amendment" in lowered:
            claim_name = "workflow.amendment_signature.v1"
        elif "workflow_evidence" in lowered:
            claim_name = "workflow_evidence.sibling_integrity.v1"
        else:
            claim_name = "workflow.declaration_signature.v1"
        verdict = "disproved"
    elif reason_code == WORKFLOW_AMENDMENT_ORDER_INVALID:
        claim_name = "workflow.effective_intent_hash.v1"
        verdict = "disproved"
    elif reason_code == WORKFLOW_EFFECTIVE_INTENT_HASH_MISMATCH:
        claim_name = (
            "workflow.permit_snapshot.v1"
            if "permit_records[" in lowered
            else "workflow.effective_intent_hash.v1"
        )
        verdict = "disproved"
    elif reason_code in {INCIDENT_MANIFEST_SCHEMA_INVALID, INCIDENT_UNKNOWN_MANIFEST_VERSION}:
        claim_name = "incident.bundle_manifest.v1"
        verdict = "disproved"
    else:
        claim_name = "workflow.effective_intent_hash.v1"
        verdict = "unverifiable_scope"
    claims.append(
        _single_subject_claim(
            claim_name,
            subject_type="workflow_or_incident",
            subject_id=None,
            verdict=verdict,
            reason_code=reason_code,
            message=message,
            evidence=["export", "manifest"],
        )
    )
    return claims


def _walk_claim_from_output(
    *,
    stdout: str,
    stderr: str,
    result: int,
) -> ClaimVerdict:
    if result == 0 and "WALK-EVENTS: VERIFIED" in stdout:
        entries = _count_from_output(stdout, "entries_walked")
        if entries is not None and entries == 0:
            verdict = "insufficient_evidence"
            reason_code = "WALK_NO_EVALUABLE_SUBJECTS"
            message = "walk-events found zero evaluable chain entries"
        else:
            verdict = "supported"
            reason_code = "WALK_EVENTS_SUPPORTED"
            message = "governance chain local continuity verified"
        return _single_subject_claim(
            "governance_chain.local_continuity.v1",
            subject_type="governance_chain",
            subject_id="chain_entries",
            verdict=verdict,
            reason_code=reason_code,
            message=message,
            evidence=["export.chain_entries", "export.records.chain_entries"],
        )

    reason_code, message = _failure_from_output(stdout, stderr)
    verdict = (
        "unverifiable_scope"
        if reason_code in {"EXPORT_STRUCTURE_INVALID", WALK_UNKNOWN_CHAIN_FORMAT}
        else "disproved"
    )
    return _single_subject_claim(
        "governance_chain.local_continuity.v1",
        subject_type="governance_chain",
        subject_id="chain_entries",
        verdict=verdict,
        reason_code=reason_code,
        message=message,
        evidence=["export.chain_entries", "export.records.chain_entries"],
    )


def _closure_claims_from_output(
    *,
    stdout: str,
    stderr: str,
    result: int,
) -> list[ClaimVerdict]:
    claims: list[ClaimVerdict] = []
    if result == 0 and "VERIFY-CLOSURE: VERIFIED" in stdout:
        closures = _count_from_output(stdout, "closures_verified") or 0
        digest_checks = _count_from_output(stdout, "digest_checks") or 0
        if closures > 0:
            claims.append(
                _single_subject_claim(
                    "closure.signature.v1",
                    subject_type="closure",
                    subject_id="permit.closed",
                    verdict="supported",
                    reason_code="CLOSURE_SIGNATURE_SUPPORTED",
                    message=f"{closures} closure signature(s) verified",
                    evidence=["export.chain_entries[permit.closed]"],
                )
            )
        else:
            claims.append(
                _single_subject_claim(
                    "closure.signature.v1",
                    subject_type="closure",
                    subject_id="permit.closed",
                    verdict="insufficient_evidence",
                    reason_code="CLOSURE_NO_EVALUABLE_SUBJECTS",
                    message="verify-closure found zero evaluable closure subjects",
                    evidence=["export.chain_entries[permit.closed]"],
                )
            )
        if digest_checks > 0:
            claims.append(
                _single_subject_claim(
                    "closure.digest_consistency.v1",
                    subject_type="closure_digest",
                    subject_id="provider_client_response",
                    verdict="supported",
                    reason_code="CLOSURE_DIGEST_CONSISTENCY_SUPPORTED",
                    message=f"{digest_checks} closure digest reference(s) verified",
                    evidence=["export.chain_entries[permit.closed]"],
                )
            )
        if "dispatch_digest_check: PASS" in stdout:
            claims.append(
                _single_subject_claim(
                    "closure.dispatch_binding.v1",
                    subject_type="closure_dispatch_digest",
                    subject_id="dispatch_request_digest_v1",
                    verdict="supported",
                    reason_code="CLOSURE_DISPATCH_BINDING_SUPPORTED",
                    message="closure dispatch request digest matches permit binding hash",
                    evidence=[
                        "export.records.permit.binding_request_hash",
                        "export.chain_entries[permit.closed]",
                    ],
                )
            )
        return claims

    reason_code, message = _failure_from_output(stdout, stderr)
    if reason_code == WALK_CLOSURE_SIGNATURE_INVALID:
        claim_name = "closure.signature.v1"
        verdict = "disproved"
    elif reason_code == WALK_CLOSURE_DISPATCH_DIGEST_MISMATCH:
        claims.append(
            _single_subject_claim(
                "closure.signature.v1",
                subject_type="closure",
                subject_id="permit.closed",
                verdict="supported",
                reason_code="CLOSURE_SIGNATURE_SUPPORTED",
                message="closure signature checks passed before dispatch binding failure",
                evidence=["export.chain_entries[permit.closed]"],
            )
        )
        claim_name = "closure.dispatch_binding.v1"
        verdict = "disproved"
    elif reason_code == WALK_CLOSURE_DIGEST_MISSING:
        claims.append(
            _single_subject_claim(
                "closure.signature.v1",
                subject_type="closure",
                subject_id="permit.closed",
                verdict="supported",
                reason_code="CLOSURE_SIGNATURE_SUPPORTED",
                message="closure signature checks passed before digest evidence failure",
                evidence=["export.chain_entries[permit.closed]"],
            )
        )
        claim_name = (
            "closure.dispatch_binding.v1"
            if "dispatch_request_digest_v1" in message
            else "closure.digest_consistency.v1"
        )
        verdict = "insufficient_evidence"
    elif reason_code == WALK_CLOSURE_DIGEST_MISMATCH:
        claims.append(
            _single_subject_claim(
                "closure.signature.v1",
                subject_type="closure",
                subject_id="permit.closed",
                verdict="supported",
                reason_code="CLOSURE_SIGNATURE_SUPPORTED",
                message="closure signature checks passed before digest consistency failure",
                evidence=["export.chain_entries[permit.closed]"],
            )
        )
        claim_name = "closure.digest_consistency.v1"
        verdict = "disproved"
    else:
        claim_name = "closure.signature.v1"
        verdict = "unverifiable_scope"
    claims.append(
        _single_subject_claim(
            claim_name,
            subject_type="closure",
            subject_id="permit.closed",
            verdict=verdict,
            reason_code=reason_code,
            message=message,
            evidence=["export.chain_entries[permit.closed]"],
        )
    )
    return claims


def verify_export_structured(args: argparse.Namespace) -> VerificationReport:
    export_path = Path(args.export_file)
    manifest_arg = getattr(args, "manifest", None)
    manifest_path = Path(manifest_arg) if manifest_arg else None
    if manifest_path is None:
        artifact = {
            "kind": "evidence_bundle",
            "payload_path": str(export_path),
        }
        if not export_path.exists():
            return _export_report(
                ok=False,
                exit_code=1,
                artifact=artifact,
                claims=[],
                error=f"Export file not found: {export_path}",
            )
        export_data = export_path.read_bytes()
        artifact["payload_hash"] = _content_hash(export_data)
        try:
            bundle = json.loads(export_data.decode("utf-8"))
        except Exception as exc:
            return _export_report(
                ok=False,
                exit_code=1,
                artifact=artifact,
                claims=[],
                error=(
                    "manifest is required for legacy split-file export input; "
                    f"single-file bundle JSON parse failed: {exc}"
                ),
            )
        if not _is_self_attesting_bundle(bundle):
            return _export_report(
                ok=False,
                exit_code=1,
                artifact=artifact,
                claims=[],
                error=(
                    "manifest is required for legacy split-file export input; "
                    "input is not keel.evidence_bundle/v1"
                ),
            )
        ok, error, body, claims, diagnostics = _verify_self_attesting_bundle_payload(
            bundle,
            artifact_id=export_path.name,
            check_tsa=True,
        )
        if body is not None:
            artifact["body_schema"] = body.get("schema")
            artifact["artifact_ref"] = body.get("artifact_ref")
        return _export_report(
            ok=ok,
            exit_code=0 if ok else 1,
            artifact=artifact,
            claims=claims,
            error=error,
            diagnostics=diagnostics,
        )
    artifact = _export_artifact_dict(
        export_path=export_path,
        manifest_path=manifest_path,
    )

    if not export_path.exists():
        return _export_report(
            ok=False,
            exit_code=1,
            artifact=artifact,
            claims=[],
            error=f"Export file not found: {export_path}",
        )
    if not manifest_path.exists():
        return _export_report(
            ok=False,
            exit_code=1,
            artifact=artifact,
            claims=[],
            error=f"Manifest file not found: {manifest_path}",
        )
    _warn_legacy_split_export()

    manifest_data = manifest_path.read_bytes()
    export_data = export_path.read_bytes()
    artifact_ref: ArtifactRef | None = None
    try:
        artifact_ref = _artifact_ref_from_export_data(export_data)
    except Exception as exc:
        return _export_report(
            ok=False,
            exit_code=1,
            artifact=artifact,
            claims=[
                _single_subject_claim(
                    "export.integrity.v1",
                    subject_type="artifact_ref",
                    subject_id=export_path.name,
                    verdict="insufficient_evidence",
                    reason_code="ARTIFACT_REF_INVALID",
                    message=f"artifact_ref is invalid: {exc}",
                    evidence=["export.artifact_ref"],
                )
            ],
            error=f"artifact_ref is invalid: {exc}",
        )
    artifact = _export_artifact_dict(
        export_path=export_path,
        manifest_path=manifest_path,
        export_data=export_data,
        manifest_data=manifest_data,
        artifact_ref=artifact_ref,
    )
    try:
        manifest = json.loads(manifest_data.decode("utf-8"))
    except Exception as exc:
        return _export_report(
            ok=False,
            exit_code=1,
            artifact=artifact,
            claims=[
                _single_subject_claim(
                    "export.integrity.v1",
                    subject_type="manifest",
                    subject_id=manifest_path.name,
                    verdict="insufficient_evidence",
                    reason_code="MANIFEST_JSON_INVALID",
                    message=f"manifest is not valid JSON: {exc}",
                    evidence=[str(manifest_path)],
                )
            ],
            error=f"manifest is not valid JSON: {exc}",
        )
    if not isinstance(manifest, dict):
        return _export_report(
            ok=False,
            exit_code=1,
            artifact=artifact,
            claims=[
                _single_subject_claim(
                    "export.integrity.v1",
                    subject_type="manifest",
                    subject_id=manifest_path.name,
                    verdict="insufficient_evidence",
                    reason_code="MANIFEST_JSON_INVALID",
                    message="manifest top-level JSON must be an object",
                    evidence=[str(manifest_path)],
                )
            ],
            error="manifest top-level JSON must be an object",
        )

    semantics = resolve_pack_semantics(
        manifest,
        pack_root=manifest_path.parent,
        default_claim_names=("export.integrity.v1",),
        allowlist=PERMANENT_ALLOWLIST,
    )
    if not semantics.ok:
        failure = semantics.failure
        assert failure is not None
        claims = _semantic_failure_claims(
            semantics,
            default_claim_names=("export.integrity.v1",),
            subject_type="semantic_resolution",
            subject_id=manifest_path.name,
            evidence=["manifest.claim_set", "manifest.semantics_pins"],
        )
        return _export_report(
            ok=False,
            exit_code=1,
            artifact=artifact,
            claims=claims,
            semantics=semantics,
            error=failure.top_level_error or failure.message,
            diagnostics=[failure.diagnostic] if failure.diagnostic else None,
        )
    semantics_dispatch = semantics.dispatch()

    claims: list[ClaimVerdict] = []
    diagnostics: list[str] = []
    expected = manifest.get("content_hash")
    actual = _content_hash(export_data)
    if expected != actual:
        message = f"content hash mismatch: expected={expected} actual={actual}"
        return _export_report(
            ok=False,
            exit_code=1,
            artifact=artifact,
            claims=[
                _export_integrity_claim(
                    export_path=export_path,
                    manifest_path=manifest_path,
                    content_verdict="disproved",
                    signature_verdict="insufficient_evidence",
                    reason_code="CONTENT_HASH_MISMATCH",
                    message=message,
                    signature_message="signature was not evaluated after content hash mismatch",
                )
            ],
            semantics=semantics,
            error=message,
        )

    sig = manifest.get("signature")
    embedded_pub = manifest.get("public_key")
    artifact_key_id = (
        manifest.get("key_id") if isinstance(manifest.get("key_id"), str) else None
    )

    if not sig:
        message = "Export manifest is unsigned (no signature in manifest)."
        signature_verdict = "insufficient_evidence"
        claims.append(
            _export_integrity_claim(
                export_path=export_path,
                manifest_path=manifest_path,
                content_verdict="supported",
                signature_verdict=signature_verdict,
                reason_code="MANIFEST_SIGNATURE_MISSING",
                message=message,
                signature_message=(
                    "--allow-unsigned compatibility: manifest has no signature; "
                    "content hash verified but signature evidence is missing"
                    if getattr(args, "allow_unsigned", False)
                    else message
                ),
            )
        )
        if getattr(args, "allow_unsigned", False):
            diagnostics.append(
                "--allow-unsigned compatibility mode: content hash verified, "
                "but export.integrity.v1 remains insufficient_evidence because "
                "the manifest signature is missing"
            )
            return _export_report(
                ok=True,
                exit_code=0,
                artifact=artifact,
                claims=claims,
                semantics=semantics,
                diagnostics=diagnostics,
            )
        return _export_report(
            ok=False,
            exit_code=1,
            artifact=artifact,
            claims=claims,
            semantics=semantics,
            error=message,
            diagnostics=diagnostics,
        )

    signing_time = _parse_iso_or_none(manifest.get("signed_at"))
    trusted_pub, trust_source, err = _resolve_trust_key(
        artifact_pub=embedded_pub if isinstance(embedded_pub, str) else None,
        artifact_key_id=artifact_key_id,
        purpose="export_signing",
        expected_public_key=args.expected_public_key,
        public_key_url=None,
        key_manifest_source=_key_manifest_source_for_args(args),
        signing_time=signing_time,
    )
    if err is not None or trusted_pub is None:
        message = str(err or "could not resolve trust root")
        claims.append(
            _export_integrity_claim(
                export_path=export_path,
                manifest_path=manifest_path,
                content_verdict="supported",
                signature_verdict="insufficient_evidence",
                reason_code="TRUST_ROOT_UNRESOLVABLE",
                message=message,
            )
        )
        return _export_report(
            ok=False,
            exit_code=1,
            artifact=artifact,
            claims=claims,
            semantics=semantics,
            error=message,
        )

    if isinstance(embedded_pub, str) and embedded_pub != trusted_pub:
        message = "Manifest public_key does not match trusted key."
        claims.append(
            _export_integrity_claim(
                export_path=export_path,
                manifest_path=manifest_path,
                content_verdict="supported",
                signature_verdict="disproved",
                reason_code="MANIFEST_PUBLIC_KEY_MISMATCH",
                message=message,
            )
        )
        return _export_report(
            ok=False,
            exit_code=1,
            artifact=artifact,
            claims=claims,
            semantics=semantics,
            error=message,
        )

    if not _verify_ed25519(trusted_pub, expected.encode("utf-8"), sig):
        message = "Signature verification failed."
        claims.append(
            _export_integrity_claim(
                export_path=export_path,
                manifest_path=manifest_path,
                content_verdict="supported",
                signature_verdict="disproved",
                reason_code="SIGNATURE_VERIFICATION_FAILED",
                message=message,
            )
        )
        return _export_report(
            ok=False,
            exit_code=1,
            artifact=artifact,
            claims=claims,
            semantics=semantics,
            error=message,
        )

    claims.append(
        _export_integrity_claim(
            export_path=export_path,
            manifest_path=manifest_path,
            content_verdict="supported",
            signature_verdict="supported",
            reason_code="EXPORT_INTEGRITY_SUPPORTED",
            message="export content hash and manifest signature verified",
        )
    )
    scope_claim = _evaluate_export_scope_identity(
        manifest=manifest,
        export_data=export_data,
    )
    if scope_claim is not None:
        claims.append(scope_claim)

    requested = semantics.requested_names()
    permit_decision_requested = _pinned_claim_requested(
        semantics,
        requested,
        PERMIT_DECISION_CLAIM_NAME,
    )
    permit_revoked_requested = _pinned_claim_requested(
        semantics,
        requested,
        PERMIT_REVOKED_CLAIM_NAME,
    )
    permit_absence_requested = _pinned_claim_requested(
        semantics,
        requested,
        PERMIT_DISPATCH_ABSENCE_CLAIM_NAME,
    )
    permit_authority_chain_requested = _pinned_claim_requested(
        semantics,
        requested,
        PERMIT_AUTHORITY_CHAIN_CLAIM_NAME,
    )
    authority_revocation_temporal_requested = _pinned_claim_requested(
        semantics,
        requested,
        AUTHORITY_REVOCATION_TEMPORAL_CLAIM_NAME,
    )
    operator_approval_pinned = _pinned_claim_requested(
        semantics,
        requested,
        PERMIT_OPERATOR_APPROVAL_CLAIM_NAME,
    )
    counter_signature_pinned = _pinned_claim_requested(
        semantics,
        requested,
        PERMIT_COUNTER_SIGNATURE_CLAIM_NAME,
    )
    audit_attestation_pinned = _pinned_claim_requested(
        semantics,
        requested,
        PERMIT_AUDIT_ATTESTATION_CLAIM_NAME,
    )
    legacy_operator_approved_pinned = _pinned_claim_requested(
        semantics,
        requested,
        PERMIT_OPERATOR_APPROVED_CLAIM_NAME,
    )
    legacy_counter_signed_pinned = _pinned_claim_requested(
        semantics,
        requested,
        PERMIT_COUNTER_SIGNED_CLAIM_NAME,
    )
    legacy_audit_attested_pinned = _pinned_claim_requested(
        semantics,
        requested,
        PERMIT_AUDIT_ATTESTED_CLAIM_NAME,
    )
    permit_revocation_dependency_requested = (
        permit_revoked_requested or permit_absence_requested
    )
    export_document_for_claims: dict[str, Any] | None = None
    permit_v2_pinned_requested = (
        operator_approval_pinned
        or counter_signature_pinned
        or audit_attestation_pinned
        or legacy_operator_approved_pinned
        or legacy_counter_signed_pinned
        or legacy_audit_attested_pinned
    )
    should_try_auto_permit_v2 = export_data.lstrip().startswith(b"{")
    if (
        permit_decision_requested
        or permit_revoked_requested
        or permit_absence_requested
        or permit_authority_chain_requested
        or authority_revocation_temporal_requested
        or permit_v2_pinned_requested
        or should_try_auto_permit_v2
    ):
        try:
            loaded_export_document = _load_export_json_document(export_data)
        except Exception as exc:
            loaded_export_document = None
            if (
                permit_decision_requested
                or permit_revoked_requested
                or permit_absence_requested
                or permit_authority_chain_requested
                or authority_revocation_temporal_requested
                or permit_v2_pinned_requested
            ):
                diagnostics.append(f"permit claim evidence is not JSON: {exc}")
        if isinstance(loaded_export_document, dict):
            export_document_for_claims = loaded_export_document
    permit_v2_auto_required = _permit_v2_auto_required_claims(export_document_for_claims)
    operator_approval_requested = (
        operator_approval_pinned
        or PERMIT_OPERATOR_APPROVAL_CLAIM_NAME in permit_v2_auto_required
    )
    counter_signature_requested = (
        counter_signature_pinned
        or PERMIT_COUNTER_SIGNATURE_CLAIM_NAME in permit_v2_auto_required
    )
    audit_attestation_requested = (
        audit_attestation_pinned
        or PERMIT_AUDIT_ATTESTATION_CLAIM_NAME in permit_v2_auto_required
    )

    should_verify_scope_faithfulness = _scope_export_declaration_present(export_data) or (
        semantics.mode == "pinned"
        and bool(
            requested
            & {
                "checkpoint.scope_state.v1",
                "export.scope_faithfulness.v1",
            }
        )
    ) or permit_absence_requested
    scope_claims: list[ClaimVerdict] = []
    if should_verify_scope_faithfulness:
        scope_claims = _adjudicate_export_scope_faithfulness_v1(
            export_data=export_data,
            manifest=manifest,
            manifest_path=manifest_path,
            key_manifest_source=_key_manifest_source_for_args(args),
            semantics_dispatch=semantics_dispatch,
            explicit_sidecar=getattr(args, "sidecar", None),
            explicit_checkpoint=getattr(args, "checkpoint", None),
        )
        claims.extend(scope_claims)
        unsupported_scope = [
            claim
            for claim in scope_claims
            if claim.aggregate_verdict != verdict_value("supported")
        ]
        if unsupported_scope and not permit_absence_requested:
            first = unsupported_scope[0]
            return _export_report(
                ok=False,
                exit_code=1,
                artifact=artifact,
                claims=claims,
                semantics=semantics,
                error=first.message or first.reason_code,
                diagnostics=diagnostics,
            )

    permit_claims: list[ClaimVerdict] = []
    revocation_claim: ClaimVerdict | None = None
    if permit_decision_requested:
        if export_document_for_claims is None:
            permit_claims.append(
                _permit_claim(
                    PERMIT_DECISION_CLAIM_NAME,
                    subject_type="permit_decision",
                    subject_id=None,
                    verdict="insufficient_evidence",
                    reason_code="PERMIT_DECISION_EVIDENCE_MISSING",
                    message="permit decision claim requires a JSON export payload",
                    evidence=["export"],
                )
            )
        else:
            permit_claims.append(
                _adjudicate_permit_decision_v1(
                    export_document=export_document_for_claims,
                    key_manifest_source=_key_manifest_source_for_args(args),
                )
            )
    if permit_revocation_dependency_requested:
        if export_document_for_claims is None:
            revocation_claim = _permit_claim(
                PERMIT_REVOKED_CLAIM_NAME,
                subject_type="permit_revocation",
                subject_id=None,
                verdict="insufficient_evidence",
                reason_code="PERMIT_REVOKED_EVIDENCE_MISSING",
                message="permit revocation claim requires a JSON export payload",
                evidence=["export"],
            )
        else:
            revocation_claim = _adjudicate_permit_revoked_v1(
                export_document=export_document_for_claims,
                manifest=manifest,
                key_manifest_source=_key_manifest_source_for_args(args),
            )
        permit_claims.append(revocation_claim)
    if permit_absence_requested:
        if export_document_for_claims is None:
            permit_claims.append(
                _absence_claim(
                    segment_id=None,
                    verdict="insufficient_evidence",
                    reason_code="EXPORT_SCOPE_DECLARATION_MISSING",
                    message="absence claim requires a JSON export payload",
                    evidence=["export"],
                )
            )
        else:
            permit_claims.append(
                _adjudicate_permit_dispatch_absence_after_revocation_v1(
                    export_document=export_document_for_claims,
                    manifest=manifest,
                    manifest_path=manifest_path,
                    key_manifest_source=_key_manifest_source_for_args(args),
                    semantics_dispatch=semantics_dispatch,
                    explicit_sidecar=getattr(args, "sidecar", None),
                    explicit_checkpoint=getattr(args, "checkpoint", None),
                    scope_claims=scope_claims,
                    revocation_claim=revocation_claim,
                )
            )
    if permit_authority_chain_requested:
        if export_document_for_claims is None:
            permit_claims.append(
                _authority_chain_claim(
                    input_doc={},
                    verdict="insufficient_evidence",
                    reason_code="authority_chain.evidence_incomplete",
                    message="authority-chain claim requires a JSON export payload",
                    evidence=["export"],
                )
            )
        else:
            permit_claims.append(
                _adjudicate_permit_authority_chain_v1(
                    export_document=export_document_for_claims,
                    key_manifest_source=_key_manifest_source_for_args(args),
                )
            )
    if authority_revocation_temporal_requested:
        if export_document_for_claims is None:
            permit_claims.append(
                _authority_revocation_temporal_claim(
                    input_doc={},
                    verdict="insufficient_evidence",
                    reason_code="authority_chain.evidence_incomplete",
                    message="authority revocation-temporal claim requires a JSON export payload",
                    evidence=["export"],
                )
            )
        else:
            permit_claims.append(
                _adjudicate_authority_revocation_temporal_v1(
                    export_document=export_document_for_claims,
                    key_manifest_source=_key_manifest_source_for_args(args),
                )
            )
    if operator_approval_requested:
        if export_document_for_claims is None:
            permit_claims.append(
                _permit_v2_slot_claim(
                    PERMIT_V2_OPERATOR_APPROVAL_SPEC,
                    permit_id=None,
                    verdict="insufficient_evidence",
                    reason_code="PERMIT_OPERATOR_APPROVAL_INVALID",
                    message="operator_approval claim requires a JSON export payload",
                    evidence=["export"],
                    epistemic_state="unverifiable",
                )
            )
        else:
            permit_claims.append(
                _adjudicate_permit_operator_approval_v1(
                    export_document=export_document_for_claims,
                    manifest=manifest,
                    key_manifest_source=_key_manifest_source_for_args(args),
                )
            )
    if legacy_operator_approved_pinned:
        if export_document_for_claims is None:
            permit_claims.append(
                _permit_v2_slot_claim(
                    PERMIT_V2_LEGACY_OPERATOR_APPROVED_SPEC,
                    permit_id=None,
                    verdict="insufficient_evidence",
                    reason_code="PERMIT_OPERATOR_APPROVAL_INVALID",
                    message="operator_approved claim requires a JSON export payload",
                    evidence=["export"],
                    epistemic_state="unverifiable",
                )
            )
        else:
            permit_claims.append(
                _adjudicate_operator_approved_v1(
                    export_document=export_document_for_claims,
                    manifest=manifest,
                    key_manifest_source=_key_manifest_source_for_args(args),
                )
            )
    if counter_signature_requested:
        if export_document_for_claims is None:
            permit_claims.append(
                _permit_v2_slot_claim(
                    PERMIT_V2_COUNTER_SIGNATURE_SPEC,
                    permit_id=None,
                    verdict="insufficient_evidence",
                    reason_code="PERMIT_COUNTER_SIGNATURE_INVALID",
                    message="counter_signature claim requires a JSON export payload",
                    evidence=["export"],
                    epistemic_state="unverifiable",
                )
            )
        else:
            permit_claims.append(
                _adjudicate_permit_counter_signature_v1(
                    export_document=export_document_for_claims,
                    manifest=manifest,
                    key_manifest_source=_key_manifest_source_for_args(args),
                )
            )
    if legacy_counter_signed_pinned:
        if export_document_for_claims is None:
            permit_claims.append(
                _permit_v2_slot_claim(
                    PERMIT_V2_LEGACY_COUNTER_SIGNED_SPEC,
                    permit_id=None,
                    verdict="insufficient_evidence",
                    reason_code="PERMIT_COUNTER_SIGNATURE_INVALID",
                    message="counter_signed claim requires a JSON export payload",
                    evidence=["export"],
                    epistemic_state="unverifiable",
                )
            )
        else:
            permit_claims.append(
                _adjudicate_pre_dispatch_counter_signed_v1(
                    export_document=export_document_for_claims,
                    manifest=manifest,
                    key_manifest_source=_key_manifest_source_for_args(args),
                )
            )
    if audit_attestation_requested:
        if export_document_for_claims is None:
            permit_claims.append(
                _permit_v2_slot_claim(
                    PERMIT_V2_AUDIT_ATTESTATION_SPEC,
                    permit_id=None,
                    verdict="insufficient_evidence",
                    reason_code="PERMIT_AUDIT_ATTESTATION_INVALID",
                    message="audit_attestation claim requires a JSON export payload",
                    evidence=["export"],
                    epistemic_state="unverifiable",
                )
            )
        else:
            permit_claims.append(
                _adjudicate_permit_audit_attestation_v1(
                    export_document=export_document_for_claims,
                    manifest=manifest,
                    key_manifest_source=_key_manifest_source_for_args(args),
                )
            )
    if legacy_audit_attested_pinned:
        if export_document_for_claims is None:
            permit_claims.append(
                _permit_v2_slot_claim(
                    PERMIT_V2_LEGACY_AUDIT_ATTESTED_SPEC,
                    permit_id=None,
                    verdict="insufficient_evidence",
                    reason_code="PERMIT_AUDIT_ATTESTATION_INVALID",
                    message="audit_attested claim requires a JSON export payload",
                    evidence=["export"],
                    epistemic_state="unverifiable",
                )
            )
        else:
            permit_claims.append(
                _adjudicate_audit_attested_v1(
                    export_document=export_document_for_claims,
                    manifest=manifest,
                    key_manifest_source=_key_manifest_source_for_args(args),
                )
            )
    claims.extend(permit_claims)
    required_permit_claim_names = requested | permit_v2_auto_required
    unsupported_permit_claims = [
        claim
        for claim in permit_claims
        if claim.name in required_permit_claim_names
        and claim.aggregate_verdict != verdict_value("supported")
    ]
    if unsupported_permit_claims:
        first = unsupported_permit_claims[0]
        return _export_report(
            ok=False,
            exit_code=1,
            artifact=artifact,
            claims=claims,
            semantics=semantics,
            error=first.message or first.reason_code,
            diagnostics=diagnostics,
        )

    if permit_absence_requested:
        unsupported_scope = [
            claim
            for claim in scope_claims
            if claim.name in requested
            and claim.aggregate_verdict != verdict_value("supported")
        ]
        if unsupported_scope:
            first = unsupported_scope[0]
            return _export_report(
                ok=False,
                exit_code=1,
                artifact=artifact,
                claims=claims,
                semantics=semantics,
                error=first.message or first.reason_code,
                diagnostics=diagnostics,
            )

    workflow_result, workflow_stdout, workflow_stderr = _captured_check(
        _verify_export_workflow_extensions,
        export_data=export_data,
        export_path=export_path,
        manifest_path=manifest_path,
        manifest=manifest,
        args=args,
    )
    claims.extend(
        _workflow_claims_from_output(
            manifest=manifest,
            stdout=workflow_stdout,
            stderr=workflow_stderr,
            result=workflow_result,
        )
    )
    if workflow_result is not None:
        return _export_report(
            ok=False,
            exit_code=workflow_result,
            artifact=artifact,
            claims=claims,
            semantics=semantics,
            error=_failure_from_output(workflow_stdout, workflow_stderr)[1],
        )

    should_walk_events = args.walk_events or (
        semantics.mode == "pinned"
        and "governance_chain.local_continuity.v1" in requested
    )
    should_verify_closure = args.verify_closure or (
        semantics.mode == "pinned"
        and bool(
            requested
            & {
                "closure.signature.v1",
                "closure.digest_consistency.v1",
                "closure.dispatch_binding.v1",
            }
        )
    )

    if should_walk_events:
        walk_result, walk_stdout, walk_stderr = _captured_check(
            _walk_export_events,
            export_data,
            semantics_dispatch,
        )
        assert walk_result is not None
        claims.append(
            _walk_claim_from_output(
                stdout=walk_stdout,
                stderr=walk_stderr,
                result=walk_result,
            )
        )
        if walk_result != 0:
            return _export_report(
                ok=False,
                exit_code=walk_result,
                artifact=artifact,
                claims=claims,
                semantics=semantics,
                error=_failure_from_output(walk_stdout, walk_stderr)[1],
            )
    if should_verify_closure:
        closure_result, closure_stdout, closure_stderr = _captured_check(
            _verify_export_closures,
            export_data,
            args,
            semantics_dispatch,
        )
        assert closure_result is not None
        claims.extend(
            _closure_claims_from_output(
                stdout=closure_stdout,
                stderr=closure_stderr,
                result=closure_result,
            )
        )
        if closure_result != 0:
            return _export_report(
                ok=False,
                exit_code=closure_result,
                artifact=artifact,
                claims=claims,
                semantics=semantics,
                error=_failure_from_output(closure_stdout, closure_stderr)[1],
            )

    return _export_report(
        ok=True,
        exit_code=0,
        artifact=artifact,
        claims=claims,
        semantics=semantics,
        diagnostics=diagnostics,
    )


def verify_scope_faithfulness_claim(
    *,
    export_file: str,
    manifest: str,
    sidecar: str | None = None,
    checkpoint: str | None = None,
    key_manifest: str | None = None,
) -> dict[str, Any]:
    args = argparse.Namespace(
        export_file=export_file,
        manifest=manifest,
        sidecar=sidecar,
        checkpoint=checkpoint,
        key_manifest=key_manifest,
        key_manifest_url=None,
        expected_public_key=None,
        public_key=None,
        self_attested=False,
        offline=False,
        allow_unsigned=False,
        walk_events=False,
        verify_closure=False,
        as_json=True,
    )
    report = verify_export_structured(args)
    scope_claims = [
        claim.to_dict()
        for claim in report.claims
        if claim.name
        in {
            "checkpoint.scope_state.v1",
            "export.scope_faithfulness.v1",
        }
    ]
    export_claim = next(
        (
            claim
            for claim in report.claims
            if claim.name == "export.scope_faithfulness.v1"
        ),
        None,
    )
    status = (
        export_claim.aggregate_verdict
        if export_claim is not None
        else ("supported" if report.ok else "insufficient_evidence")
    )
    return {
        "claim_type": "scope_faithfulness",
        "status": status,
        "ok": report.ok and status == "supported",
        "reason_code": export_claim.reason_code if export_claim is not None else None,
        "message": export_claim.message if export_claim is not None else report.error,
        "claims": scope_claims,
        "report": report.to_dict(),
    }


def verify_permit_v2_signature_claim(
    *,
    claim_type: str,
    export_file: str,
    manifest: str | None = None,
    key_manifest: str | None = None,
) -> dict[str, Any]:
    spec_by_claim_type = {
        "operator_approval": PERMIT_V2_OPERATOR_APPROVAL_SPEC,
        PERMIT_OPERATOR_APPROVAL_CLAIM_NAME: PERMIT_V2_OPERATOR_APPROVAL_SPEC,
        "counter_signature": PERMIT_V2_COUNTER_SIGNATURE_SPEC,
        PERMIT_COUNTER_SIGNATURE_CLAIM_NAME: PERMIT_V2_COUNTER_SIGNATURE_SPEC,
        "audit_attestation": PERMIT_V2_AUDIT_ATTESTATION_SPEC,
        PERMIT_AUDIT_ATTESTATION_CLAIM_NAME: PERMIT_V2_AUDIT_ATTESTATION_SPEC,
        "operator_approved": PERMIT_V2_OPERATOR_APPROVAL_SPEC,
        PERMIT_OPERATOR_APPROVED_CLAIM_NAME: PERMIT_V2_LEGACY_OPERATOR_APPROVED_SPEC,
        "counter_signed": PERMIT_V2_COUNTER_SIGNATURE_SPEC,
        PERMIT_COUNTER_SIGNED_CLAIM_NAME: PERMIT_V2_LEGACY_COUNTER_SIGNED_SPEC,
        "audit_attested": PERMIT_V2_AUDIT_ATTESTATION_SPEC,
        PERMIT_AUDIT_ATTESTED_CLAIM_NAME: PERMIT_V2_LEGACY_AUDIT_ATTESTED_SPEC,
    }
    spec = spec_by_claim_type[claim_type]
    export_document = _load_json_evidence(export_file)
    if not isinstance(export_document, dict):
        raise ValueError("permit v2 claim evidence must be a JSON object")
    manifest_body: dict[str, Any] = {}
    if manifest is not None:
        loaded_manifest = _load_json_evidence(manifest)
        if not isinstance(loaded_manifest, dict):
            raise ValueError("manifest must be a JSON object")
        manifest_body = loaded_manifest

    claim = _adjudicate_permit_v2_signature_slot(
        export_document=export_document,
        manifest=manifest_body,
        key_manifest_source=key_manifest,
        spec=spec,
    )

    return {
        "claim_type": claim_type,
        "status": claim.aggregate_verdict,
        "ok": claim.aggregate_verdict == verdict_value("supported"),
        "reason_code": claim.reason_code,
        "message": claim.message,
        "claim": claim.to_dict(),
    }


def cmd_refresh_keys(args: argparse.Namespace) -> int:
    """Pull a fresh Keel public-key manifest into ``~/.keel-verifier/trust-root.json``.

    Tries the configured channels in order (Keel API, then GitHub) and writes
    the first valid response to the cache. Subsequent verifications prefer the
    cache over the wheel-bundled trust root, so the bundled snapshot does not
    need to be regenerated when Keel rotates a signing key.
    """
    requested_source = (getattr(args, "source", "auto") or "auto").lower()
    candidates: list[tuple[str, str, str]] = []
    for slug, name, url in REFRESH_KEYS_SOURCES:
        if requested_source in {"auto", slug}:
            candidates.append((slug, name, url))
        if requested_source != "auto" and slug == requested_source:
            break
    if not candidates:
        valid = ", ".join(slug for slug, _, _ in REFRESH_KEYS_SOURCES)
        print(
            f"FAILED: unknown --source value {requested_source!r}; "
            f"valid choices: auto, {valid}",
            file=sys.stderr,
        )
        return 2

    last_error: str | None = None
    for _slug, name, url in candidates:
        print(f"trying {name} ({url})...", file=sys.stderr)
        try:
            raw = _fetch_manifest_bytes(url)
        except Exception as exc:  # network or HTTP failure
            last_error = f"{name}: fetch failed: {exc}"
            print(f"  fetch failed: {exc}", file=sys.stderr)
            continue
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            last_error = f"{name}: invalid JSON: {exc}"
            print(f"  invalid JSON: {exc}", file=sys.stderr)
            continue
        try:
            key_count = _validate_manifest_payload(payload)
        except ValueError as exc:
            last_error = f"{name}: invalid manifest: {exc}"
            print(f"  invalid manifest: {exc}", file=sys.stderr)
            continue

        try:
            CACHED_TRUST_ROOT_PATH.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = CACHED_TRUST_ROOT_PATH.with_suffix(".json.tmp")
            tmp_path.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            tmp_path.replace(CACHED_TRUST_ROOT_PATH)
        except OSError as exc:
            print(f"FAILED: could not write cache: {exc}", file=sys.stderr)
            return 1

        print(f"refreshed from {name}")
        print(f"  cache:     {CACHED_TRUST_ROOT_PATH}")
        print(f"  key count: {key_count}")
        generated_at = (
            payload.get("generated_at") if isinstance(payload, dict) else None
        )
        if isinstance(generated_at, str):
            print(f"  generated: {generated_at}")
        return 0

    print(
        "FAILED: no channel returned a valid manifest" + (
            f" (last error: {last_error})" if last_error else ""
        ),
        file=sys.stderr,
    )
    return 1


def _warn_legacy_split_export() -> None:
    global _LEGACY_SPLIT_EXPORT_WARNING_EMITTED
    if _LEGACY_SPLIT_EXPORT_WARNING_EMITTED:
        return
    _LEGACY_SPLIT_EXPORT_WARNING_EMITTED = True
    print(
        "WARNING: legacy split-file export input is deprecated; "
        "use a single keel.evidence_bundle/v1 file when available.",
        file=sys.stderr,
    )


def cmd_export(args: argparse.Namespace) -> int:
    if getattr(args, "as_json", False):
        report = verify_export_structured(args)
        if report.ok and "artifact_ref" not in report.artifact:
            _emit_legacy_artifact_ref_warning_once()
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        return report.exit_code

    export_path = Path(args.export_file)
    manifest_arg = getattr(args, "manifest", None)
    manifest_path = Path(manifest_arg) if manifest_arg else None

    if not export_path.exists():
        print(f"FAILED: Export file not found: {export_path}", file=sys.stderr)
        return 1
    if manifest_path is None:
        try:
            bundle = json.loads(export_path.read_text(encoding="utf-8"))
        except Exception as exc:
            print(
                "FAILED: manifest is required for legacy split-file export input; "
                f"single-file bundle JSON parse failed: {exc}",
                file=sys.stderr,
            )
            return 1
        if not _is_self_attesting_bundle(bundle):
            print(
                "FAILED: manifest is required for legacy split-file export input; "
                "input is not keel.evidence_bundle/v1",
                file=sys.stderr,
            )
            return 1
        ok, error, body, claims, diagnostics = _verify_self_attesting_bundle_payload(
            bundle,
            artifact_id=export_path.name,
            check_tsa=True,
        )
        for diagnostic in diagnostics:
            print(diagnostic, file=sys.stderr)
        if not ok:
            print(f"FAILED: {error}", file=sys.stderr)
            return 1
        envelope = bundle["signature_envelope"]
        artifact_ref = body.get("artifact_ref") if isinstance(body, dict) else {}
        print("VERIFIED")
        print(f"  Bundle:       {export_path.name}")
        print(f"  Schema:       {bundle.get('schema_version')}")
        print(f"  Body schema:  {body.get('schema') if isinstance(body, dict) else None}")
        print(f"  Artifact ref: {artifact_ref.get('urn') if isinstance(artifact_ref, dict) else None}")
        print(f"  Content hash: {envelope.get('content_hash')}")
        print(f"  Public key:   {envelope.get('public_key')}")
        print(f"  Key id:       {envelope.get('public_key_id')}")
        print(f"  Checks:       {', '.join(claim.reason_code for claim in claims)}")
        return 0
    if not manifest_path.exists():
        print(f"FAILED: Manifest file not found: {manifest_path}", file=sys.stderr)
        return 1
    _warn_legacy_split_export()

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    export_data = export_path.read_bytes()
    try:
        artifact_ref = _artifact_ref_from_export_data(export_data)
    except Exception as exc:
        print(f"FAILED: artifact_ref is invalid: {exc}", file=sys.stderr)
        return 1

    expected = manifest.get("content_hash")
    actual = _content_hash(export_data)
    if expected != actual:
        print(
            f"FAILED: Content hash mismatch.\n"
            f"  Expected: {expected}\n"
            f"  Actual:   {actual}",
            file=sys.stderr,
        )
        return 1

    sig = manifest.get("signature")
    embedded_pub = manifest.get("public_key")
    artifact_key_id = (
        manifest.get("key_id") if isinstance(manifest.get("key_id"), str) else None
    )

    if not sig:
        if not getattr(args, "allow_unsigned", False):
            print(
                "FAILED: Export manifest is unsigned (no signature in manifest).",
                file=sys.stderr,
            )
            return 1
        print(
            "WARNING: Export manifest is unsigned (no signature in manifest).",
            file=sys.stderr,
        )
        print(f"Content hash verified: {actual}")
        return 0

    signing_time = _parse_iso_or_none(manifest.get("signed_at"))

    trusted_pub, trust_source, err = _resolve_trust_key(
        artifact_pub=embedded_pub if isinstance(embedded_pub, str) else None,
        artifact_key_id=artifact_key_id,
        purpose="export_signing",
        expected_public_key=args.expected_public_key,
        public_key_url=None,  # export mode does not support single-key URL
        key_manifest_source=_key_manifest_source_for_args(args),
        signing_time=signing_time,
    )
    if err is not None or trusted_pub is None:
        print(f"FAILED: {err}", file=sys.stderr)
        return 1

    if isinstance(embedded_pub, str) and embedded_pub != trusted_pub:
        print(
            "FAILED: Manifest public_key does not match trusted key.\n"
            f"  Trusted:  {trusted_pub}\n"
            f"  In file:  {embedded_pub}",
            file=sys.stderr,
        )
        return 1

    if not _verify_ed25519(trusted_pub, expected.encode("utf-8"), sig):
        print("FAILED: Signature verification failed.", file=sys.stderr)
        return 1

    if artifact_ref is None:
        _emit_legacy_artifact_ref_warning_once()

    print("VERIFIED")
    print(f"  Export:       {export_path.name}")
    print(f"  Content hash: {expected}")
    print(f"  Signature:    {sig[:40]}...")
    print(f"  Public key:   {trusted_pub}")
    print(f"  Key id:       {artifact_key_id or _public_key_fingerprint(trusted_pub)}")
    print(f"  Trust source: {trust_source}")
    if artifact_ref is not None:
        print(f"  Artifact URN: {artifact_ref.urn}")
        print(f"  Artifact type:{artifact_ref.type:>23}")
    if _scope_export_declaration_present(export_data):
        scope_claims = _adjudicate_export_scope_faithfulness_v1(
            export_data=export_data,
            manifest=manifest,
            manifest_path=manifest_path,
            key_manifest_source=_key_manifest_source_for_args(args),
            semantics_dispatch=_legacy_dispatch(),
            explicit_sidecar=getattr(args, "sidecar", None),
            explicit_checkpoint=getattr(args, "checkpoint", None),
        )
        unsupported_scope = [
            claim
            for claim in scope_claims
            if claim.aggregate_verdict != verdict_value("supported")
        ]
        if unsupported_scope:
            first = unsupported_scope[0]
            print(
                f"FAILED: {first.reason_code}: {first.message}",
                file=sys.stderr,
            )
            return 1
        print("  Scope:        scope-faithful slice verified")
    workflow_result = _verify_export_workflow_extensions(
        export_data=export_data,
        export_path=export_path,
        manifest_path=manifest_path,
        manifest=manifest,
        args=args,
    )
    if workflow_result is not None:
        return workflow_result
    if args.walk_events:
        walk_result = _walk_export_events(export_data)
        if walk_result != 0:
            return walk_result
    if args.verify_closure:
        return _verify_export_closures(export_data, args)
    return 0


# ─── Mode 2/3: checkpoint (+ optional TSA) ─────────────────────────


class _DerNode:
    def __init__(self, tag_class: int, constructed: bool, tag_number: int, value: bytes):
        self.tag_class = tag_class
        self.constructed = constructed
        self.tag_number = tag_number
        self.value = value

    @property
    def universal_sequence(self) -> bool:
        return self.tag_class == 0 and self.constructed and self.tag_number == 16

    @property
    def universal_octet_string(self) -> bool:
        return self.tag_class == 0 and not self.constructed and self.tag_number == 4

    def children(self) -> list["_DerNode"]:
        if not self.constructed:
            return []
        out: list[_DerNode] = []
        offset = 0
        while offset < len(self.value):
            child, offset = _read_der_node(self.value, offset)
            out.append(child)
        if offset != len(self.value):
            raise ValueError("DER child parse did not consume value")
        return out


def _read_der_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("truncated DER length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0:
        raise ValueError("indefinite DER length is not allowed")
    if count > 4 or offset + count > len(data):
        raise ValueError("invalid DER length")
    length = int.from_bytes(data[offset : offset + count], "big")
    if length < 0x80:
        raise ValueError("non-minimal DER length")
    return length, offset + count


def _read_der_node(data: bytes, offset: int = 0) -> tuple[_DerNode, int]:
    if offset >= len(data):
        raise ValueError("truncated DER tag")
    tag = data[offset]
    offset += 1
    tag_class = tag >> 6
    constructed = bool(tag & 0x20)
    tag_number = tag & 0x1F
    if tag_number == 0x1F:
        raise ValueError("high-tag-number DER is not supported")
    length, offset = _read_der_length(data, offset)
    end = offset + length
    if end > len(data):
        raise ValueError("truncated DER value")
    return _DerNode(tag_class, constructed, tag_number, data[offset:end]), end


def _unwrap_explicit_context(node: _DerNode) -> _DerNode:
    if node.tag_class != 2 or not node.constructed:
        raise ValueError("expected explicit context-specific node")
    children = node.children()
    if len(children) != 1:
        raise ValueError("explicit context node must contain one child")
    return children[0]


def _extract_rfc3161_message_imprint(receipt_der: bytes) -> bytes:
    content_info, end = _read_der_node(receipt_der)
    if end != len(receipt_der) or not content_info.universal_sequence:
        raise ValueError("receipt is not a DER ContentInfo sequence")
    ci_children = content_info.children()
    if len(ci_children) < 2:
        raise ValueError("ContentInfo missing signedData content")

    signed_data = _unwrap_explicit_context(ci_children[1])
    if not signed_data.universal_sequence:
        raise ValueError("signedData content is not a sequence")
    sd_children = signed_data.children()
    if len(sd_children) < 3:
        raise ValueError("SignedData missing encapContentInfo")

    encap = sd_children[2]
    if not encap.universal_sequence:
        raise ValueError("encapContentInfo is not a sequence")
    encap_children = encap.children()
    content_node = next(
        (
            child
            for child in encap_children[1:]
            if child.tag_class == 2 and child.constructed and child.tag_number == 0
        ),
        None,
    )
    if content_node is None:
        raise ValueError("encapContentInfo missing TSTInfo content")
    octets = _unwrap_explicit_context(content_node)
    if not octets.universal_octet_string:
        raise ValueError("TSTInfo content is not an octet string")

    tst_info, tst_end = _read_der_node(octets.value)
    if tst_end != len(octets.value) or not tst_info.universal_sequence:
        raise ValueError("TSTInfo is not a DER sequence")
    tst_children = tst_info.children()
    if len(tst_children) < 3 or not tst_children[2].universal_sequence:
        raise ValueError("TSTInfo missing messageImprint")
    imprint_children = tst_children[2].children()
    if len(imprint_children) < 2 or not imprint_children[1].universal_octet_string:
        raise ValueError("messageImprint missing hashedMessage")
    return imprint_children[1].value


def _verify_tsa_receipt(receipt_b64: str, content_hash_hex: str) -> tuple[bool, str]:
    """Verify the embedded TSA receipt against the checkpoint composite_hash.

    This intentionally performs the verifier's historical offline check only:
    it parses the RFC 3161 TimeStampToken and confirms the MessageImprint
    equals the checkpoint composite hash. Full TSA certificate-chain validation
    is an opt-in trust extension via ``--tsa-ca-bundle``.
    """
    try:
        raw_der = base64.b64decode(receipt_b64)
        imprint = _extract_rfc3161_message_imprint(raw_der)
        expected = bytes.fromhex(content_hash_hex)
        if imprint != expected:
            return False, "TSA message imprint does not match composite_hash"
        return True, "TSA message imprint matches composite_hash"
    except Exception as exc:
        return False, f"TSA parse/verify failed: {exc}"


TSA_TRUST_SCOPE = (
    "CMS signature, certificate chain, and timestamping purpose are verified "
    "against the supplied CA bundle only."
)
TSA_TRUST_REVOCATION_NOTE = (
    "Historical revocation status at the timestamp issuance time is not "
    "checked; a chain that is valid today does not prove it was unrevoked "
    "when the timestamp was issued."
)


def _tsa_trust_report_skeleton(
    *,
    ca_bundle_path: str | None,
    openssl_version: str | None,
) -> dict[str, Any]:
    return {
        "openssl_version": openssl_version,
        "ca_bundle": (
            str(Path(ca_bundle_path).expanduser()) if ca_bundle_path else None
        ),
        "revocation_checked": False,
        "verification_scope": TSA_TRUST_SCOPE,
        "revocation_note": TSA_TRUST_REVOCATION_NOTE,
        "receipts": [],
    }


def _default_tsa_trust() -> dict[str, Any]:
    return _tsa_trust_report_skeleton(ca_bundle_path=None, openssl_version=None)


def _copy_tsa_trust(tsa_trust: dict[str, Any] | None) -> dict[str, Any]:
    source = tsa_trust if isinstance(tsa_trust, dict) else _default_tsa_trust()
    copied = dict(source)
    receipts = source.get("receipts")
    copied["receipts"] = [
        dict(receipt) for receipt in receipts if isinstance(receipt, dict)
    ] if isinstance(receipts, list) else []
    return copied


def _tsa_trust_receipt_result(
    *,
    provider: str,
    tsa_trust_status: str,
    imprint_match: bool | None,
    cms_signature_valid: bool | None,
    certificate_chain_valid: bool | None,
    eku_checked: bool,
    eku_valid: bool | None,
    verification_error: str | None,
) -> dict[str, Any]:
    return {
        "provider": provider,
        "tsa_trust_status": tsa_trust_status,
        "imprint_match": imprint_match,
        "cms_signature_valid": cms_signature_valid,
        "certificate_chain_valid": certificate_chain_valid,
        "eku_checked": eku_checked,
        "eku_valid": eku_valid,
        "verification_error": verification_error,
    }


def _parse_openssl_version_for_tsa(version_output: str) -> tuple[bool, str | None]:
    """Return whether an ``openssl version`` string supports TSA trust checks."""
    raw = version_output.strip()
    if not raw:
        return (
            False,
            "OpenSSL version output was empty; OpenSSL 3.x or newer is required "
            "for TSA trust validation.",
        )
    if raw.startswith("LibreSSL"):
        return (
            False,
            "LibreSSL is not supported for TSA trust validation; OpenSSL 3.x or "
            "newer is required.",
        )
    match = re.match(r"^OpenSSL\s+([0-9]+(?:\.[0-9]+){0,2}[a-z]*)\b", raw)
    if match is None:
        return (
            False,
            f"Unsupported openssl version output {raw!r}; OpenSSL 3.x or newer "
            "is required for TSA trust validation.",
        )
    version_token = match.group(1)
    major = int(version_token.split(".", 1)[0])
    if major < 3:
        return (
            False,
            f"OpenSSL {version_token} is too old for TSA trust validation; "
            "OpenSSL 3.x or newer is required.",
        )
    return True, None


def _openssl_tsa_runtime_status() -> dict[str, Any]:
    try:
        completed = subprocess.run(
            ["openssl", "version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except FileNotFoundError:
        return {
            "openssl_version": None,
            "supported": False,
            "verification_error": (
                "OpenSSL executable not found; OpenSSL 3.x or newer is required "
                "for TSA trust validation."
            ),
        }
    except subprocess.TimeoutExpired:
        return {
            "openssl_version": None,
            "supported": False,
            "verification_error": (
                "OpenSSL version check timed out; OpenSSL 3.x or newer is "
                "required for TSA trust validation."
            ),
        }

    version_text = (completed.stdout or completed.stderr or "").strip()
    if completed.returncode != 0:
        detail = version_text or f"exit code {completed.returncode}"
        return {
            "openssl_version": version_text or None,
            "supported": False,
            "verification_error": (
                f"OpenSSL version check failed: {detail}; OpenSSL 3.x or newer "
                "is required for TSA trust validation."
            ),
        }
    supported, error = _parse_openssl_version_for_tsa(version_text)
    return {
        "openssl_version": version_text or None,
        "supported": supported,
        "verification_error": error,
    }


def _verify_tsa_receipt_authenticity_openssl(
    receipt: dict[str, Any],
    content_hash_hex: str,
    *,
    ca_bundle_path: str,
    openssl_runtime: dict[str, Any] | None = None,
) -> dict[str, Any]:
    provider = str(receipt.get("provider") or "unknown")
    receipt_b64 = receipt.get("receipt_b64")
    if not isinstance(receipt_b64, str):
        return _tsa_trust_receipt_result(
            provider=provider,
            tsa_trust_status="invalid",
            imprint_match=False,
            cms_signature_valid=False,
            certificate_chain_valid=False,
            eku_checked=False,
            eku_valid=None,
            verification_error="receipt_b64 missing",
        )

    imprint_ok, imprint_reason = _verify_tsa_receipt(receipt_b64, content_hash_hex)
    if not imprint_ok:
        return _tsa_trust_receipt_result(
            provider=provider,
            tsa_trust_status="invalid",
            imprint_match=False,
            cms_signature_valid=False,
            certificate_chain_valid=False,
            eku_checked=False,
            eku_valid=None,
            verification_error=imprint_reason,
        )

    ca_bundle = Path(ca_bundle_path).expanduser()
    if not ca_bundle.is_file():
        return _tsa_trust_receipt_result(
            provider=provider,
            tsa_trust_status="invalid",
            imprint_match=True,
            cms_signature_valid=False,
            certificate_chain_valid=False,
            eku_checked=False,
            eku_valid=None,
            verification_error="TSA CA bundle is not readable",
        )
    try:
        with ca_bundle.open("rb"):
            pass
    except OSError:
        return _tsa_trust_receipt_result(
            provider=provider,
            tsa_trust_status="invalid",
            imprint_match=True,
            cms_signature_valid=False,
            certificate_chain_valid=False,
            eku_checked=False,
            eku_valid=None,
            verification_error="TSA CA bundle is not readable",
        )

    try:
        token_der = base64.b64decode(receipt_b64, validate=True)
    except Exception as exc:
        return _tsa_trust_receipt_result(
            provider=provider,
            tsa_trust_status="invalid",
            imprint_match=True,
            cms_signature_valid=False,
            certificate_chain_valid=False,
            eku_checked=False,
            eku_valid=None,
            verification_error=f"TSA receipt is not valid base64: {exc}",
        )

    runtime = openssl_runtime or _openssl_tsa_runtime_status()
    if not runtime.get("supported"):
        return _tsa_trust_receipt_result(
            provider=provider,
            tsa_trust_status="unsupported_runtime",
            imprint_match=True,
            cms_signature_valid=False,
            certificate_chain_valid=False,
            eku_checked=False,
            eku_valid=None,
            verification_error=str(
                runtime.get("verification_error")
                or "OpenSSL 3.x or newer is required for TSA trust validation."
            ),
        )

    with tempfile.TemporaryDirectory(prefix="keel-tsa-verify-") as tmpdir:
        token_path = Path(tmpdir) / "receipt-token.der"
        token_path.write_bytes(token_der)
        cmd = [
            "openssl",
            "ts",
            "-verify",
            "-token_in",
            "-digest",
            content_hash_hex,
            "-sha256",
            "-in",
            str(token_path),
            "-CAfile",
            str(ca_bundle),
            "-purpose",
            "timestampsign",
        ]
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except FileNotFoundError:
            return _tsa_trust_receipt_result(
                provider=provider,
                tsa_trust_status="unsupported_runtime",
                imprint_match=True,
                cms_signature_valid=False,
                certificate_chain_valid=False,
                eku_checked=False,
                eku_valid=None,
                verification_error="OpenSSL executable not found during TSA verification",
            )
        except subprocess.TimeoutExpired:
            return _tsa_trust_receipt_result(
                provider=provider,
                tsa_trust_status="invalid",
                imprint_match=True,
                cms_signature_valid=False,
                certificate_chain_valid=False,
                eku_checked=True,
                eku_valid=False,
                verification_error="OpenSSL TSA verification timed out",
            )

    if completed.returncode != 0:
        error_text = (completed.stderr or completed.stdout or "").strip()
        return _tsa_trust_receipt_result(
            provider=provider,
            tsa_trust_status="invalid",
            imprint_match=True,
            cms_signature_valid=False,
            certificate_chain_valid=False,
            eku_checked=True,
            eku_valid=False,
            verification_error=error_text or "OpenSSL TSA verification failed",
        )

    return _tsa_trust_receipt_result(
        provider=provider,
        tsa_trust_status="valid",
        imprint_match=True,
        cms_signature_valid=True,
        certificate_chain_valid=True,
        eku_checked=True,
        eku_valid=True,
        verification_error=None,
    )


def _checkpoint_tsa_receipts(cp: dict[str, Any]) -> list[dict[str, Any]]:
    """Return TSA receipt payloads, preferring multi-receipt checkpoints."""
    raw_receipts = cp.get("tsa_receipts")
    if isinstance(raw_receipts, list):
        receipts: list[dict[str, Any]] = []
        for index, receipt in enumerate(raw_receipts, start=1):
            if isinstance(receipt, dict):
                receipts.append(receipt)
            else:
                receipts.append(
                    {
                        "_invalid": f"tsa_receipts[{index}] is not an object",
                    }
                )
        if receipts:
            return receipts

    tsa = cp.get("tsa")
    if isinstance(tsa, dict) and isinstance(tsa.get("receipt_b64"), str):
        return [tsa]
    return []


def _build_tsa_trust_report(
    raw_receipts: list[dict[str, Any]],
    content_hash_hex: str | None,
    *,
    ca_bundle_path: str | None,
) -> dict[str, Any]:
    if not ca_bundle_path:
        report = _tsa_trust_report_skeleton(
            ca_bundle_path=None,
            openssl_version=None,
        )
        report["receipts"] = [
            _tsa_trust_receipt_result(
                provider=str(receipt.get("provider") or "unknown"),
                tsa_trust_status="skipped",
                imprint_match=None,
                cms_signature_valid=None,
                certificate_chain_valid=None,
                eku_checked=False,
                eku_valid=None,
                verification_error=(
                    "TSA trust validation skipped because --tsa-ca-bundle was "
                    "not supplied."
                ),
            )
            for receipt in raw_receipts
        ]
        return report

    runtime = _openssl_tsa_runtime_status()
    report = _tsa_trust_report_skeleton(
        ca_bundle_path=ca_bundle_path,
        openssl_version=runtime.get("openssl_version"),
    )
    if not content_hash_hex:
        report["receipts"] = [
            _tsa_trust_receipt_result(
                provider=str(receipt.get("provider") or "unknown"),
                tsa_trust_status="invalid",
                imprint_match=False,
                cms_signature_valid=False,
                certificate_chain_valid=False,
                eku_checked=False,
                eku_valid=None,
                verification_error=(
                    "checkpoint composite_hash unavailable; TSA trust "
                    "validation cannot run"
                ),
            )
            for receipt in raw_receipts
        ]
        return report

    report["receipts"] = [
        _verify_tsa_receipt_authenticity_openssl(
            receipt,
            content_hash_hex,
            ca_bundle_path=ca_bundle_path,
            openssl_runtime=runtime,
        )
        for receipt in raw_receipts
    ]
    return report


def _tsa_trust_has_failure(tsa_trust: dict[str, Any] | None) -> bool:
    if not isinstance(tsa_trust, dict):
        return False
    receipts = tsa_trust.get("receipts")
    if not isinstance(receipts, list):
        return False
    return any(
        isinstance(receipt, dict)
        and receipt.get("tsa_trust_status") in {"invalid", "unsupported_runtime"}
        for receipt in receipts
    )


def _load_checkpoint_body_for_tsa_trust(path: str | Path) -> dict[str, Any] | None:
    try:
        body = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return None
    if _is_self_attesting_bundle(body):
        body = body.get("body")
    return body if isinstance(body, dict) else None


def _single_line_error(value: Any) -> str:
    text = str(value or "OpenSSL TSA verification failed").strip()
    return " ".join(text.split())


def _print_tsa_trust_human(tsa_trust: dict[str, Any]) -> None:
    receipts = tsa_trust.get("receipts")
    if not isinstance(receipts, list) or not receipts:
        return
    ca_bundle = tsa_trust.get("ca_bundle")
    if ca_bundle:
        print(
            "  TSA TRUST:    chain, signature, and timestamping purpose checked "
            f"against supplied CA bundle: {ca_bundle}"
        )
        print(
            "    Revocation: historical revocation status at issuance is not checked."
        )
    for index, receipt in enumerate(receipts, start=1):
        if not isinstance(receipt, dict):
            continue
        status = receipt.get("tsa_trust_status")
        if status == "skipped":
            continue
        label = receipt.get("provider") or f"receipt {index}"
        if status == "valid":
            print(
                f"  TSA[{index}] TRUST: OK ({label}: chain/signature/purpose "
                "verified against supplied CA bundle)"
            )
        elif status == "unsupported_runtime":
            print(
                f"  TSA[{index}] TRUST: UNSUPPORTED ({label}: "
                f"{_single_line_error(receipt.get('verification_error'))})",
                file=sys.stderr,
            )
        else:
            print(
                f"  TSA[{index}] TRUST: FAILED ({label}: "
                f"{_single_line_error(receipt.get('verification_error'))})",
                file=sys.stderr,
            )


def cmd_checkpoint(args: argparse.Namespace) -> int:
    result = verify_checkpoint(
        args.checkpoint_file,
        expected_public_key=args.expected_public_key,
        public_key_url=args.public_key_url,
        key_manifest=_key_manifest_source_for_args(args),
        self_attested=getattr(args, "self_attested", False),
        check_tsa=True,
    )
    if getattr(args, "tsa_ca_bundle", None):
        body = _load_checkpoint_body_for_tsa_trust(args.checkpoint_file)
        raw_receipts = _checkpoint_tsa_receipts(body) if body is not None else []
        content_hash_hex = (
            result.composite_hash.removeprefix("sha256:")
            if isinstance(result.composite_hash, str)
            and result.composite_hash.startswith("sha256:")
            else None
        )
        result.tsa_trust = _build_tsa_trust_report(
            raw_receipts,
            content_hash_hex,
            ca_bundle_path=args.tsa_ca_bundle,
        )
    result.exit_code = 1 if (not result.ok or _tsa_trust_has_failure(result.tsa_trust)) else 0
    if getattr(args, "as_json", False):
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return result.exit_code
    if not result.ok:
        print(f"FAILED: {result.error}", file=sys.stderr)
        return result.exit_code

    print("VERIFIED")
    print(f"  Checkpoint:   {result.checkpoint_id}")
    print(f"  Computed at:  {result.computed_at}")
    print(f"  Composite:    {result.composite_hash}")
    print(f"  Public key:   {result.public_key}")
    print(f"  Key id:       {result.key_id}")
    print(f"  Trust source: {result.trust_source}")
    print(f"  Chain heads:  {result.chain_heads_count} scope(s)")

    if result.tsa_receipts:
        for index, receipt in enumerate(result.tsa_receipts, start=1):
            label = receipt.get("provider") or receipt.get("url") or f"receipt {index}"
            if receipt.get("verified") is True:
                print(f"  TSA[{index}]:      OK ({label}: {receipt.get('reason')})")
                print(f"    URL:        {receipt.get('url')}")
                print(f"    Stamped at: {receipt.get('requested_at')}")
            elif receipt.get("checked") is False:
                print(f"  TSA[{index}]:      present (skipped)")
            else:
                print(
                    f"  TSA[{index}]:      FAILED ({label}: {receipt.get('reason')})",
                    file=sys.stderr,
                )
                return 1
    elif result.tsa_present:
        print("  TSA:          present but receipt_b64 missing - skipped")

    if getattr(args, "tsa_ca_bundle", None):
        _print_tsa_trust_human(result.tsa_trust)

    return result.exit_code


# ─── Programmatic and legacy checkpoint API ─────────────────────────


def _voice_attestation_check(
    name: str,
    ok: bool,
    reason: str,
    **detail: Any,
) -> dict[str, Any]:
    if ok:
        return {"name": name, "result": "pass", **detail}
    return {"name": name, "result": "fail", "reason": reason, **detail}


def _voice_attestation_canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _voice_attestation_sha256_prefixed(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _voice_attestation_signature_payload(
    artifact: Mapping[str, Any],
) -> dict[str, Any]:
    payload = dict(artifact)
    payload.pop("signatures", None)
    return payload


def _voice_attestation_chain_entry_hash(entry: Mapping[str, Any]) -> str:
    material = dict(entry)
    material.pop("content_hash", None)
    return _voice_attestation_sha256_prefixed(
        _voice_attestation_canonical_json_bytes(material)
    )


def _is_voice_attestation_artifact(value: Any) -> bool:
    return isinstance(value, dict) and isinstance(
        value.get("verifier_compatibility"),
        dict,
    )


def _verify_voice_attestation_schema(artifact: Mapping[str, Any]) -> dict[str, Any]:
    schema_version = artifact.get("schema_version")
    expected_artifact_version = VOICE_ATTESTATION_ARTIFACT_VERSION_BY_SCHEMA.get(
        schema_version
    )
    return _voice_attestation_check(
        "artifact_schema",
        # v1 is the original voice-session artifact with embedded canonical payloads;
        # v3 is main's hash-only materialization. Both use the same signature
        # and chain hash primitives, but their top-level artifact versions differ.
        expected_artifact_version is not None
        and artifact.get("artifact_version") == expected_artifact_version
        and artifact.get("schema") == VOICE_ATTESTATION_ARTIFACT_SCHEMA
        and schema_version in SUPPORTED_VOICE_ATTESTATION_SCHEMA_VERSIONS
        and artifact.get("canonicalization_profile")
        == VOICE_ATTESTATION_CANONICALIZATION_PROFILE,
        "unsupported voice-session attestation schema/version",
    )


def _verify_voice_attestation_signature(
    artifact: Mapping[str, Any],
) -> dict[str, Any]:
    signatures = artifact.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        return _voice_attestation_check("issuer_signature", False, "missing signatures")

    canonical = _voice_attestation_canonical_json_bytes(
        _voice_attestation_signature_payload(artifact)
    )
    content_hash = _voice_attestation_sha256_prefixed(canonical)
    for entry in signatures:
        if not isinstance(entry, Mapping):
            continue
        if str(entry.get("algorithm") or "").lower() != "ed25519":
            continue
        if entry.get("content_hash") not in (None, content_hash):
            continue
        public_key = entry.get("public_key")
        signature = entry.get("signature")
        if not isinstance(public_key, str) or not isinstance(signature, str):
            continue
        if _verify_ed25519(public_key, canonical, signature):
            return {
                "name": "issuer_signature",
                "result": "pass",
                "key_id": entry.get("key_id"),
                "key_purpose": entry.get("key_purpose"),
                "content_hash": content_hash,
            }

    return _voice_attestation_check(
        "issuer_signature",
        False,
        "no valid Ed25519 signature over canonical artifact bytes",
    )


def _verify_voice_attestation_chain_v1(artifact: Mapping[str, Any]) -> dict[str, Any]:
    chain = artifact.get("chain")
    if not isinstance(chain, list):
        return _voice_attestation_check("chain_integrity", False, "chain must be an array")

    previous = VOICE_ATTESTATION_CHAIN_GENESIS_HASH
    last_hash = VOICE_ATTESTATION_CHAIN_GENESIS_HASH
    last_artifact_sequence = 0
    for index, item in enumerate(chain, start=1):
        if not isinstance(item, Mapping):
            return _voice_attestation_check(
                "chain_integrity",
                False,
                f"chain entry {index} invalid",
            )
        if item.get("previous_content_hash") != previous:
            return _voice_attestation_check(
                "chain_integrity",
                False,
                f"chain entry {index} previous_content_hash mismatch",
            )
        artifact_sequence = item.get("artifact_sequence")
        if not isinstance(artifact_sequence, int) or artifact_sequence <= last_artifact_sequence:
            return _voice_attestation_check(
                "chain_integrity",
                False,
                f"chain entry {index} artifact_sequence is not strictly increasing",
            )
        recomputed = _voice_attestation_chain_entry_hash(item)
        if item.get("content_hash") != recomputed:
            return _voice_attestation_check(
                "chain_integrity",
                False,
                f"chain entry {index} content_hash mismatch",
            )
        previous = recomputed
        last_hash = recomputed
        last_artifact_sequence = artifact_sequence

    head = artifact.get("chain_head")
    if not isinstance(head, Mapping):
        return _voice_attestation_check("chain_integrity", False, "chain_head missing")
    if head.get("content_hash") != last_hash:
        return _voice_attestation_check(
            "chain_integrity",
            False,
            "chain_head hash mismatch",
        )
    if int(head.get("event_count") or 0) != len(chain):
        return _voice_attestation_check(
            "chain_integrity",
            False,
            "chain_head event_count mismatch",
        )
    return {
        "name": "chain_integrity",
        "result": "pass",
        "events_verified": len(chain),
    }


def _verify_voice_attestation_chain_v3(artifact: Mapping[str, Any]) -> dict[str, Any]:
    chain = artifact.get("chain")
    if not isinstance(chain, list):
        return _voice_attestation_check("chain_integrity", False, "chain must be an array")

    previous = VOICE_ATTESTATION_CHAIN_GENESIS_HASH
    last_hash = VOICE_ATTESTATION_CHAIN_GENESIS_HASH
    last_artifact_sequence = 0
    for index, item in enumerate(chain, start=1):
        if not isinstance(item, Mapping):
            return _voice_attestation_check(
                "chain_integrity",
                False,
                f"chain entry {index} invalid",
            )
        if "canonicalized_payload" in item:
            return _voice_attestation_check(
                "chain_integrity",
                False,
                f"chain entry {index} embeds payload material in schema v3",
            )
        if item.get("payload_materialization") != "hash_only":
            return _voice_attestation_check(
                "chain_integrity",
                False,
                f"chain entry {index} payload_materialization must be hash_only",
            )
        payload_hash = item.get("canonicalized_payload_hash")
        if not isinstance(payload_hash, str) or not payload_hash.startswith("sha256:"):
            return _voice_attestation_check(
                "chain_integrity",
                False,
                f"chain entry {index} canonicalized_payload_hash is invalid",
            )
        if item.get("previous_content_hash") != previous:
            return _voice_attestation_check(
                "chain_integrity",
                False,
                f"chain entry {index} previous_content_hash mismatch",
            )
        artifact_sequence = item.get("artifact_sequence")
        if not isinstance(artifact_sequence, int) or artifact_sequence <= last_artifact_sequence:
            return _voice_attestation_check(
                "chain_integrity",
                False,
                f"chain entry {index} artifact_sequence is not strictly increasing",
            )
        recomputed = _voice_attestation_chain_entry_hash(item)
        if item.get("content_hash") != recomputed:
            return _voice_attestation_check(
                "chain_integrity",
                False,
                f"chain entry {index} content_hash mismatch",
            )
        previous = recomputed
        last_hash = recomputed
        last_artifact_sequence = artifact_sequence

    head = artifact.get("chain_head")
    if not isinstance(head, Mapping):
        return _voice_attestation_check("chain_integrity", False, "chain_head missing")
    if head.get("content_hash") != last_hash:
        return _voice_attestation_check(
            "chain_integrity",
            False,
            "chain_head hash mismatch",
        )
    if int(head.get("event_count") or 0) != len(chain):
        return _voice_attestation_check(
            "chain_integrity",
            False,
            "chain_head event_count mismatch",
        )
    return {
        "name": "chain_integrity",
        "result": "pass",
        "events_verified": len(chain),
    }


def _verify_voice_attestation_chain(artifact: Mapping[str, Any]) -> dict[str, Any]:
    schema_version = artifact.get("schema_version")
    if schema_version == 1:
        return _verify_voice_attestation_chain_v1(artifact)
    if schema_version == 3:
        return _verify_voice_attestation_chain_v3(artifact)
    return _voice_attestation_check(
        "chain_integrity",
        False,
        "unsupported voice-session attestation schema/version",
    )


def _verify_voice_attestation_policy_snapshot_hash(
    artifact: Mapping[str, Any],
) -> dict[str, Any]:
    metadata = artifact.get("session_metadata")
    snapshot = artifact.get("policy_snapshot")
    if not isinstance(metadata, Mapping) or not isinstance(snapshot, Mapping):
        return _voice_attestation_check(
            "policy_snapshot_hash",
            False,
            "policy snapshot missing",
        )

    embedded = dict(snapshot)
    embedded.pop("snapshot_id", None)
    embedded.pop("snapshot_hash", None)
    computed = hashlib.sha256(
        _voice_attestation_canonical_json_bytes(embedded)
    ).hexdigest()
    expected = str(metadata.get("policy_snapshot_hash") or "").strip().lower()
    if computed != expected:
        return _voice_attestation_check(
            "policy_snapshot_hash",
            False,
            "embedded policy_snapshot hash does not match session metadata",
            computed=f"sha256:{computed}",
            expected=f"sha256:{expected}" if expected else None,
        )
    return {
        "name": "policy_snapshot_hash",
        "result": "pass",
        "policy_snapshot_hash": f"sha256:{expected}",
    }


def _voice_attestation_receipts(artifact: Mapping[str, Any]) -> list[dict[str, Any]]:
    receipts: list[dict[str, Any]] = []
    raw_receipts = artifact.get("timestamp_receipts")
    if isinstance(raw_receipts, list):
        receipts.extend(receipt for receipt in raw_receipts if isinstance(receipt, dict))
    single = artifact.get("rfc3161_timestamp_receipt")
    if isinstance(single, dict) and single not in receipts:
        receipts.insert(0, single)
    return receipts


def _verify_voice_attestation_timestamp_receipt(
    artifact: Mapping[str, Any],
    *,
    check_tsa: bool,
) -> dict[str, Any]:
    receipts = _voice_attestation_receipts(artifact)
    if not receipts:
        return _voice_attestation_check(
            "rfc3161_timestamp_receipt",
            False,
            "missing RFC 3161 timestamp receipt",
        )
    if not check_tsa:
        return {
            "name": "rfc3161_timestamp_receipt",
            "result": "pass",
            "checked": False,
            "receipts_verified": 0,
        }

    project_head = artifact.get("project_chain_head")
    project_head_hash = (
        project_head.get("content_hash") if isinstance(project_head, Mapping) else None
    )
    verified = 0
    for index, receipt in enumerate(receipts, start=1):
        request_hash = str(receipt.get("request_hash") or "").strip()
        response_b64 = receipt.get("tsa_response_base64")
        covers_hash = receipt.get("covers_chain_head_hash")
        if not request_hash.startswith("sha256:") or not isinstance(response_b64, str):
            return _voice_attestation_check(
                "rfc3161_timestamp_receipt",
                False,
                f"receipt {index} is incomplete",
            )
        if project_head_hash is not None and request_hash != project_head_hash:
            return _voice_attestation_check(
                "rfc3161_timestamp_receipt",
                False,
                f"receipt {index} request_hash does not match project_chain_head",
            )
        if covers_hash is not None and covers_hash != request_hash:
            return _voice_attestation_check(
                "rfc3161_timestamp_receipt",
                False,
                f"receipt {index} covers_chain_head_hash does not match request_hash",
            )
        ok, reason = _verify_tsa_receipt(
            response_b64,
            request_hash.removeprefix("sha256:"),
        )
        if not ok:
            return _voice_attestation_check(
                "rfc3161_timestamp_receipt",
                False,
                f"receipt {index}: {reason}",
            )
        verified += 1

    return {
        "name": "rfc3161_timestamp_receipt",
        "result": "pass",
        "checked": True,
        "receipts_verified": verified,
    }


def verify_attestation_artifact(
    artifact: Mapping[str, Any],
    *,
    check_tsa: bool = True,
) -> dict[str, Any]:
    """Verify a voice-session attestation artifact."""

    checks = [
        _verify_voice_attestation_schema(artifact),
        _verify_voice_attestation_signature(artifact),
        _verify_voice_attestation_chain(artifact),
        _verify_voice_attestation_policy_snapshot_hash(artifact),
        _verify_voice_attestation_timestamp_receipt(artifact, check_tsa=check_tsa),
    ]
    failed = [check for check in checks if check.get("result") != "pass"]
    metadata = artifact.get("session_metadata")
    chain_head = artifact.get("chain_head")
    return {
        "verdict": "fail" if failed else "pass",
        "schema": artifact.get("schema"),
        "session_id": (
            metadata.get("session_id")
            if isinstance(metadata, Mapping)
            and isinstance(metadata.get("session_id"), str)
            else None
        ),
        "checks": checks,
        "failed_checks": failed,
        "head_hash": (
            chain_head.get("content_hash")
            if isinstance(chain_head, Mapping)
            and isinstance(chain_head.get("content_hash"), str)
            else None
        ),
        "head_sequence": (
            chain_head.get("sequence")
            if isinstance(chain_head, Mapping)
            and isinstance(chain_head.get("sequence"), int)
            else None
        ),
    }


@dataclass
class VerifyResult:
    ok: bool
    error: str | None = None
    exit_code: int | None = None
    artifact: dict[str, Any] = dataclass_field(default_factory=lambda: {"kind": "checkpoint"})

    checkpoint_id: str | None = None
    computed_at: str | None = None
    composite_hash: str | None = None
    chain_heads_count: int = 0

    public_key: str | None = None
    key_id: str | None = None
    trust_source: str | None = None
    self_attested: bool = False

    tsa_present: bool = False
    tsa_checked: bool = False
    tsa_verified: bool | None = None
    tsa_reason: str | None = None
    tsa_url: str | None = None
    tsa_requested_at: str | None = None
    tsa_receipts: list[dict[str, Any]] = dataclass_field(default_factory=list)
    tsa_trust: dict[str, Any] = dataclass_field(default_factory=_default_tsa_trust)

    diagnostics: list[str] = dataclass_field(default_factory=list)
    semantics: dict[str, Any] = dataclass_field(default_factory=legacy_semantics)
    claims: list[ClaimVerdict] = dataclass_field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": VERDICT_SCHEMA_ID,
            "ok": self.ok,
            "exit_code": (
                self.exit_code if self.exit_code is not None else 0 if self.ok else 1
            ),
            "error": self.error,
            "artifact": dict(self.artifact),
            "semantics": dict(self.semantics),
            "claims": [claim.to_dict() for claim in self.claims],
            "checkpoint_id": self.checkpoint_id,
            "computed_at": self.computed_at,
            "composite_hash": self.composite_hash,
            "chain_heads_count": self.chain_heads_count,
            "public_key": self.public_key,
            "key_id": self.key_id,
            "trust_source": self.trust_source,
            "self_attested": self.self_attested,
            "tsa": {
                "present": self.tsa_present,
                "checked": self.tsa_checked,
                "verified": self.tsa_verified,
                "reason": self.tsa_reason,
                "url": self.tsa_url,
                "requested_at": self.tsa_requested_at,
            },
            "tsa_receipts": list(self.tsa_receipts),
            "tsa_trust": _copy_tsa_trust(self.tsa_trust),
            "diagnostics": list(self.diagnostics),
        }


def _fetch_single_public_key(url: str) -> tuple[str | None, str | None]:
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        return None, f"could not fetch trust root from {url}: {exc}"
    pub = body.get("public_key") if isinstance(body, dict) else None
    if not isinstance(pub, str) or not pub.startswith("ed25519:"):
        return None, f"unexpected response shape from {url} (missing ed25519 public_key)"
    return pub, None


def _checkpoint_artifact_dict(path: Path, data: bytes | None = None) -> dict[str, Any]:
    artifact: dict[str, Any] = {
        "kind": "checkpoint",
        "checkpoint_path": str(path),
    }
    if data is not None:
        artifact["checkpoint_hash"] = _content_hash(data)
    return artifact


def _attach_artifact_ref(
    artifact: dict[str, Any],
    bundle: Mapping[str, Any],
) -> tuple[dict[str, Any], str | None]:
    try:
        artifact_ref = _artifact_ref_from_bundle(bundle)
    except Exception as exc:
        return artifact, f"artifact_ref is invalid: {exc}"
    if artifact_ref is not None:
        artifact = dict(artifact)
        artifact["artifact_ref"] = _artifact_ref_to_dict(artifact_ref)
    return artifact, None


def _checkpoint_composite_claim(
    *,
    verdict: str,
    reason_code: str,
    message: str,
    checkpoint_id: str | None = None,
) -> ClaimVerdict:
    return _single_subject_claim(
        "checkpoint.composite_hash.v1",
        subject_type="checkpoint",
        subject_id=checkpoint_id,
        verdict=verdict,
        reason_code=reason_code,
        message=message,
        evidence=["checkpoint.chain_heads", "checkpoint.composite_hash"],
    )


def _checkpoint_signature_claim(
    *,
    verdict: str,
    reason_code: str,
    message: str,
    key_id: str | None = None,
) -> ClaimVerdict:
    return _single_subject_claim(
        "checkpoint.signature.v1",
        subject_type="checkpoint_signature",
        subject_id=key_id,
        verdict=verdict,
        reason_code=reason_code,
        message=message,
        evidence=["checkpoint.signature", "checkpoint.public_key", "checkpoint.key_id"],
    )


def _checkpoint_tsa_claim(receipts: list[dict[str, Any]]) -> ClaimVerdict:
    subjects: list[VerdictSubject] = []
    for index, receipt in enumerate(receipts, start=1):
        label = receipt.get("provider") or receipt.get("url") or f"receipt {index}"
        ok = receipt.get("verified") is True
        reason = str(receipt.get("reason") or "")
        subjects.append(
            _subject(
                subject_type="tsa_receipt",
                subject_id=str(label),
                verdict="supported" if ok else "disproved",
                reason_code=(
                    "CHECKPOINT_TSA_IMPRINT_SUPPORTED"
                    if ok
                    else "CHECKPOINT_TSA_IMPRINT_MISMATCH"
                ),
                message=reason
                or (
                    "TSA receipt message imprint matches composite_hash"
                    if ok
                    else "TSA receipt message imprint does not match composite_hash"
                ),
                evidence=["checkpoint.tsa", "checkpoint.tsa_receipts"],
            )
        )
    verdict = "supported" if all(subject.verdict == verdict_value("supported") for subject in subjects) else None
    return ClaimVerdict(
        name="checkpoint.tsa_imprint.v1",
        subjects=subjects,
        verdict=verdict,
        reason_code=(
            "CHECKPOINT_TSA_IMPRINT_SUPPORTED"
            if verdict == "supported"
            else "CHECKPOINT_TSA_IMPRINT_MISMATCH"
        ),
        message=(
            "TSA receipt message imprint matches composite_hash"
            if verdict == "supported"
            else "one or more TSA receipt message imprints do not match composite_hash"
        ),
        evidence=["checkpoint.tsa", "checkpoint.tsa_receipts"],
    )


def _checkpoint_base_result(
    body: dict[str, Any] | None,
    *,
    ok: bool,
    error: str | None = None,
    artifact: dict[str, Any] | None = None,
    claims: list[ClaimVerdict] | None = None,
    semantics: ResolvedSemantics | None = None,
    diagnostics: list[str] | None = None,
    composite_hash: str | None = None,
    chain_heads_count: int = 0,
    public_key: str | None = None,
    key_id: str | None = None,
    trust_source: str | None = None,
    self_attested: bool = False,
    tsa_present: bool = False,
    tsa_checked: bool = False,
    tsa_verified: bool | None = None,
    tsa_reason: str | None = None,
    tsa_url: str | None = None,
    tsa_requested_at: str | None = None,
    tsa_receipts: list[dict[str, Any]] | None = None,
    tsa_trust: dict[str, Any] | None = None,
) -> VerifyResult:
    claim_list = list(claims or [])
    claim_list, ok, exit_code, error = _enforce_required_claims(
        claims=claim_list,
        semantics=semantics,
        ok=ok,
        exit_code=0 if ok else 1,
        error=error,
        subject_type="claim_set_requirement",
        subject_id=artifact.get("checkpoint_path") if artifact else None,
        evidence=["checkpoint.claim_set"],
    )
    content_hash_hex = (
        composite_hash.removeprefix("sha256:")
        if isinstance(composite_hash, str) and composite_hash.startswith("sha256:")
        else None
    )
    default_tsa_trust = _build_tsa_trust_report(
        _checkpoint_tsa_receipts(body) if isinstance(body, dict) else [],
        content_hash_hex,
        ca_bundle_path=None,
    )
    return VerifyResult(
        ok=ok,
        error=error,
        exit_code=exit_code if exit_code is not None else 0 if ok else 1,
        artifact=artifact or {"kind": "checkpoint"},
        checkpoint_id=(
            str(body.get("checkpoint_id") or "") or None
            if isinstance(body, dict)
            else None
        ),
        computed_at=(
            str(body.get("computed_at") or "") or None
            if isinstance(body, dict)
            else None
        ),
        composite_hash=composite_hash,
        chain_heads_count=chain_heads_count,
        public_key=public_key,
        key_id=key_id,
        trust_source=trust_source,
        self_attested=self_attested,
        tsa_present=tsa_present,
        tsa_checked=tsa_checked,
        tsa_verified=tsa_verified,
        tsa_reason=tsa_reason,
        tsa_url=tsa_url,
        tsa_requested_at=tsa_requested_at,
        tsa_receipts=list(tsa_receipts or []),
        tsa_trust=tsa_trust if tsa_trust is not None else default_tsa_trust,
        diagnostics=_report_diagnostics(diagnostics, semantics),
        semantics=semantics.report_semantics() if semantics is not None else legacy_semantics(),
        claims=claim_list,
    )


def _checkpoint_receipt_label(receipt: dict[str, Any], index: int) -> str:
    value = receipt.get("provider") or receipt.get("url")
    return value if isinstance(value, str) and value else f"receipt {index}"


def _verify_checkpoint_core(
    checkpoint_path: str | Path,
    *,
    expected_public_key: str | None = None,
    public_key_url: str | None = None,
    key_manifest_source: str | None = None,
    self_attested: bool = False,
    check_tsa: bool = True,
) -> VerifyResult:
    path = Path(checkpoint_path)
    artifact = _checkpoint_artifact_dict(path)

    try:
        raw = path.read_bytes()
        artifact = _checkpoint_artifact_dict(path, raw)
        body = json.loads(raw.decode("utf-8"))
    except FileNotFoundError:
        return VerifyResult(ok=False, error=f"file not found: {path}", artifact=artifact)
    except json.JSONDecodeError as exc:
        return VerifyResult(ok=False, error=f"invalid JSON: {exc}", artifact=artifact)
    except Exception as exc:
        return VerifyResult(ok=False, error=f"could not read {path}: {exc}", artifact=artifact)

    if not isinstance(body, dict):
        return VerifyResult(
            ok=False,
            error="top-level JSON must be an object",
            artifact=artifact,
        )
    bundle_claims: list[ClaimVerdict] = []
    bundle_diagnostics: list[str] = []
    if _is_self_attesting_bundle(body):
        artifact["kind"] = "checkpoint_bundle"
        ok, error, bundle_body, claims, diagnostics = _verify_self_attesting_bundle_payload(
            body,
            artifact_id=path.name,
            check_tsa=check_tsa,
        )
        bundle_claims = claims
        bundle_diagnostics = diagnostics
        if not ok or bundle_body is None:
            return VerifyResult(
                ok=False,
                error=error,
                artifact=artifact,
                diagnostics=bundle_diagnostics,
                claims=bundle_claims,
            )
        body = bundle_body
    artifact, artifact_ref_error = _attach_artifact_ref(artifact, body)
    if artifact_ref_error is not None:
        return VerifyResult(
            ok=False,
            error=artifact_ref_error,
            artifact=artifact,
            diagnostics=bundle_diagnostics,
            claims=bundle_claims,
        )

    default_claims = ("checkpoint.composite_hash.v1", "checkpoint.signature.v1")
    semantics = resolve_pack_semantics(
        body,
        pack_root=path.parent,
        default_claim_names=default_claims,
        allowlist=PERMANENT_ALLOWLIST,
    )
    if not semantics.ok:
        failure = semantics.failure
        assert failure is not None
        return _checkpoint_base_result(
            body,
            ok=False,
            error=failure.top_level_error or failure.message,
            artifact=artifact,
            claims=[
                *bundle_claims,
                *_semantic_failure_claims(
                    semantics,
                    default_claim_names=default_claims,
                    subject_type="semantic_resolution",
                    subject_id=path.name,
                    evidence=["checkpoint.claim_set", "checkpoint.semantics_pins"],
                ),
            ],
            semantics=semantics,
            diagnostics=[
                *bundle_diagnostics,
                *([failure.diagnostic] if failure.diagnostic else []),
            ],
        )
    semantics_dispatch = semantics.dispatch()

    composite = body.get("composite_hash")
    signature = body.get("signature")
    embedded_pub = body.get("public_key")
    chain_heads_raw = body.get("chain_heads") or {}
    artifact_key_id = body.get("key_id") if isinstance(body.get("key_id"), str) else None
    checkpoint_id = str(body.get("checkpoint_id") or "") or None

    if not isinstance(composite, str) or not composite.startswith("sha256:"):
        return _checkpoint_base_result(
            body,
            ok=False,
            error="missing or malformed composite_hash",
            artifact=artifact,
            claims=[
                *bundle_claims,
                _checkpoint_composite_claim(
                    verdict="insufficient_evidence",
                    reason_code="CHECKPOINT_COMPOSITE_HASH_MISSING",
                    message="missing or malformed composite_hash",
                    checkpoint_id=checkpoint_id,
                )
            ],
            semantics=semantics,
            diagnostics=bundle_diagnostics,
        )
    if not isinstance(chain_heads_raw, dict):
        return _checkpoint_base_result(
            body,
            ok=False,
            error="chain_heads must be an object",
            artifact=artifact,
            claims=[
                *bundle_claims,
                _checkpoint_composite_claim(
                    verdict="insufficient_evidence",
                    reason_code="CHECKPOINT_CHAIN_HEADS_INVALID",
                    message="chain_heads must be an object",
                    checkpoint_id=checkpoint_id,
                )
            ],
            semantics=semantics,
            composite_hash=composite,
            diagnostics=bundle_diagnostics,
        )

    for scope_key, head in chain_heads_raw.items():
        if not isinstance(head, dict):
            return _checkpoint_base_result(
                body,
                ok=False,
                error=f"chain_heads[{scope_key}] must be an object",
                artifact=artifact,
                claims=[
                    *bundle_claims,
                    _checkpoint_composite_claim(
                        verdict="insufficient_evidence",
                        reason_code="CHECKPOINT_CHAIN_HEADS_INVALID",
                        message=f"chain_heads[{scope_key}] must be an object",
                        checkpoint_id=checkpoint_id,
                    )
                ],
                semantics=semantics,
                composite_hash=composite,
                chain_heads_count=len(chain_heads_raw),
                diagnostics=bundle_diagnostics,
            )
        if not isinstance(head.get("sequence_number"), int):
            return _checkpoint_base_result(
                body,
                ok=False,
                error=f"chain_heads[{scope_key}].sequence_number must be an int",
                artifact=artifact,
                claims=[
                    *bundle_claims,
                    _checkpoint_composite_claim(
                        verdict="insufficient_evidence",
                        reason_code="CHECKPOINT_CHAIN_HEADS_INVALID",
                        message=f"chain_heads[{scope_key}].sequence_number must be an int",
                        checkpoint_id=checkpoint_id,
                    )
                ],
                semantics=semantics,
                composite_hash=composite,
                chain_heads_count=len(chain_heads_raw),
                diagnostics=bundle_diagnostics,
            )
        if not isinstance(head.get("last_record_hash"), str):
            return _checkpoint_base_result(
                body,
                ok=False,
                error=f"chain_heads[{scope_key}].last_record_hash must be a string",
                artifact=artifact,
                claims=[
                    *bundle_claims,
                    _checkpoint_composite_claim(
                        verdict="insufficient_evidence",
                        reason_code="CHECKPOINT_CHAIN_HEADS_INVALID",
                        message=f"chain_heads[{scope_key}].last_record_hash must be a string",
                        checkpoint_id=checkpoint_id,
                    )
                ],
                semantics=semantics,
                composite_hash=composite,
                chain_heads_count=len(chain_heads_raw),
                diagnostics=bundle_diagnostics,
            )

    try:
        if semantics_dispatch.composite_hash is None:
            raise ValueError("checkpoint composite-hash implementation was not resolved")
        recomputed = semantics_dispatch.composite_hash(chain_heads_raw)
    except Exception as exc:
        return _checkpoint_base_result(
            body,
            ok=False,
            error=f"could not recompute composite_hash: {exc}",
            artifact=artifact,
            claims=[
                *bundle_claims,
                _checkpoint_composite_claim(
                    verdict="insufficient_evidence",
                    reason_code="CHECKPOINT_COMPOSITE_HASH_RECOMPUTE_FAILED",
                    message=f"could not recompute composite_hash: {exc}",
                    checkpoint_id=checkpoint_id,
                )
            ],
            semantics=semantics,
            composite_hash=composite,
            chain_heads_count=len(chain_heads_raw),
            diagnostics=bundle_diagnostics,
        )
    if recomputed != composite:
        return _checkpoint_base_result(
            body,
            ok=False,
            error=(
                "composite_hash mismatch - chain_heads have been altered\n"
                f"  stored:     {composite}\n"
                f"  recomputed: {recomputed}"
            ),
            artifact=artifact,
            claims=[
                *bundle_claims,
                _checkpoint_composite_claim(
                    verdict="disproved",
                    reason_code="CHECKPOINT_COMPOSITE_HASH_MISMATCH",
                    message="composite_hash mismatch - chain_heads have been altered",
                    checkpoint_id=checkpoint_id,
                )
            ],
            semantics=semantics,
            composite_hash=composite,
            chain_heads_count=len(chain_heads_raw),
            diagnostics=bundle_diagnostics,
        )

    if not isinstance(signature, str):
        return _checkpoint_base_result(
            body,
            ok=False,
            error="export is unsigned (no signature field)",
            artifact=artifact,
            claims=[
                *bundle_claims,
                _checkpoint_composite_claim(
                    verdict="supported",
                    reason_code="CHECKPOINT_COMPOSITE_HASH_SUPPORTED",
                    message="checkpoint composite_hash matches chain_heads",
                    checkpoint_id=checkpoint_id,
                ),
                _checkpoint_signature_claim(
                    verdict="insufficient_evidence",
                    reason_code="CHECKPOINT_SIGNATURE_MISSING",
                    message="checkpoint is unsigned (no signature field)",
                    key_id=artifact_key_id,
                ),
            ],
            semantics=semantics,
            composite_hash=composite,
            chain_heads_count=len(chain_heads_raw),
            diagnostics=bundle_diagnostics,
        )

    if expected_public_key is not None and not expected_public_key.startswith("ed25519:"):
        return _checkpoint_base_result(
            body,
            ok=False,
            error="--public-key must start with 'ed25519:'",
            artifact=artifact,
            claims=[
                *bundle_claims,
                _checkpoint_composite_claim(
                    verdict="supported",
                    reason_code="CHECKPOINT_COMPOSITE_HASH_SUPPORTED",
                    message="checkpoint composite_hash matches chain_heads",
                    checkpoint_id=checkpoint_id,
                ),
                _checkpoint_signature_claim(
                    verdict="insufficient_evidence",
                    reason_code="CHECKPOINT_PUBLIC_KEY_INVALID",
                    message="--public-key must start with 'ed25519:'",
                    key_id=artifact_key_id,
                ),
            ],
            semantics=semantics,
            composite_hash=composite,
            chain_heads_count=len(chain_heads_raw),
            diagnostics=bundle_diagnostics,
        )

    signing_time = _parse_iso_or_none(body.get("computed_at"))
    trusted_pub, trust_source, err = _resolve_trust_key(
        artifact_pub=embedded_pub if self_attested and isinstance(embedded_pub, str) else None,
        artifact_key_id=artifact_key_id,
        purpose="integrity_checkpoint",
        expected_public_key=expected_public_key,
        public_key_url=public_key_url,
        key_manifest_source=key_manifest_source,
        signing_time=signing_time,
    )
    if self_attested and trust_source == "embedded":
        trust_source = "self-attested (embedded public_key)"
    if err is not None or trusted_pub is None:
        return _checkpoint_base_result(
            body,
            ok=False,
            error=err or "could not resolve trust root",
            artifact=artifact,
            claims=[
                *bundle_claims,
                _checkpoint_composite_claim(
                    verdict="supported",
                    reason_code="CHECKPOINT_COMPOSITE_HASH_SUPPORTED",
                    message="checkpoint composite_hash matches chain_heads",
                    checkpoint_id=checkpoint_id,
                ),
                _checkpoint_signature_claim(
                    verdict="insufficient_evidence",
                    reason_code="TRUST_ROOT_UNRESOLVABLE",
                    message=err or "could not resolve trust root",
                    key_id=artifact_key_id,
                ),
            ],
            semantics=semantics,
            composite_hash=composite,
            chain_heads_count=len(chain_heads_raw),
            diagnostics=bundle_diagnostics,
        )

    if isinstance(embedded_pub, str) and embedded_pub != trusted_pub:
        return _checkpoint_base_result(
            body,
            ok=False,
            error=(
                "embedded public_key does not match resolved trust root\n"
                f"  trust root: {trusted_pub}\n"
                f"  embedded:   {embedded_pub}"
            ),
            artifact=artifact,
            claims=[
                *bundle_claims,
                _checkpoint_composite_claim(
                    verdict="supported",
                    reason_code="CHECKPOINT_COMPOSITE_HASH_SUPPORTED",
                    message="checkpoint composite_hash matches chain_heads",
                    checkpoint_id=checkpoint_id,
                ),
                _checkpoint_signature_claim(
                    verdict="disproved",
                    reason_code="CHECKPOINT_PUBLIC_KEY_MISMATCH",
                    message="embedded public_key does not match resolved trust root",
                    key_id=artifact_key_id or _public_key_fingerprint(trusted_pub),
                ),
            ],
            semantics=semantics,
            composite_hash=composite,
            chain_heads_count=len(chain_heads_raw),
            diagnostics=bundle_diagnostics,
        )

    if not _verify_ed25519(trusted_pub, composite.encode("utf-8"), signature):
        return _checkpoint_base_result(
            body,
            ok=False,
            error="signature verification failed",
            artifact=artifact,
            claims=[
                *bundle_claims,
                _checkpoint_composite_claim(
                    verdict="supported",
                    reason_code="CHECKPOINT_COMPOSITE_HASH_SUPPORTED",
                    message="checkpoint composite_hash matches chain_heads",
                    checkpoint_id=checkpoint_id,
                ),
                _checkpoint_signature_claim(
                    verdict="disproved",
                    reason_code="SIGNATURE_VERIFICATION_FAILED",
                    message="signature verification failed",
                    key_id=artifact_key_id or _public_key_fingerprint(trusted_pub),
                ),
            ],
            semantics=semantics,
            composite_hash=composite,
            chain_heads_count=len(chain_heads_raw),
            public_key=trusted_pub,
            key_id=artifact_key_id or _public_key_fingerprint(trusted_pub),
            trust_source=trust_source,
            self_attested=trust_source.startswith("self-attested"),
            diagnostics=bundle_diagnostics,
        )

    tsa_inputs = _checkpoint_tsa_receipts(body)
    tsa_receipts: list[dict[str, Any]] = []
    hex_hash = composite.removeprefix("sha256:")
    for index, receipt in enumerate(tsa_inputs, start=1):
        label = _checkpoint_receipt_label(receipt, index)
        receipt_result = {
            "provider": receipt.get("provider") if isinstance(receipt.get("provider"), str) else None,
            "url": receipt.get("url") if isinstance(receipt.get("url"), str) else None,
            "requested_at": receipt.get("requested_at") if isinstance(receipt.get("requested_at"), str) else None,
            "checked": check_tsa,
            "verified": None,
            "reason": None,
        }
        if not check_tsa:
            receipt_result["reason"] = "skipped"
            tsa_receipts.append(receipt_result)
            continue
        if not isinstance(receipt.get("receipt_b64"), str):
            reason = receipt.get("_invalid") or "receipt_b64 missing"
            receipt_result["verified"] = False
            receipt_result["reason"] = f"{label}: {reason}"
            tsa_receipts.append(receipt_result)
            return _checkpoint_base_result(
                body,
                ok=False,
                error=f"TSA: {receipt_result['reason']}",
                artifact=artifact,
                claims=[
                    *bundle_claims,
                    _checkpoint_composite_claim(
                        verdict="supported",
                        reason_code="CHECKPOINT_COMPOSITE_HASH_SUPPORTED",
                        message="checkpoint composite_hash matches chain_heads",
                        checkpoint_id=checkpoint_id,
                    ),
                    _checkpoint_signature_claim(
                        verdict="supported",
                        reason_code="CHECKPOINT_SIGNATURE_SUPPORTED",
                        message="checkpoint signature verified",
                        key_id=artifact_key_id or _public_key_fingerprint(trusted_pub),
                    ),
                    _checkpoint_tsa_claim(tsa_receipts),
                ],
                semantics=semantics,
                composite_hash=composite,
                chain_heads_count=len(chain_heads_raw),
                public_key=trusted_pub,
                key_id=artifact_key_id or _public_key_fingerprint(trusted_pub),
                trust_source=trust_source,
                self_attested=trust_source.startswith("self-attested"),
                tsa_present=True,
                tsa_checked=True,
                tsa_verified=False,
                tsa_reason=receipt_result["reason"],
                tsa_url=receipt_result["url"],
                tsa_requested_at=receipt_result["requested_at"],
                tsa_receipts=tsa_receipts,
                diagnostics=bundle_diagnostics,
            )
        ok, reason = _verify_tsa_receipt(receipt["receipt_b64"], hex_hash)
        receipt_result["verified"] = ok
        receipt_result["reason"] = reason
        tsa_receipts.append(receipt_result)
        if not ok:
            return _checkpoint_base_result(
                body,
                ok=False,
                error=f"TSA: {label}: {reason}",
                artifact=artifact,
                claims=[
                    *bundle_claims,
                    _checkpoint_composite_claim(
                        verdict="supported",
                        reason_code="CHECKPOINT_COMPOSITE_HASH_SUPPORTED",
                        message="checkpoint composite_hash matches chain_heads",
                        checkpoint_id=checkpoint_id,
                    ),
                    _checkpoint_signature_claim(
                        verdict="supported",
                        reason_code="CHECKPOINT_SIGNATURE_SUPPORTED",
                        message="checkpoint signature verified",
                        key_id=artifact_key_id or _public_key_fingerprint(trusted_pub),
                    ),
                    _checkpoint_tsa_claim(tsa_receipts),
                ],
                semantics=semantics,
                composite_hash=composite,
                chain_heads_count=len(chain_heads_raw),
                public_key=trusted_pub,
                key_id=artifact_key_id or _public_key_fingerprint(trusted_pub),
                trust_source=trust_source,
                self_attested=trust_source.startswith("self-attested"),
                tsa_present=True,
                tsa_checked=True,
                tsa_verified=False,
                tsa_reason=reason,
                tsa_url=receipt_result["url"],
                tsa_requested_at=receipt_result["requested_at"],
                tsa_receipts=tsa_receipts,
                diagnostics=bundle_diagnostics,
            )

    first_receipt = tsa_receipts[0] if tsa_receipts else None
    tsa_present = bool(tsa_receipts)
    tsa_checked = tsa_present and check_tsa
    tsa_verified = (
        all(receipt.get("verified") is True for receipt in tsa_receipts)
        if tsa_checked
        else None
    )
    tsa_reason = None
    if tsa_checked:
        tsa_reason = (
            f"{len(tsa_receipts)} TSA receipt(s) match composite_hash"
            if len(tsa_receipts) != 1
            else str(first_receipt.get("reason"))
        )

    success_claims = [
        *bundle_claims,
        _checkpoint_composite_claim(
            verdict="supported",
            reason_code="CHECKPOINT_COMPOSITE_HASH_SUPPORTED",
            message="checkpoint composite_hash matches chain_heads",
            checkpoint_id=checkpoint_id,
        ),
        _checkpoint_signature_claim(
            verdict="supported",
            reason_code="CHECKPOINT_SIGNATURE_SUPPORTED",
            message="checkpoint signature verified",
            key_id=artifact_key_id or _public_key_fingerprint(trusted_pub),
        ),
    ]
    if tsa_checked:
        success_claims.append(_checkpoint_tsa_claim(tsa_receipts))

    return _checkpoint_base_result(
        body,
        ok=True,
        artifact=artifact,
        claims=success_claims,
        semantics=semantics,
        composite_hash=composite,
        chain_heads_count=len(chain_heads_raw),
        public_key=trusted_pub,
        key_id=artifact_key_id or _public_key_fingerprint(trusted_pub),
        trust_source=trust_source,
        self_attested=trust_source.startswith("self-attested"),
        tsa_present=tsa_present,
        tsa_checked=tsa_checked,
        tsa_verified=tsa_verified,
        tsa_reason=tsa_reason,
        tsa_url=(
            first_receipt.get("url")
            if isinstance(first_receipt, dict)
            and isinstance(first_receipt.get("url"), str)
            else None
        ),
        tsa_requested_at=(
            first_receipt.get("requested_at")
            if isinstance(first_receipt, dict)
            and isinstance(first_receipt.get("requested_at"), str)
            else None
        ),
        tsa_receipts=tsa_receipts,
        diagnostics=bundle_diagnostics,
    )


def verify_checkpoint(
    checkpoint_path: str | Path,
    *,
    expected_public_key: str | None = None,
    public_key_url: str | None = None,
    key_manifest: str | None = None,
    self_attested: bool = False,
    check_tsa: bool = True,
) -> VerifyResult:
    key_manifest_source = key_manifest
    if (
        key_manifest_source is None
        and not self_attested
        and expected_public_key is None
        and public_key_url is None
    ):
        key_manifest_source = _cached_key_manifest_source() or _bundled_key_manifest_source()
    return _verify_checkpoint_core(
        checkpoint_path,
        expected_public_key=expected_public_key,
        public_key_url=public_key_url,
        key_manifest_source=key_manifest_source,
        self_attested=self_attested,
        check_tsa=check_tsa,
    )


def verify(
    export_path: str | Path,
    *,
    public_key: str | None = None,
    public_key_url: str | None = None,
    self_attested: bool = False,
    check_tsa: bool = True,
) -> VerifyResult:
    """Verify a standalone artifact path.

    This preserves the historical ``python -m keel_verifier <artifact>`` and
    programmatic ``verify(path)`` surface. New signed compliance exports should
    use ``keel-verify export`` so ``--walk-events`` and ``--verify-closure`` can
    validate bundled lifecycle evidence. Voice-session attestation
    artifacts are auto-detected by their top-level ``verifier_compatibility``
    block and verified locally.
    """
    path = Path(export_path)
    try:
        raw = path.read_bytes()
        body = json.loads(raw.decode("utf-8"))
    except Exception:
        body = None
    if _is_voice_attestation_artifact(body):
        artifact = _checkpoint_artifact_dict(path, raw if "raw" in locals() else None)
        artifact["kind"] = "voice_session_attestation"
        artifact, artifact_ref_error = _attach_artifact_ref(artifact, body)
        if artifact_ref_error is not None:
            return VerifyResult(ok=False, error=artifact_ref_error, artifact=artifact)
        result = verify_attestation_artifact(body, check_tsa=check_tsa)
        checks = result["checks"]
        failed = result["failed_checks"]
        artifact.update(
            {
                "schema": result.get("schema"),
                "session_id": result.get("session_id"),
                "checks": checks,
                "head_hash": result.get("head_hash"),
                "head_sequence": result.get("head_sequence"),
            }
        )
        return VerifyResult(
            ok=result["verdict"] == "pass",
            error=(
                "; ".join(
                    f"{check.get('name')}: {check.get('reason')}"
                    for check in failed
                )
                if failed
                else None
            ),
            exit_code=0 if result["verdict"] == "pass" else 1,
            artifact=artifact,
            checkpoint_id=result.get("session_id"),
            composite_hash=result.get("head_hash"),
            chain_heads_count=int(result.get("head_sequence") or 0),
            tsa_present=any(
                check.get("name") == "rfc3161_timestamp_receipt"
                for check in checks
            ),
            tsa_checked=check_tsa,
            tsa_verified=not any(
                check.get("name") == "rfc3161_timestamp_receipt"
                and check.get("result") != "pass"
                for check in checks
            ),
            tsa_receipts=[
                {
                    "checked": check_tsa,
                    "verified": check.get("result") == "pass",
                    "reason": check.get("reason"),
                }
                for check in checks
                if check.get("name") == "rfc3161_timestamp_receipt"
            ],
        )
    return verify_checkpoint(
        export_path,
        expected_public_key=public_key,
        public_key_url=public_key_url,
        self_attested=self_attested,
        check_tsa=check_tsa,
    )


def verify_export_walk_events(export_data: bytes | str | Path) -> int:
    if isinstance(export_data, bytes):
        data = export_data
    elif isinstance(export_data, Path) or (isinstance(export_data, str) and Path(export_data).exists()):
        data = Path(export_data).read_bytes()
    else:
        data = str(export_data).encode("utf-8")
    return _walk_export_events(data)


def verify_closure_record(export_data: bytes | str | Path, *, key_manifest: str | None = None) -> int:
    if isinstance(export_data, bytes):
        data = export_data
    elif isinstance(export_data, Path) or (isinstance(export_data, str) and Path(export_data).exists()):
        data = Path(export_data).read_bytes()
    else:
        data = str(export_data).encode("utf-8")
    args = argparse.Namespace(
        key_manifest=key_manifest,
        key_manifest_url=None,
        self_attested=False,
    )
    return _verify_export_closures(data, args)


# ─── CLI plumbing ──────────────────────────────────────────────────


def _add_key_manifest_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--key-manifest",
        help=(
            "Local path to a Keel public key manifest JSON file "
            "(as returned by GET /v1/compliance/keys)."
        ),
    )
    p.add_argument(
        "--key-manifest-url",
        help=(
            "URL to fetch the key manifest from "
            "(e.g. https://api.keelapi.com/v1/compliance/keys)."
        ),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Standalone verifier for Keel trust artifacts.",
        epilog=(
            "Export mode can also walk bundled governance chain entries with "
            "--walk-events and verify permit closure records with --verify-closure."
        ),
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_export = sub.add_parser("export", help="Verify a signed compliance export.")
    p_export.add_argument("--export-file", required=True)
    p_export.add_argument("--manifest", required=True)
    p_export.add_argument("--json", action="store_true", dest="as_json")
    p_export.add_argument(
        "--walk-events",
        action="store_true",
        help=(
            "After export content hash and signature verification, parse an "
            "audit export bundle and walk bundled chain_entries."
        ),
    )
    p_export.add_argument(
        "--verify-closure",
        action="store_true",
        help=(
            "After export content hash and signature verification, verify "
            "permit.closed closure signatures and dispatch/provider/client digest "
            "consistency from bundled chain_entries."
        ),
    )
    p_export.add_argument(
        "--allow-unsigned",
        action="store_true",
        help=(
            "Allow legacy unsigned manifests after content-hash verification. "
            "Prints a warning and exits 0."
        ),
    )
    p_export.add_argument(
        "--expected-public-key",
        help="ed25519:<base64> public key the export must be signed with.",
    )
    _add_key_manifest_args(p_export)
    p_export.set_defaults(func=cmd_export)

    p_cp = sub.add_parser(
        "checkpoint", help="Verify an integrity checkpoint JSON file."
    )
    p_cp.add_argument("--checkpoint-file", required=True)
    p_cp.add_argument("--json", action="store_true", dest="as_json")
    p_cp.add_argument(
        "--expected-public-key",
        help="ed25519:<base64> public key the checkpoint must be signed with.",
    )
    p_cp.add_argument(
        "--public-key-url",
        help=(
            "URL to fetch the trust-root public key "
            "(e.g. .../v1/integrity/checkpoint-public-key)."
        ),
    )
    _add_key_manifest_args(p_cp)
    p_cp.add_argument(
        "--tsa-ca-bundle",
        help=(
            "Optional CA bundle for opt-in RFC 3161 TSA trust validation. "
            "Verifies chain, signature, and timestamping purpose against this "
            "bundle only; historical revocation is not checked."
        ),
    )
    p_cp.set_defaults(func=cmd_checkpoint)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
