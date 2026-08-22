"""Independent adjudication for strict heterogeneous ``work-chain.v2`` packs.

The v2 path is intentionally separate from :mod:`keel_verifier.work_chain`.
That keeps the released payment-only v1 contract byte-for-byte compatible
while making every new authority, identity, value, review, and pre-effect
dispatch relationship explicit and fail closed.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime, timedelta
from functools import lru_cache
from importlib import resources
import json
from pathlib import Path
from typing import Any

import jsonschema
from referencing import Registry, Resource

from keel_verifier.permit_presentation import resolve_permit_presentation
from keel_verifier.verdicts import ClaimVerdict, VerificationReport, VerdictSubject
from keel_verifier.work_chain import (
    _Failure,
    _PermitMaterial,
    _artifact_index,
    _claim,
    _claim_from_subjects,
    _content_hash,
    _digest,
    _key_for_time,
    _load_document,
    _mapping,
    _norm_sha,
    _parse_time,
    _resolve_reference,
    _signed_semantic_binding,
    _verify_manifest_signature,
    _verify_permit,
)


WORK_CLAIMS_V2 = (
    "permit.work_authority_manifest.v2",
    "permit.work_child_containment.v2",
    "permit_chain.execution_authorized_at_boundary.v2",
    "permit.work_value_conservation.v2",
    "permit.work_exact_review.v1",
)

POPULATIONS_V2 = {
    "work_authorities": ("authorities", "permit_work_authorities"),
    "child_permits": ("child_permits", "permits"),
    "work_value_events": ("value_events", "permit_work_value_events"),
    "lifecycle_events": ("lifecycle_events", "governance_events"),
    "review_transitions": ("review_transitions", "governance_events"),
    "provider_value_facts": (
        "provider_value_facts",
        "permits",
    ),
}

_SCHEMAS = (
    "work-chain-pack-v2.schema.json",
    "work-request-v2.schema.json",
    "work-package-v2.schema.json",
    "work-authority-v2.schema.json",
    "work-binding-v2.schema.json",
    "work-value-event-v2.schema.json",
    "work-review-transition-v1.schema.json",
    "provider-value-fact-v1.schema.json",
    "provider-value-fact-v2.schema.json",
    "work-dispatch-boundary-v2.schema.json",
    "work-summary-v1.schema.json",
    "permit-semantic-binding-v2.schema.json",
    "telephony-call-outbound-exact-facts-v1.schema.json",
    "telephony-call-outbound-gateway-exact-facts-v1.schema.json",
    "telephony-call-respond-gateway-exact-facts-v1.schema.json",
    "action-gateway-exact-facts-v1.schema.json",
)

_SEMANTIC_FILES = (
    "data/semantics/permit/universal_verification_v5.json",
    "data/semantics/work/authority_manifest_v2.json",
    "data/semantics/work/child_containment_v2.json",
    "data/comparator_registry/work-action-authority-v2.json",
    "data/semantics/work/execution_authorized_at_boundary_v2.json",
    "data/semantics/work/value_conservation_v2.json",
    "data/semantics/work/exact_review_v1.json",
    "data/semantics/work/provider_value_fact_v1.json",
    "data/semantics/work/provider_value_fact_v2.json",
    "data/semantics/work/summary_v1.json",
)

_CLAIM_SEMANTIC_FILES = {
    WORK_CLAIMS_V2[0]: (
        "data/semantics/work/authority_manifest_v2.json",
        "data/comparator_registry/work-action-authority-v2.json",
    ),
    WORK_CLAIMS_V2[1]: (
        "data/semantics/work/child_containment_v2.json",
        "data/comparator_registry/work-action-authority-v2.json",
        "data/semantics/work/provider_value_fact_v1.json",
        "data/semantics/work/provider_value_fact_v2.json",
    ),
    WORK_CLAIMS_V2[2]: (
        "data/semantics/work/execution_authorized_at_boundary_v2.json",
    ),
    WORK_CLAIMS_V2[3]: (
        "data/semantics/work/value_conservation_v2.json",
        "data/semantics/work/provider_value_fact_v1.json",
        "data/semantics/work/provider_value_fact_v2.json",
    ),
    WORK_CLAIMS_V2[4]: ("data/semantics/work/exact_review_v1.json",),
}

_GENERIC_TITLE = "AI Permit"
_PROVIDER_VALUE_FACT_V2_PROFILES = {
    "keel.provider_contract.sabre_lodging_quote.v1": {
        "fact_profile_id": "keel.facts.lodging_booking_value.v2",
        "connector_type": "sabre_direct",
    },
}
_CALL_SEMANTIC = "keel.action.telephony_call_outbound.v1"
_CALL_FACT_PROFILE = "keel.facts.telephony_call_outbound_exact.v1"
_CALL_FACT_TYPE = "keel.telephony_call_outbound_exact_facts.v1"
_ACTION_GATEWAY_FACT_TYPE = "keel.action_gateway_exact_facts.v1"
_ACTION_GATEWAY_PROFILES = {
    "keel.action.message_send.v1": (
        "keel.facts.message_send_gateway_exact.v1",
        "message.send",
    ),
    "keel.action.calendar_event_create_gateway.v1": (
        "keel.facts.calendar_event_create_gateway_exact.v1",
        "calendar.event.create",
    ),
}
_TELEPHONY_GATEWAY_PROFILES = {
    "keel.action.telephony_call_outbound.v1": (
        "keel.facts.telephony_call_outbound_gateway_exact.v1",
        "keel.telephony_call_outbound_gateway_exact_facts.v1",
        "call.outbound",
    ),
    "keel.action.telephony_call_respond_gateway.v1": (
        "keel.facts.telephony_call_respond_gateway_exact.v1",
        "keel.telephony_call_respond_gateway_exact_facts.v1",
        "call.respond",
    ),
}
_SELECTOR_FILES = {
    f"keel.semantic_selector_registry.v{version}": (
        f"data/permit_to_x/semantic_registry/v{version}.json"
    )
    for version in range(1, 23)
}
_FACT_PROFILE_FILES = {
    f"keel.fact_profile_registry.v{version}": (
        f"data/permit_to_x/fact_profiles/v{version}.json"
    )
    for version in range(1, 20)
}


def _json_resource(path: str) -> tuple[dict[str, Any], bytes]:
    resource = resources.files("keel_verifier").joinpath(path)
    raw = resource.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RuntimeError(f"vendored Work artifact {path} is not an object")
    return value, raw


@lru_cache(maxsize=1)
def _schema_registry() -> tuple[dict[str, Any], Registry]:
    schemas: list[dict[str, Any]] = []
    registry = Registry()
    for name in _SCHEMAS:
        schema, _raw = _json_resource(f"data/permit_to_x/schemas/{name}")
        schema_id = schema.get("$id")
        if not isinstance(schema_id, str):
            raise RuntimeError(f"vendored Work schema {name} has no $id")
        schemas.append(schema)
        registry = registry.with_resource(schema_id, Resource.from_contents(schema))
    return schemas[0], registry


def _validate_schema(instance: Any, name: str, *, code: str) -> None:
    schema, _raw = _json_resource(f"data/permit_to_x/schemas/{name}")
    _root, registry = _schema_registry()
    try:
        jsonschema.Draft202012Validator(
            schema,
            registry=registry,
            format_checker=jsonschema.FormatChecker(),
        ).validate(instance)
    except jsonschema.ValidationError as exc:
        path = ".".join(str(part) for part in exc.absolute_path) or "<root>"
        raise _Failure(
            "disproved",
            code,
            f"{name} is invalid at {path}: {exc.message}",
            (path,),
        ) from exc


@lru_cache(maxsize=1)
def _work_semantics_v2() -> dict[str, Any]:
    pins: list[dict[str, str]] = []
    for path in _SEMANTIC_FILES:
        value, raw = _json_resource(path)
        artifact_id = str(value.get("id") or value.get("$id") or value.get("version"))
        pins.append({"id": artifact_id, "hash": _content_hash(raw)})
    _claims, claims_raw = _json_resource("data/claim_registry/v6.json")
    return {
        "mode": "work_chain_pinned",
        "profile_id": "work-chain.v2",
        "profile_hash": _digest({pin["id"]: pin["hash"] for pin in pins}),
        "claim_registry_hash": _content_hash(claims_raw),
        "pins": pins,
    }


@lru_cache(maxsize=1)
def _work_claim_semantics_v2() -> dict[str, tuple[dict[str, str], ...]]:
    """Return claim-local pins without promoting pack-scoped semantics globally."""

    result: dict[str, tuple[dict[str, str], ...]] = {}
    for claim_name, paths in _CLAIM_SEMANTIC_FILES.items():
        pins: list[dict[str, str]] = []
        for path in paths:
            value, raw = _json_resource(path)
            artifact_id = str(
                value.get("id") or value.get("$id") or value.get("version")
            )
            pins.append({"id": artifact_id, "hash": _content_hash(raw)})
        result[claim_name] = tuple(pins)
    return result


def _all_claim_failure_v2(
    failure: _Failure, root_id: str | None
) -> list[ClaimVerdict]:
    subject_types = (
        "work_root",
        "work_child_population",
        "dispatch_boundary_population",
        "work_value_population",
        "work_review_population",
    )
    return [
        _claim(
            name,
            subject_type=subject_type,
            subject_id=root_id,
            verdict=failure.verdict,
            code=failure.code,
            message=failure.message,
            evidence=failure.evidence,
        )
        for name, subject_type in zip(WORK_CLAIMS_V2, subject_types, strict=True)
    ]


def _report_v2(
    *,
    artifact: dict[str, Any],
    claims: list[ClaimVerdict],
    diagnostics: list[str] | None = None,
) -> VerificationReport:
    claim_semantics = _work_claim_semantics_v2()
    claims = [
        replace(claim, semantics=list(claim_semantics[claim.name]))
        if claim.semantics is None
        else claim
        for claim in claims
    ]
    verdicts = [claim.aggregate_verdict for claim in claims if claim.required]
    ok = bool(verdicts) and all(value == "supported" for value in verdicts)
    exit_code = (
        0
        if ok
        else 1
        if "disproved" in verdicts
        else 2
        if "unverifiable_scope" in verdicts
        else 1
    )
    first_failure = next(
        (
            subject
            for claim in claims
            for subject in claim.subjects
            if claim.required and subject.required and subject.verdict != "supported"
        ),
        None,
    )
    return VerificationReport(
        ok=ok,
        exit_code=exit_code,
        error=first_failure.message if first_failure is not None else None,
        artifact=artifact,
        claims=claims,
        diagnostics=list(diagnostics or ()),
        semantics=_work_semantics_v2(),
    )


def _validate_top_level_v2(document: dict[str, Any]) -> None:
    if (
        document.get("version") != "keel.work_chain_pack.v2"
        or document.get("profile") != "work-chain.v2"
    ):
        raise _Failure(
            "unverifiable_scope",
            "WORK_VERSION_UNSUPPORTED",
            "only keel.work_chain_pack.v2 with profile work-chain.v2 is supported",
            ("version", "profile"),
        )
    if document.get("requested_claims") != list(WORK_CLAIMS_V2):
        raise _Failure(
            "unverifiable_scope",
            "WORK_VERSION_UNSUPPORTED",
            "requested_claims must use the canonical ordered five-claim Work v2 profile",
            ("requested_claims",),
        )
    schema, registry = _schema_registry()
    try:
        jsonschema.Draft202012Validator(
            schema,
            registry=registry,
            format_checker=jsonschema.FormatChecker(),
        ).validate(document)
    except jsonschema.ValidationError as exc:
        path = ".".join(str(part) for part in exc.absolute_path) or "<root>"
        raise _Failure(
            "disproved",
            "WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID",
            f"work-chain-v2 pack is invalid at {path}: {exc.message}",
            (path,),
        ) from exc


def _validate_references_v2(
    document: dict[str, Any], artifacts: dict[str, dict[str, Any]]
) -> None:
    root = document["root"]
    _resolve_reference(root["permit_artifact"], artifacts, field="root.permit_artifact")
    top_level_refs: list[tuple[str, Any]] = []
    for population in ("review_transitions", "provider_value_facts", "evidence_artifacts"):
        top_level_refs.extend(
            (f"{population}[{index}]", reference)
            for index, reference in enumerate(document[population])
        )
    for field, reference in top_level_refs:
        _resolve_reference(reference, artifacts, field=field)
    for index, child_raw in enumerate(document["child_permits"]):
        child = dict(child_raw)
        _resolve_reference(
            child["permit_artifact"],
            artifacts,
            field=f"child_permits[{index}].permit_artifact",
        )
        for key in (
            "review_transition",
            "provider_value_fact",
            "dispatch_boundary_evidence",
        ):
            if child.get(key) is not None:
                _resolve_reference(
                    child[key], artifacts, field=f"child_permits[{index}].{key}"
                )
        for fact_index, reference in enumerate(child["authorization_fact_artifacts"]):
            _resolve_reference(
                reference,
                artifacts,
                field=(
                    f"child_permits[{index}].authorization_fact_artifacts[{fact_index}]"
                ),
            )

    seen_lifecycle: set[str] = set()
    for index, event_raw in enumerate(document["lifecycle_events"]):
        event = dict(event_raw)
        event_id = str(event["event_id"])
        if event_id in seen_lifecycle:
            raise _Failure(
                "disproved",
                "WORK_ARTIFACT_INTEGRITY_INVALID",
                "lifecycle event identifiers must be unique",
                (f"lifecycle_events[{index}]",),
            )
        seen_lifecycle.add(event_id)
        matches = [
            artifact
            for artifact in artifacts.values()
            if artifact.get("artifact_type") == "governance_event"
            and artifact.get("artifact_digest") == event.get("event_digest")
        ]
        if len(matches) != 1:
            raise _Failure(
                "disproved",
                "WORK_ARTIFACT_INTEGRITY_INVALID",
                f"lifecycle event {event_id} does not resolve exactly once",
                (f"lifecycle_events[{index}]",),
            )
        payload = _mapping(
            matches[0].get("payload"),
            field=f"lifecycle_events[{index}].artifact.payload",
            code="WORK_ARTIFACT_INTEGRITY_INVALID",
        )
        if any(
            payload.get(field) != value
            for field, value in event.items()
            if field != "event_digest"
        ):
            raise _Failure(
                "disproved",
                "WORK_ARTIFACT_INTEGRITY_INVALID",
                f"lifecycle event {event_id} differs from its committed artifact payload",
                (f"lifecycle_events[{index}]",),
            )


def _scope_signature_v2(
    document: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    *,
    trust_root: str | Path | None,
) -> tuple[list[dict[str, Any]], str]:
    scope = dict(document["scope_commitment"])
    commitments = {
        item["population"]: dict(item) for item in scope["populations"]
    }
    if set(commitments) != set(POPULATIONS_V2):
        raise _Failure(
            "insufficient_evidence",
            "WORK_SCOPE_COMMITMENT_MISSING",
            "Work v2 scope must commit all six populations exactly once",
            ("scope_commitment.populations",),
        )
    for population, (document_field, source_relation) in POPULATIONS_V2.items():
        commitment = commitments[population]
        values = document[document_field]
        if (
            commitment.get("source_relation") != source_relation
            or commitment.get("included_count") != len(values)
            or commitment.get("included_set_hash") != _digest(values)
        ):
            raise _Failure(
                "disproved",
                "WORK_SCOPE_POPULATION_MISMATCH",
                f"{population} differs from its signed scope commitment",
                (f"scope_commitment.populations.{population}", document_field),
            )

    signature = dict(document["scope_commitment_signature"])
    cutoff = dict(document["declared_cutoff"])
    key_id = str(signature["binding_key_id"])
    payload = {
        "version": "keel.work_scope_commitment_signature_payload.v2",
        "project_id": document["project_id"],
        "root_permit_id": document["root_permit_id"],
        "export_source": document["export_source"],
        "recorded_through": cutoff["recorded_through"],
        "checkpoint_id": cutoff["checkpoint_id"],
        "scope_commitment": scope,
        "binding_key_id": key_id,
    }
    expected_hash = _digest(payload)
    if (
        signature["canonical_hash"] != expected_hash
        or cutoff["checkpoint_digest"] != expected_hash
    ):
        raise _Failure(
            "disproved",
            "WORK_SCOPE_COMMITMENT_SIGNATURE_INVALID",
            "Work v2 checkpoint does not match its exact signature payload",
            ("scope_commitment_signature", "declared_cutoff.checkpoint_digest"),
        )
    key_artifacts = [
        artifact
        for artifact in artifacts.values()
        if artifact.get("artifact_type") == "keel.public_key_manifest.v1"
    ]
    if len(key_artifacts) != 1:
        raise _Failure(
            "insufficient_evidence",
            "WORK_SCOPE_COMMITMENT_MISSING",
            "Work v2 pack must embed exactly one signed public-key manifest",
            ("artifacts",),
        )
    manifest = _mapping(
        key_artifacts[0]["payload"],
        field="artifacts.key_manifest.payload",
        code="WORK_SCOPE_COMMITMENT_MISSING",
    )
    entries = _verify_manifest_signature(manifest, trust_root=trust_root)
    signed_at = _parse_time(signature["signed_at"], field="scope_signature.signed_at")
    public_key = _key_for_time(
        entries,
        key_id=key_id,
        purpose="permit_binding_signing",
        signed_at=signed_at,
    )
    from keel_verifier import verifier as core

    if core._binding_key_id_from_public_key(public_key) != key_id or not core._verify_ed25519(
        public_key,
        expected_hash.removeprefix("sha256:").encode("utf-8"),
        str(signature["signature"]),
    ):
        raise _Failure(
            "disproved",
            "WORK_SCOPE_COMMITMENT_SIGNATURE_INVALID",
            "Work v2 scope commitment signature does not verify",
            ("scope_commitment_signature.signature",),
        )
    recorded_through = _parse_time(
        cutoff["recorded_through"], field="declared_cutoff.recorded_through"
    )
    if signed_at != recorded_through:
        raise _Failure(
            "disproved",
            "WORK_SCOPE_COMMITMENT_SIGNATURE_INVALID",
            "scope signature time differs from the recorded-through cutoff",
            ("scope_commitment_signature.signed_at",),
        )
    return entries, "embedded signed key manifest anchored to pinned trust root"


def _signed_object(
    value: dict[str, Any],
    *,
    schema: str,
    entries: list[dict[str, Any]],
    key_field: str,
    time_field: str,
    purpose: str,
    code: str,
) -> dict[str, Any]:
    _validate_schema(value, schema, code=code)
    preimage = dict(value)
    declared_hash = preimage.pop("canonical_hash")
    signature = preimage.pop("signature")
    actual_hash = _digest(preimage)
    if declared_hash != actual_hash:
        raise _Failure(
            "disproved",
            code,
            f"{schema} canonical hash does not match",
            ("canonical_hash",),
        )
    signed_at = _parse_time(value[time_field], field=time_field)
    public_key = _key_for_time(
        entries,
        key_id=str(value[key_field]),
        purpose=purpose,
        signed_at=signed_at,
    )
    from keel_verifier import verifier as core

    if not core._verify_ed25519(
        public_key,
        actual_hash.removeprefix("sha256:").encode("utf-8"),
        str(signature),
    ):
        raise _Failure(
            "disproved",
            code,
            f"{schema} signature does not verify",
            ("signature",),
        )
    return value


def _authority_manifest_v2(
    document: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    entries: list[dict[str, Any]],
) -> tuple[ClaimVerdict, dict[str, Any]]:
    root_id = document["root_permit_id"]
    try:
        root = dict(document["root"])
        root_artifact = _resolve_reference(
            root["permit_artifact"], artifacts, field="root.permit_artifact"
        )
        material = _verify_permit(root_artifact, entries=entries)
        canonical = material.canonical_payload
        request = dict(root["work_request"])
        package = dict(root["work_package"])
        semantic = dict(root["semantic_binding"])
        _validate_schema(
            request,
            "work-request-v2.schema.json",
            code="WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID",
        )
        _validate_schema(
            package,
            "work-package-v2.schema.json",
            code="WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID",
        )
        _validate_schema(
            semantic,
            "permit-semantic-binding-v2.schema.json",
            code="WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID",
        )
        if (
            canonical.get("binding_version") != "v7"
            or canonical.get("permit_id") != root_id
            or canonical.get("project_id") != document["project_id"]
            or canonical.get("permit_chain_role") != "work_root"
            or canonical.get("parent_permit_id") is not None
            or canonical.get("action_name") != "work.authorize"
            or canonical.get("subject_id") != package["verified_root_principal_id"]
            or material.signed_decision != "allow"
        ):
            raise _Failure(
                "disproved",
                "WORK_AUTHORITY_SCOPE_MISMATCH",
                "signed root identity, principal, role, action, or decision conflicts",
                ("root.permit_artifact",),
            )
        attrs = material.resource_attributes
        if (
            attrs.get("work_request_v2") != request
            or attrs.get("work_package_v2") != package
            or _signed_semantic_binding(attrs) != semantic
        ):
            raise _Failure(
                "disproved",
                "WORK_AUTHORITY_SCOPE_MISMATCH",
                "Work v2 request, package, or semantic binding is not signed into the root",
                ("root", "root.permit_artifact"),
            )
        if (
            semantic.get("semantic_id") != "keel.context.work.v1"
            or semantic.get("trusted_source_kind") != "work_request_server_reconciled"
            or semantic.get("chain_role") != "work_root"
            or semantic.get("action_name") != "work.authorize"
        ):
            raise _Failure(
                "disproved",
                "WORK_AUTHORITY_SCOPE_MISMATCH",
                "root semantic binding is not the server-reconciled Work root semantic",
                ("root.semantic_binding",),
            )
        root_presentation = resolve_permit_presentation(semantic)
        if (
            root_presentation.get("resolution") != "trusted_signed_semantic"
            or root_presentation.get("customer_title") != "AI Permit-to-Work"
        ):
            raise _Failure(
                "disproved",
                "WORK_AUTHORITY_SCOPE_MISMATCH",
                "root Work semantic binding does not resolve against its pinned registry",
                ("root.semantic_binding",),
            )

        request_lanes = {
            str(lane["authority_id"]): dict(lane)
            for lane in request["requested_authorities"]
        }
        if len(request_lanes) != len(request["requested_authorities"]):
            raise _Failure(
                "disproved",
                "WORK_AUTHORITY_SET_HASH_MISMATCH",
                "requested Work authority identifiers are not unique",
                ("root.work_request.requested_authorities",),
            )
        if package["requested_authority_set_hash"] != _digest(
            request["requested_authorities"]
        ):
            raise _Failure(
                "disproved",
                "WORK_AUTHORITY_SET_HASH_MISMATCH",
                "requested authority-set hash does not match the signed request preimage",
                ("root.work_request", "root.work_package.requested_authority_set_hash"),
            )
        for field in (
            "declared_purpose",
            "job_reference",
            "existing_authority",
            "resource",
            "required_authority_ids",
        ):
            if request.get(field) != package.get(field):
                raise _Failure(
                    "disproved",
                    "WORK_AUTHORITY_SCOPE_MISMATCH",
                    f"Work request and package disagree on {field}",
                    ("root.work_request", "root.work_package"),
                )
        requested_pool = request.get("customer_value_pool")
        issued_pool = package.get("customer_value_pool")
        pool_conflicts = (requested_pool is None) != (issued_pool is None)
        if isinstance(requested_pool, Mapping) and isinstance(issued_pool, Mapping):
            pool_conflicts = pool_conflicts or (
                issued_pool.get("value_domain") != requested_pool.get("value_domain")
                or issued_pool.get("currency") != requested_pool.get("currency")
                or int(issued_pool.get("value_max_minor", 0))
                > int(requested_pool.get("value_max_minor", 0))
            )
        request_start = _parse_time(request["not_before"], field="request.not_before")
        request_end = _parse_time(request["expires_at"], field="request.expires_at")
        package_start = _parse_time(package["not_before"], field="package.not_before")
        package_end = _parse_time(package["expires_at"], field="package.expires_at")
        if pool_conflicts or not (
            request_start <= package_start < package_end <= request_end
        ):
            raise _Failure(
                "disproved",
                "WORK_AUTHORITY_SCOPE_MISMATCH",
                "issued Work value pool or time window exceeds the signed request",
                ("root.work_request", "root.work_package"),
            )

        authorities: dict[str, dict[str, Any]] = {}
        for index, raw in enumerate(document["authorities"]):
            authority = dict(raw)
            _validate_schema(
                authority,
                "work-authority-v2.schema.json",
                code="WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID",
            )
            authority_id = str(authority["authority_id"])
            if authority_id in authorities:
                raise _Failure(
                    "disproved",
                    "WORK_AUTHORITY_SET_HASH_MISMATCH",
                    "Work authority identifiers must be unique",
                    (f"authorities[{index}]",),
                )
            preimage = dict(authority)
            declared_hash = preimage.pop("authority_canonical_hash")
            if declared_hash != _digest(preimage):
                raise _Failure(
                    "disproved",
                    "WORK_AUTHORITY_SET_HASH_MISMATCH",
                    f"authority {authority_id} canonical hash differs",
                    (f"authorities[{index}]",),
                )
            lane = request_lanes.get(authority_id)
            if (
                lane is None
                or authority["project_id"] != document["project_id"]
                or authority["root_permit_id"] != root_id
                or authority["trusted_action"] != lane["requested_action"]
                or authority["max_uses"] > lane["max_uses"]
                or authority["value_binding"] != lane["requested_value_binding"]
                or authority["automatic_review_threshold_minor"]
                > lane["automatic_review_threshold_minor"]
                or authority["trusted_source_reference"]["source_id"]
                != authority["trusted_action"]
            ):
                raise _Failure(
                    "disproved",
                    "WORK_AUTHORITY_SCOPE_MISMATCH",
                    f"issued authority {authority_id} differs from its signed request",
                    (f"authorities[{index}]", "root.work_request"),
                )
            for field in ("currency", "recipient_digest", "purpose_digest"):
                if lane.get(field) != authority.get(field):
                    raise _Failure(
                        "disproved",
                        "WORK_AUTHORITY_SCOPE_MISMATCH",
                        f"issued authority {authority_id} changes requested {field}",
                        (f"authorities[{index}]", "root.work_request"),
                    )
            if (
                lane.get("value_max_minor") is None
            ) != (authority.get("value_max_minor") is None) or (
                lane.get("value_max_minor") is not None
                and int(authority["value_max_minor"])
                > int(lane["value_max_minor"])
            ):
                raise _Failure(
                    "disproved",
                    "WORK_AUTHORITY_SCOPE_MISMATCH",
                    f"issued authority {authority_id} exceeds requested value_max_minor",
                    (f"authorities[{index}]", "root.work_request"),
                )
            package_start = _parse_time(package["not_before"], field="package.not_before")
            package_end = _parse_time(package["expires_at"], field="package.expires_at")
            lane_start = _parse_time(authority["not_before"], field="authority.not_before")
            lane_end = _parse_time(authority["expires_at"], field="authority.expires_at")
            if not package_start <= lane_start < lane_end <= package_end:
                raise _Failure(
                    "disproved",
                    "WORK_AUTHORITY_SCOPE_MISMATCH",
                    f"authority {authority_id} exceeds the root time window",
                    (f"authorities[{index}]",),
                )
            authorities[authority_id] = authority

        issued_refs = sorted(
            [dict(reference) for reference in package["issued_authorities"]],
            key=lambda item: item["authority_id"],
        )
        expected_refs = sorted(
            [
                {
                    "authority_id": authority_id,
                    "authority_canonical_hash": authority["authority_canonical_hash"],
                }
                for authority_id, authority in authorities.items()
            ],
            key=lambda item: item["authority_id"],
        )
        excluded_ids = {str(item["authority_id"]) for item in package["excluded_authorities"]}
        if (
            issued_refs != expected_refs
            or package["issued_authority_set_hash"] != _digest(expected_refs)
            or set(authorities) | excluded_ids != set(request_lanes)
            or set(authorities) & excluded_ids
            or not set(package["required_authority_ids"]).issubset(authorities)
        ):
            raise _Failure(
                "disproved",
                "WORK_AUTHORITY_SET_HASH_MISMATCH",
                "requested, issued, excluded, and required authority sets conflict",
                ("root.work_request", "root.work_package", "authorities"),
            )

        delegations: dict[str, dict[str, Any]] = {}
        delegation_ids: set[str] = set()
        for delegation in package["authority_delegations"]:
            authority_id = str(delegation["authority_id"])
            delegation_id = str(delegation["delegation_id"])
            if (
                authority_id not in authorities
                or authority_id in delegations
                or delegation_id in delegation_ids
                or request_lanes[authority_id].get("delegated_principal_id")
                != delegation["delegated_principal_id"]
            ):
                raise _Failure(
                    "disproved",
                    "WORK_AUTHORITY_SCOPE_MISMATCH",
                    "signed Work delegation set is duplicate, unknown, or request-inconsistent",
                    ("root.work_package.authority_delegations",),
                )
            delegations[authority_id] = dict(delegation)
            delegation_ids.add(delegation_id)
        for authority_id, lane in request_lanes.items():
            if (lane.get("delegated_principal_id") is not None) != (
                authority_id in delegations
            ):
                raise _Failure(
                    "disproved",
                    "WORK_AUTHORITY_SCOPE_MISMATCH",
                    "requested and issued delegation populations differ",
                    ("root.work_request", "root.work_package.authority_delegations"),
                )

        monetary = [
            authority
            for authority in authorities.values()
            if authority["value_binding"] != "none"
        ]
        pool = package.get("customer_value_pool")
        if bool(monetary) != isinstance(pool, Mapping) or (
            monetary
            and any(authority["currency"] != pool["currency"] for authority in monetary)
        ):
            raise _Failure(
                "disproved",
                "WORK_VALUE_CONSERVATION_MISMATCH",
                "one signed customer-value pool does not cover every monetary lane",
                ("root.work_package.customer_value_pool", "authorities"),
            )
        root_snapshots = [
            item
            for item in document["policy_snapshots"]
            if item.get("phase") == "root_issuance" and item.get("permit_id") in {None, root_id}
        ]
        if len(root_snapshots) != 1 or any(
            root_snapshots[0].get(field) != package["policy_snapshot"].get(field)
            for field in ("policy_id", "policy_version", "policy_snapshot_hash")
        ):
            raise _Failure(
                "disproved",
                "WORK_AUTHORITY_SCOPE_MISMATCH",
                "root issuance Policy snapshot differs from the signed package",
                ("policy_snapshots", "root.work_package.policy_snapshot"),
            )
        return (
            _claim(
                WORK_CLAIMS_V2[0],
                subject_type="work_root",
                subject_id=root_id,
                verdict="supported",
                code="WORK_AUTHORITY_MANIFEST_SUPPORTED",
                message="signed Work request, package, authorities, pool, and delegations match",
                evidence=("root.permit_artifact", "root.work_request", "root.work_package", "authorities"),
            ),
            {
                "request": request,
                "package": package,
                "authorities": authorities,
                "delegations": delegations,
                "root_material": material,
            },
        )
    except _Failure as failure:
        return (
            _claim(
                WORK_CLAIMS_V2[0],
                subject_type="work_root",
                subject_id=root_id,
                verdict=failure.verdict,
                code=failure.code,
                message=failure.message,
                evidence=failure.evidence,
            ),
            {},
        )


def _provider_fact(
    reference: Any,
    *,
    artifacts: dict[str, dict[str, Any]],
    entries: list[dict[str, Any]],
    child_issued_at: datetime,
) -> dict[str, Any]:
    artifact = _resolve_reference(reference, artifacts, field="provider_value_fact")
    artifact_type = artifact.get("artifact_type")
    if artifact_type not in {
        "keel.provider_value_fact.v1",
        "keel.provider_value_fact.v2",
    }:
        raise _Failure(
            "unverifiable_scope",
            "WORK_VALUE_BINDING_UNVERIFIABLE",
            "provider-verified value references an unsupported fact type",
            ("provider_value_fact",),
        )
    payload = _mapping(
        artifact.get("payload"),
        field="provider_value_fact.payload",
        code="WORK_VALUE_BINDING_UNVERIFIABLE",
    )
    schema = (
        "provider-value-fact-v2.schema.json"
        if artifact_type == "keel.provider_value_fact.v2"
        else "provider-value-fact-v1.schema.json"
    )
    verified = _signed_object(
        payload,
        schema=schema,
        entries=entries,
        key_field="signing_key_id",
        time_field="observed_at",
        purpose="provider_fact_signing",
        code="WORK_VALUE_BINDING_UNVERIFIABLE",
    )
    if artifact_type == "keel.provider_value_fact.v1":
        return verified

    profile = _PROVIDER_VALUE_FACT_V2_PROFILES.get(
        str(verified.get("provider_contract_profile_id"))
    )
    if (
        profile is None
        or verified.get("fact_profile_id") != profile["fact_profile_id"]
        or verified.get("connector_type") != profile["connector_type"]
        or not isinstance(verified.get("provider_object_commitment"), str)
    ):
        raise _Failure(
            "unverifiable_scope" if profile is None else "disproved",
            "WORK_VALUE_BINDING_UNVERIFIABLE",
            "provider value fact v2 does not match a code-pinned provider contract profile",
            ("provider_value_fact.provider_contract_profile_id",),
        )
    observed_at = _parse_time(
        verified.get("observed_at"), field="provider_value_fact.observed_at"
    )
    valid_until = _parse_time(
        verified.get("valid_until"), field="provider_value_fact.valid_until"
    )
    validity_seconds = verified.get("validity_seconds")
    if (
        not isinstance(validity_seconds, int)
        or isinstance(validity_seconds, bool)
        or not 1 <= validity_seconds <= 900
        or valid_until - observed_at != timedelta(seconds=validity_seconds)
    ):
        raise _Failure(
            "disproved",
            "WORK_VALUE_BINDING_UNVERIFIABLE",
            "provider value fact v2 validity window is inconsistent or unbounded",
            ("provider_value_fact.valid_until", "provider_value_fact.validity_seconds"),
        )
    if not observed_at <= child_issued_at < valid_until:
        raise _Failure(
            "disproved",
            "WORK_VALUE_BINDING_UNVERIFIABLE",
            "child Permit issuance is outside the provider value fact v2 validity window",
            (
                "provider_value_fact.observed_at",
                "canonical.issued_at",
                "provider_value_fact.valid_until",
            ),
        )
    return verified


def _verified_lane_title(
    *,
    child: dict[str, Any],
    material: _PermitMaterial,
    authority: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    dispatch: dict[str, Any] | None,
) -> str:
    binding = child.get("semantic_binding")
    if binding is None:
        return _GENERIC_TITLE
    if _signed_semantic_binding(material.resource_attributes) != binding:
        raise _Failure(
            "disproved",
            "WORK_CHILD_BINDING_MISMATCH",
            "child semantic binding is not signed into the Permit",
            ("child.semantic_binding",),
        )
    _validate_schema(
        binding,
        "permit-semantic-binding-v2.schema.json",
        code="WORK_CHILD_BINDING_MISMATCH",
    )
    if (
        binding.get("semantic_id") != authority["semantic_id"]
        or binding.get("action_name") != authority["trusted_action"]
        or binding.get("operation") != authority["trusted_action"]
        or binding.get("chain_role") != "action_child"
    ):
        raise _Failure(
            "disproved",
            "WORK_CHILD_BINDING_MISMATCH",
            "child semantic identity, action, operation, or role differs from its lane",
            ("child.semantic_binding", "authorities"),
        )
    presentation = resolve_permit_presentation(binding)
    if presentation.get("resolution") != "trusted_signed_semantic":
        return _GENERIC_TITLE
    selector_path = _SELECTOR_FILES.get(str(binding.get("selector_registry_version")))
    if selector_path is None:
        return _GENERIC_TITLE
    selector, _selector_raw = _json_resource(selector_path)
    selector_entries = [
        entry
        for entry in selector["entries"]
        if entry.get("semantic_id") == binding.get("semantic_id")
    ]
    if len(selector_entries) != 1:
        return _GENERIC_TITLE
    expected_fact_profile = selector_entries[0].get("fact_profile_id")
    if expected_fact_profile is None:
        return str(presentation.get("customer_title") or _GENERIC_TITLE)
    if binding.get("fact_profile_id") != expected_fact_profile:
        return _GENERIC_TITLE

    fact_registry_path = _FACT_PROFILE_FILES.get(
        str(binding.get("fact_profile_registry_version"))
    )
    if fact_registry_path is None:
        return _GENERIC_TITLE
    fact_registry, fact_registry_raw = _json_resource(fact_registry_path)
    profiles = [
        profile
        for profile in fact_registry["profiles"]
        if profile.get("fact_profile_id") == expected_fact_profile
    ]
    if len(profiles) != 1:
        return _GENERIC_TITLE
    profile = profiles[0]
    facts_schema_path = str(profile["facts_schema"])
    _facts_schema, facts_schema_raw = _json_resource(
        f"data/permit_to_x/{facts_schema_path}"
    )
    if (
        binding.get("fact_profile_registry_version") != fact_registry.get("version")
        or binding.get("fact_profile_registry_digest")
        != _content_hash(fact_registry_raw)
        or binding.get("fact_profile_entry_digest") != _digest(profile)
        or binding.get("authorization_facts_schema_digest")
        != _content_hash(facts_schema_raw)
    ):
        return _GENERIC_TITLE

    facts: list[dict[str, Any]] = []
    for index, reference in enumerate(child["authorization_fact_artifacts"]):
        artifact = _resolve_reference(
            reference,
            artifacts,
            field=f"authorization_fact_artifacts[{index}]",
        )
        if isinstance(artifact.get("payload"), Mapping):
            facts.append(dict(artifact["payload"]))
    matched = [fact for fact in facts if _digest(fact) == binding["authorization_facts_digest"]]
    if len(matched) != 1:
        return _GENERIC_TITLE
    fact = matched[0]
    try:
        _validate_schema(
            fact,
            Path(facts_schema_path).name,
            code="WORK_CHILD_BINDING_MISMATCH",
        )
    except _Failure:
        return _GENERIC_TITLE
    if (
        binding["semantic_id"] == _CALL_SEMANTIC
        and binding.get("trusted_source_kind") == "telephony_origination_service"
    ):
        if (
            binding.get("fact_profile_id") != _CALL_FACT_PROFILE
            or fact.get("version") != _CALL_FACT_TYPE
        ):
            return _GENERIC_TITLE
        exercised = child["work_binding"]["exercised_by"]
        work_binding = child["work_binding"]
        if (
            fact.get("originating_principal_id") != exercised["verified_principal_id"]
            or fact.get("work_root_permit_id") != work_binding["root_permit_id"]
            or fact.get("work_authority_id") != work_binding["authority_id"]
            or fact.get("request_digest") != child["request_digest"]
            or fact.get("provider_wire_body_digest")
            != work_binding["provider_wire_body_digest"]
            or (dispatch is not None and fact.get("provider_wire_body_digest") != dispatch["provider_wire_body_digest"])
        ):
            return _GENERIC_TITLE
    gateway_profile = _ACTION_GATEWAY_PROFILES.get(str(binding["semantic_id"]))
    if gateway_profile is not None:
        expected_profile, expected_action = gateway_profile
        exercised = child["work_binding"]["exercised_by"]
        if (
            binding.get("fact_profile_id") != expected_profile
            or fact.get("version") != _ACTION_GATEWAY_FACT_TYPE
            or fact.get("fact_profile_id") != expected_profile
            or fact.get("action") != expected_action
            or fact.get("originating_principal_id")
            != exercised["verified_principal_id"]
            or fact.get("request_digest") != child["request_digest"]
            or fact.get("provider_wire_body_digest")
            != child["work_binding"]["provider_wire_body_digest"]
            or (
                dispatch is not None
                and fact.get("provider_wire_body_digest")
                != dispatch["provider_wire_body_digest"]
            )
        ):
            return _GENERIC_TITLE
    telephony_gateway_profile = _TELEPHONY_GATEWAY_PROFILES.get(
        str(binding["semantic_id"])
    )
    if (
        telephony_gateway_profile is not None
        and binding.get("trusted_source_kind") == "telephony_gateway_service"
    ):
        expected_profile, expected_version, expected_action = (
            telephony_gateway_profile
        )
        exercised = child["work_binding"]["exercised_by"]
        work_binding = child["work_binding"]
        if (
            binding.get("trusted_source_kind") != "telephony_gateway_service"
            or binding.get("fact_profile_id") != expected_profile
            or fact.get("version") != expected_version
            or fact.get("fact_profile_id") != expected_profile
            or fact.get("action") != expected_action
            or fact.get("connector_type") != "keel_gateway_https"
            or fact.get("gateway_protocol_version") != "keel.action_gateway.v1"
            or fact.get("originating_principal_id")
            != exercised["verified_principal_id"]
            or fact.get("work_root_permit_id") != work_binding["root_permit_id"]
            or fact.get("work_authority_id") != work_binding["authority_id"]
            or fact.get("request_digest") != child["request_digest"]
            or fact.get("provider_wire_body_digest")
            != work_binding["provider_wire_body_digest"]
            or (
                dispatch is not None
                and fact.get("provider_wire_body_digest")
                != dispatch["provider_wire_body_digest"]
            )
        ):
            return _GENERIC_TITLE
    return str(presentation.get("customer_title") or _GENERIC_TITLE)


def _child_containment_v2(
    document: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    entries: list[dict[str, Any]],
    context: dict[str, Any],
) -> tuple[ClaimVerdict, dict[str, Any]]:
    if not context:
        return (
            _claim(
                WORK_CLAIMS_V2[1],
                subject_type="work_child_population",
                subject_id=document["root_permit_id"],
                verdict="insufficient_evidence",
                code="WORK_REQUIRED_AUTHORITY_MISSING",
                message="child containment requires a supported Work v2 manifest",
                evidence=(WORK_CLAIMS_V2[0],),
            ),
            {},
        )
    package = context["package"]
    authorities = context["authorities"]
    delegations = context["delegations"]
    subjects: list[VerdictSubject] = []
    children: dict[str, dict[str, Any]] = {}
    use_counts = {authority_id: 0 for authority_id in authorities}
    child_review_refs: list[dict[str, Any]] = []
    child_provider_refs: list[dict[str, Any]] = []
    for index, raw in enumerate(document["child_permits"]):
        child = dict(raw)
        child_id = str(child.get("permit_id") or "") or None
        required = True
        try:
            artifact = _resolve_reference(
                child["permit_artifact"],
                artifacts,
                field=f"child_permits[{index}].permit_artifact",
            )
            material = _verify_permit(artifact, entries=entries)
            canonical = material.canonical_payload
            attrs = material.resource_attributes
            binding = dict(child["work_binding"])
            _validate_schema(
                binding,
                "work-binding-v2.schema.json",
                code="WORK_CHILD_BINDING_MISMATCH",
            )
            authority_id = str(child["work_authority_id"])
            authority = authorities.get(authority_id)
            if authority is None:
                raise _Failure(
                    "disproved",
                    "WORK_CHILD_BINDING_MISMATCH",
                    f"child {child_id} names an unknown Work authority",
                    (f"child_permits[{index}].work_authority_id",),
                )
            exercised = dict(binding["exercised_by"])
            delegation = delegations.get(authority_id)
            root_principal = package["verified_root_principal_id"]
            if delegation is None:
                expected_identity = {
                    "verified_principal_id": root_principal,
                    "root_principal_id": root_principal,
                    "delegated_principal_id": None,
                    "delegation_id": None,
                }
            else:
                expected_identity = {
                    "verified_principal_id": delegation["delegated_principal_id"],
                    "root_principal_id": root_principal,
                    "delegated_principal_id": delegation["delegated_principal_id"],
                    "delegation_id": delegation["delegation_id"],
                }
            if any(exercised.get(key) != value for key, value in expected_identity.items()):
                raise _Failure(
                    "disproved",
                    "WORK_CHILD_OUTSIDE_AUTHORITY",
                    f"child {child_id} principal does not match its signed delegation",
                    (f"child_permits[{index}].work_binding.exercised_by",),
                )
            if (
                binding["root_permit_id"] != document["root_permit_id"]
                or binding["authority_id"] != authority_id
                or binding["authority_canonical_hash"]
                != authority["authority_canonical_hash"]
                or binding["root_manifest_hash"] != _digest(package)
                or attrs.get("work_binding_v2") != binding
            ):
                raise _Failure(
                    "disproved",
                    "WORK_CHILD_BINDING_MISMATCH",
                    f"child {child_id} Work binding differs from its signed root or lane",
                    (f"child_permits[{index}].work_binding",),
                )
            if (
                canonical.get("binding_version") != "v7"
                or canonical.get("permit_id") != child_id
                or canonical.get("project_id") != document["project_id"]
                or canonical.get("parent_permit_id") != document["root_permit_id"]
                or canonical.get("permit_chain_role") != "action_child"
                or canonical.get("action_name") != authority["trusted_action"]
                or canonical.get("subject_id") != exercised["verified_principal_id"]
                or _norm_sha(canonical.get("request_fingerprint"))
                != child["request_digest"]
            ):
                raise _Failure(
                    "disproved",
                    "WORK_CHILD_OUTSIDE_AUTHORITY",
                    f"child {child_id} signed identity, action, principal, or request differs",
                    (f"child_permits[{index}]",),
                )
            resource = attrs.get("work_resource_scope_v1")
            if not isinstance(resource, Mapping) or (
                resource.get("version") != "keel.work_resource_scope.v1"
                or {
                    "type": resource.get("type"),
                    "id": resource.get("id"),
                    "digest": resource.get("digest"),
                }
                != authority["resource_scope"]
                or attrs.get("work_resource_digest") != resource.get("digest")
            ):
                raise _Failure(
                    "disproved",
                    "WORK_CHILD_OUTSIDE_AUTHORITY",
                    f"child {child_id} resource is outside its signed Work lane",
                    ("work_resource_scope_v1", "authorities"),
                )
            issued_at = _parse_time(
                canonical.get("issued_at"), field="canonical.issued_at"
            )
            if not (
                _parse_time(authority["not_before"], field="authority.not_before")
                <= issued_at
                < _parse_time(authority["expires_at"], field="authority.expires_at")
            ):
                raise _Failure(
                    "disproved",
                    "WORK_CHILD_OUTSIDE_AUTHORITY",
                    f"child {child_id} was issued outside the lane window",
                    ("canonical.issued_at", "authorities"),
                )
            value_request = dict(binding["value_request"])
            value_binding = authority["value_binding"]
            if value_request["value_binding"] != value_binding:
                raise _Failure(
                    "disproved",
                    "WORK_CHILD_OUTSIDE_AUTHORITY",
                    f"child {child_id} changes its lane value-binding mode",
                    ("work_binding.value_request", "authorities"),
                )
            provider_fact: dict[str, Any] | None = None
            if value_binding == "none":
                if set(value_request) != {"version", "value_binding"}:
                    raise _Failure(
                        "disproved",
                        "WORK_CHILD_OUTSIDE_AUTHORITY",
                        f"non-monetary child {child_id} carries caller-declared value",
                        ("work_binding.value_request",),
                    )
                if child.get("provider_value_fact") is not None:
                    raise _Failure(
                        "disproved",
                        "WORK_VALUE_BINDING_UNVERIFIABLE",
                        f"non-monetary child {child_id} carries a provider value fact",
                        ("provider_value_fact",),
                    )
            elif value_binding == "declared_bounded":
                amount = value_request.get("declared_amount_minor")
                if (
                    not isinstance(amount, int)
                    or isinstance(amount, bool)
                    or not 0 < amount <= authority["value_max_minor"]
                    or value_request.get("currency") != authority["currency"]
                    or child.get("provider_value_fact") is not None
                ):
                    raise _Failure(
                        "disproved",
                        "WORK_CHILD_OUTSIDE_AUTHORITY",
                        f"child {child_id} declared value is not exact or within its lane",
                        ("work_binding.value_request", "authorities"),
                    )
            else:
                if set(value_request) != {"version", "value_binding"}:
                    raise _Failure(
                        "disproved",
                        "WORK_VALUE_BINDING_UNVERIFIABLE",
                        "provider_verified value may not come from caller-declared fields",
                        ("work_binding.value_request",),
                    )
                if child.get("provider_value_fact") is None:
                    raise _Failure(
                        "unverifiable_scope",
                        "WORK_VALUE_BINDING_UNVERIFIABLE",
                        f"child {child_id} lacks a trusted provider value fact",
                        ("provider_value_fact",),
                    )
                provider_fact = _provider_fact(
                    child["provider_value_fact"],
                    artifacts=artifacts,
                    entries=entries,
                    child_issued_at=issued_at,
                )
                if (
                    provider_fact["project_id"] != document["project_id"]
                    or provider_fact["root_permit_id"] != document["root_permit_id"]
                    or provider_fact["authority_id"] != authority_id
                    or provider_fact["child_permit_id"] != child_id
                    or provider_fact["request_digest"] != child["request_digest"]
                    or provider_fact["provider_wire_body_digest"]
                    != binding["provider_wire_body_digest"]
                    or provider_fact["currency"] != authority["currency"]
                    or provider_fact["amount_minor"] > authority["value_max_minor"]
                ):
                    raise _Failure(
                        "disproved",
                        "WORK_VALUE_BINDING_UNVERIFIABLE",
                        f"child {child_id} provider fact is not exact or within its lane",
                        ("provider_value_fact", "authorities"),
                    )
                child_provider_refs.append(dict(child["provider_value_fact"]))

            signed_decision = material.signed_decision
            final_decision = str(child["decision"])
            if child.get("review_transition") is None:
                if final_decision != signed_decision:
                    raise _Failure(
                        "disproved",
                        "WORK_CHILD_BINDING_MISMATCH",
                        f"child {child_id} decision differs without a review transition",
                        (f"child_permits[{index}].decision",),
                    )
            else:
                if signed_decision != "challenge" or final_decision not in {"allow", "deny"}:
                    raise _Failure(
                        "disproved",
                        "WORK_REVIEW_TRANSITION_INVALID",
                        "review transition must resolve one signed challenge to allow or deny",
                        (f"child_permits[{index}].review_transition",),
                    )
                child_review_refs.append(dict(child["review_transition"]))
            if signed_decision != "deny":
                use_counts[authority_id] += 1
            if child_id in children:
                raise _Failure(
                    "disproved",
                    "WORK_CHILD_BINDING_MISMATCH",
                    "child Permit identifiers must be unique",
                    (f"child_permits[{index}].permit_id",),
                )
            children[str(child_id)] = {
                "child": child,
                "material": material,
                "authority": authority,
                "provider_fact": provider_fact,
            }
            subjects.append(
                VerdictSubject(
                    type="work_child",
                    id=child_id,
                    verdict="supported",
                    reason_code="WORK_CHILD_CONTAINMENT_SUPPORTED",
                    message="exact signed child request, principal, value mode, and lane match",
                    evidence=[f"child_permits[{index}]", "root.work_package", "authorities"],
                    required=required,
                )
            )
        except _Failure as failure:
            subjects.append(
                VerdictSubject(
                    type="work_child",
                    id=child_id,
                    verdict=failure.verdict,
                    reason_code=failure.code,
                    message=failure.message,
                    evidence=list(failure.evidence),
                    required=required,
                )
            )
    for authority_id, count in use_counts.items():
        if count > authorities[authority_id]["max_uses"]:
            subjects.append(
                VerdictSubject(
                    type="work_authority_use_limit",
                    id=authority_id,
                    verdict="disproved",
                    reason_code="WORK_CHILD_OUTSIDE_AUTHORITY",
                    message="admitted child count exceeds the signed lane use limit",
                    evidence=["child_permits", "authorities"],
                    required=True,
                )
            )
    if sorted(child_review_refs, key=_digest) != sorted(
        [dict(item) for item in document["review_transitions"]], key=_digest
    ):
        subjects.append(
            VerdictSubject(
                type="work_review_population",
                id=document["root_permit_id"],
                verdict="disproved",
                reason_code="WORK_SCOPE_POPULATION_MISMATCH",
                message="child review references differ from the scoped review population",
                evidence=["child_permits", "review_transitions"],
                required=True,
            )
        )
    if sorted(child_provider_refs, key=_digest) != sorted(
        [dict(item) for item in document["provider_value_facts"]], key=_digest
    ):
        subjects.append(
            VerdictSubject(
                type="provider_value_population",
                id=document["root_permit_id"],
                verdict="disproved",
                reason_code="WORK_SCOPE_POPULATION_MISMATCH",
                message="child provider-fact references differ from the scoped provider population",
                evidence=["child_permits", "provider_value_facts"],
                required=True,
            )
        )
    if not subjects:
        subjects.append(
            VerdictSubject(
                type="work_child_population",
                id=document["root_permit_id"],
                verdict="supported",
                reason_code="WORK_CHILD_POPULATION_EMPTY",
                message="the signed Work child population is empty",
                evidence=["scope_commitment.populations.child_permits"],
            )
        )
    return _claim_from_subjects(WORK_CLAIMS_V2[1], subjects), {
        **context,
        "children": children,
    }


def _exact_review_v2(
    document: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    entries: list[dict[str, Any]],
    child_context: dict[str, Any],
) -> tuple[ClaimVerdict, dict[str, dict[str, Any]]]:
    if not child_context:
        return (
            _claim(
                WORK_CLAIMS_V2[4],
                subject_type="work_review_population",
                subject_id=document["root_permit_id"],
                verdict="insufficient_evidence",
                code="WORK_CHILD_BINDING_MISMATCH",
                message="exact review requires supported child containment",
                evidence=(WORK_CLAIMS_V2[1],),
            ),
            {},
        )
    subjects: list[VerdictSubject] = []
    reviews: dict[str, dict[str, Any]] = {}
    for child_id, item in child_context["children"].items():
        child = item["child"]
        reference = child.get("review_transition")
        if reference is None:
            continue
        try:
            artifact = _resolve_reference(reference, artifacts, field="review_transition")
            if artifact.get("artifact_type") != "keel.work_review_transition.v1":
                raise _Failure(
                    "unverifiable_scope",
                    "WORK_REVIEW_TRANSITION_INVALID",
                    "review transition artifact type is unsupported",
                    ("review_transition",),
                )
            transition = _mapping(
                artifact["payload"],
                field="review_transition.payload",
                code="WORK_REVIEW_TRANSITION_INVALID",
            )
            _signed_object(
                transition,
                schema="work-review-transition-v1.schema.json",
                entries=entries,
                key_field="binding_key_id",
                time_field="decided_at",
                purpose="permit_binding_signing",
                code="WORK_REVIEW_TRANSITION_INVALID",
            )
            binding = child["work_binding"]
            if (
                transition["permit_id"] != child_id
                or transition["project_id"] != document["project_id"]
                or transition["root_permit_id"] != document["root_permit_id"]
                or transition["authority_id"] != child["work_authority_id"]
                or transition["frozen_request_digest"] != child["request_digest"]
                or transition["exact_request_commitment"]
                != binding["exact_request_commitment"]
                or transition.get("provider_wire_body_digest")
                != binding["provider_wire_body_digest"]
                or transition["final_decision"] != child["decision"]
            ):
                raise _Failure(
                    "disproved",
                    "WORK_REVIEW_TRANSITION_INVALID",
                    "review transition differs from the exact frozen child or terminal decision",
                    ("review_transition", "child_permits"),
                )
            if transition["human_outcome"] == "approve":
                snapshots = [
                    snapshot
                    for snapshot in document["policy_snapshots"]
                    if snapshot.get("phase") == "review_resume"
                    and snapshot.get("permit_id") == child_id
                ]
                if len(snapshots) != 1:
                    raise _Failure(
                        "insufficient_evidence",
                        "WORK_REVIEW_TRANSITION_INVALID",
                        "approved review lacks one current review-resume Policy snapshot",
                        ("policy_snapshots",),
                    )
            if transition["final_decision"] == "deny" and child.get(
                "dispatch_boundary_evidence"
            ) is not None:
                raise _Failure(
                    "disproved",
                    "WORK_REVIEW_TRANSITION_INVALID",
                    "a final denial after review carries forbidden dispatch evidence",
                    ("dispatch_boundary_evidence",),
                )
            reviews[child_id] = transition
            subjects.append(
                VerdictSubject(
                    type="work_review_transition",
                    id=str(transition["transition_id"]),
                    verdict="supported",
                    reason_code="WORK_EXACT_REVIEW_SUPPORTED",
                    message=(
                        f"human {transition['human_outcome']} was bound to the frozen request; "
                        f"Keel's final decision was {transition['final_decision']}"
                    ),
                    evidence=["review_transition", f"child_permits.{child_id}"],
                    required=True,
                )
            )
        except _Failure as failure:
            subjects.append(
                VerdictSubject(
                    type="work_review_transition",
                    id=child_id,
                    verdict=failure.verdict,
                    reason_code=failure.code,
                    message=failure.message,
                    evidence=list(failure.evidence),
                    required=True,
                )
            )
    if not subjects:
        subjects.append(
            VerdictSubject(
                type="work_review_population",
                id=document["root_permit_id"],
                verdict="supported",
                reason_code="WORK_REVIEW_POPULATION_EMPTY",
                message="no reviewed Work child is present",
                evidence=["scope_commitment.populations.review_transitions"],
            )
        )
    return _claim_from_subjects(WORK_CLAIMS_V2[4], subjects), reviews


def _active_reservation_at(
    document: dict[str, Any], *, child_id: str, boundary_time: datetime
) -> tuple[str, int] | None:
    reservations: dict[str, int] = {}
    for event in sorted(document["value_events"], key=lambda item: item["root_sequence"]):
        if event["child_permit_id"] != child_id:
            continue
        if _parse_time(event["occurred_at"], field="value_event.occurred_at") > boundary_time:
            continue
        reservation_id = str(event["reservation_id"])
        amount = int(event["amount_minor"])
        event_type = event["event_type"]
        if event_type == "reserved":
            reservations[reservation_id] = reservations.get(reservation_id, 0) + amount
        elif event_type in {"released", "reconciled_release", "consumed", "reconciled_consume"}:
            reservations[reservation_id] = reservations.get(reservation_id, 0) - amount
    active = [(reservation_id, amount) for reservation_id, amount in reservations.items() if amount > 0]
    return active[0] if len(active) == 1 else None


def _revoked_at_boundary(
    document: dict[str, Any],
    *,
    child: dict[str, Any],
    boundary_time: datetime,
) -> str | None:
    binding = child["work_binding"]
    exercised = binding["exercised_by"]
    for event in document["lifecycle_events"]:
        occurred = _parse_time(event["occurred_at"], field="lifecycle_event.occurred_at")
        if occurred > boundary_time:
            continue
        event_type = event["event_type"]
        if event_type == "work.closed":
            return "root"
        if event_type == "permit.revoked" and event.get("permit_id") in {
            document["root_permit_id"],
            child["permit_id"],
        }:
            return "root_or_child"
        if (
            event_type == "work.authority.revoked"
            and event.get("authority_id") == child["work_authority_id"]
        ):
            return "authority"
        if (
            event_type == "work.delegation.revoked"
            and event.get("delegation_id") == exercised.get("delegation_id")
        ):
            return "delegation"
        if (
            event_type == "principal.revoked"
            and event.get("principal_id") == exercised["verified_principal_id"]
        ):
            return "principal"
        if (
            event_type == "credential.revoked"
            and event.get("authenticated_credential_id_digest")
            == exercised["authenticated_credential_id_digest"]
        ):
            return "credential"
    return None


def _execution_boundary_v2(
    document: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    entries: list[dict[str, Any]],
    child_claim: ClaimVerdict,
    review_claim: ClaimVerdict,
    child_context: dict[str, Any],
    reviews: dict[str, dict[str, Any]],
) -> tuple[ClaimVerdict, dict[str, dict[str, Any]]]:
    if (
        child_claim.aggregate_verdict != "supported"
        or review_claim.aggregate_verdict != "supported"
    ):
        return (
            _claim(
                WORK_CLAIMS_V2[2],
                subject_type="dispatch_boundary_population",
                subject_id=document["root_permit_id"],
                verdict="insufficient_evidence",
                code="WORK_CHILD_BINDING_MISMATCH",
                message="dispatch adjudication requires supported child and review evidence",
                evidence=(WORK_CLAIMS_V2[1], WORK_CLAIMS_V2[4]),
            ),
            {},
        )
    subjects: list[VerdictSubject] = []
    boundaries: dict[str, dict[str, Any]] = {}
    idempotency_digests: set[str] = set()
    cutoff = _parse_time(
        document["declared_cutoff"]["recorded_through"], field="declared_cutoff.recorded_through"
    )
    package = child_context["package"]
    for child_id, item in child_context["children"].items():
        child = item["child"]
        reference = child.get("dispatch_boundary_evidence")
        required = child["decision"] == "allow"
        if reference is None:
            subjects.append(
                VerdictSubject(
                    type="dispatch_boundary",
                    id=child_id,
                    verdict="insufficient_evidence" if required else "supported",
                    reason_code=(
                        "WORK_DISPATCH_BOUNDARY_MISSING"
                        if required
                        else "WORK_NON_EXECUTABLE_CHILD_NO_DISPATCH"
                    ),
                    message=(
                        "allowed child lacks a signed pre-effect dispatch boundary"
                        if required
                        else "non-allowed child correctly carries no dispatch boundary"
                    ),
                    evidence=["dispatch_boundary_evidence"],
                    required=required,
                )
            )
            continue
        try:
            if not required:
                raise _Failure(
                    "disproved",
                    "WORK_DISPATCH_BOUNDARY_INVALID",
                    "a denied or unresolved child carries forbidden dispatch evidence",
                    ("dispatch_boundary_evidence",),
                )
            artifact = _resolve_reference(reference, artifacts, field="dispatch_boundary_evidence")
            if artifact.get("artifact_type") != "keel.work_dispatch_boundary.v2":
                raise _Failure(
                    "unverifiable_scope",
                    "WORK_DISPATCH_BOUNDARY_INVALID",
                    "dispatch boundary artifact type is unsupported",
                    ("dispatch_boundary_evidence",),
                )
            boundary = _mapping(
                artifact["payload"],
                field="dispatch_boundary.payload",
                code="WORK_DISPATCH_BOUNDARY_INVALID",
            )
            _signed_object(
                boundary,
                schema="work-dispatch-boundary-v2.schema.json",
                entries=entries,
                key_field="binding_key_id",
                time_field="occurred_at",
                purpose="permit_binding_signing",
                code="WORK_DISPATCH_BOUNDARY_INVALID",
            )
            binding = child["work_binding"]
            exercised = binding["exercised_by"]
            if (
                boundary["project_id"] != document["project_id"]
                or boundary["root_permit_id"] != document["root_permit_id"]
                or boundary["authority_id"] != child["work_authority_id"]
                or boundary["child_permit_id"] != child_id
                or boundary["request_digest"] != child["request_digest"]
                or boundary["provider_wire_body_digest"]
                != binding["provider_wire_body_digest"]
                or boundary["authenticated_credential_id_digest"]
                != exercised["authenticated_credential_id_digest"]
            ):
                raise _Failure(
                    "disproved",
                    "WORK_DISPATCH_BOUNDARY_INVALID",
                    "dispatch boundary differs from the exact child, body, or credential",
                    ("dispatch_boundary_evidence", "child_permits"),
                )
            occurred = _parse_time(boundary["occurred_at"], field="dispatch.occurred_at")
            if occurred > cutoff or not (
                _parse_time(package["not_before"], field="package.not_before")
                <= occurred
                < _parse_time(package["expires_at"], field="package.expires_at")
                and _parse_time(item["authority"]["not_before"], field="authority.not_before")
                <= occurred
                < _parse_time(item["authority"]["expires_at"], field="authority.expires_at")
            ):
                raise _Failure(
                    "disproved",
                    "WORK_DISPATCH_BOUNDARY_INVALID",
                    "dispatch boundary is outside the signed window or declared scope cutoff",
                    ("dispatch.occurred_at",),
                )
            revoked = _revoked_at_boundary(document, child=child, boundary_time=occurred)
            if revoked is not None:
                raise _Failure(
                    "disproved",
                    "WORK_DISPATCH_LIVENESS_REVOKED",
                    f"scoped lifecycle evidence revokes the {revoked} before dispatch",
                    ("lifecycle_events", "dispatch_boundary_evidence"),
                )
            if child_id in reviews and reviews[child_id]["human_outcome"] != "approve":
                raise _Failure(
                    "disproved",
                    "WORK_DISPATCH_BOUNDARY_INVALID",
                    "dispatch follows a review that was not human-approved",
                    ("review_transition", "dispatch_boundary_evidence"),
                )
            snapshots = [
                snapshot
                for snapshot in document["policy_snapshots"]
                if snapshot.get("phase") == "dispatch"
                and snapshot.get("permit_id") == child_id
            ]
            if len(snapshots) != 1 or any(
                snapshots[0].get(field) != boundary["execution_policy"].get(field)
                for field in ("policy_id", "policy_version", "policy_snapshot_hash")
            ):
                raise _Failure(
                    "disproved",
                    "WORK_DISPATCH_BOUNDARY_INVALID",
                    "dispatch Policy snapshot differs from the signed boundary",
                    ("policy_snapshots", "dispatch.execution_policy"),
                )
            if item["authority"]["value_binding"] == "none":
                if _active_reservation_at(document, child_id=child_id, boundary_time=occurred):
                    raise _Failure(
                        "disproved",
                        "WORK_VALUE_CONSERVATION_MISMATCH",
                        "non-monetary child has an active customer-value reservation",
                        ("value_events",),
                    )
            else:
                active = _active_reservation_at(
                    document, child_id=child_id, boundary_time=occurred
                )
                expected_amount = (
                    item["provider_fact"]["amount_minor"]
                    if item["provider_fact"] is not None
                    else binding["value_request"]["declared_amount_minor"]
                )
                if active is None or active[1] != expected_amount:
                    raise _Failure(
                        "disproved",
                        "WORK_DISPATCH_RESERVATION_INVALID",
                        "dispatch lacks the exact active root customer-value reservation",
                        ("value_events", "dispatch_boundary_evidence"),
                    )
            idem = str(boundary["idempotency_key_digest"])
            if idem in idempotency_digests:
                raise _Failure(
                    "disproved",
                    "WORK_DISPATCH_BOUNDARY_INVALID",
                    "dispatch idempotency digest is reused across children",
                    ("dispatch_boundary_evidence",),
                )
            idempotency_digests.add(idem)
            boundaries[child_id] = boundary
            subjects.append(
                VerdictSubject(
                    type="dispatch_boundary",
                    id=child_id,
                    verdict="supported",
                    reason_code="WORK_EXECUTION_BOUNDARY_SUPPORTED",
                    message="signed pre-effect boundary matches live root, lane, worker, credential, request, body, Policy, and reservation",
                    evidence=["dispatch_boundary_evidence", "lifecycle_events", "value_events"],
                    required=True,
                )
            )
        except _Failure as failure:
            subjects.append(
                VerdictSubject(
                    type="dispatch_boundary",
                    id=child_id,
                    verdict=failure.verdict,
                    reason_code=failure.code,
                    message=failure.message,
                    evidence=list(failure.evidence),
                    required=True,
                )
            )
    if not subjects:
        subjects.append(
            VerdictSubject(
                type="dispatch_boundary_population",
                id=document["root_permit_id"],
                verdict="supported",
                reason_code="WORK_DISPATCH_POPULATION_EMPTY",
                message="no executable child exists in this Work evidence scope",
                evidence=["child_permits"],
            )
        )
    return _claim_from_subjects(WORK_CLAIMS_V2[2], subjects), boundaries


def _work_value_v2(
    document: dict[str, Any],
    child_context: dict[str, Any],
) -> tuple[ClaimVerdict, dict[str, Any] | None]:
    if not child_context:
        return (
            _claim(
                WORK_CLAIMS_V2[3],
                subject_type="work_value_population",
                subject_id=document["root_permit_id"],
                verdict="insufficient_evidence",
                code="WORK_REQUIRED_AUTHORITY_MISSING",
                message="root value reconstruction requires a supported Work manifest",
                evidence=(WORK_CLAIMS_V2[0],),
            ),
            None,
        )
    try:
        package = child_context["package"]
        authorities = child_context["authorities"]
        children = child_context["children"]
        pool = package.get("customer_value_pool")
        events = sorted(document["value_events"], key=lambda item: item["root_sequence"])
        if pool is None:
            if events:
                raise _Failure(
                    "disproved",
                    "WORK_VALUE_CONSERVATION_MISMATCH",
                    "customer-value events exist although the root has no monetary pool",
                    ("value_events", "root.work_package"),
                )
            return (
                _claim(
                    WORK_CLAIMS_V2[3],
                    subject_type="work_root_value_pool",
                    subject_id=document["root_permit_id"],
                    verdict="supported",
                    code="WORK_VALUE_CONSERVATION_SUPPORTED",
                    message="non-monetary Work root has no customer-value pool or events",
                    evidence=("root.work_package", "value_events"),
                ),
                None,
            )

        reserved_by_id: dict[str, int] = {}
        reservation_child: dict[str, str] = {}
        reservation_authority: dict[str, str] = {}
        reservation_amount: dict[str, int] = {}
        authority_reservations: dict[str, set[str]] = {
            authority_id: set() for authority_id in authorities
        }
        reserved_total = 0
        consumed_total = 0
        consumed_by_authority = {authority_id: 0 for authority_id in authorities}
        reserved_by_authority = {authority_id: 0 for authority_id in authorities}
        previous_hash: str | None = None
        seen_events: set[str] = set()
        seen_idempotency: set[str] = set()
        cutoff = _parse_time(
            document["declared_cutoff"]["recorded_through"],
            field="declared_cutoff.recorded_through",
        )
        for expected_sequence, event_raw in enumerate(events, start=1):
            event = dict(event_raw)
            _validate_schema(
                event,
                "work-value-event-v2.schema.json",
                code="WORK_VALUE_EVENT_SEQUENCE_INVALID",
            )
            preimage = dict(event)
            declared_hash = preimage.pop("event_canonical_hash")
            if declared_hash != _digest(preimage):
                raise _Failure(
                    "disproved",
                    "WORK_VALUE_EVENT_SEQUENCE_INVALID",
                    "Work value event canonical hash does not match",
                    (f"value_events[{expected_sequence - 1}]",),
                )
            if (
                event["root_sequence"] != expected_sequence
                or event["previous_root_event_hash"] != previous_hash
                or event["event_id"] in seen_events
                or event["idempotency_key_digest"] in seen_idempotency
                or event["project_id"] != document["project_id"]
                or event["root_permit_id"] != document["root_permit_id"]
                or event["currency"] != pool["currency"]
                or _parse_time(event["occurred_at"], field="value_event.occurred_at")
                > cutoff
            ):
                raise _Failure(
                    "disproved",
                    "WORK_VALUE_EVENT_SEQUENCE_INVALID",
                    "root value event sequence, identity, scope, currency, or cutoff differs",
                    (f"value_events[{expected_sequence - 1}]",),
                )
            authority_id = str(event["authority_id"])
            child_id = str(event["child_permit_id"])
            reservation_id = str(event["reservation_id"])
            authority = authorities.get(authority_id)
            child_item = children.get(child_id)
            if (
                authority is None
                or child_item is None
                or child_item["child"]["work_authority_id"] != authority_id
                or authority["value_binding"] == "none"
            ):
                raise _Failure(
                    "disproved",
                    "WORK_VALUE_CONSERVATION_MISMATCH",
                    "value event names an unknown child/lane or a non-monetary lane",
                    (f"value_events[{expected_sequence - 1}]",),
                )
            amount = int(event["amount_minor"])
            expected_amount = (
                child_item["provider_fact"]["amount_minor"]
                if child_item["provider_fact"] is not None
                else child_item["child"]["work_binding"]["value_request"][
                    "declared_amount_minor"
                ]
            )
            if event["event_type"] == "reserved":
                if reservation_id in reservation_amount or amount != expected_amount:
                    raise _Failure(
                        "disproved",
                        "WORK_VALUE_CONSERVATION_MISMATCH",
                        "reservation is duplicate or differs from the exact child value",
                        (f"value_events[{expected_sequence - 1}]", "child_permits"),
                    )
                reservation_amount[reservation_id] = amount
                reservation_child[reservation_id] = child_id
                reservation_authority[reservation_id] = authority_id
                reserved_by_id[reservation_id] = amount
                authority_reservations[authority_id].add(reservation_id)
                reserved_total += amount
                reserved_by_authority[authority_id] += amount
            else:
                if (
                    reservation_id not in reservation_amount
                    or reservation_child[reservation_id] != child_id
                    or reservation_authority[reservation_id] != authority_id
                    or reserved_by_id[reservation_id] < amount
                ):
                    raise _Failure(
                        "disproved",
                        "WORK_VALUE_EVENT_SEQUENCE_INVALID",
                        "value transition does not consume an exact live reservation",
                        (f"value_events[{expected_sequence - 1}]",),
                    )
                reserved_by_id[reservation_id] -= amount
                reserved_total -= amount
                reserved_by_authority[authority_id] -= amount
                if event["event_type"] in {"consumed", "reconciled_consume"}:
                    consumed_total += amount
                    consumed_by_authority[authority_id] += amount
            if authority["value_binding"] == "provider_verified" and event[
                "event_type"
            ] in {"reserved", "consumed", "reconciled_consume"}:
                reference = event.get("trusted_value_fact")
                child_reference = child_item["child"].get("provider_value_fact")
                if reference is None or reference != child_reference:
                    raise _Failure(
                        "unverifiable_scope",
                        "WORK_VALUE_BINDING_UNVERIFIABLE",
                        "provider-verified value transition lacks its exact supported fact",
                        (f"value_events[{expected_sequence - 1}].trusted_value_fact",),
                    )
            if (
                reserved_total < 0
                or consumed_total < 0
                or reserved_total + consumed_total > pool["value_max_minor"]
                or reserved_by_authority[authority_id]
                + consumed_by_authority[authority_id]
                > authority["value_max_minor"]
                or len(authority_reservations[authority_id]) > authority["max_uses"]
            ):
                raise _Failure(
                    "disproved",
                    "WORK_VALUE_CONSERVATION_MISMATCH",
                    "value events exceed the signed root pool, lane cap, or use limit",
                    ("value_events", "authorities", "root.work_package.customer_value_pool"),
                )
            expected_state = {
                "value_domain": "customer_economic_value",
                "value_max_minor": pool["value_max_minor"],
                "currency": pool["currency"],
                "reserved_value_minor": reserved_total,
                "consumed_value_minor": consumed_total,
                "remaining_value_minor": pool["value_max_minor"]
                - reserved_total
                - consumed_total,
            }
            if event["root_value_state_after"] != expected_state:
                raise _Failure(
                    "disproved",
                    "WORK_VALUE_CONSERVATION_MISMATCH",
                    "asserted root value state differs from reconstructed totals",
                    (f"value_events[{expected_sequence - 1}].root_value_state_after",),
                )
            previous_hash = declared_hash
            seen_events.add(str(event["event_id"]))
            seen_idempotency.add(str(event["idempotency_key_digest"]))
        final_state = {
            "value_domain": "customer_economic_value",
            "value_max_minor": pool["value_max_minor"],
            "currency": pool["currency"],
            "reserved_value_minor": reserved_total,
            "consumed_value_minor": consumed_total,
            "remaining_value_minor": pool["value_max_minor"]
            - reserved_total
            - consumed_total,
        }
        return (
            _claim(
                WORK_CLAIMS_V2[3],
                subject_type="work_root_value_pool",
                subject_id=document["root_permit_id"],
                verdict="supported",
                code="WORK_VALUE_CONSERVATION_SUPPORTED",
                message=(
                    "one root-wide hash-linked customer-value ledger conserves the "
                    f"signed {pool['currency']} {pool['value_max_minor']} minor-unit pool"
                ),
                evidence=("scope_commitment", "value_events", "root.work_package.customer_value_pool"),
            ),
            final_state,
        )
    except _Failure as failure:
        return (
            _claim(
                WORK_CLAIMS_V2[3],
                subject_type="work_root_value_pool",
                subject_id=document["root_permit_id"],
                verdict=failure.verdict,
                code=failure.code,
                message=failure.message,
                evidence=failure.evidence,
            ),
            None,
        )


def _money_text(currency: str, amount_minor: int) -> str:
    if currency == "USD":
        return f"USD {amount_minor / 100:.2f}"
    return f"{amount_minor} minor units in {currency}"


def _derive_summary_v2(
    document: dict[str, Any],
    child_context: dict[str, Any],
    boundaries: dict[str, dict[str, Any]],
    value_state: dict[str, Any] | None,
) -> dict[str, Any]:
    package = child_context["package"]
    cutoff = _parse_time(
        document["declared_cutoff"]["recorded_through"], field="declared_cutoff.recorded_through"
    )
    state_label = "active"
    if any(event["event_type"] == "work.closed" for event in document["lifecycle_events"]):
        state_label = "ended"
    elif any(
        event["event_type"] == "permit.revoked"
        and event.get("permit_id") == document["root_permit_id"]
        for event in document["lifecycle_events"]
    ):
        state_label = "revoked"
    elif _parse_time(package["expires_at"], field="package.expires_at") <= cutoff:
        state_label = "expired"

    lanes: list[dict[str, Any]] = []
    for authority_id, authority in sorted(child_context["authorities"].items()):
        delegation = child_context["delegations"].get(authority_id)
        principal_id = (
            delegation["delegated_principal_id"]
            if delegation is not None
            else package["verified_root_principal_id"]
        )
        lane_children = [
            item
            for item in child_context["children"].values()
            if item["child"]["work_authority_id"] == authority_id
        ]
        decisions = {decision: 0 for decision in ("allow", "deny", "challenge")}
        titles: set[str] = set()
        for item in lane_children:
            child = item["child"]
            decisions[child["decision"]] += 1
            titles.add(
                _verified_lane_title(
                    child=child,
                    material=item["material"],
                    authority=authority,
                    artifacts=child_context["artifacts"],
                    dispatch=boundaries.get(child["permit_id"]),
                )
            )
        permit_title = next(iter(titles)) if len(titles) == 1 else _GENERIC_TITLE
        lanes.append(
            {
                "authority_id": authority_id,
                "action": authority["trusted_action"],
                "permit_title": permit_title,
                "principal_id": principal_id,
                "value_binding": authority["value_binding"],
                "max_uses": authority["max_uses"],
                "child_decisions": decisions,
            }
        )
    if value_state is None:
        value_sentence = "No customer economic value pool is present."
    else:
        value_sentence = (
            "Customer economic value is limited to "
            f"{_money_text(value_state['currency'], value_state['value_max_minor'])}; "
            f"{_money_text(value_state['currency'], value_state['reserved_value_minor'])} is reserved, "
            f"{_money_text(value_state['currency'], value_state['consumed_value_minor'])} is consumed, and "
            f"{_money_text(value_state['currency'], value_state['remaining_value_minor'])} remains."
        )
    summary = {
        "version": "keel.work_summary.v1",
        "derivation": "verifier_from_verified_work_fields",
        "title": "AI Permit-to-Work",
        "state_label": state_label,
        "text": (
            f"Keel authorized a bounded Work with {len(lanes)} lanes. {value_sentence} "
            "AI and model compute spend is governed separately. This evidence does not "
            "establish provider completion, settlement, call content, or agreement."
        ),
        "root_permit_id": document["root_permit_id"],
        "customer_value_pool": value_state,
        "ai_compute_budget_boundary": "separate_keel_authority_not_in_work_customer_value_pool",
        "lanes": lanes,
        "evidence_boundary": {
            "establishes": [
                "bounded heterogeneous Work authority",
                "signed worker delegation and child containment",
                "root customer-value conservation through the declared cutoff",
            ],
            "does_not_establish": [
                "provider completion",
                "financial settlement",
                "call answer, conversation content, or agreement",
                "AI or model compute spend",
            ],
        },
    }
    _validate_schema(
        summary,
        "work-summary-v1.schema.json",
        code="WORK_SUMMARY_MISMATCH",
    )
    return summary


def _append_summary_subject(
    claim: ClaimVerdict,
    *,
    document: dict[str, Any],
    derived: dict[str, Any] | None,
    failure: _Failure | None = None,
) -> ClaimVerdict:
    subjects = list(claim.subjects)
    if failure is not None:
        subjects.append(
            VerdictSubject(
                type="work_summary",
                id=document["root_permit_id"],
                verdict=failure.verdict,
                reason_code=failure.code,
                message=failure.message,
                evidence=list(failure.evidence),
                required=True,
            )
        )
    elif derived is not None:
        matches = document["summary"] == derived
        subjects.append(
            VerdictSubject(
                type="work_summary",
                id=document["root_permit_id"],
                verdict="supported" if matches else "disproved",
                reason_code=(
                    "WORK_SUMMARY_DERIVATION_SUPPORTED"
                    if matches
                    else "WORK_SUMMARY_MISMATCH"
                ),
                message=(
                    "exported Work summary exactly matches verifier-derived fields"
                    if matches
                    else "exported Work summary differs from verifier-derived verified fields"
                ),
                evidence=["summary", "root.work_package", "authorities", "child_permits", "value_events"],
                required=True,
            )
        )
    return _claim_from_subjects(claim.name, subjects)


def verify_work_chain_pack_v2(
    pack: str | Path | Mapping[str, Any],
    *,
    trust_root: str | Path | None = None,
) -> VerificationReport:
    """Verify one strict, self-contained ``work-chain.v2`` pack offline."""

    artifact: dict[str, Any] = {"kind": "work_chain_pack"}
    try:
        document, artifact = _load_document(pack)
        root_id = document.get("root_permit_id") if isinstance(document.get("root_permit_id"), str) else None
        _validate_top_level_v2(document)
        artifacts = _artifact_index(document)
        _validate_references_v2(document, artifacts)
        entries, trust_source = _scope_signature_v2(
            document, artifacts, trust_root=trust_root
        )
    except _Failure as failure:
        artifact.update(
            {
                "project_id": locals().get("document", {}).get("project_id")
                if isinstance(locals().get("document"), dict)
                else None,
                "root_permit_id": locals().get("root_id"),
            }
        )
        return _report_v2(
            artifact=artifact,
            claims=_all_claim_failure_v2(failure, locals().get("root_id")),
        )

    artifact.update(
        {
            "project_id": document["project_id"],
            "root_permit_id": document["root_permit_id"],
            "recorded_through": document["declared_cutoff"]["recorded_through"],
            "checkpoint_id": document["declared_cutoff"]["checkpoint_id"],
            "trust_source": trust_source,
            "scope_claim": document["scope_commitment"]["claim"],
            "runtime_recording_claim": "not_asserted",
        }
    )
    authority_claim, context = _authority_manifest_v2(document, artifacts, entries)
    child_claim, child_context = _child_containment_v2(
        document, artifacts, entries, context
    )
    if child_context:
        child_context["artifacts"] = artifacts
    review_claim, reviews = _exact_review_v2(
        document, artifacts, entries, child_context
    )
    boundary_claim, boundaries = _execution_boundary_v2(
        document,
        artifacts,
        entries,
        child_claim,
        review_claim,
        child_context,
        reviews,
    )
    value_claim, value_state = _work_value_v2(document, child_context)
    derived: dict[str, Any] | None = None
    summary_failure: _Failure | None = None
    if all(
        claim.aggregate_verdict == "supported"
        for claim in (authority_claim, child_claim, review_claim, boundary_claim, value_claim)
    ):
        try:
            derived = _derive_summary_v2(
                document, child_context, boundaries, value_state
            )
            artifact["summary"] = derived
        except _Failure as failure:
            summary_failure = failure
    authority_claim = _append_summary_subject(
        authority_claim,
        document=document,
        derived=derived,
        failure=summary_failure,
    )
    return _report_v2(
        artifact=artifact,
        claims=[
            authority_claim,
            child_claim,
            boundary_claim,
            value_claim,
            review_claim,
        ],
        diagnostics=[
            "VALID means the evidence is internally and cryptographically supported; it does not mean every child was allowed.",
            "The customer-value pool is distinct from AI/model compute authority and accounting.",
            "The pre-effect boundary does not establish provider acceptance, completion, settlement, call content, or agreement.",
        ],
    )


__all__ = ["WORK_CLAIMS_V2", "verify_work_chain_pack_v2"]
