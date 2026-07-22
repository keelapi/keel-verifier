"""Independent adjudication for ``work-chain.v1`` evidence packs.

The module deliberately consumes only the downloaded JSON pack, the bundled
semantic contracts, and a pinned public-key trust root.  It never calls Keel
or assumes that an API response was truthful merely because it was returned by
the producer.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any

import rfc8785

from keel_verifier.semantics import (
    CLAIM_REGISTRY_HASH,
    RELEASED_ARTIFACT_HASHES,
    WORK_AUTHORITY_MANIFEST_ID,
    WORK_CHILD_CONTAINMENT_ID,
    WORK_EXECUTION_BOUNDARY_ID,
    WORK_PAYMENT_AUTHORITY_COMPARATOR_ID,
    WORK_VALUE_CONSERVATION_ID,
)
from keel_verifier.verdicts import (
    ClaimVerdict,
    VerificationReport,
    VerdictSubject,
    verdict_value,
)


WORK_CLAIMS = (
    "permit.work_authority_manifest.v1",
    "permit.work_child_containment.v1",
    "permit_chain.execution_authorized_at_boundary.v1",
    "permit.work_value_conservation.v1",
)
POPULATIONS = {
    "work_authorities": ("authorities", "permit_work_authorities"),
    "child_permits": ("child_permits", "permits"),
    "work_value_events": ("value_events", "permit_work_value_events"),
    "lifecycle_events": ("lifecycle_events", "governance_events"),
}
REQUIRED_LIVENESS = {
    "root_live",
    "authority_live",
    "child_live",
    "reservation_live",
    "current_policy_epoch_matched",
    "platform_safety_floor_passed",
}
SUPPORTED_SETTLEMENT_ARTIFACTS = {
    "x402_settlement_proof",
    "rail.settlement_reconciliation.v1",
}
_CURRENCY_CLASS = {
    "USD_FIAT": "USD",
    "EUR_FIAT": "EUR",
    "GBP_FIAT": "GBP",
    "USDC_STABLE": "USDC",
    "USDT_STABLE": "USDT",
    "ETH_NATIVE": "ETH",
    "BTC_NATIVE": "BTC",
}


@dataclass(frozen=True)
class _Failure(Exception):
    verdict: str
    code: str
    message: str
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class _PermitMaterial:
    canonical_payload: dict[str, Any]
    resource_attributes: dict[str, Any]
    receipt: dict[str, Any]
    signed_decision: str


def _digest(value: Any) -> str:
    return f"sha256:{hashlib.sha256(rfc8785.dumps(value)).hexdigest()}"


def _content_hash(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _parse_time(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise _Failure(
            "insufficient_evidence",
            "WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID",
            f"{field} must be an ISO-8601 timestamp",
            (field,),
        )
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise _Failure(
            "disproved",
            "WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID",
            f"{field} is not an ISO-8601 timestamp",
            (field,),
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _mapping(value: Any, *, field: str, code: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _Failure(
            "insufficient_evidence",
            code,
            f"{field} must be an object",
            (field,),
        )
    return dict(value)


def _list(value: Any, *, field: str, code: str) -> list[Any]:
    if not isinstance(value, list):
        raise _Failure(
            "insufficient_evidence",
            code,
            f"{field} must be an array",
            (field,),
        )
    return value


def _normalized_digest(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    raw = value.strip().lower()
    if raw.startswith("sha256:"):
        raw = raw[7:]
    if len(raw) != 64 or any(char not in "0123456789abcdef" for char in raw):
        return None
    return f"sha256:{raw}"


def _claim(
    name: str,
    *,
    subject_type: str,
    subject_id: str | None,
    verdict: str,
    code: str,
    message: str,
    evidence: tuple[str, ...] | list[str] = (),
    required: bool = True,
) -> ClaimVerdict:
    return ClaimVerdict(
        name=name,
        subjects=[
            VerdictSubject(
                type=subject_type,
                id=subject_id,
                verdict=verdict_value(verdict),
                reason_code=code,
                message=message,
                evidence=list(evidence),
                required=required,
            )
        ],
    )


def _claim_from_subjects(name: str, subjects: list[VerdictSubject]) -> ClaimVerdict:
    return ClaimVerdict(name=name, subjects=subjects)


def _all_claim_failure(failure: _Failure, root_id: str | None) -> list[ClaimVerdict]:
    subject_types = (
        "work_root",
        "work_child_population",
        "dispatch_boundary_population",
        "work_value_population",
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
        for name, subject_type in zip(WORK_CLAIMS, subject_types, strict=True)
    ]


def _work_semantics() -> dict[str, Any]:
    ids = (
        WORK_AUTHORITY_MANIFEST_ID,
        WORK_CHILD_CONTAINMENT_ID,
        WORK_PAYMENT_AUTHORITY_COMPARATOR_ID,
        WORK_EXECUTION_BOUNDARY_ID,
        WORK_VALUE_CONSERVATION_ID,
    )
    return {
        "mode": "work_chain_pinned",
        "profile_id": "work-chain.v1",
        "profile_hash": _digest(
            {artifact_id: RELEASED_ARTIFACT_HASHES[artifact_id] for artifact_id in ids}
        ),
        "claim_registry_hash": CLAIM_REGISTRY_HASH,
        "pins": [
            {"id": artifact_id, "hash": RELEASED_ARTIFACT_HASHES[artifact_id]}
            for artifact_id in ids
        ],
    }


def _report(
    *,
    document: dict[str, Any],
    artifact: dict[str, Any],
    claims: list[ClaimVerdict],
    diagnostics: list[str] | None = None,
) -> VerificationReport:
    verdicts = [claim.aggregate_verdict for claim in claims]
    ok = bool(verdicts) and all(value == "supported" for value in verdicts)
    exit_code = 0 if ok else 2 if "unverifiable_scope" in verdicts else 1
    first_failure = next(
        (
            subject
            for claim in claims
            for subject in claim.subjects
            if subject.required and subject.verdict != "supported"
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
        semantics=_work_semantics(),
    )


def _load_document(
    pack: str | Path | Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    if isinstance(pack, Mapping):
        document = dict(pack)
        raw = rfc8785.dumps(document)
        return document, {
            "kind": "work_chain_pack",
            "input_hash": _content_hash(raw),
        }
    path = Path(pack)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise _Failure(
            "insufficient_evidence",
            "WORK_SCOPE_COMMITMENT_MISSING",
            f"could not read Work pack: {exc}",
            (str(path),),
        ) from exc
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise _Failure(
            "disproved",
            "WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID",
            f"Work pack is not valid JSON: {exc}",
            (str(path),),
        ) from exc
    if not isinstance(parsed, dict):
        raise _Failure(
            "disproved",
            "WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID",
            "Work pack must be a JSON object",
            (str(path),),
        )
    return parsed, {
        "kind": "work_chain_pack",
        "path": str(path),
        "input_hash": _content_hash(raw),
    }


def _validate_top_level(document: dict[str, Any]) -> None:
    if (
        document.get("version") != "keel.work_chain_pack.v1"
        or document.get("profile") != "work-chain.v1"
    ):
        raise _Failure(
            "unverifiable_scope",
            "WORK_VERSION_UNSUPPORTED",
            "only keel.work_chain_pack.v1 with profile work-chain.v1 is supported",
            ("version", "profile"),
        )
    requested = document.get("requested_claims")
    if requested != list(WORK_CLAIMS):
        raise _Failure(
            "unverifiable_scope",
            "WORK_VERSION_UNSUPPORTED",
            "requested_claims must be the canonical four-claim Work profile",
            ("requested_claims",),
        )
    for field in ("project_id", "root_permit_id"):
        if not isinstance(document.get(field), str) or not document[field]:
            raise _Failure(
                "insufficient_evidence",
                "WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID",
                f"{field} is required",
                (field,),
            )
    _mapping(
        document.get("root"),
        field="root",
        code="WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID",
    )
    for field in (
        "authorities",
        "child_permits",
        "value_events",
        "lifecycle_events",
        "policy_snapshots",
        "evidence_artifacts",
        "artifacts",
    ):
        _list(
            document.get(field),
            field=field,
            code="WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID",
        )


def _artifact_index(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for position, raw in enumerate(document["artifacts"]):
        artifact = _mapping(
            raw,
            field=f"artifacts[{position}]",
            code="WORK_ARTIFACT_INTEGRITY_INVALID",
        )
        artifact_id = artifact.get("artifact_id")
        if not isinstance(artifact_id, str) or not artifact_id or artifact_id in index:
            raise _Failure(
                "disproved",
                "WORK_ARTIFACT_INTEGRITY_INVALID",
                "embedded Work artifact identifiers must be unique non-empty strings",
                (f"artifacts[{position}].artifact_id",),
            )
        if not isinstance(artifact.get("artifact_type"), str):
            raise _Failure(
                "disproved",
                "WORK_ARTIFACT_INTEGRITY_INVALID",
                f"artifact {artifact_id} has no artifact_type",
                (artifact_id,),
            )
        try:
            actual_digest = _digest(artifact.get("payload"))
        except Exception as exc:
            raise _Failure(
                "disproved",
                "WORK_ARTIFACT_INTEGRITY_INVALID",
                f"artifact {artifact_id} payload is not canonical JSON: {exc}",
                (artifact_id,),
            ) from exc
        if artifact.get("artifact_digest") != actual_digest:
            raise _Failure(
                "disproved",
                "WORK_ARTIFACT_INTEGRITY_INVALID",
                f"artifact {artifact_id} digest does not match its embedded payload",
                (artifact_id,),
            )
        index[artifact_id] = artifact
    if not index:
        raise _Failure(
            "insufficient_evidence",
            "WORK_ARTIFACT_INTEGRITY_INVALID",
            "the Work pack contains no embedded artifacts",
            ("artifacts",),
        )
    return index


def _resolve_reference(
    reference: Any,
    artifacts: dict[str, dict[str, Any]],
    *,
    field: str,
    require_type: bool = True,
) -> dict[str, Any]:
    ref = _mapping(
        reference,
        field=field,
        code="WORK_ARTIFACT_INTEGRITY_INVALID",
    )
    artifact_id = ref.get("artifact_id")
    artifact = artifacts.get(str(artifact_id))
    if artifact is None:
        raise _Failure(
            "disproved",
            "WORK_ARTIFACT_INTEGRITY_INVALID",
            f"{field} does not resolve to an embedded artifact",
            (field,),
        )
    if artifact.get("artifact_digest") != ref.get("artifact_digest"):
        raise _Failure(
            "disproved",
            "WORK_ARTIFACT_INTEGRITY_INVALID",
            f"{field} digest does not match its embedded artifact",
            (field,),
        )
    if require_type and artifact.get("artifact_type") != ref.get("artifact_type"):
        raise _Failure(
            "disproved",
            "WORK_ARTIFACT_INTEGRITY_INVALID",
            f"{field} type does not match its embedded artifact",
            (field,),
        )
    return artifact


def _validate_references(document: dict[str, Any], artifacts: dict[str, dict[str, Any]]) -> None:
    root = document["root"]
    _resolve_reference(root.get("permit_artifact"), artifacts, field="root.permit_artifact")
    for index, child_raw in enumerate(document["child_permits"]):
        child = _mapping(
            child_raw,
            field=f"child_permits[{index}]",
            code="WORK_ARTIFACT_INTEGRITY_INVALID",
        )
        _resolve_reference(
            child.get("permit_artifact"),
            artifacts,
            field=f"child_permits[{index}].permit_artifact",
        )
        if child.get("dispatch_boundary_evidence") is not None:
            _resolve_reference(
                child["dispatch_boundary_evidence"],
                artifacts,
                field=f"child_permits[{index}].dispatch_boundary_evidence",
            )
    for index, reference in enumerate(document["evidence_artifacts"]):
        _resolve_reference(
            reference,
            artifacts,
            field=f"evidence_artifacts[{index}]",
        )
    for index, event_raw in enumerate(document["value_events"]):
        event = _mapping(
            event_raw,
            field=f"value_events[{index}]",
            code="WORK_ARTIFACT_INTEGRITY_INVALID",
        )
        if event.get("evidence_reference") is not None:
            _resolve_reference(
                event["evidence_reference"],
                artifacts,
                field=f"value_events[{index}].evidence_reference",
                require_type=False,
            )
    for index, event_raw in enumerate(document["lifecycle_events"]):
        event = _mapping(
            event_raw,
            field=f"lifecycle_events[{index}]",
            code="WORK_ARTIFACT_INTEGRITY_INVALID",
        )
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
                f"lifecycle_events[{index}] does not resolve to one governance artifact",
                (f"lifecycle_events[{index}]",),
            )
        payload = _mapping(
            matches[0].get("payload"),
            field=f"lifecycle_events[{index}].artifact.payload",
            code="WORK_ARTIFACT_INTEGRITY_INVALID",
        )
        public_type = event.get("event_type")
        artifact_type = payload.get("event_type")
        if public_type == "work.closed":
            inner = payload.get("payload")
            valid_type = artifact_type == "permit.closed" and isinstance(inner, Mapping)
        else:
            valid_type = artifact_type == public_type
        if payload.get("event_id") != event.get("event_id") or not valid_type:
            raise _Failure(
                "disproved",
                "WORK_ARTIFACT_INTEGRITY_INVALID",
                f"lifecycle_events[{index}] identity conflicts with its artifact",
                (f"lifecycle_events[{index}]",),
            )


def _verify_manifest_signature(
    manifest: dict[str, Any], *, trust_root: str | Path | None
) -> list[dict[str, Any]]:
    # Import lazily: verifier.py auto-detects Work packs and therefore imports
    # this module only after its reusable trust helpers are initialized.
    from keel_verifier import verifier as core

    if manifest.get("manifest_version") != "keel.public_key_manifest.v1":
        raise _Failure(
            "insufficient_evidence",
            "WORK_SCOPE_COMMITMENT_SIGNATURE_INVALID",
            "embedded key manifest must use keel.public_key_manifest.v1",
            ("evidence_artifacts.key_manifest",),
        )
    signature = manifest.get("manifest_signature")
    if not isinstance(signature, Mapping):
        raise _Failure(
            "insufficient_evidence",
            "WORK_SCOPE_COMMITMENT_SIGNATURE_INVALID",
            "embedded key manifest is not signed",
            ("evidence_artifacts.key_manifest.manifest_signature",),
        )
    try:
        payload_bytes = core._manifest_signature_payload_bytes(manifest)
    except Exception as exc:
        raise _Failure(
            "disproved",
            "WORK_SCOPE_COMMITMENT_SIGNATURE_INVALID",
            f"embedded key manifest signed fields are malformed: {exc}",
            ("evidence_artifacts.key_manifest",),
        ) from exc
    actual_hash = _content_hash(payload_bytes)
    if (
        signature.get("signature_type") != "ed25519.content_hash.v1"
        or signature.get("purpose") != "export_signing"
        or signature.get("content_hash") != actual_hash
    ):
        raise _Failure(
            "disproved",
            "WORK_SCOPE_COMMITMENT_SIGNATURE_INVALID",
            "embedded key manifest signature envelope is invalid",
            ("evidence_artifacts.key_manifest.manifest_signature",),
        )
    root_source = str(trust_root or core.DEFAULT_TRUST_ROOT_PATH)
    try:
        root_entries = core._load_key_manifest(root_source)
    except Exception as exc:
        raise _Failure(
            "insufficient_evidence",
            "WORK_SCOPE_COMMITMENT_SIGNATURE_INVALID",
            f"Work trust root could not be loaded: {exc}",
            (root_source,),
        ) from exc
    signer_id = signature.get("key_id")
    matches = [
        entry
        for entry in root_entries
        if entry.get("key_id") == signer_id and entry.get("purpose") == "export_signing"
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("public_key"), str):
        raise _Failure(
            "insufficient_evidence",
            "WORK_SCOPE_COMMITMENT_SIGNATURE_INVALID",
            "embedded key manifest signer is not uniquely pinned by the trust root",
            (root_source,),
        )
    public_key = str(matches[0]["public_key"])
    if core._public_key_fingerprint(public_key) != signer_id:
        raise _Failure(
            "disproved",
            "WORK_SCOPE_COMMITMENT_SIGNATURE_INVALID",
            "embedded key manifest signer id does not match its public key",
            (root_source,),
        )
    if not core._verify_ed25519(
        public_key,
        actual_hash.encode("utf-8"),
        str(signature.get("signature") or ""),
    ):
        raise _Failure(
            "disproved",
            "WORK_SCOPE_COMMITMENT_SIGNATURE_INVALID",
            "embedded key manifest signature does not verify",
            ("evidence_artifacts.key_manifest.manifest_signature",),
        )
    return core._normalize_key_manifest_entries(manifest)


def _key_for_time(
    entries: list[dict[str, Any]],
    *,
    key_id: str,
    purpose: str,
    signed_at: datetime,
) -> str:
    from keel_verifier import verifier as core

    matches = [
        entry
        for entry in entries
        if entry.get("key_id") == key_id and entry.get("purpose") == purpose
    ]
    matches = core._filter_by_active_window(matches, signed_at)
    matches = [entry for entry in matches if core._entry_not_terminal_at(entry, signed_at)]
    if len(matches) != 1 or not isinstance(matches[0].get("public_key"), str):
        raise _Failure(
            "insufficient_evidence",
            "WORK_SCOPE_COMMITMENT_SIGNATURE_INVALID",
            f"no unique trusted {purpose} key {key_id!r} was active at signing time",
            ("evidence_artifacts.key_manifest",),
        )
    return str(matches[0]["public_key"])


def _scope_signature(
    document: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    *,
    trust_root: str | Path | None,
) -> tuple[list[dict[str, Any]], str]:
    scope = _mapping(
        document.get("scope_commitment"),
        field="scope_commitment",
        code="WORK_SCOPE_COMMITMENT_MISSING",
    )
    if (
        scope.get("version") != "keel.work_scope_commitment.v1"
        or scope.get("claim")
        != "scope-faithful slice of Keel-recorded work evidence through the declared cutoff"
        or scope.get("runtime_recording_claim") != "not_asserted"
    ):
        raise _Failure(
            "unverifiable_scope",
            "WORK_VERSION_UNSUPPORTED",
            "scope commitment version or claim language is unsupported",
            ("scope_commitment",),
        )
    commitments = _list(
        scope.get("populations"),
        field="scope_commitment.populations",
        code="WORK_SCOPE_COMMITMENT_MISSING",
    )
    by_population: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(commitments):
        commitment = _mapping(
            raw,
            field=f"scope_commitment.populations[{index}]",
            code="WORK_SCOPE_COMMITMENT_MISSING",
        )
        name = commitment.get("population")
        if not isinstance(name, str) or name in by_population:
            raise _Failure(
                "disproved",
                "WORK_SCOPE_POPULATION_MISMATCH",
                "scope commitment populations must be unique",
                ("scope_commitment.populations",),
            )
        by_population[name] = commitment
    if set(by_population) != set(POPULATIONS):
        raise _Failure(
            "insufficient_evidence",
            "WORK_SCOPE_COMMITMENT_MISSING",
            "scope commitment must name all four Work populations exactly once",
            ("scope_commitment.populations",),
        )
    for population, (document_field, source_relation) in POPULATIONS.items():
        values = document[document_field]
        commitment = by_population[population]
        if (
            commitment.get("source_relation") != source_relation
            or commitment.get("included_count") != len(values)
            or commitment.get("included_set_hash") != _digest(values)
        ):
            raise _Failure(
                "disproved",
                "WORK_SCOPE_POPULATION_MISMATCH",
                f"{population} does not match its signed population commitment",
                (f"scope_commitment.populations.{population}", document_field),
            )

    signature = _mapping(
        document.get("scope_commitment_signature"),
        field="scope_commitment_signature",
        code="WORK_SCOPE_COMMITMENT_MISSING",
    )
    if (
        signature.get("version") != "keel.work_scope_commitment_signature.v1"
        or signature.get("signature_profile") != "keel.canonical_json.payload.v1"
    ):
        raise _Failure(
            "unverifiable_scope",
            "WORK_VERSION_UNSUPPORTED",
            "Work scope signature version is unsupported",
            ("scope_commitment_signature",),
        )
    cutoff = _mapping(
        document.get("declared_cutoff"),
        field="declared_cutoff",
        code="WORK_SCOPE_COMMITMENT_MISSING",
    )
    key_id = signature.get("binding_key_id")
    if not isinstance(key_id, str) or not key_id:
        raise _Failure(
            "insufficient_evidence",
            "WORK_SCOPE_COMMITMENT_MISSING",
            "scope signature binding_key_id is absent",
            ("scope_commitment_signature.binding_key_id",),
        )
    payload = {
        "version": "keel.work_scope_commitment_signature_payload.v1",
        "project_id": document["project_id"],
        "root_permit_id": document["root_permit_id"],
        "export_source": document.get("export_source"),
        "recorded_through": cutoff.get("recorded_through"),
        "checkpoint_id": cutoff.get("checkpoint_id"),
        "scope_commitment": scope,
        "binding_key_id": key_id,
    }
    expected_hash = _digest(payload)
    if (
        signature.get("canonical_hash") != expected_hash
        or cutoff.get("checkpoint_digest") != expected_hash
    ):
        raise _Failure(
            "disproved",
            "WORK_SCOPE_COMMITMENT_SIGNATURE_INVALID",
            "Work scope checkpoint digest does not match the exact signature payload",
            ("scope_commitment_signature.canonical_hash", "declared_cutoff.checkpoint_digest"),
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
            "Work pack must embed exactly one public key manifest",
            ("artifacts",),
        )
    key_manifest = _mapping(
        key_artifacts[0].get("payload"),
        field="artifacts.key_manifest.payload",
        code="WORK_SCOPE_COMMITMENT_MISSING",
    )
    entries = _verify_manifest_signature(key_manifest, trust_root=trust_root)
    signed_at = _parse_time(
        signature.get("signed_at"), field="scope_commitment_signature.signed_at"
    )
    public_key = _key_for_time(
        entries,
        key_id=key_id,
        purpose="permit_binding_signing",
        signed_at=signed_at,
    )
    from keel_verifier import verifier as core

    if core._binding_key_id_from_public_key(public_key) != key_id:
        raise _Failure(
            "disproved",
            "WORK_SCOPE_COMMITMENT_SIGNATURE_INVALID",
            "scope signature key id does not match the trusted public key",
            ("scope_commitment_signature.binding_key_id",),
        )
    if not core._verify_ed25519(
        public_key,
        expected_hash.removeprefix("sha256:").encode("utf-8"),
        str(signature.get("signature") or ""),
    ):
        raise _Failure(
            "disproved",
            "WORK_SCOPE_COMMITMENT_SIGNATURE_INVALID",
            "Work scope commitment signature does not verify",
            ("scope_commitment_signature.signature",),
        )
    recorded_through = _parse_time(
        cutoff.get("recorded_through"), field="declared_cutoff.recorded_through"
    )
    if signed_at != recorded_through:
        raise _Failure(
            "disproved",
            "WORK_SCOPE_COMMITMENT_SIGNATURE_INVALID",
            "scope signature time must equal the declared recorded-through cutoff",
            ("scope_commitment_signature.signed_at", "declared_cutoff.recorded_through"),
        )
    return entries, "embedded signed key manifest anchored to pinned trust root"


def _verify_permit(
    artifact: dict[str, Any],
    *,
    entries: list[dict[str, Any]],
) -> _PermitMaterial:
    from keel_verifier import verifier as core
    from keel_verifier.canonical.permit_binding import (
        canonical_resource_attributes_payload,
    )

    payload = _mapping(
        artifact.get("payload"),
        field=f"artifact {artifact.get('artifact_id')}.payload",
        code="WORK_ARTIFACT_INTEGRITY_INVALID",
    )
    if payload.get("version") != "keel.work_permit_evidence.v1":
        raise _Failure(
            "insufficient_evidence",
            "WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID",
            "Work Permit artifact lacks exact permit.decision.v1 capability material",
            (str(artifact.get("artifact_id")),),
        )
    receipt = _mapping(
        payload.get("permit_receipt"),
        field="permit_artifact.permit_receipt",
        code="WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID",
    )
    evidence = _mapping(
        payload.get("permit_decision_binding"),
        field="permit_artifact.permit_decision_binding",
        code="WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID",
    )
    canonical = _mapping(
        evidence.get("canonical_payload"),
        field="permit_decision_binding.canonical_payload",
        code="WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID",
    )
    version = canonical.get("binding_version")
    if version not in {"v6", "v7"}:
        raise _Failure(
            "unverifiable_scope",
            "WORK_VERSION_UNSUPPORTED",
            "Work Permit decision evidence requires binding version v6 or v7",
            ("permit_decision_binding.canonical_payload.binding_version",),
        )
    expected_hash = core._compute_canonical_binding_hash(canonical)
    if evidence.get("binding_canonical_hash") != expected_hash:
        raise _Failure(
            "disproved",
            "WORK_ARTIFACT_INTEGRITY_INVALID",
            "Permit decision canonical hash does not match its exact payload",
            ("permit_decision_binding.canonical_payload",),
        )
    attrs = _mapping(
        evidence.get("resource_attributes_json"),
        field="permit_decision_binding.resource_attributes_json",
        code="WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID",
    )
    if canonical_resource_attributes_payload(attrs) != canonical.get(
        "resource_attributes_canonical_hash"
    ):
        raise _Failure(
            "disproved",
            "WORK_ARTIFACT_INTEGRITY_INVALID",
            "Permit resource attributes do not match their signed canonical hash",
            ("permit_decision_binding.resource_attributes_json",),
        )
    receipt_action = _mapping(
        receipt.get("action"),
        field="permit_receipt.action",
        code="WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID",
    )
    if receipt_action.get("resource_attributes_json") != attrs:
        raise _Failure(
            "disproved",
            "WORK_ARTIFACT_INTEGRITY_INVALID",
            "Permit receipt attributes conflict with the signed decision capability",
            ("permit_receipt.action.resource_attributes_json",),
        )
    key_id = canonical.get("binding_key_id")
    if not isinstance(key_id, str):
        raise _Failure(
            "insufficient_evidence",
            "WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID",
            "Permit decision binding_key_id is absent",
            ("permit_decision_binding.canonical_payload.binding_key_id",),
        )
    signed_at = _parse_time(
        evidence.get("binding_issued_at") or canonical.get("issued_at"),
        field="permit_decision_binding.binding_issued_at",
    )
    public_key = _key_for_time(
        entries,
        key_id=key_id,
        purpose="permit_binding_signing",
        signed_at=signed_at,
    )
    if core._binding_key_id_from_public_key(public_key) != key_id:
        raise _Failure(
            "disproved",
            "WORK_ARTIFACT_INTEGRITY_INVALID",
            "Permit decision key id conflicts with its trusted public key",
            ("permit_decision_binding.canonical_payload.binding_key_id",),
        )
    if not core._verify_ed25519(
        public_key,
        expected_hash.encode("utf-8"),
        str(evidence.get("binding_signature") or ""),
    ):
        raise _Failure(
            "disproved",
            "WORK_ARTIFACT_INTEGRITY_INVALID",
            "Permit decision signature does not verify",
            ("permit_decision_binding.binding_signature",),
        )
    signed_decision = str(canonical.get("decision") or "")
    if evidence.get("expected_decision") not in {
        signed_decision,
        receipt.get("decision", {}).get("decision")
        if isinstance(receipt.get("decision"), Mapping)
        else None,
    }:
        raise _Failure(
            "disproved",
            "WORK_ARTIFACT_INTEGRITY_INVALID",
            "Permit decision evidence conflicts with both signed and materialized decisions",
            ("permit_decision_binding.expected_decision",),
        )
    return _PermitMaterial(
        canonical_payload=canonical,
        resource_attributes=attrs,
        receipt=receipt,
        signed_decision=signed_decision,
    )


def _authority_manifest(
    document: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    entries: list[dict[str, Any]],
) -> tuple[ClaimVerdict, dict[str, Any]]:
    root_id = document["root_permit_id"]
    try:
        root = document["root"]
        root_artifact = _resolve_reference(
            root.get("permit_artifact"), artifacts, field="root.permit_artifact"
        )
        material = _verify_permit(root_artifact, entries=entries)
        canonical = material.canonical_payload
        if (
            canonical.get("permit_id") != root_id
            or canonical.get("project_id") != document["project_id"]
            or canonical.get("permit_chain_role") != "work_root"
            or canonical.get("parent_permit_id") is not None
            or canonical.get("action_name") != "work.authorize"
            or material.signed_decision != "allow"
        ):
            raise _Failure(
                "disproved",
                "WORK_AUTHORITY_SCOPE_MISMATCH",
                "signed root Permit identity, chain role, action, or decision conflicts with the Work pack",
                ("root.permit_artifact",),
            )
        package = _mapping(
            root.get("work_package"),
            field="root.work_package",
            code="WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID",
        )
        if package.get("version") != "keel.work_package.v1":
            raise _Failure(
                "unverifiable_scope",
                "WORK_VERSION_UNSUPPORTED",
                "only keel.work_package.v1 is supported",
                ("root.work_package.version",),
            )
        if material.resource_attributes.get("work_package_v1") != package:
            raise _Failure(
                "disproved",
                "WORK_AUTHORITY_SCOPE_MISMATCH",
                "root Work package does not match the signed Permit resource attributes",
                ("root.work_package", "root.permit_artifact"),
            )
        if material.resource_attributes.get("permit_semantic_binding_v1") != root.get(
            "semantic_binding"
        ):
            raise _Failure(
                "disproved",
                "WORK_AUTHORITY_SCOPE_MISMATCH",
                "root semantic binding is not the one signed into the Permit",
                ("root.semantic_binding",),
            )

        authorities: dict[str, dict[str, Any]] = {}
        for index, raw in enumerate(document["authorities"]):
            authority = _mapping(
                raw,
                field=f"authorities[{index}]",
                code="WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID",
            )
            authority_id = authority.get("authority_id")
            if not isinstance(authority_id, str) or not authority_id or authority_id in authorities:
                raise _Failure(
                    "disproved",
                    "WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID",
                    "Work authority ids must be unique non-empty strings",
                    (f"authorities[{index}].authority_id",),
                )
            if authority.get("version") != "keel.work_authority.v1":
                raise _Failure(
                    "unverifiable_scope",
                    "WORK_VERSION_UNSUPPORTED",
                    "only keel.work_authority.v1 is supported",
                    (f"authorities[{index}].version",),
                )
            canonical_authority = dict(authority)
            declared_hash = canonical_authority.pop("authority_canonical_hash", None)
            if declared_hash != _digest(canonical_authority):
                raise _Failure(
                    "disproved",
                    "WORK_AUTHORITY_SET_HASH_MISMATCH",
                    f"authority {authority_id} canonical hash does not match",
                    (f"authorities[{index}]",),
                )
            if (
                authority.get("project_id") != document["project_id"]
                or authority.get("root_permit_id") != root_id
                or authority.get("trusted_action") != "payment.execute"
                or authority.get("comparator_version") != "work-payment-authority.v1"
            ):
                raise _Failure(
                    "disproved",
                    "WORK_AUTHORITY_SCOPE_MISMATCH",
                    f"authority {authority_id} does not belong to this payment-only Work root",
                    (f"authorities[{index}]",),
                )
            authorities[authority_id] = authority

        issued = _list(
            package.get("issued_authorities"),
            field="root.work_package.issued_authorities",
            code="WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID",
        )
        issued_ids = [
            item.get("authority_id") if isinstance(item, Mapping) else None for item in issued
        ]
        if len(issued_ids) != len(set(issued_ids)) or set(issued_ids) != set(authorities):
            raise _Failure(
                "disproved",
                "WORK_AUTHORITY_SET_HASH_MISMATCH",
                "signed issued-authority ids do not equal the supplied authority population",
                ("root.work_package.issued_authorities", "authorities"),
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
        if sorted(
            issued, key=lambda item: str(item.get("authority_id"))
        ) != expected_refs or package.get("issued_authority_set_hash") != _digest(expected_refs):
            raise _Failure(
                "disproved",
                "WORK_AUTHORITY_SET_HASH_MISMATCH",
                "signed issued-authority references or set hash do not match",
                ("root.work_package.issued_authorities",),
            )
        excluded = _list(
            package.get("excluded_authorities"),
            field="root.work_package.excluded_authorities",
            code="WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID",
        )
        excluded_ids = [
            item.get("authority_id") if isinstance(item, Mapping) else None for item in excluded
        ]
        required = _list(
            package.get("required_authority_ids"),
            field="root.work_package.required_authority_ids",
            code="WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID",
        )
        if (
            len(excluded_ids) != len(set(excluded_ids))
            or set(excluded_ids).intersection(authorities)
            or not set(required).issubset(set(authorities) - set(excluded_ids))
        ):
            raise _Failure(
                "disproved",
                "WORK_REQUIRED_AUTHORITY_MISSING",
                "required, issued, and excluded authority sets conflict",
                ("root.work_package",),
            )
        root_snapshots = [
            item
            for item in document["policy_snapshots"]
            if isinstance(item, Mapping) and item.get("phase") == "root_issuance"
        ]
        policy = _mapping(
            package.get("policy_snapshot"),
            field="root.work_package.policy_snapshot",
            code="WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID",
        )
        if len(root_snapshots) != 1 or any(
            root_snapshots[0].get(field) != policy.get(field)
            for field in ("policy_id", "policy_version", "policy_snapshot_hash")
        ):
            raise _Failure(
                "disproved",
                "WORK_AUTHORITY_SCOPE_MISMATCH",
                "root issuance Policy snapshot conflicts with the signed Work package",
                ("policy_snapshots", "root.work_package.policy_snapshot"),
            )
        return (
            _claim(
                WORK_CLAIMS[0],
                subject_type="work_root",
                subject_id=root_id,
                verdict="supported",
                code="WORK_AUTHORITY_MANIFEST_SUPPORTED",
                message="signed Work authority manifest and exact authority population match",
                evidence=("root.permit_artifact", "root.work_package", "authorities"),
            ),
            {
                "package": package,
                "authorities": authorities,
                "root_material": material,
            },
        )
    except _Failure as failure:
        return (
            _claim(
                WORK_CLAIMS[0],
                subject_type="work_root",
                subject_id=root_id,
                verdict=failure.verdict,
                code=failure.code,
                message=failure.message,
                evidence=failure.evidence,
            ),
            {},
        )


def _norm_sha(value: Any) -> str | None:
    normalized = _normalized_digest(value)
    return normalized


def _child_containment(
    document: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    entries: list[dict[str, Any]],
    context: dict[str, Any],
) -> tuple[ClaimVerdict, dict[str, _PermitMaterial]]:
    if not context:
        return (
            _claim(
                WORK_CLAIMS[1],
                subject_type="work_child_population",
                subject_id=document.get("root_permit_id"),
                verdict="insufficient_evidence",
                code="WORK_REQUIRED_AUTHORITY_MISSING",
                message="child containment requires a supported Work authority manifest",
                evidence=("permit.work_authority_manifest.v1",),
            ),
            {},
        )
    subjects: list[VerdictSubject] = []
    materials: dict[str, _PermitMaterial] = {}
    package = context["package"]
    authorities = context["authorities"]
    for index, raw in enumerate(document["child_permits"]):
        child = dict(raw)
        child_id = str(child.get("permit_id") or "") or None
        decision = str(child.get("decision") or "")
        required = decision != "deny"
        try:
            if decision not in {"allow", "challenge", "deny"}:
                raise _Failure(
                    "disproved",
                    "WORK_CHILD_BINDING_MISMATCH",
                    "child decision is unsupported",
                    (f"child_permits[{index}].decision",),
                )
            artifact = _resolve_reference(
                child.get("permit_artifact"),
                artifacts,
                field=f"child_permits[{index}].permit_artifact",
            )
            material = _verify_permit(artifact, entries=entries)
            canonical = material.canonical_payload
            attrs = material.resource_attributes
            binding = _mapping(
                child.get("work_binding"),
                field=f"child_permits[{index}].work_binding",
                code="WORK_CHILD_BINDING_MISMATCH",
            )
            authority_id = str(child.get("work_authority_id") or "")
            authority = authorities.get(authority_id)
            if authority is None:
                raise _Failure(
                    "disproved",
                    "WORK_CHILD_BINDING_MISMATCH",
                    f"child {child_id} names an unknown Work authority",
                    (f"child_permits[{index}].work_authority_id",),
                )
            if (
                binding.get("version") != "keel.work_binding.v1"
                or binding.get("root_permit_id") != document["root_permit_id"]
                or binding.get("authority_id") != authority_id
                or binding.get("authority_canonical_hash")
                != authority.get("authority_canonical_hash")
                or binding.get("root_manifest_hash") != _digest(package)
                or attrs.get("work_binding_v1") != binding
            ):
                raise _Failure(
                    "disproved",
                    "WORK_CHILD_BINDING_MISMATCH",
                    f"child {child_id} Work binding conflicts with its root or authority",
                    (f"child_permits[{index}].work_binding",),
                )
            request_digest = _norm_sha(child.get("request_digest"))
            fingerprint = _norm_sha(canonical.get("request_fingerprint"))
            if (
                canonical.get("permit_id") != child_id
                or canonical.get("project_id") != document["project_id"]
                or canonical.get("parent_permit_id") != document["root_permit_id"]
                or canonical.get("permit_chain_role") != "action_child"
                or request_digest is None
                or request_digest != fingerprint
            ):
                raise _Failure(
                    "disproved",
                    "WORK_CHILD_BINDING_MISMATCH",
                    f"child {child_id} exact signed Permit identity or request digest conflicts",
                    (f"child_permits[{index}]",),
                )
            if child.get("semantic_binding") is not None and attrs.get(
                "permit_semantic_binding_v1"
            ) != child.get("semantic_binding"):
                raise _Failure(
                    "disproved",
                    "WORK_CHILD_BINDING_MISMATCH",
                    f"child {child_id} semantic binding is not signed into the Permit",
                    (f"child_permits[{index}].semantic_binding",),
                )
            if decision != "deny":
                resource = _mapping(
                    attrs.get("work_resource_scope_v1"),
                    field="permit_decision_binding.resource_attributes_json.work_resource_scope_v1",
                    code="WORK_CHILD_OUTSIDE_AUTHORITY",
                )
                spend = _mapping(
                    attrs.get("spend_scope"),
                    field="permit_decision_binding.resource_attributes_json.spend_scope",
                    code="WORK_CHILD_OUTSIDE_AUTHORITY",
                )
                try:
                    amount = int(str(spend.get("amount_max")))
                except (TypeError, ValueError) as exc:
                    raise _Failure(
                        "disproved",
                        "WORK_CHILD_OUTSIDE_AUTHORITY",
                        f"child {child_id} payment amount is malformed",
                        ("spend_scope.amount_max",),
                    ) from exc
                currency = _CURRENCY_CLASS.get(str(spend.get("currency_class")))
                recipient = _norm_sha(spend.get("recipient_address_digest"))
                purpose = _norm_sha(spend.get("description_digest"))
                issued_at = _parse_time(
                    canonical.get("issued_at"), field="canonical_payload.issued_at"
                )
                not_before = _parse_time(authority.get("not_before"), field="authority.not_before")
                expires_at = _parse_time(authority.get("expires_at"), field="authority.expires_at")
                if not (
                    canonical.get("action_name") == authority.get("trusted_action")
                    and attrs.get("operation") == "payment.execute"
                    and resource.get("version") == "keel.work_resource_scope.v1"
                    and {
                        "type": resource.get("type"),
                        "id": resource.get("id"),
                        "digest": resource.get("digest"),
                    }
                    == authority.get("resource_scope")
                    and attrs.get("work_resource_digest") == resource.get("digest")
                    and spend.get("cadence") == "one_shot"
                    and currency == authority.get("currency")
                    and amount > 0
                    and amount <= int(authority.get("value_max_minor") or 0)
                    and (
                        authority.get("recipient_digest") is None
                        or recipient == authority.get("recipient_digest")
                    )
                    and (
                        authority.get("purpose_digest") is None
                        or purpose == authority.get("purpose_digest")
                    )
                    and not_before <= issued_at < expires_at
                ):
                    raise _Failure(
                        "disproved",
                        "WORK_CHILD_OUTSIDE_AUTHORITY",
                        f"child {child_id} exact payment request is outside its signed Work authority",
                        (f"child_permits[{index}]", "authorities"),
                    )
            materials[str(child_id)] = material
            subjects.append(
                VerdictSubject(
                    type="work_child",
                    id=child_id,
                    verdict="supported",
                    reason_code=(
                        "WORK_CHILD_DENIED_WITHOUT_AUTHORITY"
                        if decision == "deny"
                        else "WORK_CHILD_CONTAINMENT_SUPPORTED"
                    ),
                    message=(
                        "denied child carried no executable authority"
                        if decision == "deny"
                        else "exact linked action Permit fits its named Work authority"
                    ),
                    evidence=[f"child_permits[{index}]", "permit_artifact"],
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
    return _claim_from_subjects(WORK_CLAIMS[1], subjects), materials


def _event_body(artifact: dict[str, Any]) -> dict[str, Any]:
    payload = _mapping(
        artifact.get("payload"),
        field="dispatch_boundary_evidence.payload",
        code="WORK_DISPATCH_BOUNDARY_MISSING",
    )
    inner = payload.get("payload")
    return dict(inner) if isinstance(inner, Mapping) else payload


def _execution_boundary(
    document: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    child_claim: ClaimVerdict,
) -> ClaimVerdict:
    if child_claim.aggregate_verdict != "supported":
        return _claim(
            WORK_CLAIMS[2],
            subject_type="dispatch_boundary_population",
            subject_id=document["root_permit_id"],
            verdict="insufficient_evidence",
            code="WORK_CHILD_BINDING_MISMATCH",
            message="dispatch-boundary adjudication requires supported child containment",
            evidence=("permit.work_child_containment.v1",),
        )
    lifecycle = [dict(item) for item in document["lifecycle_events"]]
    subjects: list[VerdictSubject] = []
    for index, child_raw in enumerate(document["child_permits"]):
        child = dict(child_raw)
        child_id = str(child.get("permit_id") or "") or None
        reference = child.get("dispatch_boundary_evidence")
        decision = child.get("decision")
        required = decision == "allow"
        if reference is None:
            subjects.append(
                VerdictSubject(
                    type="dispatch_boundary",
                    id=child_id,
                    verdict="insufficient_evidence",
                    reason_code="WORK_DISPATCH_BOUNDARY_MISSING",
                    message="no recorded dispatch boundary is present for this child Permit",
                    evidence=[f"child_permits[{index}].dispatch_boundary_evidence"],
                    required=required,
                )
            )
            continue
        try:
            if decision != "allow":
                raise _Failure(
                    "disproved",
                    "WORK_ANCESTOR_NOT_LIVE_AT_DISPATCH",
                    "a non-allow child carries dispatch-boundary evidence",
                    (f"child_permits[{index}].decision",),
                )
            artifact = _resolve_reference(
                reference,
                artifacts,
                field=f"child_permits[{index}].dispatch_boundary_evidence",
            )
            body = _event_body(artifact)
            if (
                body.get("version") != "keel.work_dispatch_boundary.v1"
                or body.get("event_type") != "dispatch.egress_bound"
                or body.get("root_permit_id") != document["root_permit_id"]
                or body.get("child_permit_id") != child_id
            ):
                raise _Failure(
                    "unverifiable_scope",
                    "WORK_VERSION_UNSUPPORTED",
                    "dispatch-boundary event version or identity is unsupported",
                    (f"child_permits[{index}].dispatch_boundary_evidence",),
                )
            liveness = _mapping(
                body.get("liveness"),
                field="dispatch_boundary.liveness",
                code="WORK_ANCESTOR_NOT_LIVE_AT_DISPATCH",
            )
            if not REQUIRED_LIVENESS.issubset(liveness) or any(
                liveness.get(field) is not True for field in REQUIRED_LIVENESS
            ):
                raise _Failure(
                    "disproved",
                    "WORK_ANCESTOR_NOT_LIVE_AT_DISPATCH",
                    "root, authority, child, reservation, Policy, or safety-floor liveness was false",
                    ("dispatch_boundary.liveness",),
                )
            execution_policy = _mapping(
                body.get("execution_policy"),
                field="dispatch_boundary.execution_policy",
                code="WORK_EXECUTION_POLICY_BLOCKED",
            )
            snapshots = [
                item
                for item in document["policy_snapshots"]
                if isinstance(item, Mapping)
                and item.get("phase") == "dispatch"
                and item.get("permit_id") == child_id
            ]
            if len(snapshots) != 1 or any(
                snapshots[0].get(field) != execution_policy.get(field)
                for field in ("policy_id", "policy_version", "policy_snapshot_hash")
            ):
                raise _Failure(
                    "disproved",
                    "WORK_EXECUTION_POLICY_BLOCKED",
                    "dispatch Policy snapshot is missing or conflicts with the boundary event",
                    ("policy_snapshots", "dispatch_boundary.execution_policy"),
                )
            if any(
                body.get(field) is not False
                for field in (
                    "asserts_provider_acceptance",
                    "asserts_business_job_completed",
                    "asserts_settlement",
                )
            ):
                raise _Failure(
                    "disproved",
                    "WORK_ARTIFACT_INTEGRITY_INVALID",
                    "dispatch boundary improperly asserts an outcome or settlement",
                    ("dispatch_boundary",),
                )
            boundary_time = _parse_time(
                body.get("occurred_at")
                or next(
                    (
                        event.get("occurred_at")
                        for event in lifecycle
                        if event.get("event_digest") == artifact.get("artifact_digest")
                    ),
                    None,
                ),
                field="dispatch_boundary.occurred_at",
            )
            for event in lifecycle:
                if event.get("event_type") not in {"work.closed", "permit.revoked"}:
                    continue
                permit_id = event.get("permit_id")
                if permit_id not in {document["root_permit_id"], child_id}:
                    continue
                if (
                    _parse_time(event.get("occurred_at"), field="lifecycle_event.occurred_at")
                    <= boundary_time
                ):
                    raise _Failure(
                        "disproved",
                        "WORK_ANCESTOR_NOT_LIVE_AT_DISPATCH",
                        "root or child authority ended before the recorded dispatch boundary",
                        ("lifecycle_events",),
                    )
            subjects.append(
                VerdictSubject(
                    type="dispatch_boundary",
                    id=child_id,
                    verdict="supported",
                    reason_code="WORK_EXECUTION_BOUNDARY_SUPPORTED",
                    message="recorded dispatch boundary was inside live Work authority",
                    evidence=[f"child_permits[{index}].dispatch_boundary_evidence"],
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
                    required=required,
                )
            )
    if not subjects:
        subjects.append(
            VerdictSubject(
                type="dispatch_boundary_population",
                id=document["root_permit_id"],
                verdict="insufficient_evidence",
                reason_code="WORK_DISPATCH_BOUNDARY_MISSING",
                message="the Work pack contains no child dispatch boundary",
                evidence=["child_permits"],
            )
        )
    return _claim_from_subjects(WORK_CLAIMS[2], subjects)


def _work_value(
    document: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    context: dict[str, Any],
) -> ClaimVerdict:
    if not context:
        return _claim(
            WORK_CLAIMS[3],
            subject_type="work_value_population",
            subject_id=document["root_permit_id"],
            verdict="insufficient_evidence",
            code="WORK_REQUIRED_AUTHORITY_MISSING",
            message="value conservation requires a supported Work authority manifest",
            evidence=("permit.work_authority_manifest.v1",),
        )
    events_by_authority: dict[str, list[dict[str, Any]]] = {
        authority_id: [] for authority_id in context["authorities"]
    }
    unknown_authority = False
    for event in document["value_events"]:
        if isinstance(event, Mapping) and event.get("authority_id") in events_by_authority:
            events_by_authority[str(event["authority_id"])].append(dict(event))
        else:
            unknown_authority = True
    subjects: list[VerdictSubject] = []
    if unknown_authority:
        subjects.append(
            VerdictSubject(
                type="work_value_population",
                id=document["root_permit_id"],
                verdict="disproved",
                reason_code="WORK_VALUE_CONSERVATION_MISMATCH",
                message="a Work value event names an unknown authority",
                evidence=["value_events"],
            )
        )
    child_ids = {
        str(child.get("permit_id"))
        for child in document["child_permits"]
        if isinstance(child, Mapping)
    }
    cutoff = _parse_time(
        document["declared_cutoff"].get("recorded_through"),
        field="declared_cutoff.recorded_through",
    )
    for authority_id, authority in context["authorities"].items():
        try:
            events = events_by_authority[authority_id]
            sequences = [event.get("authority_sequence") for event in events]
            transitions = [event.get("idempotency_key_digest") for event in events]
            event_ids = [event.get("event_id") for event in events]
            if (
                sequences != list(range(1, len(events) + 1))
                or len(transitions) != len(set(transitions))
                or len(event_ids) != len(set(event_ids))
            ):
                raise _Failure(
                    "disproved",
                    "WORK_VALUE_EVENT_SEQUENCE_INVALID",
                    f"authority {authority_id} value events have a gap or duplicate transition",
                    ("value_events",),
                )
            states: dict[str, str] = {}
            amounts: dict[str, int] = {}
            reserved_value = 0
            consumed_value = 0
            reserved_uses = 0
            consumed_uses = 0
            for index, event in enumerate(events):
                if (
                    event.get("version") != "keel.work_value_event.v1"
                    or event.get("project_id") != document["project_id"]
                    or event.get("root_permit_id") != document["root_permit_id"]
                    or event.get("currency") != authority.get("currency")
                ):
                    raise _Failure(
                        "disproved",
                        "WORK_VALUE_CONSERVATION_MISMATCH",
                        f"authority {authority_id} value event identity or currency conflicts",
                        (f"value_events[{index}]",),
                    )
                child_id = str(event.get("child_permit_id") or "")
                if not child_id or child_id not in child_ids:
                    raise _Failure(
                        "disproved",
                        "WORK_VALUE_CONSERVATION_MISMATCH",
                        "value event does not name a child in the signed population",
                        (f"value_events[{index}].child_permit_id",),
                    )
                try:
                    amount = int(event.get("amount_minor"))
                except (TypeError, ValueError) as exc:
                    raise _Failure(
                        "disproved",
                        "WORK_VALUE_CONSERVATION_MISMATCH",
                        "value event amount is malformed",
                        (f"value_events[{index}].amount_minor",),
                    ) from exc
                occurred_at = _parse_time(
                    event.get("occurred_at"), field=f"value_events[{index}].occurred_at"
                )
                if amount <= 0 or occurred_at > cutoff:
                    raise _Failure(
                        "disproved",
                        "WORK_VALUE_CONSERVATION_MISMATCH",
                        "value event amount or cutoff is invalid",
                        (f"value_events[{index}]",),
                    )
                event_type = event.get("event_type")
                state = states.get(child_id)
                if event_type == "reserved" and state is None:
                    states[child_id] = "reserved"
                    amounts[child_id] = amount
                    reserved_value += amount
                    reserved_uses += 1
                elif (
                    event_type == "released" and state == "reserved" and amounts[child_id] == amount
                ):
                    states[child_id] = "released"
                    reserved_value -= amount
                    reserved_uses -= 1
                elif (
                    event_type == "dispatched"
                    and state == "reserved"
                    and amounts[child_id] == amount
                ):
                    states[child_id] = "dispatched"
                    reserved_value -= amount
                    reserved_uses -= 1
                    consumed_value += amount
                    consumed_uses += 1
                elif (
                    event_type == "provider_accepted"
                    and state == "dispatched"
                    and amounts[child_id] == amount
                ):
                    states[child_id] = "provider_accepted"
                elif (
                    event_type == "outcome_unknown"
                    and state in {"dispatched", "provider_accepted"}
                    and amounts[child_id] == amount
                ):
                    states[child_id] = "outcome_unknown"
                elif (
                    event_type == "reconciled"
                    and state == "outcome_unknown"
                    and amounts[child_id] == amount
                ):
                    if event.get("evidence_reference") is None:
                        raise _Failure(
                            "insufficient_evidence",
                            "WORK_VALUE_CONSERVATION_MISMATCH",
                            "reconciled transition lacks evidence resolving the unknown outcome",
                            (f"value_events[{index}].evidence_reference",),
                        )
                    states[child_id] = "reconciled"
                elif (
                    event_type == "settled"
                    and state in {"dispatched", "provider_accepted", "outcome_unknown"}
                    and amounts[child_id] == amount
                ):
                    reference = event.get("evidence_reference")
                    if reference is None:
                        raise _Failure(
                            "insufficient_evidence",
                            "WORK_SETTLEMENT_EVIDENCE_MISSING",
                            "settled transition lacks an independently checkable settlement artifact",
                            (f"value_events[{index}].evidence_reference",),
                        )
                    settlement = _resolve_reference(
                        reference,
                        artifacts,
                        field=f"value_events[{index}].evidence_reference",
                        require_type=False,
                    )
                    if settlement.get("artifact_type") not in SUPPORTED_SETTLEMENT_ARTIFACTS:
                        raise _Failure(
                            "insufficient_evidence",
                            "WORK_SETTLEMENT_EVIDENCE_MISSING",
                            "settlement artifact type is not independently supported",
                            (f"value_events[{index}].evidence_reference",),
                        )
                    settlement_payload = settlement.get("payload")
                    if isinstance(settlement_payload, Mapping) and (
                        settlement_payload.get("amount_minor") not in {None, amount}
                        or settlement_payload.get("currency")
                        not in {None, authority.get("currency")}
                    ):
                        raise _Failure(
                            "disproved",
                            "WORK_VALUE_CONSERVATION_MISMATCH",
                            "settlement artifact amount or currency conflicts with the value event",
                            (f"value_events[{index}].evidence_reference",),
                        )
                    states[child_id] = "settled"
                else:
                    raise _Failure(
                        "disproved",
                        "WORK_VALUE_EVENT_SEQUENCE_INVALID",
                        f"invalid {event_type!r} transition for child {child_id}",
                        (f"value_events[{index}]",),
                    )
                if (
                    reserved_value < 0
                    or consumed_value < 0
                    or reserved_uses < 0
                    or consumed_uses < 0
                    or reserved_value + consumed_value > int(authority.get("value_max_minor") or 0)
                    or reserved_uses + consumed_uses > int(authority.get("max_uses") or 0)
                ):
                    raise _Failure(
                        "disproved",
                        "WORK_VALUE_CONSERVATION_MISMATCH",
                        f"authority {authority_id} exceeds its signed value or use limit",
                        ("value_events", "authorities"),
                    )
            subjects.append(
                VerdictSubject(
                    type="work_authority_value_ledger",
                    id=authority_id,
                    verdict="supported",
                    reason_code="WORK_VALUE_CONSERVATION_SUPPORTED",
                    message=(
                        "scope-signed payment-value events conserve the authority limits; "
                        "authorization and provider acceptance do not imply settlement"
                    ),
                    evidence=["scope_commitment", "value_events", "authorities"],
                )
            )
        except _Failure as failure:
            subjects.append(
                VerdictSubject(
                    type="work_authority_value_ledger",
                    id=authority_id,
                    verdict=failure.verdict,
                    reason_code=failure.code,
                    message=failure.message,
                    evidence=list(failure.evidence),
                )
            )
    if not subjects:
        subjects.append(
            VerdictSubject(
                type="work_value_population",
                id=document["root_permit_id"],
                verdict="insufficient_evidence",
                reason_code="WORK_REQUIRED_AUTHORITY_MISSING",
                message="no Work authority exists for value-conservation adjudication",
                evidence=["authorities"],
            )
        )
    return _claim_from_subjects(WORK_CLAIMS[3], subjects)


def verify_work_chain_pack(
    pack: str | Path | Mapping[str, Any],
    *,
    trust_root: str | Path | None = None,
) -> VerificationReport:
    """Verify a downloaded ``work-chain.v1`` pack offline.

    ``trust_root`` is optional.  Production packs default to the verifier's
    bundled Keel trust root; tests and private deployments may pin a local
    signed or legacy key manifest explicitly.
    """

    artifact: dict[str, Any] = {"kind": "work_chain_pack"}
    try:
        document, artifact = _load_document(pack)
        root_id = (
            document.get("root_permit_id")
            if isinstance(document.get("root_permit_id"), str)
            else None
        )
        _validate_top_level(document)
        artifacts = _artifact_index(document)
        _validate_references(document, artifacts)
        entries, trust_source = _scope_signature(
            document,
            artifacts,
            trust_root=trust_root,
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
        claims = _all_claim_failure(failure, locals().get("root_id"))
        return _report(document=locals().get("document", {}), artifact=artifact, claims=claims)

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
    authority_claim, context = _authority_manifest(document, artifacts, entries)
    child_claim, _materials = _child_containment(document, artifacts, entries, context)
    boundary_claim = _execution_boundary(document, artifacts, child_claim)
    value_claim = _work_value(document, artifacts, context)
    return _report(
        document=document,
        artifact=artifact,
        claims=[authority_claim, child_claim, boundary_claim, value_claim],
        diagnostics=[
            "The scope commitment is faithful to Keel-recorded populations through the cutoff; it does not assert comprehensive runtime recording.",
            "Authorization, dispatch, provider acceptance, business completion, and settlement remain distinct evidence states.",
        ],
    )


__all__ = ["WORK_CLAIMS", "verify_work_chain_pack"]
