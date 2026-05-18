"""Pack-pinned semantic resolution for verifier-claims.v0."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any, Callable


CLAIM_REGISTRY_ID = "keel.verifier_claim_registry.v0"
CLAIM_REGISTRY_VERSION = "verifier-claims.v0"
SEMANTICS_PINS_VERSION = "keel-semantics-pins.v0"
LEGACY_PROFILE_ID = "keel.pre_pinning_default.v0"
LEGACY_PROFILE_WARNING = (
    "pack has no semantics_pins; evaluated under the permanent pre-pinning v0 profile"
)

EXPORT_MANIFEST_INTEGRITY_ID = "keel.export_manifest.integrity.v1"
GOVERNANCE_RECORD_HASH_ID = "keel.governance_chain.record_hash.v1"
CLOSURE_FORMAT_V1_ID = "keel.closure.format.v1"
CLOSURE_FORMAT_V2_ID = "keel.closure.format.v2"
CLOSURE_DIGEST_RULES_ID = "keel.closure.digest_rules.v1"
PERMIT_BINDING_CANONICAL_REQUEST_ID = "keel.permit_binding.canonical_request.v1"
WORKFLOW_CANONICALIZATION_ID = "keel.workflow.canonicalization.v1"
WORKFLOW_EVIDENCE_SIBLING_INTEGRITY_ID = "keel.workflow_evidence.sibling_integrity.v1"
INCIDENT_BUNDLE_MANIFEST_ID = "keel.incident.bundle_manifest.v2"
CHECKPOINT_COMPOSITE_HASH_ID = "keel.checkpoint.composite_hash.v1"
CHECKPOINT_SIGNATURE_ID = "keel.checkpoint.signature.v1"
CHECKPOINT_TSA_IMPRINT_ID = "keel.checkpoint.tsa_imprint.v1"
AUTHORITY_ENVELOPE_V0_ID = "authority-envelope.v0"

CLAIM_REGISTRY_HASH = (
    "sha256:b315ef722a8e4fafe3d3807bc7c8ccaafd601cab0e7d7985230da8248124337b"
)
EXPORT_MANIFEST_INTEGRITY_HASH = (
    "sha256:d1d67dca7eb9a662d26463c3dec841f47f8791df2fafb21e911dd26a83dabb76"
)
GOVERNANCE_RECORD_HASH_HASH = (
    "sha256:a3213706c9e9531a74cd2355f2f05e537c7a70604cb869b7b76c65cba4a2b707"
)
CLOSURE_FORMAT_V1_HASH = (
    "sha256:b208b82fbf8187ecdc85410630fbfa30f86f34c4da28d4b418c5788a8ec893ba"
)
CLOSURE_FORMAT_V2_HASH = (
    "sha256:476b9aaf8f1b3e0fd46b9cfae522062e803ecbb1c24fdbb6ec60775b979d59f1"
)
CLOSURE_DIGEST_RULES_HASH = (
    "sha256:eca06d960a9e16468a622938a17b77244d487b58459be4dce3e55ef006f29454"
)
PERMIT_BINDING_CANONICAL_REQUEST_HASH = (
    "sha256:59633003ed97b2a65e756007fddd6f525a8c056de57a1cd40971034fa044f0ac"
)
WORKFLOW_CANONICALIZATION_HASH = (
    "sha256:b7359ae11dc1d8cfad51bf3e6fec32a0209bf38097a01fa4f878e3a068184501"
)
WORKFLOW_EVIDENCE_SIBLING_INTEGRITY_HASH = (
    "sha256:c4e99745893e6c66afa89ad46602b0cf1931530f78875e18387381fca8c2a5aa"
)
INCIDENT_BUNDLE_MANIFEST_HASH = (
    "sha256:ed112e365985d79192a4cb7c3248625d8294d2d2c5210ce31960eb7d55f4b9eb"
)
CHECKPOINT_COMPOSITE_HASH_HASH = (
    "sha256:68aafa26d6f1c8cf5ba83c7596209888d8e529d81f1a2c58f31e2fc41fc136de"
)
CHECKPOINT_SIGNATURE_HASH = (
    "sha256:af16c66e8a0b295cd2e5e436169bf0e3d628c1fc4901b6eba6596e86e3ad256b"
)
CHECKPOINT_TSA_IMPRINT_HASH = (
    "sha256:a4e02133537a190c3795737beb4bb2ddf823cd09d5b6dcba43c682fb9e37d79e"
)
LEGACY_PROFILE_HASH = (
    "sha256:b7b31f30a91a50517693494d9a868c781ae5dbd82bd06228fd34e0d517b5a153"
)
AUTHORITY_ENVELOPE_V0_HASH = (
    "sha256:a2505ac94f27c1d0096fa977f25be699fa00a9ff507a0c4cbe0d1edf2e44cee2"
)

SemanticsKey = tuple[str, str]
RecordHashV1 = Callable[..., str]
ClosureVerifier = Callable[..., int | None]
CompositeHash = Callable[[dict[str, dict[str, Any]]], str]


CLAIM_SEMANTICS: dict[str, tuple[str, ...]] = {
    "export.integrity.v1": (EXPORT_MANIFEST_INTEGRITY_ID,),
    "export.scope_identity.v1": (EXPORT_MANIFEST_INTEGRITY_ID,),
    "governance_chain.local_continuity.v1": (GOVERNANCE_RECORD_HASH_ID,),
    "closure.signature.v1": (
        CLOSURE_FORMAT_V1_ID,
        CLOSURE_FORMAT_V2_ID,
        PERMIT_BINDING_CANONICAL_REQUEST_ID,
    ),
    "closure.digest_consistency.v1": (
        CLOSURE_FORMAT_V1_ID,
        CLOSURE_FORMAT_V2_ID,
        CLOSURE_DIGEST_RULES_ID,
    ),
    "closure.dispatch_binding.v1": (
        CLOSURE_FORMAT_V2_ID,
        CLOSURE_DIGEST_RULES_ID,
        PERMIT_BINDING_CANONICAL_REQUEST_ID,
    ),
    "workflow.declaration_signature.v1": (
        WORKFLOW_CANONICALIZATION_ID,
        PERMIT_BINDING_CANONICAL_REQUEST_ID,
    ),
    "workflow.amendment_signature.v1": (
        WORKFLOW_CANONICALIZATION_ID,
        PERMIT_BINDING_CANONICAL_REQUEST_ID,
    ),
    "workflow.effective_intent_hash.v1": (WORKFLOW_CANONICALIZATION_ID,),
    "workflow.permit_snapshot.v1": (WORKFLOW_CANONICALIZATION_ID,),
    "incident.bundle_manifest.v1": (INCIDENT_BUNDLE_MANIFEST_ID,),
    "checkpoint.composite_hash.v1": (CHECKPOINT_COMPOSITE_HASH_ID,),
    "checkpoint.signature.v1": (CHECKPOINT_SIGNATURE_ID,),
    "checkpoint.tsa_imprint.v1": (CHECKPOINT_TSA_IMPRINT_ID,),
    "workflow_evidence.sibling_integrity.v1": (
        WORKFLOW_EVIDENCE_SIBLING_INTEGRITY_ID,
    ),
}

RELEASED_ARTIFACT_PATHS: dict[str, str] = {
    CLAIM_REGISTRY_ID: "claim_registry/v0.json",
    EXPORT_MANIFEST_INTEGRITY_ID: "semantics/export_manifest/integrity_v1.json",
    GOVERNANCE_RECORD_HASH_ID: "semantics/governance_chain/record_hash_v1.json",
    CLOSURE_FORMAT_V1_ID: "semantics/closure/format_v1.json",
    CLOSURE_FORMAT_V2_ID: "semantics/closure/format_v2.json",
    CLOSURE_DIGEST_RULES_ID: "semantics/closure/digest_rules_v1.json",
    PERMIT_BINDING_CANONICAL_REQUEST_ID: (
        "semantics/permit_binding/canonical_request_v1.json"
    ),
    WORKFLOW_CANONICALIZATION_ID: "semantics/workflow/canonicalization_v1.json",
    WORKFLOW_EVIDENCE_SIBLING_INTEGRITY_ID: (
        "semantics/workflow_evidence/sibling_integrity_v1.json"
    ),
    INCIDENT_BUNDLE_MANIFEST_ID: "semantics/incident/bundle_manifest_v2.json",
    CHECKPOINT_COMPOSITE_HASH_ID: "semantics/checkpoint/composite_hash_v1.json",
    CHECKPOINT_SIGNATURE_ID: "semantics/checkpoint/signature_v1.json",
    CHECKPOINT_TSA_IMPRINT_ID: "semantics/checkpoint/tsa_imprint_v1.json",
    LEGACY_PROFILE_ID: "semantics/profiles/pre_pinning_default_v0.json",
    AUTHORITY_ENVELOPE_V0_ID: "comparator_registry/v0.json",
}

RELEASED_ARTIFACT_HASHES: dict[str, str] = {
    CLAIM_REGISTRY_ID: CLAIM_REGISTRY_HASH,
    EXPORT_MANIFEST_INTEGRITY_ID: EXPORT_MANIFEST_INTEGRITY_HASH,
    GOVERNANCE_RECORD_HASH_ID: GOVERNANCE_RECORD_HASH_HASH,
    CLOSURE_FORMAT_V1_ID: CLOSURE_FORMAT_V1_HASH,
    CLOSURE_FORMAT_V2_ID: CLOSURE_FORMAT_V2_HASH,
    CLOSURE_DIGEST_RULES_ID: CLOSURE_DIGEST_RULES_HASH,
    PERMIT_BINDING_CANONICAL_REQUEST_ID: PERMIT_BINDING_CANONICAL_REQUEST_HASH,
    WORKFLOW_CANONICALIZATION_ID: WORKFLOW_CANONICALIZATION_HASH,
    WORKFLOW_EVIDENCE_SIBLING_INTEGRITY_ID: WORKFLOW_EVIDENCE_SIBLING_INTEGRITY_HASH,
    INCIDENT_BUNDLE_MANIFEST_ID: INCIDENT_BUNDLE_MANIFEST_HASH,
    CHECKPOINT_COMPOSITE_HASH_ID: CHECKPOINT_COMPOSITE_HASH_HASH,
    CHECKPOINT_SIGNATURE_ID: CHECKPOINT_SIGNATURE_HASH,
    CHECKPOINT_TSA_IMPRINT_ID: CHECKPOINT_TSA_IMPRINT_HASH,
    LEGACY_PROFILE_ID: LEGACY_PROFILE_HASH,
    AUTHORITY_ENVELOPE_V0_ID: AUTHORITY_ENVELOPE_V0_HASH,
}


@dataclass(frozen=True)
class SemanticImplementation:
    id: str
    hash: str
    kind: str
    record_hashers: dict[str, RecordHashV1] = field(default_factory=dict)
    closure_verifiers: dict[str, ClosureVerifier] = field(default_factory=dict)
    composite_hash: CompositeHash | None = None

    @property
    def key(self) -> SemanticsKey:
        return (self.id, self.hash)


@dataclass(frozen=True)
class ResolvedArtifact:
    id: str
    hash: str
    source: str
    status: str = "allowlisted"

    @property
    def key(self) -> SemanticsKey:
        return (self.id, self.hash)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "hash": self.hash,
            "source": self.source,
            "status": self.status,
        }


@dataclass(frozen=True)
class ClaimRequest:
    name: str
    required: bool = True


@dataclass(frozen=True)
class SemanticsFailure:
    verdict: str
    reason_code: str
    message: str
    claim_names: tuple[str, ...]
    top_level_error: str | None = None
    diagnostic: str | None = None
    integrity_error: bool = False


@dataclass(frozen=True)
class SemanticsDispatch:
    record_hashers: dict[str, RecordHashV1]
    closure_verifiers: dict[str, ClosureVerifier]
    composite_hash: CompositeHash | None


@dataclass(frozen=True)
class ResolvedSemantics:
    mode: str
    profile_id: str | None
    profile_hash: str | None
    requested_claims: tuple[ClaimRequest, ...]
    artifacts: dict[str, ResolvedArtifact]
    implementations: dict[SemanticsKey, SemanticImplementation]
    failure: SemanticsFailure | None = None
    diagnostics: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.failure is None

    def required_for(self, name: str) -> bool:
        for request in self.requested_claims:
            if request.name == name:
                return request.required
        return True

    def requested_names(self) -> set[str]:
        return {request.name for request in self.requested_claims}

    def semantics_for_claim(self, name: str) -> list[dict[str, str | None]]:
        ids = CLAIM_SEMANTICS.get(name, ())
        return [
            {
                "id": semantic_id,
                "hash": (
                    self.artifacts[semantic_id].hash
                    if semantic_id in self.artifacts
                    else None
                ),
            }
            for semantic_id in ids
        ]

    def report_semantics(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "mode": self.mode,
            "profile_id": self.profile_id,
            "profile_hash": self.profile_hash,
        }
        if self.mode == "legacy_unpinned":
            payload["warning"] = LEGACY_PROFILE_WARNING
        pins = [artifact.to_dict() for artifact in self.artifacts.values()]
        if pins:
            payload["pins"] = pins
        return payload

    def dispatch(self) -> SemanticsDispatch:
        record_hashers: dict[str, RecordHashV1] = {}
        closure_verifiers: dict[str, ClosureVerifier] = {}
        composite_hash: CompositeHash | None = None
        for artifact in self.artifacts.values():
            impl = self.implementations.get(artifact.key)
            if impl is None:
                continue
            record_hashers.update(impl.record_hashers)
            closure_verifiers.update(impl.closure_verifiers)
            if impl.composite_hash is not None:
                composite_hash = impl.composite_hash
        return SemanticsDispatch(
            record_hashers=record_hashers,
            closure_verifiers=closure_verifiers,
            composite_hash=composite_hash,
        )


def _content_hash(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _product_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _keel_permit_root() -> Path:
    return _product_root() / "keel-permit"


def candidate_registry_paths() -> list[Path]:
    paths: list[Path] = []
    env_path = os.getenv("KEEL_CLAIM_REGISTRY")
    if env_path:
        paths.append(Path(env_path).expanduser())

    package_root = Path(__file__).resolve().parents[1]
    product_root = Path(__file__).resolve().parents[2]
    paths.extend(
        [
            product_root / "keel-permit" / "claim_registry" / "v0.json",
            package_root / ".." / "keel-permit" / "claim_registry" / "v0.json",
        ]
    )
    return paths


def _candidate_local_paths(relative_path: str, *, pack_root: Path | None) -> list[Path]:
    rel = Path(relative_path)
    paths: list[Path] = []
    if pack_root is not None and not rel.is_absolute():
        paths.append(pack_root / rel)
    elif rel.is_absolute():
        paths.append(rel)
    paths.append(_keel_permit_root() / rel)
    return paths


def _read_bundled_claim_registry() -> bytes | None:
    try:
        bundled = resources.files("keel_verifier").joinpath(
            "data/claim_registry_v0.json"
        )
        return bundled.read_bytes()
    except Exception:
        return None


def _read_bundled_legacy_profile() -> bytes | None:
    try:
        bundled = resources.files("keel_verifier").joinpath(
            "data/semantics/profiles/pre_pinning_default_v0.json"
        )
        return bundled.read_bytes()
    except Exception:
        return None


def _resolve_artifact_bytes(
    ref: dict[str, Any],
    *,
    pack_root: Path | None,
) -> tuple[bytes | None, str | None, str | None]:
    content_b64 = ref.get("content_b64")
    path_value = ref.get("path")
    if isinstance(content_b64, str):
        try:
            return base64.b64decode(content_b64, validate=True), "inline content_b64", None
        except Exception as exc:
            return None, None, f"invalid content_b64 for {ref.get('id')!r}: {exc}"

    if isinstance(path_value, str) and path_value:
        errors: list[str] = []
        for path in _candidate_local_paths(path_value, pack_root=pack_root):
            try:
                if path.exists():
                    return path.read_bytes(), str(path), None
            except OSError as exc:
                errors.append(f"{path}: {exc}")
        if ref.get("id") == CLAIM_REGISTRY_ID:
            bundled = _read_bundled_claim_registry()
            if bundled is not None:
                return bundled, "bundled keel_verifier/data/claim_registry_v0.json", None
        if ref.get("id") == LEGACY_PROFILE_ID:
            bundled = _read_bundled_legacy_profile()
            if bundled is not None:
                return (
                    bundled,
                    "bundled keel_verifier/data/semantics/profiles/pre_pinning_default_v0.json",
                    None,
                )
        details = "; ".join(errors)
        suffix = f" ({details})" if details else ""
        return None, None, f"could not resolve path {path_value!r}{suffix}"

    return None, None, "artifact reference must include content_b64 or path"


def _parse_json_bytes(data: bytes, *, source: str) -> dict[str, Any] | None:
    payload = json.loads(data.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{source} top-level JSON must be an object")
    return payload


def _reference_id(ref: dict[str, Any]) -> str | None:
    value = ref.get("id")
    return value if isinstance(value, str) and value else None


def _reference_hash(ref: dict[str, Any]) -> str | None:
    value = ref.get("hash")
    return value if isinstance(value, str) and value else None


def _validate_artifact_identity(
    *,
    artifact_id: str,
    payload: dict[str, Any],
) -> None:
    parsed_id = payload.get("id")
    if isinstance(parsed_id, str) and parsed_id != artifact_id:
        raise ValueError(
            f"artifact id mismatch: reference id {artifact_id!r}, JSON id {parsed_id!r}"
        )
    if artifact_id == CLAIM_REGISTRY_ID and payload.get("version") != CLAIM_REGISTRY_VERSION:
        raise ValueError(
            f"claim registry version {payload.get('version')!r}, expected "
            f"{CLAIM_REGISTRY_VERSION!r}"
        )
    if artifact_id == AUTHORITY_ENVELOPE_V0_ID and payload.get("version") != artifact_id:
        raise ValueError(
            f"comparator registry version {payload.get('version')!r}, expected "
            f"{artifact_id!r}"
        )


def _resolve_reference(
    ref: dict[str, Any],
    *,
    pack_root: Path | None,
    source_label: str,
) -> tuple[ResolvedArtifact | None, dict[str, Any] | None, SemanticsFailure | None]:
    artifact_id = _reference_id(ref)
    declared_hash = _reference_hash(ref)
    if artifact_id is None or declared_hash is None:
        return (
            None,
            None,
            SemanticsFailure(
                verdict="insufficient_evidence",
                reason_code="SEMANTIC_PIN_UNRESOLVED",
                message=f"{source_label} must include id and hash",
                claim_names=(),
            ),
        )

    raw, raw_source, error = _resolve_artifact_bytes(ref, pack_root=pack_root)
    if raw is None or raw_source is None:
        return (
            None,
            None,
            SemanticsFailure(
                verdict="insufficient_evidence",
                reason_code="SEMANTIC_PIN_UNRESOLVED",
                message=f"{artifact_id} unresolved: {error}",
                claim_names=(),
            ),
        )

    actual_hash = _content_hash(raw)
    if actual_hash != declared_hash:
        message = (
            f"{artifact_id} hash mismatch: declared={declared_hash} "
            f"actual={actual_hash}"
        )
        return (
            ResolvedArtifact(
                id=artifact_id,
                hash=declared_hash,
                source=source_label,
                status="hash_mismatch",
            ),
            None,
            SemanticsFailure(
                verdict="insufficient_evidence",
                reason_code="SEMANTIC_PIN_HASH_MISMATCH",
                message=message,
                claim_names=(),
                top_level_error=message,
                diagnostic=message,
                integrity_error=True,
            ),
        )

    try:
        payload = _parse_json_bytes(raw, source=raw_source)
        assert payload is not None
        _validate_artifact_identity(artifact_id=artifact_id, payload=payload)
    except Exception as exc:
        return (
            ResolvedArtifact(
                id=artifact_id,
                hash=declared_hash,
                source=source_label,
                status="unresolved",
            ),
            None,
            SemanticsFailure(
                verdict="insufficient_evidence",
                reason_code="SEMANTIC_PIN_UNRESOLVED",
                message=f"{artifact_id} could not be parsed: {exc}",
                claim_names=(),
            ),
        )

    return (
        ResolvedArtifact(id=artifact_id, hash=declared_hash, source=source_label),
        payload,
        None,
    )


def _allowlist_lookup(
    artifact: ResolvedArtifact,
    *,
    allowlist: dict[SemanticsKey, SemanticImplementation],
) -> SemanticsFailure | None:
    if artifact.key not in allowlist:
        return SemanticsFailure(
            verdict="unverifiable_scope",
            reason_code="SEMANTIC_PIN_NOT_ALLOWLISTED",
            message=f"{artifact.id} with hash {artifact.hash} is not allowlisted",
            claim_names=(),
        )
    return None


def _claim_requests_from_claim_set(
    claim_set: dict[str, Any],
    *,
    registry_payload: dict[str, Any],
) -> tuple[ClaimRequest, ...]:
    if claim_set.get("version") != CLAIM_REGISTRY_VERSION:
        raise ValueError(
            f"claim_set.version must be {CLAIM_REGISTRY_VERSION!r}"
        )
    claims_raw = claim_set.get("claims")
    if not isinstance(claims_raw, list) or not claims_raw:
        raise ValueError("claim_set.claims must be a non-empty array")

    registry_claims = {
        item.get("name")
        for item in registry_payload.get("claims", [])
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    requests: list[ClaimRequest] = []
    for index, item in enumerate(claims_raw):
        if not isinstance(item, dict):
            raise ValueError(f"claim_set.claims[{index}] must be an object")
        name = item.get("name")
        required = item.get("required")
        if not isinstance(name, str) or not name:
            raise ValueError(f"claim_set.claims[{index}].name must be a string")
        if not isinstance(required, bool):
            raise ValueError(f"claim_set.claims[{index}].required must be a boolean")
        if name not in registry_claims:
            raise ValueError(f"claim {name!r} is not in the resolved registry")
        requests.append(ClaimRequest(name=name, required=required))
    return tuple(requests)


def _legacy_profile_ref() -> dict[str, str]:
    return {
        "id": LEGACY_PROFILE_ID,
        "hash": LEGACY_PROFILE_HASH,
        "path": RELEASED_ARTIFACT_PATHS[LEGACY_PROFILE_ID],
    }


def _all_known_claim_requests() -> tuple[ClaimRequest, ...]:
    return tuple(ClaimRequest(name=name, required=True) for name in CLAIM_SEMANTICS)


def _with_failure_claims(
    failure: SemanticsFailure,
    *,
    claim_names: tuple[str, ...],
) -> SemanticsFailure:
    return SemanticsFailure(
        verdict=failure.verdict,
        reason_code=failure.reason_code,
        message=failure.message,
        claim_names=claim_names,
        top_level_error=failure.top_level_error,
        diagnostic=failure.diagnostic,
        integrity_error=failure.integrity_error,
    )


def resolve_legacy_semantics(
    *,
    allowlist: dict[SemanticsKey, SemanticImplementation],
) -> ResolvedSemantics:
    profile_artifact, profile_payload, failure = _resolve_reference(
        _legacy_profile_ref(),
        pack_root=None,
        source_label="legacy profile keel.pre_pinning_default.v0",
    )
    artifacts: dict[str, ResolvedArtifact] = {}
    if profile_artifact is not None:
        artifacts[profile_artifact.id] = profile_artifact
    if failure is not None or profile_payload is None:
        failure = failure or SemanticsFailure(
            verdict="insufficient_evidence",
            reason_code="SEMANTIC_PROFILE_UNRESOLVED",
            message="legacy semantic profile could not be resolved",
            claim_names=tuple(CLAIM_SEMANTICS),
        )
        return ResolvedSemantics(
            mode="legacy_unpinned",
            profile_id=LEGACY_PROFILE_ID,
            profile_hash=LEGACY_PROFILE_HASH,
            requested_claims=_all_known_claim_requests(),
            artifacts=artifacts,
            implementations=allowlist,
            failure=_with_failure_claims(failure, claim_names=tuple(CLAIM_SEMANTICS)),
        )
    failure = _allowlist_lookup(profile_artifact, allowlist=allowlist)
    if failure is not None:
        return ResolvedSemantics(
            mode="legacy_unpinned",
            profile_id=LEGACY_PROFILE_ID,
            profile_hash=LEGACY_PROFILE_HASH,
            requested_claims=_all_known_claim_requests(),
            artifacts=artifacts,
            implementations=allowlist,
            failure=_with_failure_claims(failure, claim_names=tuple(CLAIM_SEMANTICS)),
        )

    body = profile_payload.get("body")
    components = body.get("components") if isinstance(body, dict) else None
    if not isinstance(components, list):
        failure = SemanticsFailure(
            verdict="insufficient_evidence",
            reason_code="SEMANTIC_PROFILE_UNRESOLVED",
            message="legacy semantic profile has no component list",
            claim_names=tuple(CLAIM_SEMANTICS),
        )
        return ResolvedSemantics(
            mode="legacy_unpinned",
            profile_id=LEGACY_PROFILE_ID,
            profile_hash=LEGACY_PROFILE_HASH,
            requested_claims=_all_known_claim_requests(),
            artifacts=artifacts,
            implementations=allowlist,
            failure=failure,
        )

    for index, component in enumerate(components):
        if not isinstance(component, dict):
            continue
        component_id = _reference_id(component)
        component_hash = _reference_hash(component)
        if component_id is None or component_hash is None:
            failure = SemanticsFailure(
                verdict="insufficient_evidence",
                reason_code="SEMANTIC_PROFILE_UNRESOLVED",
                message=f"legacy profile component {index} has no id/hash",
                claim_names=tuple(CLAIM_SEMANTICS),
            )
            return ResolvedSemantics(
                mode="legacy_unpinned",
                profile_id=LEGACY_PROFILE_ID,
                profile_hash=LEGACY_PROFILE_HASH,
                requested_claims=_all_known_claim_requests(),
                artifacts=artifacts,
                implementations=allowlist,
                failure=failure,
            )
        artifact = ResolvedArtifact(
            id=component_id,
            hash=component_hash,
            source=f"legacy profile components[{index}]",
        )
        failure = _allowlist_lookup(artifact, allowlist=allowlist)
        if failure is not None:
            return ResolvedSemantics(
                mode="legacy_unpinned",
                profile_id=LEGACY_PROFILE_ID,
                profile_hash=LEGACY_PROFILE_HASH,
                requested_claims=_all_known_claim_requests(),
                artifacts=artifacts,
                implementations=allowlist,
                failure=_with_failure_claims(
                    failure,
                    claim_names=tuple(CLAIM_SEMANTICS),
                ),
            )
        artifacts[component_id] = artifact

    return ResolvedSemantics(
        mode="legacy_unpinned",
        profile_id=LEGACY_PROFILE_ID,
        profile_hash=LEGACY_PROFILE_HASH,
        requested_claims=_all_known_claim_requests(),
        artifacts=artifacts,
        implementations=allowlist,
    )


def resolve_pack_semantics(
    pack: dict[str, Any],
    *,
    pack_root: Path | None,
    default_claim_names: tuple[str, ...],
    allowlist: dict[SemanticsKey, SemanticImplementation],
) -> ResolvedSemantics:
    claim_set = pack.get("claim_set")
    semantics_pins = pack.get("semantics_pins")
    if claim_set is None and semantics_pins is None:
        return resolve_legacy_semantics(allowlist=allowlist)

    fallback_claims = default_claim_names or tuple(CLAIM_SEMANTICS)
    artifacts: dict[str, ResolvedArtifact] = {}
    requests: tuple[ClaimRequest, ...] = tuple(
        ClaimRequest(name=name, required=True) for name in fallback_claims
    )

    if not isinstance(claim_set, dict):
        failure = SemanticsFailure(
            verdict="insufficient_evidence",
            reason_code="CLAIM_REGISTRY_UNRESOLVED",
            message="pinned pack is missing claim_set",
            claim_names=fallback_claims,
        )
        return ResolvedSemantics(
            mode="pinned",
            profile_id=None,
            profile_hash=None,
            requested_claims=requests,
            artifacts=artifacts,
            implementations=allowlist,
            failure=failure,
        )
    if not isinstance(semantics_pins, dict):
        claim_names = tuple(
            item.get("name")
            for item in claim_set.get("claims", [])
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        ) or fallback_claims
        requests = tuple(ClaimRequest(name=name, required=True) for name in claim_names)
        failure = SemanticsFailure(
            verdict="insufficient_evidence",
            reason_code="SEMANTIC_PIN_MISSING",
            message="pinned pack is missing semantics_pins",
            claim_names=claim_names,
        )
        return ResolvedSemantics(
            mode="pinned",
            profile_id=None,
            profile_hash=None,
            requested_claims=requests,
            artifacts=artifacts,
            implementations=allowlist,
            failure=failure,
        )

    registry_ref = claim_set.get("registry")
    if not isinstance(registry_ref, dict):
        failure = SemanticsFailure(
            verdict="insufficient_evidence",
            reason_code="CLAIM_REGISTRY_UNRESOLVED",
            message="claim_set.registry is missing",
            claim_names=fallback_claims,
        )
        return ResolvedSemantics(
            mode="pinned",
            profile_id=None,
            profile_hash=None,
            requested_claims=requests,
            artifacts=artifacts,
            implementations=allowlist,
            failure=failure,
        )

    registry_artifact, registry_payload, failure = _resolve_reference(
        registry_ref,
        pack_root=pack_root,
        source_label="claim_set.registry",
    )
    if registry_artifact is not None:
        artifacts[registry_artifact.id] = registry_artifact
    if failure is not None or registry_payload is None:
        failure = failure or SemanticsFailure(
            verdict="insufficient_evidence",
            reason_code="CLAIM_REGISTRY_UNRESOLVED",
            message="claim registry could not be resolved",
            claim_names=fallback_claims,
        )
        return ResolvedSemantics(
            mode="pinned",
            profile_id=None,
            profile_hash=None,
            requested_claims=requests,
            artifacts=artifacts,
            implementations=allowlist,
            failure=_with_failure_claims(failure, claim_names=fallback_claims),
            diagnostics=tuple([failure.diagnostic] if failure.diagnostic else []),
        )
    failure = _allowlist_lookup(registry_artifact, allowlist=allowlist)
    if failure is not None:
        return ResolvedSemantics(
            mode="pinned",
            profile_id=None,
            profile_hash=None,
            requested_claims=requests,
            artifacts=artifacts,
            implementations=allowlist,
            failure=_with_failure_claims(failure, claim_names=fallback_claims),
        )

    try:
        requests = _claim_requests_from_claim_set(
            claim_set,
            registry_payload=registry_payload,
        )
    except ValueError as exc:
        failure = SemanticsFailure(
            verdict="insufficient_evidence",
            reason_code="CLAIM_REGISTRY_UNRESOLVED",
            message=str(exc),
            claim_names=fallback_claims,
        )
        return ResolvedSemantics(
            mode="pinned",
            profile_id=None,
            profile_hash=None,
            requested_claims=requests,
            artifacts=artifacts,
            implementations=allowlist,
            failure=failure,
        )

    requested_claim_names = tuple(request.name for request in requests)
    if semantics_pins.get("version") != SEMANTICS_PINS_VERSION:
        failure = SemanticsFailure(
            verdict="insufficient_evidence",
            reason_code="SEMANTIC_PIN_UNRESOLVED",
            message=f"semantics_pins.version must be {SEMANTICS_PINS_VERSION!r}",
            claim_names=requested_claim_names,
        )
        return ResolvedSemantics(
            mode="pinned",
            profile_id=None,
            profile_hash=None,
            requested_claims=requests,
            artifacts=artifacts,
            implementations=allowlist,
            failure=failure,
        )
    if semantics_pins.get("mode") != "pinned":
        failure = SemanticsFailure(
            verdict="insufficient_evidence",
            reason_code="SEMANTIC_PIN_UNRESOLVED",
            message="semantics_pins.mode must be 'pinned'",
            claim_names=requested_claim_names,
        )
        return ResolvedSemantics(
            mode="pinned",
            profile_id=None,
            profile_hash=None,
            requested_claims=requests,
            artifacts=artifacts,
            implementations=allowlist,
            failure=failure,
        )

    declared_refs: dict[str, dict[str, Any]] = {}
    profile_id: str | None = None
    profile_hash: str | None = None
    profile_ref = semantics_pins.get("profile")
    if isinstance(profile_ref, dict):
        profile_artifact, profile_payload, failure = _resolve_reference(
            profile_ref,
            pack_root=pack_root,
            source_label="semantics_pins.profile",
        )
        if profile_artifact is not None:
            artifacts[profile_artifact.id] = profile_artifact
            profile_id = profile_artifact.id
            profile_hash = profile_artifact.hash
        if failure is not None or profile_payload is None:
            failure = failure or SemanticsFailure(
                verdict="insufficient_evidence",
                reason_code="SEMANTIC_PROFILE_UNRESOLVED",
                message="semantic profile could not be resolved",
                claim_names=requested_claim_names,
            )
            return ResolvedSemantics(
                mode="pinned",
                profile_id=profile_id,
                profile_hash=profile_hash,
                requested_claims=requests,
                artifacts=artifacts,
                implementations=allowlist,
                failure=_with_failure_claims(
                    failure,
                    claim_names=requested_claim_names,
                ),
                diagnostics=tuple([failure.diagnostic] if failure.diagnostic else []),
            )
        failure = _allowlist_lookup(profile_artifact, allowlist=allowlist)
        if failure is not None:
            return ResolvedSemantics(
                mode="pinned",
                profile_id=profile_id,
                profile_hash=profile_hash,
                requested_claims=requests,
                artifacts=artifacts,
                implementations=allowlist,
                failure=_with_failure_claims(
                    failure,
                    claim_names=requested_claim_names,
                ),
            )
        body = profile_payload.get("body")
        components = body.get("components") if isinstance(body, dict) else None
        if isinstance(components, list):
            for index, component in enumerate(components):
                if isinstance(component, dict) and isinstance(component.get("id"), str):
                    declared_refs.setdefault(
                        component["id"],
                        {**component, "_source_label": f"profile components[{index}]"},
                    )

    artifacts_raw = semantics_pins.get("artifacts")
    if not isinstance(artifacts_raw, list):
        artifacts_raw = []
    for index, ref in enumerate(artifacts_raw):
        if isinstance(ref, dict) and isinstance(ref.get("id"), str):
            declared_refs[ref["id"]] = {
                **ref,
                "_source_label": f"semantics_pins.artifacts[{index}]",
            }

    for claim_name in requested_claim_names:
        if claim_name not in CLAIM_SEMANTICS:
            failure = SemanticsFailure(
                verdict="unverifiable_scope",
                reason_code="SEMANTIC_PIN_NOT_ALLOWLISTED",
                message=f"no verifier semantic mapping for claim {claim_name!r}",
                claim_names=(claim_name,),
            )
            return ResolvedSemantics(
                mode="pinned",
                profile_id=profile_id,
                profile_hash=profile_hash,
                requested_claims=requests,
                artifacts=artifacts,
                implementations=allowlist,
                failure=failure,
            )
        for semantic_id in CLAIM_SEMANTICS[claim_name]:
            if semantic_id in artifacts:
                continue
            ref = declared_refs.get(semantic_id)
            if ref is None:
                failure = SemanticsFailure(
                    verdict="insufficient_evidence",
                    reason_code="SEMANTIC_PIN_MISSING",
                    message=f"required semantic pin missing: {semantic_id}",
                    claim_names=(claim_name,),
                )
                return ResolvedSemantics(
                    mode="pinned",
                    profile_id=profile_id,
                    profile_hash=profile_hash,
                    requested_claims=requests,
                    artifacts=artifacts,
                    implementations=allowlist,
                    failure=failure,
                )
            source_label = str(ref.get("_source_label") or f"semantics[{semantic_id}]")
            artifact, _payload, failure = _resolve_reference(
                ref,
                pack_root=pack_root,
                source_label=source_label,
            )
            if artifact is not None:
                artifacts[artifact.id] = artifact
            if failure is not None or artifact is None:
                failure = failure or SemanticsFailure(
                    verdict="insufficient_evidence",
                    reason_code="SEMANTIC_PIN_UNRESOLVED",
                    message=f"required semantic pin unresolved: {semantic_id}",
                    claim_names=(claim_name,),
                )
                return ResolvedSemantics(
                    mode="pinned",
                    profile_id=profile_id,
                    profile_hash=profile_hash,
                    requested_claims=requests,
                    artifacts=artifacts,
                    implementations=allowlist,
                    failure=_with_failure_claims(failure, claim_names=(claim_name,)),
                    diagnostics=tuple([failure.diagnostic] if failure.diagnostic else []),
                )
            failure = _allowlist_lookup(artifact, allowlist=allowlist)
            if failure is not None:
                return ResolvedSemantics(
                    mode="pinned",
                    profile_id=profile_id,
                    profile_hash=profile_hash,
                    requested_claims=requests,
                    artifacts=artifacts,
                    implementations=allowlist,
                    failure=_with_failure_claims(failure, claim_names=(claim_name,)),
                )

    return ResolvedSemantics(
        mode="pinned",
        profile_id=profile_id,
        profile_hash=profile_hash,
        requested_claims=requests,
        artifacts=artifacts,
        implementations=allowlist,
    )


def make_permanent_allowlist(
    *,
    record_hash_v1: RecordHashV1,
    closure_v1: ClosureVerifier,
    closure_v2: ClosureVerifier,
    composite_hash: CompositeHash,
) -> dict[SemanticsKey, SemanticImplementation]:
    entries = [
        SemanticImplementation(
            CLAIM_REGISTRY_ID,
            CLAIM_REGISTRY_HASH,
            "claim_registry",
        ),
        SemanticImplementation(
            EXPORT_MANIFEST_INTEGRITY_ID,
            EXPORT_MANIFEST_INTEGRITY_HASH,
            "export_manifest_integrity",
        ),
        SemanticImplementation(
            GOVERNANCE_RECORD_HASH_ID,
            GOVERNANCE_RECORD_HASH_HASH,
            "governance_chain_record_hash",
            record_hashers={"v1": record_hash_v1},
        ),
        SemanticImplementation(
            CLOSURE_FORMAT_V1_ID,
            CLOSURE_FORMAT_V1_HASH,
            "closure_format",
            closure_verifiers={"closure_v1": closure_v1},
        ),
        SemanticImplementation(
            CLOSURE_FORMAT_V2_ID,
            CLOSURE_FORMAT_V2_HASH,
            "closure_format",
            closure_verifiers={"closure_v2": closure_v2},
        ),
        SemanticImplementation(
            CLOSURE_DIGEST_RULES_ID,
            CLOSURE_DIGEST_RULES_HASH,
            "closure_digest_rules",
        ),
        SemanticImplementation(
            PERMIT_BINDING_CANONICAL_REQUEST_ID,
            PERMIT_BINDING_CANONICAL_REQUEST_HASH,
            "permit_binding_canonical_request",
        ),
        SemanticImplementation(
            WORKFLOW_CANONICALIZATION_ID,
            WORKFLOW_CANONICALIZATION_HASH,
            "workflow_canonicalization",
        ),
        SemanticImplementation(
            WORKFLOW_EVIDENCE_SIBLING_INTEGRITY_ID,
            WORKFLOW_EVIDENCE_SIBLING_INTEGRITY_HASH,
            "workflow_evidence_sibling_integrity",
        ),
        SemanticImplementation(
            INCIDENT_BUNDLE_MANIFEST_ID,
            INCIDENT_BUNDLE_MANIFEST_HASH,
            "incident_bundle_manifest",
        ),
        SemanticImplementation(
            CHECKPOINT_COMPOSITE_HASH_ID,
            CHECKPOINT_COMPOSITE_HASH_HASH,
            "checkpoint_composite_hash",
            composite_hash=composite_hash,
        ),
        SemanticImplementation(
            CHECKPOINT_SIGNATURE_ID,
            CHECKPOINT_SIGNATURE_HASH,
            "checkpoint_signature",
        ),
        SemanticImplementation(
            CHECKPOINT_TSA_IMPRINT_ID,
            CHECKPOINT_TSA_IMPRINT_HASH,
            "checkpoint_tsa_imprint",
        ),
        SemanticImplementation(
            LEGACY_PROFILE_ID,
            LEGACY_PROFILE_HASH,
            "semantic_profile",
        ),
        SemanticImplementation(
            AUTHORITY_ENVELOPE_V0_ID,
            AUTHORITY_ENVELOPE_V0_HASH,
            "authority_envelope_comparator",
        ),
    ]
    return {entry.key: entry for entry in entries}
