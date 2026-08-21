"""Structured verifier verdicts.

The verdict enum and claim names are loaded from the current claim registry
rather than duplicated in code. Historical registries remain available to the
pack-pinned semantics resolver. The bundled current copy is the
verifier-build-time source of truth; set KEEL_CLAIM_REGISTRY for explicit
offline drift checks against a source checkout.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from functools import lru_cache
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _metadata_version
from importlib import resources
from pathlib import Path
from typing import Any

from keel_verifier.semantics import (
    CLAIM_SEMANTICS,
    LEGACY_PROFILE_HASH,
    LEGACY_PROFILE_ID,
    LEGACY_PROFILE_WARNING,
    RELEASED_ARTIFACT_HASHES,
)

VERDICT_SCHEMA_ID = "keel.verifier.verdicts/v0"
CLAIM_REGISTRY_VERSION = "verifier-claims.v6"
CLAIM_REGISTRY_V1_ID = "keel.verifier_claim_registry.v1"
CLAIM_REGISTRY_V1_VERSION = "verifier-claims.v1"


def _source_tree_version() -> str | None:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    if not pyproject.is_file():
        return None
    current_section: str | None = None
    for raw_line in pyproject.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line.strip("[]")
            continue
        if current_section == "project" and line.startswith("version "):
            _, value = line.split("=", 1)
            return value.strip().strip('"')
    return None


def verifier_version() -> str:
    source_tree_version = _source_tree_version()
    if source_tree_version is not None:
        return source_tree_version
    try:
        return _metadata_version("keel-verifier")
    except PackageNotFoundError:
        return "unknown"


@dataclass(frozen=True)
class ClaimDefinition:
    name: str
    verdict_enum: tuple[str, ...]
    does_not_establish: tuple[str, ...] = ()


@dataclass(frozen=True)
class ClaimRegistry:
    version: str
    verdict_enum: tuple[str, ...]
    claims: dict[str, ClaimDefinition]
    source: str

    def verdict(self, value: str) -> str:
        if value not in self.verdict_enum:
            raise ValueError(
                f"{value!r} is not in {self.version} verdict enum from {self.source}"
            )
        return value

    def claim(self, name: str) -> ClaimDefinition:
        try:
            return self.claims[name]
        except KeyError as exc:
            raise ValueError(
                f"{name!r} is not defined in {self.version} claim registry from {self.source}"
            ) from exc


def _candidate_registry_paths() -> list[Path]:
    env_path = os.getenv("KEEL_CLAIM_REGISTRY")
    return [Path(env_path).expanduser()] if env_path else []


def _load_registry_payload() -> tuple[dict[str, Any], str]:
    for path in _candidate_registry_paths():
        try:
            if path.exists():
                return json.loads(path.read_text(encoding="utf-8")), str(path)
        except OSError:
            continue

    try:
        bundled = resources.files("keel_verifier").joinpath(
            "data/claim_registry/v6.json"
        )
        return json.loads(bundled.read_text(encoding="utf-8")), str(bundled)
    except Exception as exc:
        raise RuntimeError(
            "could not load the current verifier claim registry; set KEEL_CLAIM_REGISTRY"
        ) from exc


def _compose_registry_payload(
    payload: dict[str, Any],
    *,
    source: str,
) -> dict[str, Any]:
    """Resolve a digest-pinned registry chain without mutating any artifact."""

    extension = payload.get("extends")
    if not isinstance(extension, dict):
        return payload
    artifact_id = extension.get("artifact_id")
    base_version = extension.get("version")
    if not isinstance(artifact_id, str) or not isinstance(base_version, str):
        raise ValueError(f"claim registry at {source} has an unsupported base")
    prefix = "keel.verifier_claim_registry.v"
    if not artifact_id.startswith(prefix):
        raise ValueError(f"claim registry at {source} has an unsupported base")
    suffix = artifact_id.removeprefix(prefix)
    if not suffix.isdigit():
        raise ValueError(f"claim registry at {source} has an unsupported base")
    try:
        base_resource = resources.files("keel_verifier").joinpath(
            f"data/claim_registry/v{suffix}.json"
        )
        base_raw = base_resource.read_bytes()
        base_source = str(base_resource)
    except Exception as exc:
        raise RuntimeError(
            f"could not load verifier claim registry v{suffix} base"
        ) from exc
    expected_digest = str(extension.get("sha256") or "")
    actual_digest = hashlib.sha256(base_raw).hexdigest()
    if expected_digest != actual_digest:
        raise ValueError(
            f"claim registry at {source} pins v{suffix} digest {expected_digest!r}, "
            f"but {base_source} has {actual_digest!r}"
        )
    base = json.loads(base_raw)
    if base.get("version") != base_version:
        raise ValueError(f"claim registry base at {base_source} has wrong version")
    base = _compose_registry_payload(base, source=base_source)
    base_claims = base.get("claims")
    extension_claims = payload.get("claims")
    if not isinstance(base_claims, list) or not isinstance(extension_claims, list):
        raise ValueError(f"claim registry at {source} has invalid extension claims")
    base_names = {
        item.get("name")
        for item in base_claims
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    extension_names = [
        item.get("name")
        for item in extension_claims
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    ]
    duplicates = sorted(base_names.intersection(extension_names))
    if duplicates:
        raise ValueError(
            f"claim registry at {source} duplicates base claims: {duplicates}"
        )
    return {
        **payload,
        "claims": [*base_claims, *extension_claims],
    }


@lru_cache(maxsize=1)
def load_claim_registry() -> ClaimRegistry:
    payload, source = _load_registry_payload()
    payload = _compose_registry_payload(payload, source=source)
    version = payload.get("version")
    if version != CLAIM_REGISTRY_VERSION:
        raise ValueError(
            f"claim registry at {source} has version {version!r}, expected "
            f"{CLAIM_REGISTRY_VERSION!r}"
        )
    enum_raw = payload.get("verdict_enum")
    if not isinstance(enum_raw, list) or not all(
        isinstance(item, str) for item in enum_raw
    ):
        raise ValueError(f"claim registry at {source} has invalid verdict_enum")
    claims_raw = payload.get("claims")
    if not isinstance(claims_raw, list):
        raise ValueError(f"claim registry at {source} has invalid claims")

    verdict_enum = tuple(enum_raw)
    claims: dict[str, ClaimDefinition] = {}
    for item in claims_raw:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            continue
        claim_enum_raw = item.get("verdict_enum", enum_raw)
        if not isinstance(claim_enum_raw, list) or not all(
            isinstance(value, str) for value in claim_enum_raw
        ):
            raise ValueError(
                f"claim registry at {source} has invalid verdict_enum for "
                f"{item.get('name')!r}"
            )
        claims[item["name"]] = ClaimDefinition(
            name=item["name"],
            verdict_enum=tuple(claim_enum_raw),
            does_not_establish=tuple(
                value
                for value in item.get("does_not_establish", [])
                if isinstance(value, str) and value
            ),
        )
    return ClaimRegistry(
        version=version,
        verdict_enum=verdict_enum,
        claims=claims,
        source=source,
    )


def verdict_value(value: str) -> str:
    return load_claim_registry().verdict(value)


def _clean_dict(value: dict[str, Any]) -> dict[str, Any]:
    cleaned: dict[str, Any] = {}
    for key, item in value.items():
        if item is None:
            continue
        if isinstance(item, list) and not item:
            continue
        if isinstance(item, dict) and not item:
            continue
        cleaned[key] = item
    return cleaned


def legacy_semantics() -> dict[str, Any]:
    return {
        "mode": "legacy_unpinned",
        "profile_id": LEGACY_PROFILE_ID,
        "profile_hash": LEGACY_PROFILE_HASH,
        "warning": LEGACY_PROFILE_WARNING,
    }


def claim_semantics(name: str) -> list[dict[str, Any]]:
    load_claim_registry().claim(name)
    return [
        {"id": semantic_id, "hash": RELEASED_ARTIFACT_HASHES.get(semantic_id)}
        for semantic_id in CLAIM_SEMANTICS[name]
    ]


@dataclass(frozen=True)
class VerdictSubject:
    type: str
    id: str | None
    verdict: str
    reason_code: str | None = None
    message: str | None = None
    evidence: list[str] = field(default_factory=list)
    required: bool = True

    def __post_init__(self) -> None:
        verdict_value(self.verdict)

    def to_dict(self) -> dict[str, Any]:
        return _clean_dict(
            {
                "type": self.type,
                "id": self.id,
                "verdict": self.verdict,
                "required": self.required,
                "reason_code": self.reason_code,
                "message": self.message,
                "evidence": list(self.evidence),
                "verifier_version": verifier_version(),
            }
        )


def aggregate_subject_verdicts(subjects: list[VerdictSubject]) -> str:
    evaluable = [subject for subject in subjects if subject.required]
    if not evaluable:
        return verdict_value("insufficient_evidence")
    if any(subject.verdict == verdict_value("disproved") for subject in evaluable):
        return verdict_value("disproved")
    if any(
        subject.verdict == verdict_value("unverifiable_scope")
        for subject in evaluable
    ):
        return verdict_value("unverifiable_scope")
    if any(
        subject.verdict == verdict_value("insufficient_evidence")
        for subject in evaluable
    ):
        return verdict_value("insufficient_evidence")
    return verdict_value("supported")


@dataclass(frozen=True)
class ClaimVerdict:
    name: str
    subjects: list[VerdictSubject] = field(default_factory=list)
    required: bool = True
    verdict: str | None = None
    semantics: list[dict[str, Any]] | None = None
    evidence: list[str] = field(default_factory=list)
    does_not_establish: list[str] | None = None
    epistemic_state: dict[str, str] | None = None
    reason_code: str | None = None
    message: str | None = None
    diagnostics: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        load_claim_registry().claim(self.name)
        if self.verdict is not None:
            verdict_value(self.verdict)

    @property
    def aggregate_verdict(self) -> str:
        if self.verdict is not None:
            return self.verdict
        return aggregate_subject_verdicts(self.subjects)

    def to_dict(self) -> dict[str, Any]:
        definition = load_claim_registry().claim(self.name)
        subject_dicts = [subject.to_dict() for subject in self.subjects]
        reason_code = self.reason_code
        message = self.message
        if reason_code is None:
            reason_code = next(
                (subject.reason_code for subject in self.subjects if subject.reason_code),
                None,
            )
        if message is None:
            message = next(
                (subject.message for subject in self.subjects if subject.message),
                None,
            )
        return _clean_dict(
            {
                "name": self.name,
                "verdict": self.aggregate_verdict,
                "required": self.required,
                "subjects": subject_dicts,
                "semantics": (
                    list(self.semantics)
                    if self.semantics is not None
                    else claim_semantics(self.name)
                ),
                "evidence": list(self.evidence),
                "does_not_establish": (
                    list(self.does_not_establish)
                    if self.does_not_establish is not None
                    else list(definition.does_not_establish)
                ),
                "epistemic_state": (
                    dict(self.epistemic_state)
                    if self.epistemic_state is not None
                    else None
                ),
                "reason_code": reason_code,
                "message": message,
                "verifier_version": verifier_version(),
                "diagnostics": list(self.diagnostics),
            }
        )


@dataclass(frozen=True)
class VerificationReport:
    ok: bool
    exit_code: int
    artifact: dict[str, Any]
    claims: list[ClaimVerdict] = field(default_factory=list)
    error: str | None = None
    diagnostics: list[str] = field(default_factory=list)
    semantics: dict[str, Any] = field(default_factory=legacy_semantics)

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema": VERDICT_SCHEMA_ID,
            "ok": self.ok,
            "exit_code": self.exit_code,
            "error": self.error,
            "artifact": dict(self.artifact),
            "semantics": dict(self.semantics),
            "claims": [claim.to_dict() for claim in self.claims],
            "diagnostics": list(self.diagnostics),
        }
        if payload["error"] is None:
            payload.pop("error")
        return payload


def verdict_output_json_schema() -> dict[str, Any]:
    verdict_enum = list(load_claim_registry().verdict_enum)
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": VERDICT_SCHEMA_ID,
        "type": "object",
        "required": [
            "schema",
            "ok",
            "exit_code",
            "artifact",
            "semantics",
            "claims",
            "diagnostics",
        ],
        "properties": {
            "schema": {"const": VERDICT_SCHEMA_ID},
            "ok": {"type": "boolean"},
            "exit_code": {"type": "integer", "enum": [0, 1, 2]},
            "error": {"type": ["string", "null"]},
            "artifact": {"type": "object"},
            "semantics": {
                "type": "object",
                "required": ["mode", "profile_id", "profile_hash"],
                "properties": {
                    "mode": {"type": "string"},
                    "profile_id": {"type": ["string", "null"]},
                    "profile_hash": {"type": ["string", "null"]},
                    "warning": {"type": "string"},
                },
            },
            "claims": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": [
                        "name",
                        "verdict",
                        "required",
                        "semantics",
                        "reason_code",
                        "message",
                    ],
                    "properties": {
                        "name": {"type": "string"},
                        "verdict": {"type": "string", "enum": verdict_enum},
                        "required": {"type": "boolean"},
                        "semantics": {"type": "array"},
                        "reason_code": {"type": "string"},
                        "message": {"type": "string"},
                        "verifier_version": {"type": "string"},
                        "subjects": {"type": "array"},
                        "evidence": {"type": "array"},
                        "does_not_establish": {
                            "type": "array",
                            "items": {"type": "string"},
                            "uniqueItems": True,
                        },
                        "epistemic_state": {
                            "type": "object",
                            "additionalProperties": {
                                "type": "string",
                                "enum": ["observed", "verified", "unverifiable"],
                            },
                        },
                        "diagnostics": {"type": "array"},
                    },
                },
            },
            "diagnostics": {"type": "array"},
        },
    }


VERDICT_OUTPUT_JSON_SCHEMA = verdict_output_json_schema()
