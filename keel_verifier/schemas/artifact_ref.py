"""artifact_ref.v1 schema parsing."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Literal

from pydantic import BaseModel, field_validator, model_validator

ArtifactType = Literal[
    "compliance_export",
    "checkpoint_envelope",
    "voice_session_attestation",
    "decision_evidence",
    "rail_evidence",
]

_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_LOWERCASE_RE = re.compile(r"^[^A-Z]+$")
_UUID_RE = re.compile(
    r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"
)
_ID_PREFIXES: dict[str, tuple[str, ...]] = {
    "compliance_export": ("exp_", "export_"),
    "checkpoint_envelope": ("chk_", "checkpoint_"),
    "voice_session_attestation": ("sess_", "voice_session_"),
    "decision_evidence": ("pmt_", "permit_", "decision_"),
    "rail_evidence": ("rail_",),
}
_PREFIXED_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$")


class ArtifactRef(BaseModel):
    schema_version: Literal["artifact_ref.v1"] = "artifact_ref.v1"
    type: ArtifactType
    id: str
    urn: str
    region: str
    path: str
    canonical_url: str
    digest: str

    @field_validator("digest")
    @classmethod
    def _validate_digest(cls, value: str) -> str:
        if not _DIGEST_RE.fullmatch(value):
            raise ValueError("digest must be sha256:<64 lowercase hex characters>")
        return value

    @field_validator("id")
    @classmethod
    def _validate_id_lowercase(cls, value: str) -> str:
        if not value or not _LOWERCASE_RE.fullmatch(value):
            raise ValueError("id must be non-empty lowercase text")
        return value

    @field_validator("urn")
    @classmethod
    def _validate_urn_lowercase(cls, value: str) -> str:
        if not value or not _LOWERCASE_RE.fullmatch(value):
            raise ValueError("urn must be lowercase")
        return value

    @field_validator("path")
    @classmethod
    def _validate_path(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("path must start with '/'")
        return value

    @field_validator("canonical_url")
    @classmethod
    def _validate_canonical_url(cls, value: str) -> str:
        if not value.startswith(("https://", "http://")):
            raise ValueError("canonical_url must be an absolute HTTP(S) URL")
        return value

    @model_validator(mode="after")
    def _validate_cross_field_invariants(self) -> "ArtifactRef":
        expected_urn = f"urn:x-keel:artifact:{self.type}:{self.id}"
        parts = self.urn.split(":")
        if len(parts) != 5 or self.urn != expected_urn:
            raise ValueError(
                "urn must be urn:x-keel:artifact:<type>:<id> with exactly five segments"
            )
        if not _id_matches_type(self.type, self.id):
            raise ValueError(f"id does not match existing {self.type} ID format")
        return self


def _id_matches_type(artifact_type: str, artifact_id: str) -> bool:
    if _UUID_RE.fullmatch(artifact_id):
        return True
    prefixes = _ID_PREFIXES[artifact_type]
    return artifact_id.startswith(prefixes) and bool(_PREFIXED_ID_RE.fullmatch(artifact_id))


def parse_artifact_ref(bundle: Mapping[str, Any]) -> ArtifactRef | None:
    """Parse ``artifact_ref`` from a bundle object.

    Returns ``None`` for legacy bundles where ``artifact_ref`` is absent.
    Raises ``ValueError`` when the field is present but malformed.
    """
    if not isinstance(bundle, Mapping):
        raise TypeError("bundle must be a mapping")
    if "artifact_ref" not in bundle:
        return None
    raw = bundle["artifact_ref"]
    if not isinstance(raw, Mapping):
        raise ValueError("artifact_ref must be an object")
    return ArtifactRef.model_validate(raw)
