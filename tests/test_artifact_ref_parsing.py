from __future__ import annotations

import pytest

from keel_verifier.schemas.artifact_ref import ArtifactRef, ArtifactType, parse_artifact_ref


def _artifact_ref(**overrides: str) -> dict[str, str]:
    value = {
        "schema_version": "artifact_ref.v1",
        "type": "compliance_export",
        "id": "40000000-0000-0000-0000-000000000001",
        "urn": (
            "urn:x-keel:artifact:compliance_export:"
            "40000000-0000-0000-0000-000000000001"
        ),
        "region": "us-east-1",
        "path": "/v1/compliance/exports/40000000-0000-0000-0000-000000000001",
        "canonical_url": (
            "https://api.keelapi.com/v1/compliance/exports/"
            "40000000-0000-0000-0000-000000000001"
        ),
        "digest": "sha256:" + "a" * 64,
    }
    value.update(overrides)
    return value


def test_parse_artifact_ref_from_new_format_bundle() -> None:
    parsed = parse_artifact_ref({"artifact_ref": _artifact_ref(), "records": []})

    assert isinstance(parsed, ArtifactRef)
    assert parsed.schema_version == "artifact_ref.v1"
    assert parsed.type == "compliance_export"
    assert parsed.urn == (
        "urn:x-keel:artifact:compliance_export:"
        "40000000-0000-0000-0000-000000000001"
    )


def test_parse_artifact_ref_returns_none_for_legacy_bundle() -> None:
    assert parse_artifact_ref({"records": []}) is None


@pytest.mark.parametrize(
    ("artifact_type", "artifact_id", "path"),
    [
        (
            "compliance_export",
            "40000000-0000-0000-0000-000000000001",
            "/v1/compliance/exports/40000000-0000-0000-0000-000000000001",
        ),
        (
            "checkpoint_envelope",
            "40000000-0000-0000-0000-000000000002",
            "/v1/integrity/checkpoints/40000000-0000-0000-0000-000000000002",
        ),
        (
            "voice_session_attestation",
            "customer_supplied_session_id",
            "/v1/voice/sessions/customer_supplied_session_id/attestation",
        ),
        (
            "decision_evidence",
            "40000000-0000-0000-0000-000000000003",
            "/v1/decisions/40000000-0000-0000-0000-000000000003/evidence",
        ),
        (
            "rail_evidence",
            "1" * 64,
            "/v1/rails/evidence/" + "1" * 64,
        ),
    ],
)
def test_parse_artifact_ref_round_trips_keel_api_emitted_id_shapes(
    artifact_type: ArtifactType,
    artifact_id: str,
    path: str,
) -> None:
    ref = {
        "schema_version": "artifact_ref.v1",
        "type": artifact_type,
        "id": artifact_id,
        "urn": f"urn:x-keel:artifact:{artifact_type}:{artifact_id}",
        "region": "us-east-1",
        "path": path,
        "canonical_url": f"https://api.keelapi.com{path}",
        "digest": "sha256:" + "b" * 64,
    }

    parsed = parse_artifact_ref({"artifact_ref": ref})

    assert parsed is not None
    assert parsed.model_dump() == ref
    assert parsed.type == artifact_type
    assert parsed.id == artifact_id
    assert parsed.urn == ref["urn"]


@pytest.mark.parametrize(
    "override",
    [
        {"urn": "urn:x-keel:artifact:compliance_export:EXPORT_123"},
        {"urn": "urn:x-keel:artifact:compliance_export:export_123:extra"},
        {"id": "EXPORT_123", "urn": "urn:x-keel:artifact:compliance_export:EXPORT_123"},
        {"id": "export:123", "urn": "urn:x-keel:artifact:compliance_export:export:123"},
        {"digest": "sha256:" + "A" * 64},
    ],
)
def test_parse_artifact_ref_raises_for_malformed_ref(
    override: dict[str, str],
) -> None:
    with pytest.raises(ValueError):
        parse_artifact_ref({"artifact_ref": _artifact_ref(**override)})
