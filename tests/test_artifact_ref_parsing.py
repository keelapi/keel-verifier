from __future__ import annotations

import pytest

from keel_verifier.schemas.artifact_ref import ArtifactRef, parse_artifact_ref


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
    "override",
    [
        {"urn": "urn:x-keel:artifact:compliance_export:EXPORT_123"},
        {"urn": "urn:x-keel:artifact:compliance_export:export_123:extra"},
        {
            "type": "rail_evidence",
            "id": "export_123",
            "urn": "urn:x-keel:artifact:rail_evidence:export_123",
        },
        {"digest": "sha256:" + "A" * 64},
    ],
)
def test_parse_artifact_ref_raises_for_malformed_ref(
    override: dict[str, str],
) -> None:
    with pytest.raises(ValueError):
        parse_artifact_ref({"artifact_ref": _artifact_ref(**override)})
