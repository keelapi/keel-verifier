"""Unit tests for the engine-side permit projection.

The projection lifts a permit's signature-verified fields into
``report.artifact["permit"]`` so the renderer can show a permit-first view.
The safety property under test: fields are surfaced ONLY when the relevant
claim verdict is ``supported`` -- the verifier must never present permit
identity/action data it did not authenticate.
"""

from __future__ import annotations

from keel_verifier.verdicts import ClaimVerdict
from keel_verifier.verifier import (
    _PERMIT_VIEW_CANONICAL_FIELDS,
    _PERMIT_VIEW_V2_FIELDS,
    _attach_permit_view,
    _permit_view_fields,
)


def test_permit_view_fields_normalizes_canonical_payload() -> None:
    canonical = {
        "permit_id": "p1",
        "decision": "allow",
        "action_name": "mpp.purchase",
        "provider": "openai",
        "model": "gpt-5",
        "reason": "policy.allow",
        "issued_at": "t1",
        "expires_at": "t2",
        "project_id": "proj",
    }
    view = _permit_view_fields(canonical, _PERMIT_VIEW_CANONICAL_FIELDS)
    assert view["permit_id"] == "p1"
    assert view["decision"] == "allow"
    assert view["authorized_action"] == "mpp.purchase"
    assert view["provider"] == "openai"
    assert view["model"] == "gpt-5"
    assert view["policy"] == "policy.allow"
    assert view["scope"] == "proj"


def test_permit_view_fields_normalizes_v2_object() -> None:
    obj = {
        "id": "p2",
        "decision": "allow",
        "action_name": "generate_report",
        "resource_provider": "openai",
        "resource_model": "gpt-5",
        "created_at": "t1",
        "expires_at": "t2",
        "subject_id": "s1",
        "account_id": "a1",
    }
    view = _permit_view_fields(obj, _PERMIT_VIEW_V2_FIELDS)
    assert view["permit_id"] == "p2"
    assert view["provider"] == "openai"
    assert view["model"] == "gpt-5"
    assert view["issued_at"] == "t1"
    assert view["subject"] == "s1"
    assert view["account"] == "a1"


def test_attach_permit_view_only_when_claim_supported() -> None:
    doc = {
        "id": "p2",
        "decision": "allow",
        "action_name": "generate_report",
        "resource_provider": "openai",
        "resource_model": "gpt-5",
    }

    # Not supported -> no permit block surfaced (never show unauthenticated data).
    artifact: dict = {"kind": "export"}
    _attach_permit_view(
        artifact,
        [ClaimVerdict(name="permit.operator_approval.v1", verdict="insufficient_evidence")],
        doc,
    )
    assert "permit" not in artifact

    # Supported -> permit block populated from the verified permit object.
    artifact = {"kind": "export"}
    _attach_permit_view(
        artifact,
        [ClaimVerdict(name="permit.operator_approval.v1", verdict="supported")],
        doc,
    )
    assert artifact["permit"]["permit_id"] == "p2"
    assert artifact["permit"]["authorized_action"] == "generate_report"
    assert artifact["permit"]["provider"] == "openai"


def test_attach_permit_view_ignores_non_dict_document() -> None:
    artifact: dict = {"kind": "export"}
    _attach_permit_view(
        artifact,
        [ClaimVerdict(name="permit.operator_approval.v1", verdict="supported")],
        None,
    )
    assert "permit" not in artifact
