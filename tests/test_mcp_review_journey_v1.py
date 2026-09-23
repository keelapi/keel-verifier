from __future__ import annotations

import argparse
import base64
import copy
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keel_verifier.verifier import (
    _artifact_ref_digest_for_body,
    _bundle_canonical_json_bytes,
    _content_hash,
    verify_export_structured,
)


FIXTURES = Path(__file__).parent / "fixtures"
TEST_EXPORT_KEY = Ed25519PrivateKey.from_private_bytes(b"\x22" * 32)


def _resign(bundle: dict) -> None:
    body = bundle["body"]
    body["artifact_ref"]["digest"] = _artifact_ref_digest_for_body(
        {key: value for key, value in body.items() if key != "artifact_ref"}
    )
    content_hash = _content_hash(_bundle_canonical_json_bytes(body))
    envelope = bundle["signature_envelope"]
    envelope["content_hash"] = content_hash
    envelope["signature"] = base64.b64encode(
        TEST_EXPORT_KEY.sign(content_hash.encode("utf-8"))
    ).decode("ascii")


def _verify(tmp_path: Path, bundle: dict):
    path = tmp_path / "journey.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    return verify_export_structured(
        argparse.Namespace(
            export_file=str(path),
            manifest=None,
            key_manifest=str(FIXTURES / "mcp_review_journey_keys.json"),
            key_manifest_url=None,
            expected_public_key=None,
            self_attested=False,
        )
    )


def _bundle() -> dict:
    return json.loads((FIXTURES / "mcp_review_journey_v1.json").read_text())


def test_signed_review_execution_and_closure_verify(tmp_path: Path) -> None:
    report = _verify(tmp_path, _bundle())
    assert report.ok, report.error
    assert report.artifact["journey"]["state"] == "execution_recorded"
    assert report.artifact["journey"]["closure_status"] == "closed"
    journey = next(c for c in report.claims if c.name == "mcp.review_journey.v1")
    assert journey.aggregate_verdict == "supported"
    assert {s.reason_code for s in journey.subjects} == {
        "MCP_JOURNEY_REVIEW_IDENTITY",
        "MCP_JOURNEY_APPROVAL_IDENTITY",
        "MCP_JOURNEY_EXECUTION_LINK",
        "MCP_JOURNEY_CLOSURE_SIGNATURE",
    }


def test_signed_outer_bundle_cannot_substitute_reviewed_permit(tmp_path: Path) -> None:
    bundle = _bundle()
    bundle["body"]["reviewed_permit_id"] = "00000000-0000-0000-0000-000000000000"
    _resign(bundle)
    report = _verify(tmp_path, bundle)
    assert not report.ok
    assert any(
        s.reason_code == "MCP_JOURNEY_REVIEW_IDENTITY" and s.verdict == "disproved"
        for c in report.claims
        for s in c.subjects
    )


def test_signed_outer_bundle_cannot_rewrite_closure(tmp_path: Path) -> None:
    bundle = _bundle()
    bundle["body"]["execution_closure"]["closure_status"] = "closed_by_provider"
    _resign(bundle)
    report = _verify(tmp_path, bundle)
    assert not report.ok
    assert any(
        s.reason_code == "MCP_JOURNEY_CLOSURE_SIGNATURE" and s.verdict == "disproved"
        for c in report.claims
        for s in c.subjects
    )


def test_recorded_closure_requires_signed_closure_payload(tmp_path: Path) -> None:
    bundle = _bundle()
    bundle["body"]["execution_closure"] = None
    _resign(bundle)
    report = _verify(tmp_path, bundle)
    assert not report.ok
    assert any(
        s.reason_code == "MCP_JOURNEY_CLOSURE_MISSING" for c in report.claims for s in c.subjects
    )


def test_pending_review_does_not_claim_execution_absence(tmp_path: Path) -> None:
    bundle = copy.deepcopy(_bundle())
    body = bundle["body"]
    body["execution_permit_id"] = None
    body["execution_permit_bundle"] = None
    body["execution_closure"] = None
    reviewed = body["reviewed_permit_bundle"]
    reviewed["body"]["review_transition"] = {"status": "not_present"}
    _resign(reviewed)
    _resign(bundle)
    report = _verify(tmp_path, bundle)
    assert report.ok, report.error
    assert (
        report.artifact["journey"]["state"]
        == "review_without_approval_transition_in_export"
    )
