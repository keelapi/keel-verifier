"""R4 LEDGER (prove half) — anchor-contingent reservation-linkage adjudication.

The round-5 invariant: over an UNANCHORED self-attesting bundle the verifier must
NEVER emit ``keel_attested_unsigned`` for ``quota.reservation_linkage.v1``; it
withholds or emits the strictly-weaker ``keel_self_signed_unanchored``. This is
the negative corpus (memo §6) plus the positive anchored/signed paths.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keel_verifier.verifier import (
    BundleTrustContext,
    _adjudicate_quota_reservation_linkage_v1,
    _canonical_json_bytes,
    _content_hash,
    verify_export_structured,
)

from tests.test_self_attesting_bundle import (
    _artifact_ref,
    _bundle,
    _export_args,
    _signing_material,
    _write,
)

_ANCHOR = {
    "kind": "published_checkpoint",
    "checkpoint_id": "33333333-3333-4333-8333-333333333333",
    "composite_hash": "sha256:" + "a" * 64,
    "published_at": "2026-06-14T12:05:00Z",
}


def _reserve_commit_events(
    *,
    reservation_id: str = "res-1",
    permit_id: str = "permit-1",
    allocation_id: str = "alloc-1",
    envelope_id: str = "env-1",
) -> list[dict[str, Any]]:
    """A reservation that reconciles: reserve 100 then settle (reserved->0)."""
    return [
        {
            "transition": "reserve",
            "metric": "agent_allocation",
            "reservation_id": reservation_id,
            "permit_id": permit_id,
            "allocation_id": allocation_id,
            "envelope_id": envelope_id,
            "amount_usd_micros": 100,
            "seq": 1,
        },
        {
            "transition": "commit",
            "metric": "agent_allocation",
            "reservation_id": reservation_id,
            "permit_id": permit_id,
            "allocation_id": allocation_id,
            "envelope_id": envelope_id,
            "reserved_released_usd_micros": 100,
            "spent_added_usd_micros": 80,
            "seq": 2,
        },
    ]


def _make_body(
    events: list[dict[str, Any]],
    *,
    anchored: bool,
    attestation: dict[str, Any] | None = None,
    envelopes: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "schema": "keel.evidence/v1",
        "source": "keel",
        "generated_at": "2026-06-14T12:00:00Z",
        "project_id": "11111111-1111-4111-8111-111111111111",
        "export_id": "22222222-2222-4222-8222-222222222222",
        "decision_source": "Decision made by Keel",
        "record_count": 0,
        "records": [],
        "budget_allocation_events": events,
    }
    if envelopes is not None:
        body["budget_envelopes"] = envelopes
    if attestation is not None:
        body["reservation_linkage_attestation"] = attestation
    # Compute artifact_ref LAST, over the complete body (the verifier excludes
    # anchor + artifact_ref from the digest material, so anchor is added after).
    body["artifact_ref"] = _artifact_ref(
        artifact_type="compliance_export",
        artifact_id=body["export_id"],
        body=body,
    )
    if anchored:
        body["anchor"] = dict(_ANCHOR)
    return body


def _signed_attestation(
    tuple_obj: dict[str, Any], private_key: Ed25519PrivateKey, public_key: str
) -> dict[str, Any]:
    message = _content_hash(_canonical_json_bytes(tuple_obj)).encode("utf-8")
    signature = base64.b64encode(private_key.sign(message)).decode("ascii")
    return {"tuple": tuple_obj, "signature": signature, "public_key": public_key}


def _verify(tmp_path: Path, body: dict[str, Any]) -> Any:
    private_key, public_key, key_id = _signing_material()
    path = _write(
        tmp_path / "export_bundle.json", _bundle(body, private_key, public_key, key_id)
    )
    return verify_export_structured(_export_args(path))


def _linkage_claim(report: Any) -> Any:
    for claim in report.claims:
        if claim.name == "quota.reservation_linkage.v1":
            return claim
    return None


# --- negative corpus (memo §6) ---------------------------------------------


def test_unanchored_unsigned_never_emits_keel_attested_unsigned(tmp_path: Path) -> None:
    body = _make_body(_reserve_commit_events(), anchored=False)
    report = _verify(tmp_path, body)
    claim = _linkage_claim(report)
    assert claim is not None
    assert claim.epistemic_state["trust_grade"] == "keel_self_signed_unanchored"
    assert claim.aggregate_verdict == "supported"
    # The strong token must not appear ANYWHERE in the structured JSON report.
    blob = json.dumps(report.to_dict())
    assert "keel_attested_unsigned" not in blob


def test_anchored_unsigned_emits_keel_attested_unsigned(tmp_path: Path) -> None:
    body = _make_body(_reserve_commit_events(), anchored=True)
    report = _verify(tmp_path, body)
    claim = _linkage_claim(report)
    assert claim is not None
    assert claim.epistemic_state["trust_grade"] == "keel_attested_unsigned"
    assert claim.epistemic_state["anchor_present"] == "true"
    assert claim.aggregate_verdict == "supported"


def test_signed_identity_without_anchor_outranks_anchor_state(tmp_path: Path) -> None:
    private_key, public_key, _ = _signing_material()
    tuple_obj = {
        "project_id": "11111111-1111-4111-8111-111111111111",
        "permit_id": "permit-1",
        "reservation_id": "res-1",
        "allocation_id": "alloc-1",
        "envelope_id": "env-1",
        "reserved_amount": 100,
    }
    attestation = _signed_attestation(tuple_obj, private_key, public_key)
    body = _make_body(
        _reserve_commit_events(), anchored=False, attestation=attestation
    )
    report = _verify(tmp_path, body)
    claim = _linkage_claim(report)
    assert claim is not None
    assert claim.epistemic_state["trust_grade"] == "signed_identity"
    assert claim.epistemic_state["signed_identity"] == "true"
    assert claim.aggregate_verdict == "supported"


def test_anchor_removed_and_resigned_downgrades(tmp_path: Path) -> None:
    # Same events, anchor absent but bundle re-signed correctly => weak grade.
    body = _make_body(_reserve_commit_events(), anchored=False)
    report = _verify(tmp_path, body)
    claim = _linkage_claim(report)
    assert claim is not None
    assert claim.epistemic_state["trust_grade"] == "keel_self_signed_unanchored"


def test_anchor_inserted_without_resigning_fails_before_quota_claim(
    tmp_path: Path,
) -> None:
    private_key, public_key, key_id = _signing_material()
    body = _make_body(_reserve_commit_events(), anchored=False)
    bundle = _bundle(body, private_key, public_key, key_id)
    # Tamper: insert an anchor into the signed body WITHOUT recomputing the hash.
    bundle["body"]["anchor"] = dict(_ANCHOR)
    path = _write(tmp_path / "tampered.json", bundle)
    report = verify_export_structured(_export_args(path))
    assert report.ok is False
    # The quota claim must not be adjudicated as supported on a tampered bundle.
    claim = _linkage_claim(report)
    assert claim is None or claim.aggregate_verdict != "supported"
    blob = json.dumps(report.to_dict())
    assert "keel_attested_unsigned" not in blob


def test_signed_tuple_conflicts_with_unsigned_rows_is_disproved(
    tmp_path: Path,
) -> None:
    private_key, public_key, _ = _signing_material()
    # Signed tuple references a DIFFERENT reservation than the unsigned rows.
    tuple_obj = {
        "project_id": "11111111-1111-4111-8111-111111111111",
        "permit_id": "permit-9",
        "reservation_id": "res-OTHER",
        "reserved_amount": 100,
    }
    attestation = _signed_attestation(tuple_obj, private_key, public_key)
    body = _make_body(
        _reserve_commit_events(), anchored=True, attestation=attestation
    )
    report = _verify(tmp_path, body)
    claim = _linkage_claim(report)
    assert claim is not None
    assert claim.aggregate_verdict == "disproved"
    assert any(
        s.reason_code == "RESERVATION_LINKAGE_CONFLICT" for s in claim.subjects
    )


def test_multi_permit_reservation_is_conflict(tmp_path: Path) -> None:
    events = [
        {
            "transition": "reserve",
            "metric": "agent_allocation",
            "reservation_id": "res-1",
            "permit_id": "permit-A",
            "allocation_id": "alloc-1",
            "envelope_id": "env-1",
            "amount_usd_micros": 100,
            "seq": 1,
        },
        {
            "transition": "reserve",
            "metric": "agent_allocation",
            "reservation_id": "res-1",
            "permit_id": "permit-B",
            "allocation_id": "alloc-1",
            "envelope_id": "env-1",
            "amount_usd_micros": 50,
            "seq": 2,
        },
    ]
    report = _verify(tmp_path, _make_body(events, anchored=True))
    claim = _linkage_claim(report)
    assert claim is not None
    assert claim.aggregate_verdict == "disproved"


def test_legacy_no_reservation_id_yields_no_linkage_claim(tmp_path: Path) -> None:
    # Shadow/legacy events carry no reservation_id => typed no-linkage (omitted).
    events = [
        {
            "transition": "reserve",
            "metric": "agent_allocation",
            "allocation_id": "alloc-1",
            "envelope_id": "env-1",
            "amount_usd_micros": 100,
            "seq": 1,
        }
    ]
    report = _verify(tmp_path, _make_body(events, anchored=True))
    assert _linkage_claim(report) is None


def test_pinned_minimum_grade_over_unanchored_is_insufficient() -> None:
    # Direct adjudicator unit test (the pin source wires minimum_trust_grade).
    ctx = BundleTrustContext(
        bundle_valid=True,
        signature_valid=True,
        anchor_present=False,
        anchor_kind=None,
        anchor_hash=None,
        tsa_receipts_present=False,
    )
    body = {"budget_allocation_events": _reserve_commit_events()}
    claims = _adjudicate_quota_reservation_linkage_v1(
        body, bundle_context=ctx, minimum_trust_grade="keel_attested_unsigned"
    )
    assert len(claims) == 1
    assert claims[0].aggregate_verdict == "insufficient_evidence"
    assert claims[0].epistemic_state["trust_grade"] == "keel_self_signed_unanchored"


# --- partition ledger -------------------------------------------------------


def _cap_events() -> list[dict[str, Any]]:
    return [
        {
            "transition": "cap_allocate",
            "metric": "agent_allocation_cap",
            "allocation_id": "alloc-1",
            "envelope_id": "env-1",
            "is_active": True,
            "amount_usd_micros": 600,
            "seq": 1,
        },
        {
            "transition": "cap_allocate",
            "metric": "agent_allocation_cap",
            "allocation_id": "alloc-2",
            "envelope_id": "env-1",
            "is_active": True,
            "amount_usd_micros": 300,
            "seq": 1,
        },
    ]


def _partition_claim(report: Any) -> Any:
    for claim in report.claims:
        if claim.name == "budget.partition_ledger.v1":
            return claim
    return None


def test_partition_ledger_within_capacity_supported(tmp_path: Path) -> None:
    body = _make_body(
        _cap_events(),
        anchored=True,
        envelopes=[{"id": "env-1", "total_budget_usd_micros": 1000}],
    )
    report = _verify(tmp_path, body)
    claim = _partition_claim(report)
    assert claim is not None
    assert claim.aggregate_verdict == "supported"
    assert claim.epistemic_state["trust_grade"] == "keel_attested_unsigned"


def test_partition_ledger_overcommit_disproved(tmp_path: Path) -> None:
    body = _make_body(
        _cap_events(),
        anchored=True,
        envelopes=[{"id": "env-1", "total_budget_usd_micros": 800}],
    )
    report = _verify(tmp_path, body)
    claim = _partition_claim(report)
    assert claim is not None
    assert claim.aggregate_verdict == "disproved"
    assert any(
        s.reason_code == "PARTITION_LEDGER_OVERCOMMIT" for s in claim.subjects
    )
