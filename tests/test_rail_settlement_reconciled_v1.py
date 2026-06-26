"""Tests for the ``rail.settlement_reconciled.v1`` adjudicator (Tier C1a).

Mirror of ``tests/test_authority_chain_v1.py``'s edge-revocation coverage,
adapted to facilitator-attested x402 settlement reconciliation. Exercises the
adjudicator (supported / disproved / insufficient_evidence / source_class /
unverifiable_scope), the extractor, the registry-hash lockstep + historical
roll, and that existing claims are unaffected.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from keel_verifier import semantics
from keel_verifier.verifier import (
    RAIL_SETTLEMENT_RECONCILED_CLAIM_NAME,
    _adjudicate_rail_settlement_reconciled_v1,
    _iter_rail_settlement_records,
    _recompute_rail_settlement_reconciliation,
    _rail_settlement_reconciliation_digest,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def _producer_reconcile(
    *,
    settlement_record: dict[str, Any],
    authority: dict[str, Any],
) -> dict[str, Any]:
    """Verbatim reproduction of keel-api ``reconcile_x402_settlement``.

    Kept independent of the verifier helpers so the tests pin the producer
    contract directly (a divergence between producer and verifier must fail a
    test here, not silently agree).
    """

    transaction = str(settlement_record.get("transaction") or "").strip()
    network = str(settlement_record.get("network") or "").strip()
    settled_amount_raw = str(settlement_record.get("amount") or "").strip()
    payer = str(settlement_record.get("payer") or "").strip() or None
    success = bool(settlement_record.get("success", False))

    amount_ok = False
    try:
        settled_amount_int = int(settled_amount_raw) if settled_amount_raw else None
        amount_max = int(authority.get("amount_max") or 0)
        amount_ok = settled_amount_int is not None and settled_amount_int <= amount_max
    except (ValueError, TypeError):
        amount_ok = False

    network_ok = bool(network)
    recipient_ok = payer is not None

    failure_code: str | None = None
    if not success:
        failure_code = "settlement_not_successful"
    elif not amount_ok:
        failure_code = "amount_exceeds_authority"
    elif not network_ok:
        failure_code = "network_missing"

    reconciled = success and amount_ok and network_ok

    result: dict[str, Any] = {
        "reconciled": reconciled,
        "source_class": "facilitator_attested",
        "settlement_reference": {"transaction": transaction, "network": network},
        "amount_ok": amount_ok,
        "network_ok": network_ok,
        "recipient_ok": recipient_ok,
    }
    if failure_code is not None:
        result["failure_code"] = failure_code
    if payer is not None:
        result["payer"] = payer
    if settled_amount_raw:
        result["settled_amount"] = settled_amount_raw

    material = json.dumps(result, sort_keys=True, separators=(",", ":"))
    result["reconciliation_digest"] = hashlib.sha256(
        material.encode("utf-8")
    ).hexdigest()
    return result


def _settlement_record(
    *,
    transaction: str = "0x" + "3" * 64,
    network: str = "eip155:84532",
    payer: str = "0x857b06519E91e3A54538791bDbb0E22373e36b66",
    amount: str = "500",
    success: bool = True,
) -> dict[str, Any]:
    return {
        "success": success,
        "transaction": transaction,
        "network": network,
        "payer": payer,
        "amount": amount,
    }


def _settlement_export(
    *,
    settlement_record: dict[str, Any] | None = None,
    authority: dict[str, Any] | None = None,
    rail: str = "x402",
    source_class: str = "facilitator_attested",
    permit_id: str = "permit_abc123",
    override_digest: str | None = None,
    override_reference: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build an export carrying a producer-faithful ``rail_settlement`` block."""

    record = settlement_record if settlement_record is not None else _settlement_record()
    auth = authority if authority is not None else {"amount_max": 500}
    producer_result = _producer_reconcile(settlement_record=record, authority=auth)
    reference = override_reference or {
        "transaction": str(record.get("transaction") or "").strip(),
        "network": str(record.get("network") or "").strip(),
    }
    digest = (
        override_digest
        if override_digest is not None
        else producer_result["reconciliation_digest"]
    )
    return {
        "permit": {"permit_id": permit_id},
        "rail_settlement": {
            "rail": rail,
            "source_class": source_class,
            "settlement_reference": reference,
            "reconciliation_digest": digest,
            "settlement_record": record,
            "authority": auth,
        },
    }


# --------------------------------------------------------------------------- #
# Adjudicator
# --------------------------------------------------------------------------- #


def test_rail_settlement_reconciled_supported() -> None:
    export = _settlement_export(
        settlement_record=_settlement_record(amount="500"),
        authority={"amount_max": 500},
    )

    claim = _adjudicate_rail_settlement_reconciled_v1(export_document=export)

    assert claim.aggregate_verdict == "supported"
    assert claim.reason_code == "RAIL_SETTLEMENT_RECONCILED_SUPPORTED"
    assert claim.epistemic_state == {"rail_settlement_reconciled": "verified"}


def test_rail_settlement_reconciled_amount_exceeds_authority_is_disproved() -> None:
    export = _settlement_export(
        settlement_record=_settlement_record(amount="600"),
        authority={"amount_max": 500},
    )

    claim = _adjudicate_rail_settlement_reconciled_v1(export_document=export)

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == (
        "rail_settlement_reconciled.amount_exceeds_authority"
    )
    assert claim.epistemic_state == {"rail_settlement_reconciled": "observed"}


def test_rail_settlement_reconciled_unsuccessful_is_disproved() -> None:
    export = _settlement_export(
        settlement_record=_settlement_record(success=False, amount="100"),
        authority={"amount_max": 500},
    )

    claim = _adjudicate_rail_settlement_reconciled_v1(export_document=export)

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == (
        "rail_settlement_reconciled.settlement_not_successful"
    )


def test_rail_settlement_reconciled_reference_mismatch_is_disproved() -> None:
    # The bound reference disagrees with the settlement record's own tx/network.
    export = _settlement_export(
        override_reference={"transaction": "0xdeadbeef", "network": "eip155:1"},
    )

    claim = _adjudicate_rail_settlement_reconciled_v1(export_document=export)

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "rail_settlement_reconciled.reference_mismatch"


def test_rail_settlement_reconciled_digest_mismatch_is_disproved() -> None:
    # The bound digest does not reproduce from the record + authority.
    export = _settlement_export(override_digest="0" * 64)

    claim = _adjudicate_rail_settlement_reconciled_v1(export_document=export)

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "rail_settlement_reconciled.reference_mismatch"


def test_rail_settlement_reconciled_no_settlement_is_insufficient() -> None:
    # Every x402 execution recorded today: no bound settlement block at all.
    export = {"permit": {"permit_id": "permit_abc123"}}

    claim = _adjudicate_rail_settlement_reconciled_v1(export_document=export)

    assert claim.aggregate_verdict == "insufficient_evidence"
    assert claim.reason_code == (
        "rail_settlement_reconciled.settlement_evidence_missing"
    )


def test_rail_settlement_reconciled_missing_record_is_insufficient() -> None:
    export = _settlement_export()
    del export["rail_settlement"]["settlement_record"]

    claim = _adjudicate_rail_settlement_reconciled_v1(export_document=export)

    assert claim.aggregate_verdict == "insufficient_evidence"
    assert claim.reason_code == (
        "rail_settlement_reconciled.settlement_evidence_missing"
    )


def test_rail_settlement_reconciled_chain_read_source_is_unverifiable_scope() -> None:
    export = _settlement_export(source_class="chain_read")

    claim = _adjudicate_rail_settlement_reconciled_v1(export_document=export)

    assert claim.aggregate_verdict == "unverifiable_scope"
    assert claim.reason_code is None
    assert "chain_read" in claim.message


def test_rail_settlement_reconciled_unknown_source_is_unverifiable_scope() -> None:
    export = _settlement_export(source_class="self_attested")

    claim = _adjudicate_rail_settlement_reconciled_v1(export_document=export)

    assert claim.aggregate_verdict == "unverifiable_scope"


def test_rail_settlement_reconciled_non_settlement_rail_is_unverifiable_scope() -> None:
    export = _settlement_export(rail="stripe_mpp")

    claim = _adjudicate_rail_settlement_reconciled_v1(export_document=export)

    assert claim.aggregate_verdict == "unverifiable_scope"


def test_rail_settlement_reconciled_subject_id_is_permit_id() -> None:
    export = _settlement_export(permit_id="permit_xyz789")

    claim = _adjudicate_rail_settlement_reconciled_v1(export_document=export)

    subjects = [s.id for s in claim.subjects]
    assert "permit_xyz789" in subjects
    assert all(s.type == "rail_settlement_reconciled" for s in claim.subjects)


# --------------------------------------------------------------------------- #
# Extractor
# --------------------------------------------------------------------------- #


def test_extractor_finds_top_level_rail_settlement() -> None:
    export = _settlement_export()
    records = _iter_rail_settlement_records(export)
    assert len(records) == 1
    record, path = records[0]
    assert path == "rail_settlement"
    assert record["reconciliation_digest"]


def test_extractor_finds_records_list() -> None:
    block = _settlement_export()["rail_settlement"]
    export = {"rail_settlements": [block]}
    records = _iter_rail_settlement_records(export)
    assert len(records) == 1
    assert records[0][1] == "rail_settlements[0]"


def test_extractor_finds_embedded_payload_block() -> None:
    block = _settlement_export()["rail_settlement"]
    export = {"records": [{"payload_json": {"rail_settlement": block}}]}
    records = _iter_rail_settlement_records(export)
    assert any("payload_json" in path for _, path in records)


def test_extractor_returns_empty_for_todays_exports() -> None:
    # No settlement block — the default for every execution recorded so far.
    assert _iter_rail_settlement_records({"permit": {"permit_id": "p"}}) == []


# --------------------------------------------------------------------------- #
# Byte-faithful digest reproduction (producer parity)
# --------------------------------------------------------------------------- #


def test_verifier_reproduces_producer_reconciliation_digest() -> None:
    for record, authority in [
        (_settlement_record(amount="500"), {"amount_max": 500}),
        (_settlement_record(amount="600"), {"amount_max": 500}),
        (_settlement_record(success=False, amount="100"), {"amount_max": 500}),
        (_settlement_record(network="", amount="100"), {"amount_max": 500}),
        (_settlement_record(amount="abc"), {"amount_max": 500}),
    ]:
        producer = _producer_reconcile(settlement_record=record, authority=authority)
        recomputed = _recompute_rail_settlement_reconciliation(
            settlement_record=record,
            settlement_reference={
                "transaction": str(record.get("transaction") or "").strip(),
                "network": str(record.get("network") or "").strip(),
            },
            authority=authority,
        )
        # The result dict (minus the digest key) must be identical.
        producer_no_digest = {
            k: v for k, v in producer.items() if k != "reconciliation_digest"
        }
        assert recomputed == producer_no_digest
        # And the recomputed digest must reproduce the producer's digest.
        assert (
            _rail_settlement_reconciliation_digest(recomputed)
            == producer["reconciliation_digest"]
        )


# --------------------------------------------------------------------------- #
# Registry + semantics registration
# --------------------------------------------------------------------------- #


def test_rail_settlement_reconciled_is_registered_in_semantics() -> None:
    assert semantics.RAIL_SETTLEMENT_RECONCILED_ID == (
        "keel.rail.settlement_reconciled.v1"
    )
    assert semantics.CLAIM_SEMANTICS["rail.settlement_reconciled.v1"] == (
        semantics.RAIL_SETTLEMENT_RECONCILED_ID,
    )
    assert (
        semantics.RELEASED_ARTIFACT_HASHES[semantics.RAIL_SETTLEMENT_RECONCILED_ID]
        == semantics.RAIL_SETTLEMENT_RECONCILED_HASH
    )
    assert (
        semantics.RELEASED_ARTIFACT_PATHS[semantics.RAIL_SETTLEMENT_RECONCILED_ID]
        == "semantics/rail/settlement_reconciled_v1.json"
    )


def test_rail_settlement_reconciled_semantic_hash_matches_bundled_recipe() -> None:
    recipe_path = (
        REPO_ROOT
        / "keel_verifier"
        / "data"
        / semantics.RELEASED_ARTIFACT_PATHS[semantics.RAIL_SETTLEMENT_RECONCILED_ID]
    )
    digest = f"sha256:{hashlib.sha256(recipe_path.read_bytes()).hexdigest()}"
    assert digest == semantics.RAIL_SETTLEMENT_RECONCILED_HASH


def test_rail_settlement_reconciled_recipe_failure_code_verdicts() -> None:
    recipe_path = (
        REPO_ROOT
        / "keel_verifier"
        / "data"
        / semantics.RELEASED_ARTIFACT_PATHS[semantics.RAIL_SETTLEMENT_RECONCILED_ID]
    )
    recipe = _load_json(recipe_path)
    failures = recipe["body"]["failure_codes"]
    by_code = {item["code"]: item["verdict"] for item in failures}

    assert by_code[
        "rail_settlement_reconciled.amount_exceeds_authority"
    ] == "disproved"
    assert by_code[
        "rail_settlement_reconciled.settlement_evidence_missing"
    ] == "insufficient_evidence"
    assert recipe["id"] == "keel.rail.settlement_reconciled.v1"
    assert recipe["status"] == "released"
    assert recipe["body"]["verdict_vocabulary"] == [
        "supported",
        "disproved",
        "unverifiable_scope",
        "insufficient_evidence",
    ]


def test_claim_registry_includes_settlement_reconciled_in_both_copies() -> None:
    registry_bytes = (
        REPO_ROOT / "keel_verifier" / "data" / "claim_registry" / "v0.json"
    ).read_bytes()
    legacy_bytes = (
        REPO_ROOT / "keel_verifier" / "data" / "claim_registry_v0.json"
    ).read_bytes()

    assert registry_bytes == legacy_bytes

    registry = json.loads(registry_bytes)
    rows = {claim["name"]: claim for claim in registry["claims"]}
    assert "rail.settlement_reconciled.v1" in rows
    row = rows["rail.settlement_reconciled.v1"]
    assert row["verdict_enum"] == [
        "supported",
        "disproved",
        "insufficient_evidence",
        "unverifiable_scope",
    ]


def test_claim_registry_hash_lockstep_and_historical_rollover() -> None:
    registry_bytes = (
        REPO_ROOT / "keel_verifier" / "data" / "claim_registry" / "v0.json"
    ).read_bytes()

    # The live registry hash is the raw sha256 of the bundled bytes.
    digest = f"sha256:{hashlib.sha256(registry_bytes).hexdigest()}"
    assert digest == semantics.CLAIM_REGISTRY_HASH
    assert semantics.CLAIM_REGISTRY_HASH == (
        "sha256:02b6fa04d9471905bee9d7e45698c96bd16124bf167ee19ae859213935b264e5"
    )

    # The edge-revocation registry rolled into PREVIOUS, with a bundled snapshot.
    assert semantics.CLAIM_REGISTRY_PREVIOUS_HASH == (
        "sha256:bfdc09a7eb33bb9c902335342ebe122270f0f2fe8e9a82078f0496e724b261e7"
    )
    assert (
        semantics.CLAIM_REGISTRY_PREVIOUS_HASH
        in semantics.CLAIM_REGISTRY_HISTORICAL_HASHES
    )
    assert (
        semantics.CLAIM_REGISTRY_HASH
        not in semantics.CLAIM_REGISTRY_HISTORICAL_HASHES
    )

    previous_digest = semantics.CLAIM_REGISTRY_PREVIOUS_HASH.removeprefix("sha256:")
    historical_path = (
        REPO_ROOT
        / "keel_verifier"
        / "data"
        / "claim_registry"
        / "historical"
        / f"v0-sha256-{previous_digest}.json"
    )
    assert historical_path.exists()
    assert (
        f"sha256:{hashlib.sha256(historical_path.read_bytes()).hexdigest()}"
        == semantics.CLAIM_REGISTRY_PREVIOUS_HASH
    )


# --------------------------------------------------------------------------- #
# Existing claims unaffected
# --------------------------------------------------------------------------- #


def test_existing_claims_unaffected_by_additive_row() -> None:
    registry = _load_json(
        REPO_ROOT / "keel_verifier" / "data" / "claim_registry" / "v0.json"
    )
    names = [claim["name"] for claim in registry["claims"]]

    # The pre-existing authority cluster is untouched and in its original order.
    assert "authority.edge_revocation.v1" in names
    root_index = names.index("authority.root_status_temporal.v1")
    assert names[root_index + 1] == "authority.edge_revocation.v1"

    # The new row is purely additive (appended at the end).
    assert names[-1] == "rail.settlement_reconciled.v1"

    # The edge-revocation semantic hash is unchanged.
    assert semantics.AUTHORITY_EDGE_REVOCATION_HASH == (
        "sha256:226c7261d98458aa40a14b89b9386ab310774afbcb6486cd3332253db670c289"
    )


def test_claim_name_constant_matches_registry() -> None:
    assert RAIL_SETTLEMENT_RECONCILED_CLAIM_NAME == "rail.settlement_reconciled.v1"
    registry = _load_json(
        REPO_ROOT / "keel_verifier" / "data" / "claim_registry" / "v0.json"
    )
    names = [claim["name"] for claim in registry["claims"]]
    assert RAIL_SETTLEMENT_RECONCILED_CLAIM_NAME in names


def test_dispatch_gate_fires_only_when_pinned_and_requested() -> None:
    from keel_verifier.semantics import ClaimRequest, ResolvedSemantics
    from keel_verifier.verifier import _pinned_claim_requested

    pinned = ResolvedSemantics(
        mode="pinned",
        profile_id=None,
        profile_hash=None,
        requested_claims=(
            ClaimRequest(
                name=RAIL_SETTLEMENT_RECONCILED_CLAIM_NAME,
                required=True,
                minimum_trust_grade="keel_attested_unsigned",
            ),
        ),
        artifacts={},
        implementations={},
    )
    requested = pinned.requested_names()

    # Fires when pinned + requested.
    assert _pinned_claim_requested(
        pinned, requested, RAIL_SETTLEMENT_RECONCILED_CLAIM_NAME
    )
    # Does not fire for an unrelated claim name.
    assert not _pinned_claim_requested(
        pinned, requested, "permit.decision.v1"
    )

    # Does not fire when the pack is not pinned (legacy mode).
    legacy = ResolvedSemantics(
        mode="legacy",
        profile_id=None,
        profile_hash=None,
        requested_claims=(),
        artifacts={},
        implementations={},
    )
    assert not _pinned_claim_requested(
        legacy, set(), RAIL_SETTLEMENT_RECONCILED_CLAIM_NAME
    )
