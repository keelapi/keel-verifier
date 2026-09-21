"""Local continuity across a filtered governance-events export.

A filtered export discloses only the events that match its filter, so its
records are not a contiguous run of the chain. The export also carries, inside
its signed ``scope_faithfulness`` block, one proof-bridge record for every
event the filter left out between the first and last disclosed record. Each
bridge holds that event's chain-hash preimage as selector metadata only; the
v1 record hash covers no payload content, so none is needed.

These tests pin two things. The walk now uses those bridges, so an honest
filtered export is walked across every gap with every hash recomputed. And a
bridge buys nothing a real chain entry would not: altering, removing,
reordering, or forging one fails with the same codes a tampered record does.
The fixtures mirror what keel-api emits: records in the
``keel.governance_events/v1`` shape and bridges in the
``_auditor_safe_chain_entry_ref`` shape, with ``resource_type``,
``resource_id``, ``outcome`` and ``severity`` inside the selector-only
``payload_json`` rather than at the top level.
"""

from __future__ import annotations

import copy
import json
from typing import Any

from keel_verifier import verifier


PROJECT_ID = "00000000-0000-0000-0000-000000000041"
CHAIN_SCOPE = f"project:{PROJECT_ID}"
PERMIT_ID = "20000000-0000-4000-8000-000000000001"
OTHER_PERMIT_ID = "20000000-0000-4000-8000-000000000002"

# (event_type, permit_id, resource_type, resource_id, outcome, severity)
_CHAIN_SHAPE: list[tuple[str, str | None, str | None, str | None, str | None, str]] = [
    ("dispatch.egress_bound", PERMIT_ID, "permit", PERMIT_ID, "success", "info"),
    ("audit.integrity_digest", None, "governance_event_batch", "batch_1", "success", "info"),
    ("permit.evaluated", OTHER_PERMIT_ID, None, None, "success", "info"),
    ("policy.evaluated", None, None, None, None, "info"),
    ("dispatch.egress_bound", PERMIT_ID, "permit", PERMIT_ID, "success", "info"),
    ("permit.closed", OTHER_PERMIT_ID, "permit", OTHER_PERMIT_ID, "success", "warning"),
    ("usage.recorded", OTHER_PERMIT_ID, None, None, "success", "info"),
    ("dispatch.egress_bound", PERMIT_ID, "permit", PERMIT_ID, "success", "info"),
]
DISPATCH = "dispatch.egress_bound"


def _chain() -> list[dict[str, Any]]:
    """A real v1 hash chain, as keel-api's chain_entry_from_governance_event emits."""

    prev_hash = "a" * 64
    entries: list[dict[str, Any]] = []
    for offset, shape in enumerate(_CHAIN_SHAPE):
        event_type, permit_id, resource_type, resource_id, outcome, severity = shape
        sequence_number = 100 + offset
        occurred_at = f"2026-09-18T21:39:{10 + offset:02d}.{offset:06d}Z"
        record_hash = verifier._compute_record_hash_v1(
            event_id=f"gev_{sequence_number}",
            event_type=event_type,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            severity=severity,
            created_at=occurred_at,
            prev_hash=prev_hash,
            sequence_number=sequence_number,
        )
        entries.append(
            {
                "event_id": f"gev_{sequence_number}",
                "event_type": event_type,
                "permit_id": permit_id,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "outcome": outcome,
                "severity": severity,
                "occurred_at": occurred_at,
                "sequence_number": sequence_number,
                "prev_hash": prev_hash,
                "record_hash": record_hash,
            }
        )
        prev_hash = record_hash
    return entries


def _record(entry: dict[str, Any]) -> dict[str, Any]:
    """keel-api _event_to_record: selector-only payload, chain fields top-level."""

    occurred_at = entry["occurred_at"].replace("Z", "+00:00")
    payload = {
        key: value
        for key, value in {
            "project_id": PROJECT_ID,
            "permit_id": entry["permit_id"],
            "event_type": entry["event_type"],
            "resource_type": entry["resource_type"],
            "resource_id": entry["resource_id"],
            "outcome": entry["outcome"],
            "severity": entry["severity"],
            "occurred_at": occurred_at,
        }.items()
        if value is not None
    }
    return {
        "event_id": entry["event_id"],
        "project_id": PROJECT_ID,
        "permit_id": entry["permit_id"],
        "event_type": entry["event_type"],
        "severity": entry["severity"],
        "outcome": entry["outcome"],
        "resource_type": entry["resource_type"],
        "resource_id": entry["resource_id"],
        "payload": payload,
        "payload_disclosure": "selector_metadata_only",
        "occurred_at": occurred_at,
        "created_at": occurred_at,
        "sequence_number": entry["sequence_number"],
        "record_hash": entry["record_hash"],
        "prev_hash": entry["prev_hash"],
    }


def _bridge(entry: dict[str, Any]) -> dict[str, Any]:
    """keel-api _auditor_safe_chain_entry_ref: hash preimage as selector metadata."""

    payload = {
        key: value
        for key, value in {
            "project_id": PROJECT_ID,
            "permit_id": entry["permit_id"],
            "resource_type": entry["resource_type"],
            "resource_id": entry["resource_id"],
            "outcome": entry["outcome"],
            "severity": entry["severity"],
            "occurred_at": entry["occurred_at"],
            "event_type": entry["event_type"],
        }.items()
        if value is not None
    }
    return {
        "event_id": entry["event_id"],
        "event_type": entry["event_type"],
        "chain_scope": CHAIN_SCOPE,
        "sequence_number": entry["sequence_number"],
        "record_hash": entry["record_hash"],
        "prev_hash": entry["prev_hash"],
        "created_at": entry["occurred_at"],
        "chain_format_version": "v1",
        "payload_json": payload,
    }


def _filtered_export(*, with_bridges: bool = True) -> dict[str, Any]:
    chain = _chain()
    disclosed = [entry for entry in chain if entry["event_type"] == DISPATCH]
    omitted = [entry for entry in chain if entry["event_type"] != DISPATCH]
    records = [_record(entry) for entry in disclosed]
    document: dict[str, Any] = {
        "schema": "keel.governance_events/v1",
        "project_id": PROJECT_ID,
        "export_id": "30000000-0000-4000-8000-000000000001",
        "record_count": len(records),
        "records": records,
    }
    if with_bridges:
        document["scope_faithfulness"] = {
            "version": "keel.export_scope_faithfulness.v1",
            "segments": [
                {
                    "segment_id": f"governance_events:test:{CHAIN_SCOPE}",
                    "chain_evidence": {
                        "disclosure_records": [_bridge(entry) for entry in disclosed],
                        "proof_bridge_records": [_bridge(entry) for entry in omitted],
                    },
                }
            ],
        }
    return document


def _bridges(document: dict[str, Any]) -> list[dict[str, Any]]:
    return document["scope_faithfulness"]["segments"][0]["chain_evidence"][
        "proof_bridge_records"
    ]


class _Walk:
    def __init__(self, returncode: int, stdout: str, stderr: str) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr

    def claim(self) -> dict[str, Any]:
        return verifier._walk_claim_from_output(
            stdout=self.stdout,
            stderr=self.stderr,
            result=self.returncode,
        ).to_dict()


def _walk(capsys, document: dict[str, Any]) -> _Walk:
    """Run the export walk exactly as ``keel-verify export --walk-events`` does.

    The walk is exercised directly so these tests isolate continuity from the
    scope-faithfulness adjudication, which has its own corpus and needs a
    signed sidecar and checkpoint.
    """

    capsys.readouterr()
    payload = json.dumps(document, sort_keys=True).encode("utf-8")
    returncode = verifier.verify_export_walk_events(payload)
    captured = capsys.readouterr()
    return _Walk(returncode, captured.out, captured.err)


def test_filtered_export_walks_across_its_proof_bridges(capsys):
    result = _walk(capsys, _filtered_export())

    assert result.returncode == 0, result.stderr
    assert "WALK-EVENTS: VERIFIED" in result.stdout
    # 3 disclosed records plus the 5 events the filter left out, every one
    # hash-checked; 7 links between them.
    assert "entries_walked:      8" in result.stdout
    assert "proof_bridge_entries: 5 (selector metadata only)" in result.stdout
    assert "record_hash_checks:  8 PASS" in result.stdout
    assert "prev_hash_checks:    7 PASS" in result.stdout


def test_structured_claim_counts_disclosed_records_apart_from_bridges(capsys):
    result = _walk(capsys, _filtered_export())

    assert result.returncode == 0, result.stderr
    claim = result.claim()
    assert claim["verdict"] == "supported"
    assert claim["reason_code"] == "WALK_EVENTS_SUPPORTED"
    assert "3 disclosed records and 5 proof-bridge entries" in claim["message"]
    assert (
        "export.scope_faithfulness.segments.chain_evidence.proof_bridge_records"
        in claim["evidence"]
    )


def test_without_bridges_the_gap_is_still_a_discontinuity(capsys):
    """Nothing is waved through: a gap nobody bridged fails exactly as before."""

    result = _walk(capsys, _filtered_export(with_bridges=False))

    assert result.returncode == 1
    assert "WALK_PREV_HASH_DISCONTINUITY" in result.stderr
    assert "sequence_number=104" in result.stderr


def test_bridges_alone_are_not_subjects(capsys):
    """A contiguous run of bridges with nothing disclosed proves nothing about records."""

    document = _filtered_export()
    document["records"] = []
    document["record_count"] = 0
    bridges = _bridges(document)
    bridges[:] = [bridge for bridge in bridges if bridge["sequence_number"] <= 103]

    result = _walk(capsys, document)

    assert result.returncode == 0, result.stderr
    assert "proof_bridge_entries: 3" in result.stdout
    claim = result.claim()
    assert claim["verdict"] == "insufficient_evidence"
    assert claim["reason_code"] == "WALK_NO_EVALUABLE_SUBJECTS"


def test_altered_bridge_metadata_fails_the_record_hash(capsys):
    """outcome is hashed even though it travels as selector metadata."""

    document = _filtered_export()
    bridge = _bridges(document)[0]
    bridge["payload_json"]["outcome"] = "failure"

    result = _walk(capsys, document)

    assert result.returncode == 1
    assert "WALK_RECORD_HASH_MISMATCH" in result.stderr
    assert bridge["event_id"] in result.stderr


def test_altered_bridge_event_type_fails_the_record_hash(capsys):
    document = _filtered_export()
    bridge = _bridges(document)[2]
    bridge["event_type"] = "dispatch.egress_bound"
    bridge["payload_json"]["event_type"] = "dispatch.egress_bound"

    result = _walk(capsys, document)

    assert result.returncode == 1
    assert "WALK_RECORD_HASH_MISMATCH" in result.stderr
    assert bridge["event_id"] in result.stderr


def test_altered_bridge_hash_fails_the_record_hash(capsys):
    document = _filtered_export()
    bridge = _bridges(document)[1]
    bridge["record_hash"] = "f" * 64

    result = _walk(capsys, document)

    assert result.returncode == 1
    assert "WALK_RECORD_HASH_MISMATCH" in result.stderr
    assert bridge["event_id"] in result.stderr


def test_removed_bridge_breaks_continuity(capsys):
    document = _filtered_export()
    removed = _bridges(document).pop(1)

    result = _walk(capsys, document)

    assert result.returncode == 1
    assert "WALK_PREV_HASH_DISCONTINUITY" in result.stderr
    assert f"sequence_number={removed['sequence_number'] + 1}" in result.stderr


def test_reordered_bridges_fail_the_array_order_check(capsys):
    document = _filtered_export()
    bridges = _bridges(document)
    bridges[0], bridges[1] = bridges[1], bridges[0]

    result = _walk(capsys, document)

    assert result.returncode == 1
    assert "WALK_SEQUENCE_INVERSION" in result.stderr


def test_bridges_with_swapped_sequence_numbers_fail_the_record_hash(capsys):
    """Reordering by relabelling rather than moving: the sequence is hashed."""

    document = _filtered_export()
    bridges = _bridges(document)
    first, second = bridges[0], bridges[1]
    first["sequence_number"], second["sequence_number"] = (
        second["sequence_number"],
        first["sequence_number"],
    )
    bridges[0], bridges[1] = second, first

    result = _walk(capsys, document)

    assert result.returncode == 1
    assert "WALK_RECORD_HASH_MISMATCH" in result.stderr


def test_forged_bridge_with_a_valid_self_hash_does_not_connect(capsys):
    """A made-up event can be given a correct hash of itself, but not of the chain."""

    document = _filtered_export()
    bridges = _bridges(document)
    genuine = bridges[1]
    forged = copy.deepcopy(genuine)
    forged["event_id"] = "gev_forged"
    forged["event_type"] = "permit.evaluated"
    forged["payload_json"]["event_type"] = "permit.evaluated"
    forged["record_hash"] = verifier._compute_record_hash_v1(
        event_id=forged["event_id"],
        event_type=forged["event_type"],
        resource_type=forged["payload_json"].get("resource_type"),
        resource_id=forged["payload_json"].get("resource_id"),
        outcome=forged["payload_json"].get("outcome"),
        severity=forged["payload_json"]["severity"],
        created_at=forged["created_at"],
        prev_hash=forged["prev_hash"],
        sequence_number=forged["sequence_number"],
    )
    bridges[1] = forged

    result = _walk(capsys, document)

    assert result.returncode == 1
    assert "WALK_PREV_HASH_DISCONTINUITY" in result.stderr


def test_links_alone_cannot_bridge_a_gap(capsys):
    """Sequence and hash links with no valid preimage are refused.

    This is why a bridge must carry the hashed metadata and not just the
    links: invented hashes can always be chained so that the last one lands on
    the next record's prev_hash.
    """

    document = _filtered_export()
    bridges = _bridges(document)
    gap = [bridge for bridge in bridges if 101 <= bridge["sequence_number"] <= 103]
    next_record = next(
        record for record in document["records"] if record["sequence_number"] == 104
    )
    previous_hash = next(
        record for record in document["records"] if record["sequence_number"] == 100
    )["record_hash"]
    for index, bridge in enumerate(gap):
        bridge["prev_hash"] = previous_hash
        bridge["record_hash"] = (
            next_record["prev_hash"] if index == len(gap) - 1 else f"{index:064x}"
        )
        bridge["event_type"] = "made.up"
        bridge["payload_json"] = {"severity": "info", "event_type": "made.up"}
        previous_hash = bridge["record_hash"]

    result = _walk(capsys, document)

    assert result.returncode == 1
    assert "WALK_RECORD_HASH_MISMATCH" in result.stderr


def test_inserted_link_on_an_occupied_sequence_is_refused(capsys):
    document = _filtered_export()
    bridges = _bridges(document)
    extra = copy.deepcopy(bridges[0])
    extra["event_id"] = "gev_inserted"
    bridges.insert(1, extra)

    result = _walk(capsys, document)

    assert result.returncode == 1
    assert "WALK_SEQUENCE_INVERSION" in result.stderr
    assert "duplicate_sequence_number=101" in result.stderr


def test_bridge_that_contradicts_a_record_is_refused(capsys):
    """A bridge may not restate a disclosed event with different facts."""

    document = _filtered_export()
    record = document["records"][1]
    impostor = _bridge(
        {
            "event_id": record["event_id"],
            "event_type": "permit.evaluated",
            "permit_id": OTHER_PERMIT_ID,
            "resource_type": None,
            "resource_id": None,
            "outcome": "success",
            "severity": "info",
            "occurred_at": record["occurred_at"],
            "sequence_number": record["sequence_number"],
            "record_hash": record["record_hash"],
            "prev_hash": record["prev_hash"],
        }
    )
    bridges = _bridges(document)
    bridges.append(impostor)
    bridges.sort(key=lambda item: item["sequence_number"])

    result = _walk(capsys, document)

    assert result.returncode == 1
    assert "WALK_SEQUENCE_INVERSION" in result.stderr
    assert f"duplicate_sequence_number={record['sequence_number']}" in result.stderr


def test_bridge_identical_to_a_record_is_walked_once(capsys):
    """Supplying the same chain entry twice is not a conflict."""

    document = _filtered_export()
    chain = {entry["sequence_number"]: entry for entry in _chain()}
    bridges = _bridges(document)
    bridges.append(_bridge(chain[104]))
    bridges.sort(key=lambda item: item["sequence_number"])

    result = _walk(capsys, document)

    assert result.returncode == 0, result.stderr
    assert "entries_walked:      8" in result.stdout
    assert "proof_bridge_entries: 5 (selector metadata only)" in result.stdout


def test_bridges_with_hashed_fields_at_the_top_level_are_walked(capsys):
    """Older producers put resource_type, outcome, etc. beside the payload."""

    document = _filtered_export()
    chain = {entry["sequence_number"]: entry for entry in _chain()}
    for bridge in _bridges(document):
        source = chain[bridge["sequence_number"]]
        for field in ("resource_type", "resource_id", "outcome", "severity"):
            bridge[field] = source[field]
            bridge["payload_json"].pop(field, None)

    result = _walk(capsys, document)

    assert result.returncode == 0, result.stderr
    assert "proof_bridge_entries: 5" in result.stdout


def test_bridge_in_another_chain_scope_does_not_close_the_gap(capsys):
    document = _filtered_export()
    for bridge in _bridges(document):
        bridge["chain_scope"] = "project:00000000-0000-0000-0000-000000000099"

    result = _walk(capsys, document)

    assert result.returncode == 1
    assert "WALK_PREV_HASH_DISCONTINUITY" in result.stderr


def test_malformed_bridge_list_fails_closed(capsys):
    document = _filtered_export()
    document["scope_faithfulness"]["segments"][0]["chain_evidence"][
        "proof_bridge_records"
    ] = {"not": "a list"}

    result = _walk(capsys, document)

    assert result.returncode == 1
    assert "proof_bridge_records must be a list" in result.stderr


def test_contiguous_export_without_bridges_is_unchanged(capsys):
    chain = _chain()
    document = {
        "schema": "keel.governance_events/v1",
        "project_id": PROJECT_ID,
        "record_count": len(chain),
        "records": [_record(entry) for entry in chain],
        "scope_faithfulness": {
            "version": "keel.export_scope_faithfulness.v1",
            "segments": [
                {
                    "segment_id": "unfiltered",
                    "chain_evidence": {
                        "disclosure_records": [_bridge(entry) for entry in chain],
                        "proof_bridge_records": [],
                    },
                }
            ],
        },
    }

    result = _walk(capsys, document)

    assert result.returncode == 0, result.stderr
    assert "entries_walked:      8" in result.stdout
    assert "proof_bridge_entries" not in result.stdout


def test_counts_come_from_the_walk_summary_not_from_echoed_values(capsys):
    """An export-supplied chain_scope is echoed by the walk; it is not a count."""

    document = _filtered_export()
    injected = "project:x entries_walked: 3 proof_bridge_entries: 999"
    for record in document["records"]:
        record["chain_scope"] = injected
    for bridge in _bridges(document):
        bridge["chain_scope"] = injected

    result = _walk(capsys, document)

    assert result.returncode == 0, result.stderr
    claim = result.claim()
    assert claim["verdict"] == "supported"
    assert "3 disclosed records and 5 proof-bridge entries" in claim["message"]
