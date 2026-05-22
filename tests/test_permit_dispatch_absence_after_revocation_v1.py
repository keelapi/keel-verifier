from __future__ import annotations

from pathlib import Path

from step4_permit_helpers import (
    EFFECTIVE_AT,
    absence_case,
    absence_predicate,
    scope_record,
)
from keel_verifier.verifier import (
    _adjudicate_permit_dispatch_absence_after_revocation_v1,
)


def _claim(case: dict):
    return _adjudicate_permit_dispatch_absence_after_revocation_v1(
        export_document=case["export_document"],
        manifest=case["manifest"],
        manifest_path=case["manifest_path"],
        key_manifest_source=None,
        scope_claims=case["scope_claims"],
        revocation_claim=case["revocation_claim"],
    )


def test_dispatch_absence_after_revocation_supported(tmp_path: Path) -> None:
    claim = _claim(absence_case(tmp_path))

    assert claim.aggregate_verdict == "supported"
    assert claim.reason_code == "PERMIT_DISPATCH_ABSENCE_AFTER_REVOCATION_SUPPORTED"


def test_dispatch_absence_disproved_when_sidecar_reports_matching_count(
    tmp_path: Path,
) -> None:
    claim = _claim(absence_case(tmp_path, matching_count=1))

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "EXPORT_SCOPE_POST_REVOCATION_DISPATCH_PRESENT"


def test_dispatch_absence_disproved_when_disclosure_record_matches(
    tmp_path: Path,
) -> None:
    claim = _claim(
        absence_case(
            tmp_path,
            disclosure_records=[
                scope_record(occurred_at="2026-05-21T10:06:00.000000Z")
            ],
        )
    )

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "EXPORT_SCOPE_POST_REVOCATION_DISPATCH_PRESENT"


def test_dispatch_absence_disproved_when_bridge_record_matches(
    tmp_path: Path,
) -> None:
    claim = _claim(
        absence_case(
            tmp_path,
            proof_bridge_records=[
                scope_record(occurred_at="2026-05-21T10:06:00.000000Z")
            ],
        )
    )

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "EXPORT_SCOPE_BRIDGE_RECORD_MATCHES_PREDICATE"


def test_dispatch_absence_predicate_out_of_grammar_is_unverifiable(
    tmp_path: Path,
) -> None:
    predicate = absence_predicate()
    predicate["equals"]["event_type"] = ["dispatch.egress_bound"]

    claim = _claim(absence_case(tmp_path, predicate=predicate))

    assert claim.aggregate_verdict == "unverifiable_scope"
    assert claim.reason_code == "EXPORT_SCOPE_PREDICATE_OUT_OF_GRAMMAR"


def test_dispatch_absence_missing_checkpoint_is_insufficient(tmp_path: Path) -> None:
    claim = _claim(absence_case(tmp_path, write_checkpoint=False))

    assert claim.aggregate_verdict == "insufficient_evidence"
    assert claim.reason_code == "CHECKPOINT_SCOPE_STATE_CHECKPOINT_MISSING"


def test_dispatch_absence_missing_sidecar_is_insufficient(tmp_path: Path) -> None:
    claim = _claim(absence_case(tmp_path, write_sidecar=False))

    assert claim.aggregate_verdict == "insufficient_evidence"
    assert claim.reason_code == "CHECKPOINT_SCOPE_STATE_MISSING"


def test_pre_revocation_dispatch_still_supported(tmp_path: Path) -> None:
    claim = _claim(
        absence_case(
            tmp_path,
            disclosure_records=[
                scope_record(occurred_at="2026-05-21T10:04:59.999999Z")
            ],
        )
    )

    assert claim.aggregate_verdict == "supported"
    assert claim.reason_code == "PERMIT_DISPATCH_ABSENCE_AFTER_REVOCATION_SUPPORTED"


def test_occurred_at_equal_to_effective_at_disproves(tmp_path: Path) -> None:
    claim = _claim(
        absence_case(
            tmp_path,
            disclosure_records=[scope_record(occurred_at=EFFECTIVE_AT)],
        )
    )

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "EXPORT_SCOPE_POST_REVOCATION_DISPATCH_PRESENT"


def test_challenge_events_do_not_disrupt_absence(tmp_path: Path) -> None:
    claim = _claim(
        absence_case(
            tmp_path,
            disclosure_records=[
                scope_record(
                    event_type="permit.challenge.transition",
                    occurred_at="2026-05-21T10:06:00.000000Z",
                )
            ],
        )
    )

    assert claim.aggregate_verdict == "supported"
    assert claim.reason_code == "PERMIT_DISPATCH_ABSENCE_AFTER_REVOCATION_SUPPORTED"
