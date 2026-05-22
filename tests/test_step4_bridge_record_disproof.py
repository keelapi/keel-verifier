from __future__ import annotations

from pathlib import Path

from step4_permit_helpers import absence_case, scope_record
from keel_verifier.verifier import (
    _adjudicate_permit_dispatch_absence_after_revocation_v1,
)


def test_bridge_record_satisfying_absence_predicate_is_disproved(
    tmp_path: Path,
) -> None:
    case = absence_case(
        tmp_path,
        proof_bridge_records=[
            scope_record(occurred_at="2026-05-21T10:06:00.000000Z")
        ],
    )

    claim = _adjudicate_permit_dispatch_absence_after_revocation_v1(
        export_document=case["export_document"],
        manifest=case["manifest"],
        manifest_path=case["manifest_path"],
        key_manifest_source=None,
        scope_claims=case["scope_claims"],
        revocation_claim=case["revocation_claim"],
    )

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "EXPORT_SCOPE_BRIDGE_RECORD_MATCHES_PREDICATE"
