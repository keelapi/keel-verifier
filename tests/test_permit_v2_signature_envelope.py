from __future__ import annotations

import argparse
import json
from pathlib import Path

from keel_verifier.verifier import (
    _adjudicate_permit_audit_attestation_v1,
    _adjudicate_permit_counter_signature_v1,
    _adjudicate_permit_operator_approval_v1,
    verify_export_structured,
)


FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "permit_v2_signature_envelope"
CORPUS = FIXTURE_ROOT / "corpus.json"


def _records() -> list[dict]:
    return json.loads(CORPUS.read_text(encoding="utf-8"))["records"]


def _record(fixture_id: str) -> dict:
    return next(record for record in _records() if record["id"] == fixture_id)


def _path(record: dict, key: str) -> Path:
    return FIXTURE_ROOT / record["pack"][key]


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _args(record: dict) -> argparse.Namespace:
    return argparse.Namespace(
        export_file=str(_path(record, "export_file")),
        manifest=str(_path(record, "manifest")),
        key_manifest=str(_path(record, "key_manifest")),
        key_manifest_url=None,
        expected_public_key=None,
        public_key=None,
        self_attested=False,
        offline=False,
        allow_unsigned=False,
        walk_events=False,
        verify_closure=False,
        as_json=True,
    )


def _claim(report, name: str) -> dict:
    for claim in report.to_dict()["claims"]:
        if claim["name"] == name:
            return claim
    raise AssertionError(f"missing claim {name}")


def _slot_for_claim(name: str) -> str:
    return {
        "permit.operator_approval.v1": "operator_approval",
        "permit.counter_signature.v1": "counter_signature",
        "permit.audit_attestation.v1": "audit_attestation",
    }[name]


def test_permit_v2_signature_envelope_corpus_auto_requires_claims() -> None:
    records = _records()
    by_claim_kind = {
        (claim, kind): sum(
            1 for record in records if record["claim"] == claim and record["kind"] == kind
        )
        for claim in {record["claim"] for record in records}
        for kind in {"positive", "negative", "edge"}
    }
    for claim in {
        "permit.operator_approval.v1",
        "permit.counter_signature.v1",
        "permit.audit_attestation.v1",
    }:
        assert by_claim_kind[(claim, "positive")] >= 6
        assert by_claim_kind[(claim, "negative")] >= 4
        assert by_claim_kind[(claim, "edge")] >= 2

    for record in records:
        report = verify_export_structured(_args(record))
        expected_exit = 0 if record["expected_verdict"] == "supported" else 1
        assert report.exit_code == expected_exit, record["id"]
        claim = _claim(report, record["claim"])
        assert claim["verdict"] == record["expected_verdict"], record["id"]
        assert claim["reason_code"] == record["expected_code"], record["id"]
        expected_state = {
            "supported": "verified",
            "disproved": "observed",
            "insufficient_evidence": "unverifiable",
        }[record["expected_verdict"]]
        assert claim["epistemic_state"][_slot_for_claim(record["claim"])] == expected_state


def test_payload_type_mismatch_disproves_slot_claim() -> None:
    record = _record("operator_approval_negative_payload_type_mismatch")
    report = verify_export_structured(_args(record))

    operator = _claim(report, "permit.operator_approval.v1")
    assert operator["verdict"] == "disproved"
    assert operator["reason_code"] == "PAYLOAD_TYPE_MISMATCH"


def test_direct_operator_approval_adjudicator_happy_and_failure() -> None:
    happy = _record("operator_approval_positive_01")
    failure = _record("operator_approval_negative_signed_payload_hash_tampered")

    happy_claim = _adjudicate_permit_operator_approval_v1(
        export_document=_json(_path(happy, "export_file")),
        manifest=_json(_path(happy, "manifest")),
        key_manifest_source=str(_path(happy, "key_manifest")),
    )
    failure_claim = _adjudicate_permit_operator_approval_v1(
        export_document=_json(_path(failure, "export_file")),
        manifest=_json(_path(failure, "manifest")),
        key_manifest_source=str(_path(failure, "key_manifest")),
    )

    assert happy_claim.aggregate_verdict == "supported"
    assert happy_claim.reason_code == "PERMIT_OPERATOR_APPROVAL_SUPPORTED"
    assert failure_claim.aggregate_verdict == "disproved"
    assert failure_claim.reason_code == "PERMIT_OPERATOR_APPROVAL_INVALID"


def test_direct_counter_signature_adjudicator_happy_and_failure() -> None:
    happy = _record("counter_signature_positive_01")
    failure = _record("counter_signature_negative_counter_post_revocation")

    happy_claim = _adjudicate_permit_counter_signature_v1(
        export_document=_json(_path(happy, "export_file")),
        manifest=_json(_path(happy, "manifest")),
        key_manifest_source=str(_path(happy, "key_manifest")),
    )
    failure_claim = _adjudicate_permit_counter_signature_v1(
        export_document=_json(_path(failure, "export_file")),
        manifest=_json(_path(failure, "manifest")),
        key_manifest_source=str(_path(failure, "key_manifest")),
    )

    assert happy_claim.aggregate_verdict == "supported"
    assert happy_claim.reason_code == "PERMIT_COUNTER_SIGNATURE_SUPPORTED"
    assert failure_claim.aggregate_verdict == "disproved"
    assert failure_claim.reason_code == "PERMIT_COUNTER_SIGNATURE_INVALID"


def test_direct_counter_signature_execution_intent_mismatch() -> None:
    record = _record("counter_signature_negative_execution_intent_mismatch")

    claim = _adjudicate_permit_counter_signature_v1(
        export_document=_json(_path(record, "export_file")),
        manifest=_json(_path(record, "manifest")),
        key_manifest_source=str(_path(record, "key_manifest")),
    )

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "counter_signature.execution_intent_mismatch"


def test_direct_audit_attestation_adjudicator_happy_and_failure() -> None:
    happy = _record("audit_attestation_positive_01")
    failure = _record("audit_attestation_negative_audit_batch_unknown")

    happy_claim = _adjudicate_permit_audit_attestation_v1(
        export_document=_json(_path(happy, "export_file")),
        manifest=_json(_path(happy, "manifest")),
        key_manifest_source=str(_path(happy, "key_manifest")),
    )
    failure_claim = _adjudicate_permit_audit_attestation_v1(
        export_document=_json(_path(failure, "export_file")),
        manifest=_json(_path(failure, "manifest")),
        key_manifest_source=str(_path(failure, "key_manifest")),
    )

    assert happy_claim.aggregate_verdict == "supported"
    assert happy_claim.reason_code == "PERMIT_AUDIT_ATTESTATION_SUPPORTED"
    assert failure_claim.aggregate_verdict == "disproved"
    assert failure_claim.reason_code == "PERMIT_AUDIT_ATTESTATION_BATCH_MISMATCH"


def test_direct_adjudicators_report_missing_key_registry_data() -> None:
    cases = [
        ("operator_approval_edge_missing_key_registry", _adjudicate_permit_operator_approval_v1),
        ("counter_signature_edge_missing_key_registry", _adjudicate_permit_counter_signature_v1),
        ("audit_attestation_edge_missing_key_registry", _adjudicate_permit_audit_attestation_v1),
    ]
    for fixture_id, adjudicator in cases:
        record = _record(fixture_id)
        claim = adjudicator(
            export_document=_json(_path(record, "export_file")),
            manifest=_json(_path(record, "manifest")),
            key_manifest_source=str(_path(record, "key_manifest")),
        )

        assert claim.aggregate_verdict == "insufficient_evidence"
        assert claim.reason_code.endswith("KEY_NOT_TRUSTED")


def test_permit_v2_claim_cli_subcommands(run_cli) -> None:
    cases = [
        ("operator_approval_positive_01", "permit.operator_approval.v1"),
        ("counter_signature_positive_01", "permit.counter_signature.v1"),
        ("audit_attestation_positive_01", "permit.audit_attestation.v1"),
    ]
    for fixture_id, command in cases:
        record = _record(fixture_id)
        result = run_cli(
            "claim",
            command,
            str(_path(record, "export_file").parent),
        )
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        assert payload["status"] == "supported"
        assert payload["claim"]["name"] == record["claim"]


def test_permit_v2_claim_cli_failure_path(run_cli) -> None:
    record = _record("counter_signature_negative_execution_intent_mismatch")
    result = run_cli(
        "claim",
        "permit.counter_signature.v1",
        str(_path(record, "export_file").parent),
    )
    payload = json.loads(result.stdout)

    assert result.returncode == 1
    assert payload["status"] == "disproved"
    assert payload["reason_code"] == "counter_signature.execution_intent_mismatch"
