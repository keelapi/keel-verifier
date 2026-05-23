from __future__ import annotations

import argparse
import json
from pathlib import Path

from keel_verifier.verifier import (
    _adjudicate_audit_attested_v1,
    _adjudicate_operator_approved_v1,
    _adjudicate_pre_dispatch_counter_signed_v1,
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


def test_permit_v2_signature_envelope_corpus_auto_requires_claims() -> None:
    records = _records()
    assert len(records) == 8

    for record in records:
        report = verify_export_structured(_args(record))
        expected_exit = 0 if record["expected_verdict"] == "supported" else 1
        assert report.exit_code == expected_exit, record["id"]
        claim = _claim(report, record["claim"])
        assert claim["verdict"] == record["expected_verdict"], record["id"]
        assert claim["reason_code"] == record["expected_code"], record["id"]


def test_cross_slot_replay_payload_type_mismatch_does_not_satisfy_operator_claim() -> None:
    record = _record("operator_approval_payload_type_mismatch")
    report = verify_export_structured(_args(record))
    claims = report.to_dict()["claims"]

    counter = _claim(report, "permit.counter_signed.v1")
    assert counter["verdict"] == "disproved"
    assert counter["reason_code"] == "PAYLOAD_TYPE_MISMATCH"
    assert "permit.operator_approved.v1" not in {claim["name"] for claim in claims}


def test_direct_operator_approved_adjudicator_happy_and_failure() -> None:
    happy = _record("happy_path_operator_approved")
    failure = _record("signed_payload_hash_tampered")

    happy_claim = _adjudicate_operator_approved_v1(
        export_document=_json(_path(happy, "export_file")),
        manifest=_json(_path(happy, "manifest")),
        key_manifest_source=str(_path(happy, "key_manifest")),
    )
    failure_claim = _adjudicate_operator_approved_v1(
        export_document=_json(_path(failure, "export_file")),
        manifest=_json(_path(failure, "manifest")),
        key_manifest_source=str(_path(failure, "key_manifest")),
    )

    assert happy_claim.aggregate_verdict == "supported"
    assert happy_claim.reason_code == "PERMIT_OPERATOR_APPROVAL_SUPPORTED"
    assert failure_claim.aggregate_verdict == "disproved"
    assert failure_claim.reason_code == "PERMIT_OPERATOR_APPROVAL_INVALID"


def test_direct_counter_signed_adjudicator_happy_and_failure() -> None:
    happy = _record("happy_path_counter_signed_pre_dispatch")
    failure = _record("counter_signature_post_revocation_signed_at")

    happy_claim = _adjudicate_pre_dispatch_counter_signed_v1(
        export_document=_json(_path(happy, "export_file")),
        manifest=_json(_path(happy, "manifest")),
        key_manifest_source=str(_path(happy, "key_manifest")),
    )
    failure_claim = _adjudicate_pre_dispatch_counter_signed_v1(
        export_document=_json(_path(failure, "export_file")),
        manifest=_json(_path(failure, "manifest")),
        key_manifest_source=str(_path(failure, "key_manifest")),
    )

    assert happy_claim.aggregate_verdict == "supported"
    assert happy_claim.reason_code == "PERMIT_COUNTER_SIGNATURE_SUPPORTED"
    assert failure_claim.aggregate_verdict == "disproved"
    assert failure_claim.reason_code == "PERMIT_COUNTER_SIGNATURE_INVALID"


def test_direct_audit_attested_adjudicator_happy_and_failure() -> None:
    happy = _record("happy_path_audit_attested")
    failure = _record("audit_attestation_batch_unknown")

    happy_claim = _adjudicate_audit_attested_v1(
        export_document=_json(_path(happy, "export_file")),
        manifest=_json(_path(happy, "manifest")),
        key_manifest_source=str(_path(happy, "key_manifest")),
    )
    failure_claim = _adjudicate_audit_attested_v1(
        export_document=_json(_path(failure, "export_file")),
        manifest=_json(_path(failure, "manifest")),
        key_manifest_source=str(_path(failure, "key_manifest")),
    )

    assert happy_claim.aggregate_verdict == "supported"
    assert happy_claim.reason_code == "PERMIT_AUDIT_ATTESTATION_SUPPORTED"
    assert failure_claim.aggregate_verdict == "disproved"
    assert failure_claim.reason_code == "PERMIT_AUDIT_ATTESTATION_BATCH_MISMATCH"


def test_direct_adjudicator_reports_unknown_signer_in_registry() -> None:
    record = _record("signer_id_unknown_in_registry")

    claim = _adjudicate_operator_approved_v1(
        export_document=_json(_path(record, "export_file")),
        manifest=_json(_path(record, "manifest")),
        key_manifest_source=str(_path(record, "key_manifest")),
    )

    assert claim.aggregate_verdict == "insufficient_evidence"
    assert claim.reason_code == "PERMIT_OPERATOR_APPROVAL_KEY_NOT_TRUSTED"


def test_permit_v2_claim_cli_subcommands(run_cli) -> None:
    cases = [
        ("happy_path_operator_approved", "operator_approved"),
        ("happy_path_counter_signed_pre_dispatch", "counter_signed"),
        ("happy_path_audit_attested", "audit_attested"),
    ]
    for fixture_id, command in cases:
        record = _record(fixture_id)
        result = run_cli(
            "claim",
            command,
            "--export-file",
            str(_path(record, "export_file")),
            "--manifest",
            str(_path(record, "manifest")),
            "--key-manifest",
            str(_path(record, "key_manifest")),
        )
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        assert payload["status"] == "supported"
        assert payload["claim"]["name"] == record["claim"]


def test_permit_v2_claim_cli_failure_path(run_cli) -> None:
    record = _record("operator_approval_payload_type_mismatch")
    result = run_cli(
        "claim",
        "counter_signed",
        "--export-file",
        str(_path(record, "export_file")),
        "--manifest",
        str(_path(record, "manifest")),
        "--key-manifest",
        str(_path(record, "key_manifest")),
    )
    payload = json.loads(result.stdout)

    assert result.returncode == 1
    assert payload["status"] == "disproved"
    assert payload["reason_code"] == "PAYLOAD_TYPE_MISMATCH"
