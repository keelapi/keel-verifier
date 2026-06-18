from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from keel_verifier.verifier import (
    _adjudicate_permit_audit_attestation_v1,
    _adjudicate_permit_counter_signature_v1,
    _adjudicate_permit_operator_approval_v1,
    verify_export_structured,
)


FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "permit_v2_signature_envelope"
CORPUS = FIXTURE_ROOT / "corpus.json"
ACCOUNT_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
ACCOUNT_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def _legacy_json_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _public_key(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return "ed25519:" + base64.b64encode(raw).decode("ascii")


def _slot_key_id(public_key: str) -> str:
    raw = base64.b64decode(public_key.removeprefix("ed25519:"))
    return hashlib.sha256(raw).hexdigest()


def _v7_permit_hash(permit: dict[str, Any], *, legacy: bool = False) -> str:
    excluded = {
        "operator_approval",
        "counter_signature",
        "audit_attestation",
        "permit_format_version",
        "issuer_signature_hash",
        "permit_canonical_hash",
        "permit_v2_signed_payloads",
        "signature_payloads",
        "revocation",
        "audit_batch",
        "audit_batches",
        "known_audit_batches",
        "batches",
        "counter_signature_execution_intent",
        "counter_signature_execution_intent_v1",
        "execution_intent",
        "dispatch_facts",
    }
    payload = {key: value for key, value in permit.items() if key not in excluded}
    payload_bytes = _legacy_json_bytes(payload) if legacy else rfc8785.dumps(payload)
    return hashlib.sha256(payload_bytes).hexdigest()


def _sign_v7_operator_slot(
    permit: dict[str, Any],
    private_key: Ed25519PrivateKey,
    *,
    legacy_payload_bytes: bool = False,
) -> None:
    slot = permit["operator_approval"]
    payload = {
        "payload_type": "permit.operator_approval.v1",
        "permit_id": permit["id"],
        "issuer_signature_hash": permit["issuer_signature_hash"],
        "permit_canonical_hash": _v7_permit_hash(
            permit,
            legacy=legacy_payload_bytes,
        ),
        "operator_id": slot["signer_id"],
        "signed_at": slot["signed_at"],
    }
    payload_bytes = (
        _legacy_json_bytes(payload) if legacy_payload_bytes else rfc8785.dumps(payload)
    )
    slot["signed_payload_hash"] = hashlib.sha256(payload_bytes).hexdigest()
    slot["signature"] = base64.b64encode(private_key.sign(payload_bytes)).decode(
        "ascii"
    )


def _v7_operator_fixture(
    *,
    key_account_id: str,
    manifest_account_id: str | None = None,
    permit_account_id: str | None = ACCOUNT_A,
    legacy_slot_payload: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    record = _record("operator_approval_positive_01")
    permit = copy.deepcopy(_json(_path(record, "export_file")))
    manifest = copy.deepcopy(_json(_path(record, "manifest")))
    private_key = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"v7-operator-negative-corpus").digest()
    )
    public_key = _public_key(private_key)
    slot = permit["operator_approval"]

    permit["binding_version"] = "v7"
    if permit_account_id is None:
        permit.pop("account_id", None)
    else:
        permit["account_id"] = permit_account_id
    if manifest_account_id is None:
        manifest.pop("account_id", None)
    else:
        manifest["account_id"] = manifest_account_id
    slot["key_id"] = _slot_key_id(public_key)
    _sign_v7_operator_slot(
        permit,
        private_key,
        legacy_payload_bytes=legacy_slot_payload,
    )
    key_manifest = {
        "keys": [
            {
                "account_id": key_account_id,
                "algorithm": "ed25519",
                "key_id": slot["key_id"],
                "public_key": public_key,
                "purpose": "permit_v2_operator",
                "signer_id": slot["signer_id"],
                "signer_role": "operator",
                "status": "active",
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": None,
            }
        ]
    }
    return permit, manifest, key_manifest


def _operator_claim(
    tmp_path: Path,
    *,
    permit: dict[str, Any],
    manifest: dict[str, Any],
    key_manifest: dict[str, Any],
):
    key_manifest_path = tmp_path / "key_manifest.json"
    key_manifest_path.write_text(
        json.dumps(key_manifest, sort_keys=True),
        encoding="utf-8",
    )
    return _adjudicate_permit_operator_approval_v1(
        export_document=permit,
        manifest=manifest,
        key_manifest_source=str(key_manifest_path),
    )


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


def _v2_claim_for_v1(name: str) -> str:
    return name.removesuffix(".v1") + ".v2"


def _assert_omitted_key_status_floor(report, record: dict) -> None:
    assert report.exit_code == 1, record["id"]
    completeness = _claim(report, "key.status.completeness.v1")
    assert completeness["verdict"] == "insufficient_evidence", record["id"]
    assert (
        completeness["reason_code"] == "KEY_STATUS_COMPLETENESS_MANIFEST_MISSING"
    ), record["id"]
    v2_claim = _claim(report, _v2_claim_for_v1(record["claim"]))
    assert v2_claim["verdict"] == "insufficient_evidence", record["id"]
    assert v2_claim["reason_code"].endswith(
        "KEY_STATUS_COMPLETENESS_UNSUPPORTED"
    ), record["id"]


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
        claim = _claim(report, record["claim"])
        assert claim["verdict"] == record["expected_verdict"], record["id"]
        assert claim["reason_code"] == record["expected_code"], record["id"]
        expected_state = {
            "supported": "verified",
            "disproved": "observed",
            "insufficient_evidence": "unverifiable",
        }[record["expected_verdict"]]
        assert claim["epistemic_state"][_slot_for_claim(record["claim"])] == expected_state
        if record["expected_verdict"] == "supported":
            _assert_omitted_key_status_floor(report, record)
        else:
            assert report.exit_code == 1, record["id"]


def test_permit_v2_auto_required_floor_rejects_omitted_key_status_completeness() -> None:
    record = _record("operator_approval_positive_01")
    report = verify_export_structured(_args(record))

    operator = _claim(report, "permit.operator_approval.v1")
    assert operator["verdict"] == "supported"
    _assert_omitted_key_status_floor(report, record)


def test_payload_type_mismatch_disproves_slot_claim() -> None:
    record = _record("operator_approval_negative_payload_type_mismatch")
    report = verify_export_structured(_args(record))

    operator = _claim(report, "permit.operator_approval.v1")
    assert operator["verdict"] == "disproved"
    assert operator["reason_code"] == "PAYLOAD_TYPE_MISMATCH"


def test_v7_operator_slot_rejects_signed_account_manifest_mismatch(
    tmp_path: Path,
) -> None:
    permit, manifest, key_manifest = _v7_operator_fixture(
        permit_account_id=ACCOUNT_A,
        manifest_account_id=ACCOUNT_B,
        key_account_id=ACCOUNT_A,
    )

    claim = _operator_claim(
        tmp_path,
        permit=permit,
        manifest=manifest,
        key_manifest=key_manifest,
    )

    assert claim.aggregate_verdict != "supported"
    assert "account" in claim.message.lower()


def test_v7_operator_slot_rejects_manifest_only_account_for_key_lookup(
    tmp_path: Path,
) -> None:
    permit, manifest, key_manifest = _v7_operator_fixture(
        permit_account_id=None,
        manifest_account_id=ACCOUNT_A,
        key_account_id=ACCOUNT_A,
    )

    claim = _operator_claim(
        tmp_path,
        permit=permit,
        manifest=manifest,
        key_manifest=key_manifest,
    )

    assert claim.aggregate_verdict == "insufficient_evidence"
    assert claim.reason_code == "PERMIT_OPERATOR_APPROVAL_KEY_NOT_TRUSTED"
    assert "account_id" in claim.message


def test_v7_operator_slot_rejects_legacy_json_signed_payload_bytes(
    tmp_path: Path,
) -> None:
    permit, manifest, key_manifest = _v7_operator_fixture(
        permit_account_id=ACCOUNT_A,
        key_account_id=ACCOUNT_A,
        legacy_slot_payload=True,
    )

    claim = _operator_claim(
        tmp_path,
        permit=permit,
        manifest=manifest,
        key_manifest=key_manifest,
    )

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "PERMIT_OPERATOR_APPROVAL_INVALID"
    assert "signed_payload_hash" in claim.message


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
