"""NAE M1 native action evidence (``nae-m1-interface`` §4.3, §7).

Inputs are keel-api's committed vectors, copied byte for byte (see
``tests/fixtures/native_action/SOURCE.md``), and the native action packs that a
local keel-api candidate exported over HTTP after a real propose → review →
resume lifecycle (throwaway test keys; public keys only).

Covers:
* the 11 canonical-action golden vectors (hash, JCS length, verdict, reason);
* the 3 keyed-digest vectors (the documented rule, recomputed here);
* the 9 pack vectors (RFC 6902 patches over the API's real ``base_export``);
* the real candidate packs end to end through ``native-action-pack``,
  ``export --json``, ``export --raw`` and a zip;
* every pack-vector mutation applied to the real export and re-signed, so the
  native checks (not the content hash) are what refuses it;
* the checks this verifier adds beyond the API's reference implementation.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import zipfile
from pathlib import Path

import pytest
import rfc8785

from conftest import keypair, write_json, write_signed_export
from keel_verifier.native_action import (
    ADDITIONAL_CHECKS,
    check_native_action_pack,
    evaluate_native_action_attribute,
    exact_review_v2_hash,
    jcs,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "native_action"
GOLDEN = json.loads((FIXTURES / "native_action_golden_vectors_v1.json").read_text("utf-8"))
PACK_VECTORS = json.loads((FIXTURES / "native_action_pack_vectors_v1.json").read_text("utf-8"))
CANDIDATE = FIXTURES / "candidate"
REVIEW_RUN = CANDIDATE / "review_run"
REVIEWED = REVIEW_RUN / "reviewed_permit"
EXECUTION = REVIEW_RUN / "execution_permit"
INSTANCE_ROOT = REVIEW_RUN / "instance-root.json"
ALLOW_RUN = CANDIDATE / "allow_run"
ALLOWED = ALLOW_RUN / "allowed_permit"
ALLOW_ROOT = ALLOW_RUN / "instance-root.json"

SOURCE_SHA256 = {
    "native_action_golden_vectors_v1.json": "4e4a6717f1c0a137e73ee808473d4616571c4cbab5feeb1b6625272767cb9db6",
    "native_action_pack_vectors_v1.json": "4f144367fa259c77d21293c42e6c6b442f20b63195382378cff5d3558aec067e",
}


def apply_patch(document, patch):
    """Minimal RFC 6902 (add/remove/replace/copy), as the vectors use."""

    document = copy.deepcopy(document)

    def resolve(pointer):
        parts = [p.replace("~1", "/").replace("~0", "~") for p in pointer.split("/")[1:]]
        current = document
        for part in parts[:-1]:
            current = current[int(part)] if isinstance(current, list) else current[part]
        return current, parts[-1]

    for operation in patch:
        kind = operation["op"]
        if kind == "copy":
            source, key = resolve(operation["from"])
            value = copy.deepcopy(source[int(key)] if isinstance(source, list) else source[key])
            kind = "add"
        else:
            value = operation.get("value")
        parent, key = resolve(operation["path"])
        if kind == "remove":
            parent.pop(int(key) if isinstance(parent, list) else key)
        elif isinstance(parent, list):
            if key == "-":
                parent.append(value)
            elif kind == "add":
                parent.insert(int(key), value)
            else:
                parent[int(key)] = value
        else:
            if kind == "replace":
                assert key in parent, operation
            parent[key] = value
    return document


def test_vector_files_are_the_recorded_api_bytes():
    for name, digest in SOURCE_SHA256.items():
        assert hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest() == digest, name
    assert GOLDEN["schema"] == "native_action_golden_vectors.v1"
    assert PACK_VECTORS["schema"] == "native_action_pack_vectors.v1"
    assert len(GOLDEN["canonical_action_vectors"]) == 11
    assert len(GOLDEN["keyed_digest_vectors"]) == 3
    assert len(PACK_VECTORS["vectors"]) == 9


# ---------------------------------------------------------------------------
# Golden canonical-action vectors (§7.6)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "vector", GOLDEN["canonical_action_vectors"], ids=lambda v: v["id"]
)
def test_canonical_action_golden_vector(vector):
    verdict, reason, binding_hash = evaluate_native_action_attribute(vector["native_action"])

    assert verdict == vector["expected_verdict"]
    assert reason == vector["expected_reason_code"]
    if vector.get("expected_action_binding_hash"):
        assert binding_hash == vector["expected_action_binding_hash"]
        canonical = vector["native_action"]["canonical_action"]
        assert len(jcs(canonical)) == vector["jcs_length"]
        assert binding_hash == hashlib.sha256(rfc8785.dumps(canonical)).hexdigest()


def test_ca_basic_hash_is_the_interface_value():
    basic = next(v for v in GOLDEN["canonical_action_vectors"] if v["id"] == "ca_basic")
    _, _, binding_hash = evaluate_native_action_attribute(basic["native_action"])
    assert binding_hash == "a22b0644cca41451250766b4418050995865cad65ba0633e8fe3ab58b7c376d0"


def test_binding_hash_is_not_blind_to_timestamps():
    """The fingerprint-strip regression: created_at must move the hash."""

    vectors = {v["id"]: v for v in GOLDEN["canonical_action_vectors"]}
    assert (
        vectors["ca_basic"]["expected_action_binding_hash"]
        != vectors["ca_created_at_plus_1s"]["expected_action_binding_hash"]
    )


def test_unknown_action_schema_is_out_of_scope_not_disproved():
    basic = next(v for v in GOLDEN["canonical_action_vectors"] if v["id"] == "ca_basic")
    attribute = copy.deepcopy(basic["native_action"])
    attribute["action_schema"] = "keel.canonical_action/v2"
    assert evaluate_native_action_attribute(attribute) == (
        "unverifiable_scope",
        "native.action_schema",
        None,
    )


# ---------------------------------------------------------------------------
# Keyed-digest vectors (§7.6): the rule, recomputed independently
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vector", GOLDEN["keyed_digest_vectors"], ids=lambda v: v["id"])
def test_keyed_digest_vector(vector):
    root = bytes.fromhex(GOLDEN["keyed_digest_rule"]["test_root_key_hex"])
    assert root == bytes(range(32))
    inputs = vector["inputs"]
    if vector["id"] == "bik_basic":
        key = hmac.new(
            root, b"keel.native.bik.v1\x00" + inputs["project_id"].encode("ascii"), hashlib.sha256
        ).digest()
        payload = {
            "v": "keel.native.bik.repository_pull_request_create.v1",
            "project_id": inputs["project_id"],
            "connector_identity": "github",
            "repository_reference": inputs["repository_reference"].strip().lower(),
            "base_branch": inputs["base_branch"],
            "head_branch": inputs["head_branch"],
            "head_commit_sha": inputs["head_commit_sha"],
        }
        digest = hmac.new(key, rfc8785.dumps(payload), hashlib.sha256).hexdigest()
    else:
        purpose_key = hmac.new(root, inputs["label"].encode("utf-8"), hashlib.sha256).digest()
        digest = hmac.new(purpose_key, inputs["value"].encode("utf-8"), hashlib.sha256).hexdigest()
    assert digest == vector["expected"]


# ---------------------------------------------------------------------------
# Pack vectors (§7.2) against the API's real base_export
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vector", PACK_VECTORS["vectors"], ids=lambda v: v["id"])
def test_pack_vector(vector):
    document = apply_patch(PACK_VECTORS["base_export"], vector["json_patch"])
    result = check_native_action_pack(document, requested_levels=vector["requested_levels"])

    assert (result.verdict, result.reason_code) == (
        vector["expected_verdict"],
        vector["expected_reason_code"],
    )


def test_base_export_supported_result_shape():
    result = check_native_action_pack(PACK_VECTORS["base_export"])
    payload = result.to_dict()

    assert payload["verdict"] == "supported"
    assert payload["level_ceiling"] == "D"
    assert payload["dispatch_started_count"] == 1
    assert payload["upstream_outcome"] == "upstream_reported_success"
    assert payload["review_present"] is True
    assert payload["does_not_establish"] == [
        "provider execution",
        "external state change",
        "exclusive mediation",
    ]
    assert payload["checks_passed"] == [
        "evidence_present",
        "canonical_action_shape",
        "action_binding_hash",
        "cross_field",
        "review_binding",
        "closure_events",
        "level_ceiling",
    ]


@pytest.mark.parametrize("level", ["A", "B", "C", "D"])
def test_levels_up_to_d_are_supported(level):
    result = check_native_action_pack(PACK_VECTORS["base_export"], requested_levels=[level])
    assert result.verdict == "supported"


def test_level_f_is_not_supported():
    result = check_native_action_pack(PACK_VECTORS["base_export"], requested_levels=["F"])
    assert (result.verdict, result.reason_code) == ("not_supported", "native.level_ceiling")


def test_non_native_document_is_out_of_scope():
    result = check_native_action_pack({"bundle_type": "permit_audit_bundle"})
    assert (result.verdict, result.reason_code) == ("unverifiable_scope", "native.pack_schema")


# ---------------------------------------------------------------------------
# Checks beyond the API reference (each from the interface text)
# ---------------------------------------------------------------------------


def _base():
    return copy.deepcopy(PACK_VECTORS["base_export"])


def _canonical_payload(document):
    return document["permit_audit_bundle"]["permit_decision"]["canonical_payload"]


def _events(document, event_type):
    return [e for e in document["closure_events"] if e["event_type"] == event_type]


def _additional_cases():
    def project_mismatch(d):
        _canonical_payload(d)["project_id"] = "00000000-0000-4000-8000-000000000000"

    def principal_mismatch(d):
        _canonical_payload(d)["subject_id"] = "00000000-0000-4000-8000-000000000000"

    def inputs_version(d):
        d["permit_audit_bundle"]["permit_decision"]["canonical_payload"]["constraints"][
            "native_decision_inputs_v1"
        ]["version"] = "keel.native_decision_inputs.v2"
        d["permit_audit_bundle"]["record"]["permit"]["constraints_json"][
            "native_decision_inputs_v1"
        ]["version"] = "keel.native_decision_inputs.v2"

    def review_extra_key(d):
        d["exact_review_v2"]["trusted_facts"]["title"] = "plaintext"
        d["approval"]["exact_review_v2_hash"] = exact_review_v2_hash(d["exact_review_v2"])
        for event in _events(d, "native.action.review_decided"):
            event["payload"]["exact_review_v2_hash"] = d["approval"]["exact_review_v2_hash"]

    def review_other_permit(d):
        d["exact_review_v2"]["permit_id"] = "00000000-0000-4000-8000-000000000000"
        d["approval"]["exact_review_v2_hash"] = exact_review_v2_hash(d["exact_review_v2"])
        for event in _events(d, "native.action.review_decided"):
            event["payload"]["exact_review_v2_hash"] = d["approval"]["exact_review_v2_hash"]

    def approval_v1_hash(d):
        d["approval"]["v1_review_hash"] = "0" * 64

    def review_decided_other_hash(d):
        _events(d, "native.action.review_decided")[0]["payload"]["exact_review_v2_hash"] = "0" * 64

    def dispatch_after_result(d):
        started = _events(d, "native.action.dispatch_started")[0]
        result = _events(d, "native.action.upstream_result")[0]
        started["sequence_number"], result["sequence_number"] = (
            result["sequence_number"],
            started["sequence_number"],
        )

    def result_without_dispatch(d):
        d["closure_events"] = [
            e for e in d["closure_events"] if e["event_type"] != "native.action.dispatch_started"
        ]

    def two_results(d):
        d["closure_events"].append(copy.deepcopy(_events(d, "native.action.upstream_result")[0]))

    def flag_not_exactly_true(d):
        _events(d, "native.action.dispatch_started")[0]["payload"]["frozen_arguments_equal"] = 1

    def dispatch_other_action(d):
        _events(d, "native.action.dispatch_started")[0]["payload"]["action_id"] = (
            "00000000-0000-7000-8000-000000000000"
        )

    def unknown_outcome(d):
        _events(d, "native.action.upstream_result")[0]["payload"]["outcome"] = "merged"

    def event_not_object(d):
        d["closure_events"].append("not an event")

    def attestation_missing(d):
        _events(d, "native.action.review_decided")[0]["payload"]["attestation_id"] = None

    def attestation_differs(d):
        d["approval"]["attestation_id"] = "00000000-0000-4000-8000-0000000000a1"

    def final_hash_missing(d):
        _events(d, "native.action.dispatch_started")[0]["payload"]["final_request_hash"] = None

    def final_hash_not_signed_one(d):
        _canonical_payload(d)["final_request_hash"] = "0" * 64

    return [
        ("project_mismatch", project_mismatch, "disproved", "native.cross_field_mismatch"),
        ("principal_mismatch", principal_mismatch, "disproved", "native.cross_field_mismatch"),
        ("inputs_version", inputs_version, "unverifiable_scope", "native.decision_inputs_version"),
        ("review_extra_key", review_extra_key, "disproved", "native.review_binding"),
        ("review_other_permit", review_other_permit, "disproved", "native.review_binding"),
        ("approval_v1_hash", approval_v1_hash, "disproved", "native.review_binding"),
        ("review_decided_other_hash", review_decided_other_hash, "disproved", "native.review_binding"),
        ("dispatch_after_result", dispatch_after_result, "disproved", "native.single_dispatch"),
        ("result_without_dispatch", result_without_dispatch, "disproved", "native.single_dispatch"),
        ("two_results", two_results, "disproved", "native.single_dispatch"),
        ("flag_not_exactly_true", flag_not_exactly_true, "disproved", "native.single_dispatch"),
        ("dispatch_other_action", dispatch_other_action, "disproved", "native.single_dispatch"),
        ("unknown_outcome", unknown_outcome, "disproved", "native.single_dispatch"),
        ("event_not_object", event_not_object, "disproved", "native.evidence_incomplete"),
        ("attestation_missing", attestation_missing, "disproved", "native.review_binding"),
        ("attestation_differs", attestation_differs, "disproved", "native.review_binding"),
        ("final_hash_missing", final_hash_missing, "disproved", "native.single_dispatch"),
        ("final_hash_not_signed_one", final_hash_not_signed_one, "disproved", "native.single_dispatch"),
    ]


@pytest.mark.parametrize(
    "name,mutate,verdict,reason", _additional_cases(), ids=[c[0] for c in _additional_cases()]
)
def test_additional_check(name, mutate, verdict, reason):
    document = _base()
    mutate(document)
    result = check_native_action_pack(document)
    assert (result.verdict, result.reason_code) == (verdict, reason), result.message


def test_review_may_name_the_proposal_permit_in_an_execution_pack():
    """An execution Permit's pack carries the review of the action's proposal Permit."""

    document = _base()
    _canonical_payload(document)["permit_id"] = "00000000-0000-4000-8000-0000000000e1"
    proposal = _events(document, "native.action.proposed")[0]["payload"]["permit_id"]
    assert document["exact_review_v2"]["permit_id"] == proposal
    assert check_native_action_pack(document).verdict == "supported"


def test_review_naming_neither_permit_is_refused():
    document = _base()
    _canonical_payload(document)["permit_id"] = "00000000-0000-4000-8000-0000000000e1"
    _events(document, "native.action.proposed")[0]["payload"]["permit_id"] = (
        "00000000-0000-4000-8000-0000000000e2"
    )
    result = check_native_action_pack(document)
    assert (result.verdict, result.reason_code) == ("disproved", "native.review_binding")


def test_outcome_unknown_without_dispatch_is_supported():
    """Interface 1.3.0: an interrupted resume closes with outcome_unknown and no dispatch_started."""

    document = _base()
    document["closure_events"] = [
        e for e in document["closure_events"] if e["event_type"] != "native.action.dispatch_started"
    ]
    _events(document, "native.action.upstream_result")[0]["payload"]["outcome"] = "outcome_unknown"
    assert check_native_action_pack(document).verdict == "supported"


def test_closure_events_list_order_is_not_chain_order():
    """The pack lists events by second-resolution created_at; reversing the list changes nothing."""

    document = _base()
    document["closure_events"].reverse()
    assert check_native_action_pack(document).verdict == "supported"


def test_additional_checks_are_documented():
    assert len(ADDITIONAL_CHECKS) == 13


# ---------------------------------------------------------------------------
# Real candidate packs through the CLI
# ---------------------------------------------------------------------------


def _json(result):
    return json.loads(result.stdout)


def test_reviewed_permit_pack_verifies(run_cli):
    result = run_cli(
        "native-action-pack", "--json", str(REVIEWED), "--trust-root", str(INSTANCE_ROOT)
    )
    report = _json(result)

    assert result.returncode == 0, result.stdout + result.stderr
    assert report["ok"] is True
    claims = {claim["name"]: claim["verdict"] for claim in report["claims"]}
    assert claims["export.integrity.v1"] == "supported"
    assert claims["permit.decision.v1"] == "supported"
    native = report["artifact"]["native_action"]
    assert native["verdict"] == "supported"
    assert native["action_id"] == "01a1c11b-358f-7da9-b969-f63526b90e6f"
    assert native["action_binding_hash"] == (
        "8a37d35a89e4cc19621944550867323b3ec6b479d0ee104ef57869d29b01b869"
    )
    assert native["state"] == "upstream_reported_success"
    assert report["artifact"]["kind"] == "native_action_pack"


@pytest.mark.parametrize(
    "pack,root,final_bound",
    [(EXECUTION, INSTANCE_ROOT, True), (ALLOWED, ALLOW_ROOT, True), (REVIEWED, INSTANCE_ROOT, False)],
    ids=["execution", "allowed", "reviewed"],
)
def test_every_native_permit_pack_verifies(pack, root, final_bound, run_cli):
    """keel-api 24177dd8d (interface 1.5.0): every native Permit's pack carries its signed decision.

    The review-resume execution Permit and the allow-path dispatch Permit are
    signed with a final-request binding; dispatch_started names the same hash.
    """

    result = run_cli("native-action-pack", "--json", str(pack), "--trust-root", str(root))
    report = _json(result)

    assert result.returncode == 0, result.stdout + result.stderr
    claims = {claim["name"]: claim["verdict"] for claim in report["claims"]}
    assert claims["export.integrity.v1"] == "supported"
    assert claims["permit.decision.v1"] == "supported"
    assert report["artifact"]["native_action"]["verdict"] == "supported"
    document = json.loads((pack / "export.json").read_text("utf-8"))
    signed_final = document["permit_audit_bundle"]["permit_decision"]["canonical_payload"][
        "final_request_hash"
    ]
    dispatch = _events(document, "native.action.dispatch_started")[0]["payload"]
    assert (signed_final is not None) is final_bound
    if final_bound:
        assert dispatch["final_request_hash"] == signed_final


def test_allow_path_pack_has_no_review_and_one_dispatch():
    document = json.loads((ALLOWED / "export.json").read_text("utf-8"))
    assert document["exact_review_v2"] is None and document["approval"] is None
    types = [event["event_type"] for event in document["closure_events"]]
    assert types == [
        "native.action.proposed",
        "native.action.dispatch_started",
        "native.action.upstream_result",
    ]


@pytest.mark.parametrize("pack", [REVIEWED, EXECUTION, ALLOWED], ids=["reviewed", "execution", "allowed"])
def test_real_closure_events_are_in_chain_order(pack):
    """keel-api 1.4.0: closure events come per action, in hash-chain order."""

    document = json.loads((pack / "export.json").read_text("utf-8"))
    events = document["closure_events"]
    sequence = [event["sequence_number"] for event in events]
    assert sequence == sorted(sequence) and len(set(sequence)) == len(sequence)
    action_id = document["permit_audit_bundle"]["record"]["permit"]["resource_attributes_json"][
        "native_action"
    ]["canonical_action"]["action_id"]
    assert {event["payload"]["action_id"] for event in events} == {action_id}


def test_pack_requires_a_pinned_key_manifest_signer(run_cli):
    result = run_cli("native-action-pack", "--json", str(REVIEWED))
    assert result.returncode == 1
    assert _json(result)["ok"] is False


def test_requested_level_e_fails_the_pack(run_cli):
    result = run_cli(
        "native-action-pack",
        "--json",
        str(REVIEWED),
        "--trust-root",
        str(INSTANCE_ROOT),
        "--request-level",
        "E",
    )
    report = _json(result)
    assert result.returncode == 1
    assert report["artifact"]["native_action"]["verdict"] == "not_supported"
    assert report["artifact"]["native_action"]["reason_code"] == "native.level_ceiling"


def test_export_subcommand_adds_native_checks(run_cli):
    result = run_cli(
        "export",
        "--json",
        str(REVIEWED / "export.json"),
        str(REVIEWED / "manifest.json"),
        "--key-manifest",
        str(REVIEWED / "key_manifest.json"),
        "--trust-root",
        str(INSTANCE_ROOT),
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert _json(result)["artifact"]["native_action"]["verdict"] == "supported"


def test_export_raw_mode_agrees(tmp_path, run_cli):
    ok = run_cli(
        "export",
        "--raw",
        str(REVIEWED / "export.json"),
        str(REVIEWED / "manifest.json"),
        "--key-manifest",
        str(REVIEWED / "key_manifest.json"),
        "--trust-root",
        str(INSTANCE_ROOT),
    )
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert "Native action: supported" in ok.stdout
    document = json.loads((EXECUTION / "export.json").read_text("utf-8"))
    _events(document, "native.action.dispatch_started")[0]["payload"]["final_request_hash"] = "0" * 64
    trusted = _resigned_pack(tmp_path, document, key_source=EXECUTION)
    bad = run_cli(
        "export",
        "--raw",
        str(tmp_path / "export.json"),
        str(tmp_path / "manifest.json"),
        "--key-manifest",
        str(trusted),
    )
    assert bad.returncode == 1
    assert "native.single_dispatch" in bad.stderr


def _zip(tmp_path, source, *, extra=None, name="pack.zip"):
    path = tmp_path / name
    with zipfile.ZipFile(path, "w") as archive:
        for member in ("export.json", "manifest.json", "key_manifest.json"):
            archive.write(source / member, member)
        for member, data in (extra or {}).items():
            archive.writestr(member, data)
    return path


def test_zip_pack_verifies_and_is_auto_detected(tmp_path, run_cli):
    pack = _zip(tmp_path, REVIEWED)

    explicit = run_cli("native-action-pack", "--json", str(pack), "--trust-root", str(INSTANCE_ROOT))
    auto = run_cli(str(pack), "--json", "--trust-root", str(INSTANCE_ROOT))

    assert explicit.returncode == 0, explicit.stdout + explicit.stderr
    assert auto.returncode == 0, auto.stdout + auto.stderr
    assert _json(auto)["artifact"]["native_action"]["verdict"] == "supported"


def test_zip_with_duplicate_member_is_refused(tmp_path, run_cli):
    pack = tmp_path / "dup.zip"
    with zipfile.ZipFile(pack, "w") as archive:
        archive.write(REVIEWED / "manifest.json", "manifest.json")
        archive.write(REVIEWED / "key_manifest.json", "key_manifest.json")
        archive.write(REVIEWED / "export.json", "export.json")
        with pytest.warns(UserWarning):
            archive.writestr("export.json", b"{}")
    result = run_cli("native-action-pack", str(pack), "--trust-root", str(INSTANCE_ROOT))
    assert result.returncode == 1
    assert "more than one export.json" in result.stderr


def test_zip_member_paths_are_never_used_on_disk(tmp_path, run_cli):
    pack = _zip(tmp_path, REVIEWED, extra={"../escape.json": b"{}"})
    result = run_cli("native-action-pack", "--json", str(pack), "--trust-root", str(INSTANCE_ROOT))
    assert result.returncode == 0, result.stdout + result.stderr
    assert not (tmp_path.parent / "escape.json").exists()


def test_non_native_export_is_refused_by_the_pack_command(tmp_path, run_cli):
    private, public, key_id = keypair()
    export_file, manifest = write_signed_export(
        tmp_path,
        {"bundle_type": "audit_export_bundle", "schema_version": 1, "records": []},
        export_private_key=private,
        export_public_key=public,
        export_key_id=key_id,
    )
    key_manifest = write_json(
        tmp_path / "keys.json",
        {
            "keys": [
                {
                    "key_id": key_id,
                    "algorithm": "ed25519",
                    "public_key": public,
                    "purpose": "export_signing",
                    "status": "active",
                    "valid_from": "2026-01-01T00:00:00Z",
                    "valid_to": None,
                }
            ]
        },
    )
    result = run_cli("native-action-pack", "--json", str(tmp_path), "--key-manifest", str(key_manifest))
    report = _json(result)
    assert result.returncode == 1
    assert report["error"].startswith("NATIVE_ACTION_PACK_SCHEMA")
    assert "native_action" not in report["artifact"]


# ---------------------------------------------------------------------------
# Every pack-vector mutation on the REAL export, re-signed
# ---------------------------------------------------------------------------


def _resigned_pack(tmp_path, document, *, key_source=REVIEWED):
    """Sign ``document`` with a fresh test export key; trust it plus the candidate binding key."""

    private, public, key_id = keypair()
    export_file, manifest = write_signed_export(
        tmp_path, document, export_private_key=private, export_public_key=public, export_key_id=key_id
    )
    candidate_keys = json.loads((key_source / "key_manifest.json").read_text("utf-8"))["keys"]
    binding = [key for key in candidate_keys if key["purpose"] == "permit_binding_signing"]
    assert binding
    write_json(
        tmp_path / "trusted-keys.json",
        {
            "keys": [
                {
                    "key_id": key_id,
                    "algorithm": "ed25519",
                    "public_key": public,
                    "purpose": "export_signing",
                    "status": "active",
                    "valid_from": "2026-01-01T00:00:00Z",
                    "valid_to": None,
                },
                *binding,
            ]
        },
    )
    return tmp_path / "trusted-keys.json"


@pytest.mark.parametrize("vector", PACK_VECTORS["vectors"], ids=lambda v: v["id"])
def test_real_export_mutation_resigned(vector, tmp_path, run_cli):
    base = json.loads((REVIEWED / "export.json").read_text("utf-8"))
    document = apply_patch(base, vector["json_patch"])
    trusted = _resigned_pack(tmp_path, document)
    levels = [arg for level in vector["requested_levels"] for arg in ("--request-level", level)]

    result = run_cli(
        "native-action-pack", "--json", str(tmp_path), "--key-manifest", str(trusted), *levels
    )
    report = _json(result)
    native = report["artifact"]["native_action"]

    assert (native["verdict"], native.get("reason_code")) == (
        vector["expected_verdict"],
        vector["expected_reason_code"],
    )
    assert result.returncode == (0 if vector["expected_verdict"] == "supported" else 1)
    claims = {claim["name"]: claim["verdict"] for claim in report["claims"]}
    assert claims["export.integrity.v1"] == "supported"


def test_real_export_mutation_unsigned_fails_on_content_hash(tmp_path, run_cli):
    base = json.loads((REVIEWED / "export.json").read_text("utf-8"))
    base["permit_audit_bundle"]["permit_decision"]["resource_attributes_json"]["native_action"][
        "canonical_action"
    ]["canonical_input"]["draft"] = True
    write_json(tmp_path / "export.json", base)
    for member in ("manifest.json", "key_manifest.json"):
        (tmp_path / member).write_bytes((REVIEWED / member).read_bytes())

    result = run_cli("native-action-pack", "--json", str(tmp_path), "--trust-root", str(INSTANCE_ROOT))

    assert result.returncode == 1
    assert "content hash mismatch" in _json(result)["error"]


def test_signed_decision_also_refuses_a_flipped_canonical_action(tmp_path, run_cli):
    """Defence in depth: the v7 resource-attributes hash catches the same edit."""

    base = json.loads((REVIEWED / "export.json").read_text("utf-8"))
    for location in (
        base["permit_audit_bundle"]["permit_decision"]["resource_attributes_json"],
        base["permit_audit_bundle"]["record"]["permit"]["resource_attributes_json"],
    ):
        location["native_action"]["canonical_action"]["canonical_input"]["draft"] = True
    trusted = _resigned_pack(tmp_path, base)

    report = _json(run_cli("native-action-pack", "--json", str(tmp_path), "--key-manifest", str(trusted)))
    claims = {claim["name"]: claim["verdict"] for claim in report["claims"]}

    assert claims["permit.decision.v1"] == "disproved"
    assert report["artifact"]["native_action"]["reason_code"] == "native.action_binding_hash_mismatch"


def test_resigned_real_export_without_mutation_is_supported(tmp_path, run_cli):
    base = json.loads((REVIEWED / "export.json").read_text("utf-8"))
    trusted = _resigned_pack(tmp_path, base)
    result = run_cli("native-action-pack", "--json", str(tmp_path), "--key-manifest", str(trusted))
    assert result.returncode == 0, result.stdout + result.stderr


def test_review_hash_rule_matches_the_real_approval():
    base = json.loads((REVIEWED / "export.json").read_text("utf-8"))
    assert exact_review_v2_hash(base["exact_review_v2"]) == base["approval"]["exact_review_v2_hash"]
    assert exact_review_v2_hash(base["exact_review_v2"]) == hashlib.sha256(
        rfc8785.dumps(base["exact_review_v2"])
    ).hexdigest()
