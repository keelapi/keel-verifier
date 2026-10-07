from copy import deepcopy
import hashlib
import pytest
import rfc8785
import test_work_chain_v1 as v1
import test_work_chain_v2 as v2
from keel_verifier.work_chain import verify_work_chain_pack


@pytest.mark.parametrize("version", [v1, v2])
def test_approved_work_review_retains_challenge_and_verifies_exact_transition(tmp_path, version):
    pack, root = version._build_pack(tmp_path, reviewed_root=True)
    report = verify_work_chain_pack(pack, trust_root=root)
    assert report.ok, report.to_dict()
    canonical = next(
        a
        for a in pack["artifacts"]
        if a["artifact_id"] == pack["root"]["permit_artifact"]["artifact_id"]
    )["payload"]["permit_decision_binding"]["canonical_payload"]
    assert canonical["decision"] == "challenge"


@pytest.mark.parametrize("version", [v1, v2])
@pytest.mark.parametrize(
    "defect",
    [
        "missing",
        "wrong_root",
        "wrong_project",
        "wrong_actor",
        "tamper",
        "rejected",
        "expired",
        "unsigned_allow",
        "duplicate",
    ],
)
def test_approved_work_review_refuses_invalid_authority(tmp_path, version, defect):
    other = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    overrides = {
        "wrong_root": {"permit_id": other},
        "wrong_project": {"project_id": other},
        "wrong_actor": {"actor_id": other},
        "rejected": {"event_type": "permit.challenge_rejected", "to_decision": "deny"},
        "expired": {"decision_at": "2099-01-01T00:00:00Z"},
    }.get(defect)
    pack, root = version._build_pack(
        tmp_path, reviewed_root=True, root_transition_overrides=overrides
    )
    artifact = pack["artifacts"][-1]
    signed = artifact["payload"]["payload"]["challenge_transition_event"]
    if defect in ["missing", "unsigned_allow"]:
        pack["evidence_artifacts"] = pack["evidence_artifacts"][:-1]
    elif defect == "wrong_root":
        signed["permit_id"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    elif defect == "wrong_project":
        signed["project_id"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    elif defect == "wrong_actor":
        signed["actor_id"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    elif defect == "tamper":
        signed["signature"] = "A" * 88
    elif defect == "rejected":
        signed["event_type"] = "permit.challenge_rejected"
        signed["to_decision"] = "deny"
    elif defect == "expired":
        signed["decision_at"] = "2099-01-01T00:00:00Z"
    elif defect == "duplicate":
        pack["evidence_artifacts"].append(deepcopy(pack["evidence_artifacts"][-1]))
    artifact["artifact_digest"] = (
        "sha256:" + hashlib.sha256(rfc8785.dumps(artifact["payload"])).hexdigest()
    )
    for ref in pack["evidence_artifacts"]:
        if ref["artifact_id"] == artifact["artifact_id"]:
            ref["artifact_digest"] = artifact["artifact_digest"]
    report = verify_work_chain_pack(pack, trust_root=root)
    assert not report.ok
    claim = next(
        c
        for c in report.to_dict()["claims"]
        if c["name"].startswith("permit.work_authority_manifest.")
    )
    assert claim["verdict"] != "supported"
