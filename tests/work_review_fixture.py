"""Existing signed generic approval carrier, unchanged by Work export."""

import base64
import hashlib
import json
from datetime import datetime, timedelta
import rfc8785


def append_root_approval(pack, private, overrides=None):
    root = next(
        a
        for a in pack["artifacts"]
        if a["artifact_id"] == pack["root"]["permit_artifact"]["artifact_id"]
    )
    canonical = root["payload"]["permit_decision_binding"]["canonical_payload"]
    at = (
        (
            datetime.fromisoformat(canonical["issued_at"].replace("Z", "+00:00"))
            + timedelta(seconds=1)
        )
        .isoformat()
        .replace("+00:00", "Z")
    )
    signed = {
        "event_type": "permit.challenge_approved",
        "permit_id": pack["root_permit_id"],
        "project_id": pack["project_id"],
        "decision_at": at,
        "actor_id": canonical["constraints"]["work"]["approval_requirement"].get(
            "user_id", "99999999-9999-4999-8999-999999999999"
        ),
        "actor_kind": "user",
        "from_decision": "challenge",
        "from_status": "awaiting_attestation",
        "to_decision": "allow",
        "to_status": "attested",
    }
    signed.update(overrides or {})
    at = signed["decision_at"]
    digest = hashlib.sha256(
        json.dumps(signed, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    signed["signature"] = base64.b64encode(private.sign(digest.encode())).decode()
    payload = {
        "event_id": "gev_root_approval",
        "event_type": signed["event_type"],
        "permit_id": pack["root_permit_id"],
        "project_id": pack["project_id"],
        "occurred_at": at,
        "payload": {
            "challenge_transition_event": signed,
            "challenge_transition_canonical_hash": digest,
            "signature_profile": "keel.canonical_json.payload.v1",
        },
    }
    artifact = {
        "artifact_id": "urn:x-keel:artifact:root-approval",
        "artifact_type": "governance_event",
        "artifact_digest": "sha256:" + hashlib.sha256(rfc8785.dumps(payload)).hexdigest(),
        "payload": payload,
    }
    pack["artifacts"].append(artifact)
    pack["evidence_artifacts"].append(
        {k: artifact[k] for k in ["artifact_id", "artifact_type", "artifact_digest"]}
    )
    root["payload"]["permit_receipt"]["decision"] = {"decision": "allow", "status": "attested"}
    root["artifact_digest"] = "sha256:" + hashlib.sha256(rfc8785.dumps(root["payload"])).hexdigest()
    pack["root"]["permit_artifact"]["artifact_digest"] = root["artifact_digest"]
