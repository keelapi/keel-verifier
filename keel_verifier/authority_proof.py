"""Per-pack adjudication of Keel authority-chain proof exports.

An ``authority_inventory`` export requested with ``format=chain_proof_json``
is a transport document: it carries one pack per Permit and each pack carries
separately extractable inputs for the released authority claims. This module
extracts those inputs and runs the released adjudicators pack by pack.

A refusal pack (``chain_proof_status="assembled_denial"``) proves something
different from an allow pack. The refused Permit has no authority chain, so
no chain claim is made for it. The pack instead carries the signed deny
Permit, the signed ``authority_edge.v1`` payloads of the chains Keel recorded
at the enforcement boundary, and the signed ``key.status.v1`` revocations of
those edges. ``authority.refusal_after_edge_revocation`` is a composite that
this verifier derives from released checks only; it is not a registry claim.
It is supported when every check below holds:

* the deny Permit verifies under a trusted permit-binding key, and its signed
  decision and reason are an R1 authority-chain refusal of an agent subject;
* every recorded edge hashes to its digest and verifies under the delegator's
  published key, the chain is contiguous from a user or service-principal
  root, and its leaf delegate is the Permit's signed subject;
* for every recorded chain, released ``authority.edge_revocation.v1`` is
  disproved at the Permit's signed ``issued_at``: a signed revocation of an
  in-chain edge took effect at or before the refusal.
"""

from __future__ import annotations

from typing import Any

from keel_verifier import verifier as _v

COMPOSITE_REFUSAL_CLAIM = "authority.refusal_after_edge_revocation"
R1_REFUSAL_REASON = "agent.authority_chain_unresolvable"
_REVOKED_CODE = "authority_edge_revocation.edge_revoked_at_or_before_resolution"


def _claim_dict(verdict: Any) -> dict[str, Any]:
    return {
        "claim": verdict.name,
        "verdict": verdict.aggregate_verdict,
        "reason_code": verdict.reason_code,
        "message": verdict.message,
    }


def _pack_claim(pack: dict[str, Any], name: str) -> dict[str, Any] | None:
    for claim in pack.get("authority_chain_proofs") or []:
        if isinstance(claim, dict) and claim.get("claim") == name:
            return claim
    return None


def _signed_edge_status_events(claim: dict[str, Any] | None) -> list[dict[str, Any]]:
    events = []
    for item in (claim or {}).get("edge_revoke_events") or []:
        if isinstance(item, dict) and isinstance(item.get("signed_event"), dict):
            events.append(item["signed_event"])
    return events


def _allow_pack_claims(
    pack: dict[str, Any],
    *,
    key_manifest_source: str | None,
    action_class_map: dict[str, Any] | None,
    authority_trust_root: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    chain_claim = _pack_claim(pack, "permit.authority_chain.v1") or {}
    inputs = chain_claim.get("required_pack_inputs") or {}
    root_claim = _pack_claim(pack, "authority.root_status_temporal.v2") or {}
    document: dict[str, Any] = {
        "permit": inputs.get("permit"),
        "authority_chain": chain_claim.get("authority_chain"),
        "authority_edges": chain_claim.get("authority_edges"),
        "resolution_time": inputs.get("resolution_time") or pack.get("resolution_time"),
        "requested_action": inputs.get("requested_action"),
        "edge_status_events": _signed_edge_status_events(
            _pack_claim(pack, "authority.edge_revocation.v1")
        ),
        "root_status_events": [
            event.get("payload")
            for event in (root_claim.get("root_status_events") or [])
            + (root_claim.get("root_status_v2_events") or [])
            if isinstance(event, dict) and isinstance(event.get("payload"), dict)
        ],
    }
    if action_class_map is not None:
        document["action_class_map"] = action_class_map
    adjudicators = (
        _v._adjudicate_permit_authority_chain_v1,
        _v._adjudicate_authority_revocation_temporal_v1,
        _v._adjudicate_authority_root_status_temporal_v1,
        _v._adjudicate_authority_root_status_temporal_v2,
        _v._adjudicate_authority_edge_revocation_v1,
    )
    return [
        _claim_dict(
            adjudicate(
                export_document=document,
                key_manifest_source=key_manifest_source,
                trust_root=authority_trust_root,
            )
        )
        for adjudicate in adjudicators
    ]


def _edge_failure(
    edges: list[dict[str, Any]], records: dict[str, dict[str, Any]]
) -> str | None:
    for edge in edges:
        payload = edge.get("payload")
        if not isinstance(payload, dict):
            return "edge payload missing"
        payload_bytes = _v._authority_edge_payload_bytes(edge)
        if _v._authority_sha256_hex(payload_bytes) != edge.get("edge_digest"):
            return "edge digest does not match RFC 8785 payload bytes"
        signing_key = payload.get("signing_key")
        key_id = signing_key.get("key_id") if isinstance(signing_key, dict) else None
        record = records.get(key_id) if isinstance(key_id, str) else None
        if record is None:
            return "edge signing key is not in the trust root"
        if record.get("signer_id") != (payload.get("delegator") or {}).get("principal_id"):
            return "edge signing key is not bound to the delegator principal"
        public_key = _v._authority_public_key(record)
        if public_key is None or not _v._verify_ed25519(
            public_key, payload_bytes, str(edge.get("signature"))
        ):
            return "edge signature does not verify"
        if _v._authority_signing_key_validity_code(payload, record) is not None:
            return "edge signing key was not valid at signed_at"
    return None


def _contiguity_failure(edges: list[dict[str, Any]], subject_id: Any) -> str | None:
    root = edges[0]["payload"]
    if root.get("parent_edge_digest") is not None or (root.get("delegator") or {}).get(
        "principal_type"
    ) not in {"user", "service_principal"}:
        return "root edge is not anchored by a user or service-principal delegator"
    for parent, child in zip(edges, edges[1:]):
        if child["payload"].get("parent_edge_digest") != parent.get("edge_digest"):
            return "recorded chain is not contiguous"
        if (child["payload"].get("delegator") or {}).get("principal_id") != (
            parent["payload"].get("delegate") or {}
        ).get("principal_id"):
            return "child delegator is not the parent delegate"
    if (edges[-1]["payload"].get("delegate") or {}).get("principal_id") != subject_id:
        return "leaf edge delegate is not the refused Permit's signed subject"
    return None


def _composite(verdict: str, message: str, checks: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "claim": COMPOSITE_REFUSAL_CLAIM,
        "composite": True,
        "derived_from": [
            "permit.decision.v1",
            "authority_edge.v1 signatures",
            "authority.edge_revocation.v1",
        ],
        "verdict": verdict,
        "message": message,
        "checks": checks,
    }


def _denial_pack_claims(
    pack: dict[str, Any],
    *,
    key_manifest_source: str | None,
    authority_trust_root: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    decision = _v._adjudicate_permit_decision_v1(
        export_document={"permit_decision": pack.get("permit_decision")},
        key_manifest_source=key_manifest_source,
    )
    checks.append(_claim_dict(decision))
    if decision.aggregate_verdict != "supported":
        return [_composite("insufficient_evidence", "refusal Permit does not verify", checks)]
    signed = pack["permit_decision"]["canonical_payload"]
    if (
        signed.get("decision") != "deny"
        or signed.get("reason") != R1_REFUSAL_REASON
        or signed.get("subject_type") != "agent"
        or signed.get("authority_chain_digest") is not None
    ):
        return [
            _composite(
                "disproved",
                "signed Permit is not an R1 authority-chain refusal of an agent",
                checks,
            )
        ]
    resolution_time = signed.get("issued_at")
    records = _v._authority_key_records(
        trust_root=authority_trust_root, key_manifest_source=key_manifest_source
    )
    edges_by_digest = {
        edge.get("edge_digest"): edge
        for edge in pack.get("authority_edges") or []
        if isinstance(edge, dict)
    }
    status_events = _signed_edge_status_events(
        _pack_claim(pack, "authority.edge_revocation.v1")
    )
    chains = [chain for chain in pack.get("recorded_chains") or [] if isinstance(chain, dict)]
    if not chains:
        return [_composite("insufficient_evidence", "no recorded chain to adjudicate", checks)]
    overall = "supported"
    for chain in chains:
        digests = chain.get("chain_edge_digests") or []
        edges = [edges_by_digest.get(digest) for digest in digests]
        entry: dict[str, Any] = {"leaf_edge_digest": chain.get("leaf_edge_digest")}
        checks.append(entry)
        if not digests or any(edge is None for edge in edges):
            entry["verdict"] = "insufficient_evidence"
            entry["message"] = "recorded chain edges are missing from the pack"
            overall = "insufficient_evidence"
            continue
        failure = _edge_failure(edges, records) or _contiguity_failure(
            edges, signed.get("subject_id")
        )
        if failure is not None:
            entry["verdict"] = "disproved"
            entry["message"] = failure
            overall = "disproved"
            continue
        revocation = _v._adjudicate_authority_edge_revocation_v1(
            export_document={
                "authority_chain": {"payload": {"edge_digests": list(digests)}},
                "authority_edges": edges,
                "resolution_time": resolution_time,
                "edge_status_events": status_events,
            },
            key_manifest_source=key_manifest_source,
            trust_root=authority_trust_root,
        )
        entry["authority.edge_revocation.v1"] = _claim_dict(revocation)
        if (
            revocation.aggregate_verdict == "disproved"
            and revocation.reason_code == _REVOKED_CODE
        ):
            entry["verdict"] = "supported"
            entry["message"] = (
                "a signed revocation of an in-chain edge took effect at or "
                "before the refusal Permit's signed issued_at"
            )
        else:
            entry["verdict"] = "insufficient_evidence"
            entry["message"] = (
                "no signed revocation of an in-chain edge at or before the "
                "refusal; this chain's refusal is not explained by revocation"
            )
            if overall == "supported":
                overall = "insufficient_evidence"
    message = {
        "supported": "refusal follows a signed edge revocation on every recorded chain",
        "disproved": "a recorded chain contradicts the refusal evidence",
        "insufficient_evidence": "refusal evidence is incomplete",
    }[overall]
    return [_composite(overall, message, checks)]


def adjudicate_authority_chain_proof_document(
    document: dict[str, Any],
    *,
    key_manifest_source: str | None,
    action_class_map: dict[str, Any] | None = None,
    authority_trust_root: dict[str, Any] | None = None,
    permit_id: str | None = None,
) -> dict[str, Any]:
    """Adjudicate every pack (or one, by ``permit_id``).

    ``key_manifest_source`` is the instance key manifest (permit-binding and
    key.status signers). ``authority_trust_root`` holds the delegator-bound
    authority-edge signing keys, as published by GET /v1/authority/verifier-keys.
    """
    packs = [
        pack
        for pack in document.get("authority_chain_proofs") or []
        if isinstance(pack, dict) and (permit_id is None or pack.get("permit_id") == permit_id)
    ]
    results = []
    for pack in packs:
        status = pack.get("chain_proof_status")
        if status == "assembled":
            claims = _allow_pack_claims(
                pack,
                key_manifest_source=key_manifest_source,
                action_class_map=action_class_map,
                authority_trust_root=authority_trust_root,
            )
        elif status == "assembled_denial":
            claims = _denial_pack_claims(
                pack,
                key_manifest_source=key_manifest_source,
                authority_trust_root=authority_trust_root,
            )
        else:
            claims = []
        results.append(
            {
                "permit_id": pack.get("permit_id"),
                "chain_proof_status": status,
                "claims": claims,
            }
        )
    return {
        "schema": document.get("schema"),
        "pack_count": len(results),
        "packs": results,
    }
