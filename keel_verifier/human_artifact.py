"""Deterministic human Permit projection over already-verified report fields.

This module is presentation-only.  It is deliberately downstream of
adjudication and cannot change claims, verdicts, trust resolution, or exit
codes.  Caller-supplied titles and summaries are never consulted.
"""

from __future__ import annotations

from collections.abc import Mapping
from importlib import resources
import json
import re
import unicodedata
from typing import Any

from keel_verifier.permit_presentation import resolve_permit_presentation


_WHITESPACE = re.compile(r"\s+")


def _summary_contract() -> dict[str, Any]:
    resource = resources.files("keel_verifier").joinpath(
        "data/semantics/permit/human_summary_v1.json"
    )
    value = json.loads(resource.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("human summary semantics must be an object")
    return value


def _normalize(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = _WHITESPACE.sub(
        " ", unicodedata.normalize("NFC", value).strip()
    )
    return normalized or None


def _permit(report: Mapping[str, Any]) -> dict[str, Any]:
    artifact = report.get("artifact")
    if not isinstance(artifact, Mapping):
        return {}
    permit = artifact.get("permit")
    if not isinstance(permit, Mapping):
        return {}
    return dict(permit)


def _verdicts(report: Mapping[str, Any]) -> dict[str, str]:
    claims = report.get("claims")
    if not isinstance(claims, list):
        return {}
    return {
        str(claim["name"]): str(claim.get("verdict") or "")
        for claim in claims
        if isinstance(claim, Mapping) and isinstance(claim.get("name"), str)
    }


def _latest_receipt(permit: Mapping[str, Any]) -> dict[str, Any] | None:
    receipts = permit.get("provider_receipts")
    if not isinstance(receipts, list):
        return None
    valid = [dict(item) for item in receipts if isinstance(item, Mapping)]
    if not valid:
        return None
    return max(valid, key=lambda item: int(item.get("receipt_sequence") or 0))


def _action(permit: Mapping[str, Any]) -> str | None:
    return _normalize(
        permit.get("authorized_action")
        or permit.get("action")
        or permit.get("operation")
    )


def _agent(permit: Mapping[str, Any]) -> str | None:
    return _normalize(
        permit.get("agent")
        or permit.get("agent_id")
        or permit.get("subject")
        or permit.get("subject_id")
        or permit.get("principal")
        or permit.get("principal_id")
    )


def _commitment_label(value: Any, noun: str) -> str | None:
    if not isinstance(value, Mapping):
        return None
    digest = _normalize(value.get("digest"))
    return f"{noun} commitment {digest}" if digest else None


def _target(permit: Mapping[str, Any]) -> str | None:
    direct = _normalize(permit.get("target") or permit.get("resource"))
    if direct:
        return direct
    facts = permit.get("authorization_facts")
    if not isinstance(facts, Mapping):
        return None
    provider = _normalize(facts.get("provider"))
    model = _normalize(facts.get("model"))
    committed_target = _commitment_label(
        facts.get("original_payment_reference_commitment"), "payment"
    ) or _commitment_label(
        facts.get("recipient_reference_commitment"), "recipient"
    ) or _commitment_label(
        facts.get("intended_child_reference_commitment"), "child"
    ) or _commitment_label(
        facts.get("subscription_reference_commitment"), "subscription"
    ) or _commitment_label(
        facts.get("ticket_reference_commitment"), "support case"
    ) or _commitment_label(
        facts.get("customer_reference_commitment"), "customer"
    )
    if committed_target:
        return committed_target
    if provider and model:
        return f"{provider}/{model}"
    rail = _normalize(facts.get("payment_rail"))
    if rail:
        return rail
    return None


def _status(report: Mapping[str, Any], permit: Mapping[str, Any]) -> str:
    decision = _normalize(permit.get("decision"))
    if decision == "deny":
        return "denied"
    if decision in {"challenge", "review"}:
        return "awaiting_approval"
    verdicts = _verdicts(report)
    if verdicts.get("permit.revoked.v1") == "supported":
        return "revoked"
    receipt = _latest_receipt(permit)
    provider_state = _normalize(receipt.get("state")) if receipt else None
    if provider_state == "completed":
        return "provider_completed"
    if provider_state in {"accepted", "running"}:
        return "provider_accepted"
    if provider_state in {"rejected", "failed", "rolled_back"}:
        return "provider_rejected"
    if provider_state == "outcome_unknown":
        return "outcome_unknown"
    transitions = permit.get("bounded_use_transitions")
    if receipt or (isinstance(transitions, list) and transitions):
        return "dispatched"
    return "authorized"


def _integrity_verdict(evidence_state: str) -> str:
    if evidence_state == "VERIFIED":
        return "pass"
    if evidence_state in {"TAMPERED", "INVALID", "UNTRUSTED SIGNER"}:
        return "fail"
    return "not_run"


def derive_human_summary(
    report: Mapping[str, Any],
    *,
    evidence_state: str,
    trust_mode: Mapping[str, Any] | None,
) -> str | None:
    """Render the contract summary from verified fields, omitting unknowns."""

    permit = _permit(report)
    if not permit:
        return None
    templates = _summary_contract().get("templates")
    if not isinstance(templates, Mapping):
        raise ValueError("human summary templates are missing")
    action = _action(permit)
    target = _target(permit)
    agent = _agent(permit)
    issued_at = _normalize(permit.get("issued_at"))
    expires_at = _normalize(permit.get("expires_at"))
    decision = _normalize(permit.get("decision"))
    sentences: list[str] = []

    if decision == "deny" and action and target:
        sentences.append(str(templates["denial"]).format(action=action, target=target))
    elif decision in {"challenge", "review"} and action and target:
        sentences.append(str(templates["review"]).format(action=action, target=target))
    elif agent and action and target:
        sentences.append(
            str(templates["permit_authorization"]).format(
                agent=agent,
                action=action,
                target=target,
            )
        )

    if decision not in {"deny", "challenge", "review"} and issued_at:
        key = "permit_validity_bounded" if expires_at else "permit_validity_unbounded"
        sentences.append(
            str(templates[key]).format(issued_at=issued_at, expires_at=expires_at)
        )

    if decision not in {"challenge", "review"}:
        receipt = _latest_receipt(permit)
        transitions = permit.get("bounded_use_transitions")
        dispatched = bool(receipt) or (
            isinstance(transitions, list) and bool(transitions)
        )
        if not dispatched:
            sentences.append(str(templates["not_dispatched"]))
        elif receipt:
            state = _normalize(receipt.get("state"))
            reference = _normalize(receipt.get("provider_object_id"))
            if state == "outcome_unknown" or not state:
                sentences.append(str(templates["outcome_unknown"]))
            elif reference:
                sentences.append(
                    str(templates["provider_observed_with_id"]).format(
                        provider_state=state,
                        provider_object_id=reference,
                    )
                )
            else:
                sentences.append(
                    str(templates["provider_observed_without_id"]).format(
                        provider_state=state
                    )
                )
        else:
            sentences.append(str(templates["outcome_unknown"]))

    trust_label = _normalize(trust_mode.get("label")) if trust_mode else None
    if trust_label:
        sentences.append(
            str(templates["verification"]).format(
                integrity_verdict=_integrity_verdict(evidence_state),
                trust_mode=trust_label,
            )
        )
    return " ".join(_normalize(sentence) or "" for sentence in sentences).strip() or None


def derive_human_artifact(
    report: Mapping[str, Any],
    *,
    evidence_state: str,
    trust_mode: Mapping[str, Any] | None,
    session: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Build schema-shaped human output without changing verifier truth."""

    permit = _permit(report)
    if not permit:
        return None
    binding = permit.get("semantic_binding")
    binding = binding if isinstance(binding, Mapping) else None
    presentation = resolve_permit_presentation(binding)
    action = _action(permit)
    target = _target(permit)
    if not action or not target:
        return None
    decision = _normalize(permit.get("decision"))
    artifact_kind = (
        "denial"
        if decision == "deny"
        else "review"
        if decision in {"challenge", "review"}
        else "permit"
    )
    issued_at = _normalize(permit.get("issued_at"))
    if artifact_kind == "permit" and not issued_at:
        return None
    status = _status(report, permit)
    registry = presentation
    contract = registry.get("human_artifact_contract")
    if not isinstance(contract, Mapping):
        current_registry = resources.files("keel_verifier").joinpath(
            "data/permit_to_x/presentation_registry/v5.json"
        )
        current = json.loads(current_registry.read_text(encoding="utf-8"))
        contract = current.get("human_artifact_contract", {})
    state_labels = contract.get("status_labels")
    if not isinstance(state_labels, Mapping):
        return None
    summary = derive_human_summary(
        report,
        evidence_state=evidence_state,
        trust_mode=trust_mode,
    )
    if not summary:
        return None
    receipt = _latest_receipt(permit)
    transitions = permit.get("bounded_use_transitions")
    dispatched = bool(receipt) or (
        isinstance(transitions, list) and bool(transitions)
    )
    session = session or {}
    claims = report.get("claims")
    claims = claims if isinstance(claims, list) else []
    establishes = [
        str(claim["name"])
        for claim in claims
        if isinstance(claim, Mapping)
        and claim.get("verdict") == "supported"
        and isinstance(claim.get("name"), str)
    ]
    does_not_establish = [
        str(value)
        for value in permit.get("does_not_establish", [])
        if isinstance(value, str)
    ]
    for claim in claims:
        if not isinstance(claim, Mapping):
            continue
        for value in claim.get("does_not_establish", []) or []:
            if isinstance(value, str) and value not in does_not_establish:
                does_not_establish.append(value)
    title = (
        "AI Action Denied"
        if artifact_kind == "denial"
        else "AI Action Awaiting Approval"
        if artifact_kind == "review"
        else str(presentation.get("customer_title") or "AI Permit")
    )
    return {
        "version": "keel.permit_human_artifact.v1",
        "artifact_kind": artifact_kind,
        "title": title,
        "state_label": str(state_labels.get(status) or status),
        "source": {
            "permit_exact_profile": permit.get("profile"),
            "permit_id": permit.get("permit_id"),
            "semantic_id": permit.get("semantic_id"),
            "presentation_registry_version": presentation.get(
                "presentation_registry_version"
            ),
            "presentation_registry_digest": presentation.get(
                "presentation_registry_digest"
            ),
            "presentation_profile_id": presentation.get(
                "presentation_profile_id"
            ),
        },
        "identity": {
            "agent": _agent(permit),
            "principal": _normalize(
                permit.get("principal") or permit.get("principal_id")
            ),
            "project": _normalize(permit.get("project_id")),
        },
        "authorization": {
            "action": action,
            "target": target,
            "display_fields": [],
            "limits": {},
            "policy": None,
            "approval": None,
        },
        "lifecycle": {
            "issued_at": issued_at if artifact_kind == "permit" else None,
            "expires_at": _normalize(permit.get("expires_at")),
            "verified_at": _normalize(session.get("verified_at")),
            "status": status,
        },
        "outcome": {
            "dispatch_state": "dispatched" if dispatched else "not_dispatched",
            "provider_state": _normalize(receipt.get("state")) if receipt else None,
            "provider_object_id": (
                _normalize(receipt.get("provider_object_id")) if receipt else None
            ),
            "readback_state": None,
            "observed_at": (
                _normalize(receipt.get("observed_at")) if receipt else None
            ),
        },
        "evidence_boundary": {
            "establishes": establishes,
            "does_not_establish": does_not_establish,
        },
        "summary": {
            "text": summary,
            "derivation": "verifier_from_verified_fields",
        },
        "verification": {
            "integrity_verdict": _integrity_verdict(evidence_state),
            "trust_mode": str(
                trust_mode.get("label") if trust_mode else "not determined"
            ),
            "key_id": permit.get("key_id"),
            "input_digest": session.get("input_digest"),
            "verified_at": session.get("verified_at"),
        },
        "advanced": {"available": True, "representations": []},
    }


__all__ = ["derive_human_artifact", "derive_human_summary"]
