"""Tests for the human permit report renderer (keel_verifier.report_render).

The renderer is a pure function over the VerificationReport model. These tests
construct representative model dicts (the ``to_dict`` shape) rather than running
real artifacts, so they are deterministic and exercise exactly the verdict
combinations that matter: clean pass, tamper, authentic-evidence-of-violation,
partial coverage, incomplete, and the self-attested trust mode.
"""

from __future__ import annotations

import hashlib
import json
from importlib import resources

import jsonschema
import pytest
import rfc8785

from keel_verifier.report_render import (
    build_human_artifact,
    build_report_lines,
    load_presentation_registry,
    render_human,
)


def _payment_binding() -> dict:
    raw = (
        resources.files("keel_verifier")
        .joinpath("data/permit_to_x/semantic_registry/v4.json")
        .read_bytes()
    )
    registry = json.loads(raw)
    entry = next(
        item
        for item in registry["entries"]
        if item["semantic_id"] == "keel.action.payment_execute.v1"
    )
    return {
        "version": "keel.permit_semantic_binding.v2",
        "semantic_id": "keel.action.payment_execute.v1",
        "trusted_source_kind": "action_verb_execute",
        "chain_role": "action_child",
        "action_name": "payment.execute",
        "operation": "payment.execute",
        "governed_surface": "payment_rail",
        "non_authorizing_presentation_profile_id": "permit_to_pay.r1",
        "selector_registry_version": registry["version"],
        "selector_registry_digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
        "selector_entry_digest": (
            f"sha256:{hashlib.sha256(rfc8785.dumps(entry)).hexdigest()}"
        ),
    }


def _release_binding(semantic_id: str) -> dict:
    raw = (
        resources.files("keel_verifier")
        .joinpath("data/permit_to_x/semantic_registry/v9.json")
        .read_bytes()
    )
    registry = json.loads(raw)
    entry = next(
        item for item in registry["entries"] if item["semantic_id"] == semantic_id
    )
    presentation = json.loads(
        resources.files("keel_verifier")
        .joinpath("data/permit_to_x/presentation_registry/v8.json")
        .read_text(encoding="utf-8")
    )
    profile = next(
        item for item in presentation["profiles"] if item["semantic_id"] == semantic_id
    )
    return {
        "version": "keel.permit_semantic_binding.v2",
        "semantic_id": semantic_id,
        "trusted_source_kind": "action_verb_execute",
        "chain_role": "action_child",
        "action_name": entry["match"]["action_names"][0],
        "operation": "call.tools",
        "governed_surface": "mcp_tool",
        "non_authorizing_presentation_profile_id": profile[
            "presentation_profile_id"
        ],
        "selector_registry_version": registry["version"],
        "selector_registry_digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
        "selector_entry_digest": (
            f"sha256:{hashlib.sha256(rfc8785.dumps(entry)).hexdigest()}"
        ),
    }


def _identity_security_binding(semantic_id: str) -> dict:
    raw = (
        resources.files("keel_verifier")
        .joinpath("data/permit_to_x/semantic_registry/v10.json")
        .read_bytes()
    )
    registry = json.loads(raw)
    entry = next(
        item for item in registry["entries"] if item["semantic_id"] == semantic_id
    )
    presentation = json.loads(
        resources.files("keel_verifier")
        .joinpath("data/permit_to_x/presentation_registry/v9.json")
        .read_text(encoding="utf-8")
    )
    profile = next(
        item for item in presentation["profiles"] if item["semantic_id"] == semantic_id
    )
    return {
        "version": "keel.permit_semantic_binding.v2",
        "semantic_id": semantic_id,
        "trusted_source_kind": "action_verb_execute",
        "chain_role": "action_child",
        "action_name": entry["match"]["action_names"][0],
        "operation": "call.tools",
        "governed_surface": "mcp_tool",
        "non_authorizing_presentation_profile_id": profile[
            "presentation_profile_id"
        ],
        "selector_registry_version": registry["version"],
        "selector_registry_digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
        "selector_entry_digest": (
            f"sha256:{hashlib.sha256(rfc8785.dumps(entry)).hexdigest()}"
        ),
    }


def _coding_workspace_binding(semantic_id: str) -> dict:
    raw = (
        resources.files("keel_verifier")
        .joinpath("data/permit_to_x/semantic_registry/v11.json")
        .read_bytes()
    )
    registry = json.loads(raw)
    entry = next(
        item for item in registry["entries"] if item["semantic_id"] == semantic_id
    )
    presentation = json.loads(
        resources.files("keel_verifier")
        .joinpath("data/permit_to_x/presentation_registry/v10.json")
        .read_text(encoding="utf-8")
    )
    profile = next(
        item for item in presentation["profiles"] if item["semantic_id"] == semantic_id
    )
    return {
        "version": "keel.permit_semantic_binding.v2",
        "semantic_id": semantic_id,
        "trusted_source_kind": "action_verb_execute",
        "chain_role": "action_child",
        "action_name": entry["match"]["action_names"][0],
        "operation": "call.tools",
        "governed_surface": "mcp_tool",
        "non_authorizing_presentation_profile_id": profile[
            "presentation_profile_id"
        ],
        "selector_registry_version": registry["version"],
        "selector_registry_digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
        "selector_entry_digest": (
            f"sha256:{hashlib.sha256(rfc8785.dumps(entry)).hexdigest()}"
        ),
    }


def _claim(name: str, verdict: str, *, required: bool = True, **extra: object) -> dict:
    return {"name": name, "verdict": verdict, "required": required, **extra}


def _report(claims: list[dict], *, artifact: dict | None = None) -> dict:
    return {
        "schema": "keel.verifier.verdicts/v0",
        "ok": all(c["verdict"] == "supported" for c in claims),
        "exit_code": 0,
        "artifact": artifact if artifact is not None else {"kind": "export"},
        "semantics": {
            "mode": "legacy_unpinned",
            "profile_id": "keel.pre_pinning_default.v0",
        },
        "claims": claims,
        "diagnostics": [],
    }


@pytest.fixture(scope="module")
def presentation() -> dict:
    return load_presentation_registry()


def test_verified_allow_self_attested() -> None:
    report = _report(
        [
            _claim("export.integrity.v1", "supported"),
            _claim("governance_chain.local_continuity.v1", "supported"),
            _claim("permit.decision.v1", "supported", verifier_version="3.4.2"),
            _claim("permit.operator_approval.v1", "supported"),
            _claim("closure.dispatch_binding.v1", "supported"),
        ],
        artifact={
            "kind": "export",
            "decision": "allow",
            "trust_source": "self-attested (embedded public_key)",
        },
    )
    out = render_human(report)
    assert out.startswith("AI PERMIT — Verification Report")
    assert "Evidence:  VERIFIED" in out
    assert "Self-attested (embedded key only)" in out
    assert "Does not prove Keel signed this artifact." in out
    assert "Finding:   Permit decision ALLOW. Recorded action matched the permit." in out
    assert "✓ Permit decision signed by the issuing key (issuance-time)" in out
    # Next step is mechanical and points at the trust mode.
    assert "Re-run without --self-attested" in out
    assert "Verifier 3.4.2" in out


def test_tampered_decision_is_tampered_not_invalid() -> None:
    report = _report(
        [
            _claim("export.integrity.v1", "supported"),
            _claim("permit.decision.v1", "disproved"),
        ],
        artifact={"kind": "export", "trust_source": "embedded"},
    )
    out = render_human(report)
    assert "Evidence:  TAMPERED" in out
    assert "Keel production trust root" in out
    assert "✗ Permit decision signature INVALID" in out


def test_authentic_evidence_of_violation() -> None:
    """Authenticity passes, but a violation claim is disproved.

    Evidence must stay VERIFIED (the report is trustworthy) while the Finding
    surfaces the violation. This is the case a naive authenticity->green hides.
    """
    report = _report(
        [
            _claim("export.integrity.v1", "supported"),
            _claim("governance_chain.local_continuity.v1", "supported"),
            _claim("permit.revoked.v1", "supported"),
            _claim("permit.dispatch_absence_after_revocation.v1", "disproved"),
        ],
        artifact={"kind": "export", "trust_source": "embedded"},
    )
    out = render_human(report)
    assert "Evidence:  VERIFIED" in out
    assert "Finding:   ⚠ VIOLATION — dispatch occurred after the permit was revoked" in out
    assert "✗ VIOLATION: dispatch occurred AFTER revocation" in out


def test_partial_coverage_warns_and_suggests_upgrade() -> None:
    report = _report(
        [
            _claim("export.integrity.v1", "supported"),
            _claim("permit.decision.v1", "unverifiable_scope"),
        ],
        artifact={"kind": "export", "trust_source": "embedded"},
    )
    out = render_human(report)
    assert "Evidence:  VERIFIED — partial coverage ⚠" in out
    assert "Upgrade keel-verifier" in out


def test_incomplete_required_evidence() -> None:
    report = _report(
        [
            _claim("export.integrity.v1", "supported"),
            _claim("permit.decision.v1", "insufficient_evidence"),
        ],
        artifact={"kind": "export", "trust_source": "embedded"},
    )
    out = render_human(report)
    assert "Evidence:  INCOMPLETE" in out
    assert "Provide the missing evidence" in out


def test_stale_cached_permit_binding_trust_root_has_refresh_command() -> None:
    report = _report(
        [
            _claim("export.integrity.v1", "supported"),
            _claim(
                "permit.decision.v1",
                "insufficient_evidence",
                reason_code="PERMIT_DECISION_UNTRUSTED_KEY",
                message=(
                    "key manifest contains no entry with "
                    "purpose='permit_binding_signing'"
                ),
            ),
            _claim(
                "permit.review_transition.v1",
                "insufficient_evidence",
                reason_code=(
                    "PERMIT_REVIEW_TRANSITION_TRUST_ROOT_UNRESOLVABLE"
                ),
                message=(
                    "key manifest contains no entry with "
                    "purpose='permit_binding_signing'"
                ),
            ),
        ],
        artifact={"kind": "permit_exact"},
    )
    cache = "/Users/example/.keel-verifier/trust-root.json"

    out = render_human(
        report,
        session={
            "trust_root_source": cache,
            "trust_root_source_kind": "cached",
        },
    )

    assert f"Refresh the cached trust root at {cache}" in out
    assert "keel-verify refresh-keys --source api" in out
    assert "Provide the missing evidence" not in out


def test_explicit_incomplete_trust_root_does_not_recommend_cache_refresh() -> None:
    report = _report(
        [
            _claim(
                "permit.decision.v1",
                "insufficient_evidence",
                reason_code="PERMIT_DECISION_UNTRUSTED_KEY",
                message=(
                    "key manifest contains no entry with "
                    "purpose='permit_binding_signing'"
                ),
            )
        ],
        artifact={"kind": "permit_exact"},
    )

    out = render_human(
        report,
        session={
            "trust_root_source": "/audit/pinned-trust-root.json",
            "trust_root_source_kind": "explicit_or_bundled",
        },
    )

    assert "Provide the missing evidence" in out
    assert "refresh-keys" not in out


def test_checkpoint_uses_audit_checkpoint_title_and_no_finding() -> None:
    report = _report(
        [_claim("checkpoint.signature.v1", "supported")],
        artifact={
            "kind": "checkpoint",
            "trust_source": "embedded",
            "checkpoint_id": "ckpt_123",
            "composite_hash": "sha256:abc",
        },
    )
    out = render_human(report)
    assert out.startswith("AUDIT CHECKPOINT")
    assert "Finding:" not in out
    assert "Checkpoint: ckpt_123" in out


def test_live_checkpoint_shape_uses_top_level_session_and_identity_fields() -> None:
    report = _report(
        [
            _claim("checkpoint.composite_hash.v1", "supported"),
            _claim("checkpoint.signature.v1", "supported"),
            _claim("checkpoint.tsa_imprint.v1", "supported"),
        ],
        artifact={"kind": "checkpoint", "checkpoint_path": "checkpoint.json"},
    )
    report.update(
        {
            "checkpoint_id": "ckpt_live",
            "computed_at": "2026-04-15T12:00:00Z",
            "composite_hash": "sha256:abc",
            "trust_source": "self-attested (embedded public_key)",
        }
    )

    out = render_human(report)

    assert "Evidence:  VERIFIED (Self-attested (embedded key only))" in out
    assert "Checkpoint: ckpt_live" in out
    assert "Computed at: 2026-04-15T12:00:00Z" in out
    assert "Composite: sha256:abc" in out
    assert "Trust mode: Self-attested (embedded key only)" in out


def test_failed_report_without_claims_is_not_verified() -> None:
    report = _report(
        [],
        artifact={"kind": "evidence_bundle", "payload_path": "sample/export.json"},
    )
    report.update(
        {
            "ok": False,
            "exit_code": 1,
            "error": (
                "manifest is required for legacy split-file export input; "
                "input is not keel.evidence_bundle/v1"
            ),
        }
    )

    out = render_human(report)

    assert "Evidence:  INCOMPLETE" in out
    assert "Finding:   Verification did not complete." in out
    assert "Evidence:  VERIFIED" not in out


def test_tamper_precedes_untrusted_signer() -> None:
    report = _report(
        [_claim("permit.decision.v1", "disproved")],
        artifact={"kind": "export"},
    )
    out = render_human(report, session={"trust_mode": "untrusted_signer"})
    assert "Evidence:  TAMPERED" in out
    assert "UNTRUSTED SIGNER" not in out


def test_every_assertion_line_carries_known_provenance(presentation: dict) -> None:
    classes = set(presentation["provenance_classes"])
    report = _report(
        [
            _claim("export.integrity.v1", "supported"),
            _claim("permit.decision.v1", "supported"),
            _claim("permit.counter_signature.v1", "supported"),
            _claim("closure.dispatch_binding.v1", "supported"),
            _claim("permit.revoked.v1", "supported"),
            _claim("permit.dispatch_absence_after_revocation.v1", "supported"),
            _claim("permit.authority_chain.v1", "supported"),
            _claim("export.scope_faithfulness.v1", "supported"),
        ],
        artifact={
            "kind": "export",
            "decision": "allow",
            "permit_id": "pmt_1",
            "trust_source": "embedded",
        },
    )
    lines = build_report_lines(report, presentation=presentation)
    for line in lines:
        if line.structural:
            assert line.provenance is None
        else:
            assert line.provenance in classes, (
                f"line missing/invalid provenance: {line.text!r} -> {line.provenance!r}"
            )


def test_output_never_uses_forbidden_wording(presentation: dict) -> None:
    forbidden = [w.lower() for w in presentation["global_forbidden_wording"]]
    reports = [
        _report(
            [
                _claim("permit.decision.v1", "supported"),
                _claim("closure.dispatch_binding.v1", "supported"),
            ],
            artifact={"kind": "export", "decision": "allow", "trust_source": "embedded"},
        ),
        _report(
            [_claim("permit.decision.v1", "disproved")],
            artifact={"kind": "export", "trust_source": "embedded"},
        ),
    ]
    for report in reports:
        out = render_human(report, presentation=presentation).lower()
        for phrase in forbidden:
            assert phrase not in out, f"forbidden phrase {phrase!r} in rendered output"


def test_permit_identity_and_authorized_action_from_permit_block() -> None:
    report = _report(
        [
            _claim("export.integrity.v1", "supported"),
            _claim("permit.operator_approval.v1", "supported"),
        ],
        artifact={
            "kind": "export",
            "trust_source": "key manifest (x) key_id=y status=active",
            "permit": {
                "permit_id": "11111111-aaaa-4aaa-8aaa-111111111111",
                "decision": "allow",
                "issued_at": "2026-05-23T12:00:00Z",
                "expires_at": "2026-05-23T14:00:00Z",
                "authorized_action": "generate_report",
                "provider": "openai",
                "model": "gpt-5",
                "scope": "proj-1",
                "policy": "policy.allow",
                "subject": "subject-001",
                "account": "acct-1",
            },
        },
    )
    out = render_human(report)
    assert "Permit: 11111111-aaaa-4aaa-8aaa-111111111111" in out
    assert "Decision: allow" in out
    assert "Subject: subject-001" in out
    assert "Authorized action" in out
    assert "Action: generate_report" in out
    assert "Provider: openai" in out
    assert "Model: gpt-5" in out
    # trust_source carried from export verification -> resolved trust mode.
    assert "Trust mode: Keel production trust root" in out
    assert "Finding:   Permit decision ALLOW." in out


def test_operator_approval_family_collapses_to_one_line() -> None:
    """v1 supported + v2 insufficient must read as one verified line, not two."""
    report = _report(
        [
            _claim("export.integrity.v1", "supported"),
            _claim("permit.operator_approval.v1", "supported"),
            _claim("permit.operator_approval.v2", "insufficient_evidence"),
        ],
        artifact={"kind": "export", "trust_source": "embedded"},
    )
    out = render_human(report)
    assert "✓ Operator approval verified" in out
    # The contradictory "insufficient evidence" slot line is gone.
    assert "Operator approval: insufficient evidence" not in out


def test_evidence_coverage_lists_present_and_absent() -> None:
    report = _report(
        [
            _claim("export.integrity.v1", "supported"),
            _claim("permit.operator_approval.v1", "supported"),
        ],
        artifact={"kind": "export", "trust_source": "embedded"},
    )
    out = render_human(report)
    assert "Evidence coverage" in out
    assert "Operator approval: verified" in out
    assert "Dispatch: not provided" in out
    assert "Timestamp: not provided" in out


def test_exact_payment_report_uses_permit_to_pay_title_and_signed_facts() -> None:
    report = _report(
        [],
        artifact={
            "kind": "permit_exact",
            "permit": {
                "permit_id": "permit-123",
                "profile": "keel.permit_exact/v3",
                "decision": "allow",
                "agent": "voice-agent-7",
                "authorized_action": "payment.execute",
                "target": "stripe.payment_intent",
                "issued_at": "2026-08-09T12:00:00Z",
                "expires_at": "2026-08-09T12:05:00Z",
                "semantic_id": "keel.action.payment_execute.v1",
                "semantic_binding": _payment_binding(),
                "amount_minor": 5000,
                "currency": "USD",
                "recipient": "Irene",
                "payment_rail": "stripe.payment_intent",
                "request_digest": "sha256:" + "a" * 64,
                "recipient_opening_status": "disclosed",
            },
        },
    )
    out = render_human(report)
    assert out.startswith("AI Permit-to-Pay — Verification Report")
    assert "Amount: 50.00 USD" in out
    assert "Recipient: Irene" in out
    assert "Status: Authorized, not dispatched" in out
    assert (
        "Keel authorized voice-agent-7 to payment.execute on "
        "stripe.payment_intent." in out
    )


def test_exact_title_fails_generic_without_verified_semantic_binding() -> None:
    report = _report(
        [],
        artifact={
            "kind": "permit_exact",
            "permit": {
                "permit_id": "permit-unsigned-label",
                "decision": "allow",
                "authorized_action": "payment.execute",
            },
        },
    )
    assert render_human(report).startswith("AI Permit — Verification Report")


def test_human_artifact_validates_and_ignores_caller_title_and_summary() -> None:
    report = _report(
        [_claim("permit.decision.v1", "supported")],
        artifact={
            "kind": "permit_exact",
            "trust_source": "key manifest",
            "permit": {
                "profile": "keel.permit_exact/v3",
                "permit_id": "permit-123",
                "project_id": "project-1",
                "decision": "allow",
                "agent": "voice-agent-7",
                "authorized_action": "payment.execute",
                "target": "stripe.payment_intent",
                "issued_at": "2026-08-09T12:00:00Z",
                "expires_at": "2026-08-09T12:05:00Z",
                "semantic_id": "keel.action.payment_execute.v1",
                "semantic_binding": _payment_binding(),
                "title": "AI Permit-to-Drain-Account",
                "summary": "Caller says this is safe.",
                "does_not_establish": ["financial settlement"],
            },
        },
    )
    human = build_human_artifact(
        report,
        session={
            "verified_at": "2026-08-09T12:01:00Z",
            "input_digest": "sha256:" + "1" * 64,
        },
    )
    assert human is not None
    schema = json.loads(
        resources.files("keel_verifier")
        .joinpath(
            "data/permit_to_x/schemas/permit-human-artifact-v1.schema.json"
        )
        .read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    ).validate(human)
    assert human["title"] == "AI Permit-to-Pay"
    assert "Drain" not in human["summary"]["text"]
    assert "Caller says" not in human["summary"]["text"]
    assert human["source"]["presentation_registry_version"] == (
        "keel.presentation_registry.v3"
    )


@pytest.mark.parametrize(
    ("authorization_facts", "expected_target"),
    (
        (
            {"customer_reference_commitment": {"digest": "sha256:" + "1" * 64}},
            "customer commitment sha256:" + "1" * 64,
        ),
        (
            {
                "subscription_reference_commitment": {
                    "digest": "sha256:" + "2" * 64
                },
                "customer_reference_commitment": {
                    "digest": "sha256:" + "3" * 64
                },
            },
            "subscription commitment sha256:" + "2" * 64,
        ),
        (
            {"ticket_reference_commitment": {"digest": "sha256:" + "4" * 64}},
            "support case commitment sha256:" + "4" * 64,
        ),
    ),
)
def test_human_artifact_resolves_transactional_cx_committed_targets(
    authorization_facts: dict,
    expected_target: str,
) -> None:
    report = _report(
        [_claim("permit.decision.v1", "supported")],
        artifact={
            "kind": "permit_exact",
            "trust_source": "key manifest",
            "permit": {
                "profile": "keel.permit_exact/v3",
                "permit_id": "permit-cx",
                "project_id": "project-1",
                "decision": "allow",
                "agent": "customer-resolution-agent",
                "authorized_action": "transactional.cx.action",
                "issued_at": "2026-08-10T12:00:00Z",
                "expires_at": "2026-08-10T12:05:00Z",
                "authorization_facts": authorization_facts,
            },
        },
    )

    human = build_human_artifact(report)

    assert human is not None
    assert human["authorization"]["target"] == expected_target
    assert expected_target in human["summary"]["text"]


@pytest.mark.parametrize(
    ("semantic_id", "expected_title", "facts", "expected_target"),
    (
        (
            "keel.action.repository_pull_request_merge.v1",
            "AI Permit-to-Merge-Pull-Request",
            {"repository_reference_commitment": {"digest": "sha256:" + "5" * 64}},
            "repository commitment sha256:" + "5" * 64,
        ),
        (
            "keel.action.deployment_commit_deploy.v1",
            "AI Permit-to-Deploy-Commit",
            {"fly_machine_reference_commitment": {"digest": "sha256:" + "6" * 64}},
            "production machine commitment sha256:" + "6" * 64,
        ),
        (
            "keel.action.deployment_rollback.v1",
            "AI Permit-to-Roll-Back-Deployment",
            {"fly_machine_reference_commitment": {"digest": "sha256:" + "7" * 64}},
            "production machine commitment sha256:" + "7" * 64,
        ),
    ),
)
def test_human_artifact_resolves_release_title_and_committed_target(
    semantic_id: str,
    expected_title: str,
    facts: dict,
    expected_target: str,
) -> None:
    binding = _release_binding(semantic_id)
    report = _report(
        [_claim("permit.decision.v1", "supported")],
        artifact={
            "kind": "permit_exact",
            "trust_source": "key manifest",
            "permit": {
                "profile": "keel.permit_exact/v3",
                "permit_id": "permit-release",
                "project_id": "project-1",
                "decision": "allow",
                "agent": "release-agent",
                "authorized_action": binding["action_name"],
                "issued_at": "2026-08-10T12:00:00Z",
                "expires_at": "2026-08-10T12:05:00Z",
                "semantic_id": semantic_id,
                "semantic_binding": binding,
                "authorization_facts": facts,
            },
        },
    )

    human = build_human_artifact(report)

    assert human is not None
    assert human["title"] == expected_title
    assert human["authorization"]["target"] == expected_target
    assert expected_target in human["summary"]["text"]
    assert human["lifecycle"]["issued_at"] == "2026-08-10T12:00:00Z"
    assert human["lifecycle"]["expires_at"] == "2026-08-10T12:05:00Z"


@pytest.mark.parametrize(
    ("semantic_id", "expected_title", "facts", "expected_target"),
    (
        (
            "keel.action.identity_mfa_reset.v1",
            "AI Permit-to-Reset-MFA",
            {"user_reference_commitment": {"digest": "sha256:" + "8" * 64}},
            "identity commitment sha256:" + "8" * 64,
        ),
        (
            "keel.action.identity_sessions_revoke.v1",
            "AI Permit-to-Revoke-Sessions",
            {"user_reference_commitment": {"digest": "sha256:" + "9" * 64}},
            "identity commitment sha256:" + "9" * 64,
        ),
        (
            "keel.action.identity_disable.v1",
            "AI Permit-to-Disable-Identity",
            {"user_reference_commitment": {"digest": "sha256:" + "a" * 64}},
            "identity commitment sha256:" + "a" * 64,
        ),
        (
            "keel.action.identity_group_access_grant.v1",
            "AI Permit-to-Grant-Group-Access",
            {"user_reference_commitment": {"digest": "sha256:" + "b" * 64}},
            "identity commitment sha256:" + "b" * 64,
        ),
        (
            "keel.action.identity_group_access_remove.v1",
            "AI Permit-to-Remove-Group-Access",
            {"user_reference_commitment": {"digest": "sha256:" + "c" * 64}},
            "identity commitment sha256:" + "c" * 64,
        ),
        (
            "keel.action.security_indicator_block.v1",
            "AI Permit-to-Block-Indicator",
            {"indicator_reference_commitment": {"digest": "sha256:" + "d" * 64}},
            "security indicator commitment sha256:" + "d" * 64,
        ),
    ),
)
def test_human_artifact_resolves_identity_security_title_and_committed_target(
    semantic_id: str,
    expected_title: str,
    facts: dict,
    expected_target: str,
) -> None:
    binding = _identity_security_binding(semantic_id)
    report = _report(
        [_claim("permit.decision.v1", "supported")],
        artifact={
            "kind": "permit_exact",
            "trust_source": "pinned expected public key",
            "permit": {
                "profile": "keel.permit_exact/v3",
                "permit_id": "permit-identity-security",
                "project_id": "project-1",
                "decision": "allow",
                "agent": "identity-security-agent",
                "authorized_action": binding["action_name"],
                "issued_at": "2026-08-10T12:00:00Z",
                "expires_at": "2026-08-10T12:05:00Z",
                "semantic_id": semantic_id,
                "semantic_binding": binding,
                "authorization_facts": facts,
            },
        },
    )

    human = build_human_artifact(report)

    assert human is not None
    assert human["title"] == expected_title
    assert human["authorization"]["target"] == expected_target
    assert expected_target in human["summary"]["text"]
    assert human["lifecycle"]["issued_at"] == "2026-08-10T12:00:00Z"
    assert human["lifecycle"]["expires_at"] == "2026-08-10T12:05:00Z"


@pytest.mark.parametrize(
    ("semantic_id", "expected_title", "facts", "expected_target"),
    (
        (
            "keel.action.code_package_install.v1",
            "AI Permit-to-Install-Package",
            {"package_name": "is-odd", "target_dependency_version": "3.0.1"},
            "package is-odd@3.0.1",
        ),
        (
            "keel.action.repository_branch_push.v1",
            "AI Permit-to-Push-Branch",
            {
                "repository_reference_commitment": {
                    "digest": "sha256:" + "e" * 64
                },
                "target_branch": "keel/package-demo",
            },
            "repository commitment sha256:" + "e" * 64 + ", branch keel/package-demo",
        ),
        (
            "keel.action.repository_pull_request_create.v1",
            "AI Permit-to-Create-Pull-Request",
            {
                "repository_reference_commitment": {
                    "digest": "sha256:" + "f" * 64
                },
                "head_branch": "keel/package-demo",
                "base_branch": "main",
            },
            "repository commitment sha256:" + "f" * 64 + ", keel/package-demo to main",
        ),
    ),
)
def test_human_artifact_resolves_coding_workspace_title_and_exact_target(
    semantic_id: str,
    expected_title: str,
    facts: dict,
    expected_target: str,
) -> None:
    binding = _coding_workspace_binding(semantic_id)
    report = _report(
        [_claim("permit.decision.v1", "supported")],
        artifact={
            "kind": "permit_exact",
            "trust_source": "pinned expected public key",
            "permit": {
                "profile": "keel.permit_exact/v3",
                "permit_id": "permit-coding-workspace",
                "project_id": "project-1",
                "decision": "allow",
                "agent": "coding-workspace-agent",
                "authorized_action": binding["action_name"],
                "issued_at": "2026-08-10T12:00:00Z",
                "expires_at": "2026-08-10T12:05:00Z",
                "semantic_id": semantic_id,
                "semantic_binding": binding,
                "authorization_facts": facts,
            },
        },
    )

    human = build_human_artifact(report)

    assert human is not None
    assert human["title"] == expected_title
    assert human["authorization"]["target"] == expected_target
    assert expected_target in human["summary"]["text"]
    assert human["lifecycle"]["issued_at"] == "2026-08-10T12:00:00Z"
    assert human["lifecycle"]["expires_at"] == "2026-08-10T12:05:00Z"
