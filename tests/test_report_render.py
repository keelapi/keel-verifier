"""Tests for the human permit report renderer (keel_verifier.report_render).

The renderer is a pure function over the VerificationReport model. These tests
construct representative model dicts (the ``to_dict`` shape) rather than running
real artifacts, so they are deterministic and exercise exactly the verdict
combinations that matter: clean pass, tamper, authentic-evidence-of-violation,
partial coverage, incomplete, and the self-attested trust mode.
"""

from __future__ import annotations

import pytest

from keel_verifier.report_render import (
    build_report_lines,
    load_presentation_registry,
    render_human,
)


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
