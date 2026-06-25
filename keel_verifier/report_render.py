"""Human-readable permit verification report.

A *pure* rendering layer over the existing ``VerificationReport`` model
(``keel_verifier.verdicts``). ``render_human`` takes the report's ``to_dict``
shape plus the presentation registry (``data/report_presentation_v0.json``) and
returns a string. It derives no verification conclusions of its own; it only
relabels, groups, and reduces verdicts that the engine already computed.

Design contract: ``_internal-local/design/verification-report.md``.

Purity: ``render_human`` is a deterministic function of its arguments. Values
that are not in the model (wall-clock ``verified_at``, input digest, trust-root
digest) are supplied via the optional ``session`` mapping, never read from the
environment here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from typing import Any

__all__ = [
    "ReportLine",
    "load_presentation_registry",
    "build_report_lines",
    "render_human",
]

_VERDICT_MARKERS = {
    "supported": "✓",  # check
    "disproved": "✗",  # cross
    "insufficient_evidence": "—",  # em dash
    "unverifiable_scope": "?",
}

_CHECKPOINT_KINDS = {"checkpoint", "checkpoint_bundle"}

# Permit identity block (signed fields). Each row: label -> candidate keys,
# looked up in the merged {artifact, artifact["permit"]} source.
_IDENTITY_LINES = (
    ("Permit", ("permit_id", "id")),
    ("Decision", ("decision",)),
    ("Issued", ("issued_at", "binding_issued_at", "created_at", "issued")),
    ("Expires", ("expires_at", "not_after", "expires")),
    ("Subject", ("subject", "subject_id")),
    ("Account", ("account", "account_id")),
)

# "Authorized action" block (signed fields).
_ACTION_LINES = (
    ("Action", ("authorized_action", "action_name", "tool", "action", "operation")),
    ("Provider", ("provider", "resource_provider")),
    ("Model", ("model", "resource_model")),
    ("Scope", ("scope", "scope_key", "project_id")),
    ("Policy", ("policy", "policy_id", "reason")),
)

# Evidence coverage (explicit negative space): evidence type -> claim name(s).
_COVERAGE = (
    ("Permit decision signature", ("permit.decision.v1",)),
    (
        "Operator approval",
        (
            "permit.operator_approval.v1",
            "permit.operator_approval.v2",
            "permit.operator_approved.v1",
        ),
    ),
    (
        "Counter-signature",
        (
            "permit.counter_signature.v1",
            "permit.counter_signature.v2",
            "permit.counter_signed.v1",
        ),
    ),
    ("Dispatch", ("closure.dispatch_binding.v1",)),
    ("Closure", ("closure.signature.v1",)),
    ("Revocation", ("permit.revoked.v1",)),
    ("Timestamp", ("checkpoint.tsa_imprint.v1",)),
)

_COVERAGE_STATUS = {
    "supported": "verified",
    "disproved": "present (failed)",
    "insufficient_evidence": "not provided",
    "unverifiable_scope": "out of scope",
}


@dataclass(frozen=True)
class ReportLine:
    """One rendered line.

    ``structural`` lines (headers, blanks, rules) carry no provenance. Every
    non-structural line is a displayed assertion and MUST carry a provenance
    class from the registry's ``provenance_classes``.
    """

    text: str
    provenance: str | None = None
    structural: bool = False


def load_presentation_registry() -> dict[str, Any]:
    bundled = resources.files("keel_verifier").joinpath(
        "data/report_presentation_v0.json"
    )
    return json.loads(bundled.read_text(encoding="utf-8"))


def _trust_mode(
    report: dict[str, Any],
    session: dict[str, Any] | None,
    presentation: dict[str, Any],
) -> dict[str, Any] | None:
    modes = {m["id"]: m for m in presentation["trust_modes"]}
    if session and session.get("trust_mode") in modes:
        return modes[session["trust_mode"]]
    trust_source = report.get("trust_source")
    if not isinstance(trust_source, str):
        trust_source = (report.get("artifact") or {}).get("trust_source")
    if isinstance(trust_source, str):
        # Match by prefix, not substring: the self-attested source string
        # ("self-attested (embedded public_key)") contains "embedded", which
        # would otherwise be misread as the keel_root trust mode.
        for mode in presentation["trust_modes"]:
            for needle in mode.get("trust_source_strings", []):
                if needle and trust_source.startswith(needle):
                    return mode
    return None


def _verdicts_by_claim(report: dict[str, Any]) -> dict[str, str]:
    return {
        claim["name"]: claim.get("verdict")
        for claim in report.get("claims", [])
        if isinstance(claim.get("name"), str)
    }


def _evidence_state(
    report: dict[str, Any],
    presentation: dict[str, Any],
    trust_mode: dict[str, Any] | None,
) -> tuple[str, str | None]:
    """Reduce claims[] + trust mode to (evidence_state, qualifier).

    Mirrors ``header_reduction.evidence_line`` precedence. Violation claims are
    excluded here -- a disproved violation claim is authentic evidence of a
    real-world violation and surfaces in the Finding line, not as TAMPERED.
    Whether a disproved claim reads as TAMPERED (forged/altered) vs INVALID is
    driven by ``integrity_claims``, independent of the display dimension.
    """
    violation_claims = {
        entry["claim"]
        for entry in presentation["assertions"]
        if entry.get("violation_on_disproved")
    }
    integrity_claims = set(presentation.get("integrity_claims", []))
    claims = report.get("claims", [])

    required_disproved = [
        c
        for c in claims
        if c.get("required")
        and c.get("verdict") == "disproved"
        and c.get("name") not in violation_claims
    ]
    if any(c.get("name") in integrity_claims for c in required_disproved):
        return "TAMPERED", None
    if required_disproved:
        return "INVALID", None
    if trust_mode and trust_mode.get("id") == "untrusted_signer":
        return "UNTRUSTED SIGNER", None
    if report.get("error") and not claims:
        return "INCOMPLETE", None
    if any(
        c.get("required") and c.get("verdict") == "insufficient_evidence"
        for c in claims
    ):
        return "INCOMPLETE", None
    if any(c.get("verdict") == "unverifiable_scope" for c in claims):
        return "VERIFIED", "partial coverage"
    return "VERIFIED", None


def _finding(
    report: dict[str, Any],
    presentation: dict[str, Any],
    verdicts: dict[str, str],
) -> str:
    if report.get("error") and not report.get("claims"):
        return "Verification did not complete."

    violation_claims = {
        entry["claim"]
        for entry in presentation["assertions"]
        if entry.get("violation_on_disproved")
    }
    artifact = report.get("artifact") or {}
    permit = artifact.get("permit") if isinstance(artifact.get("permit"), dict) else {}
    decision = str(permit.get("decision") or artifact.get("decision") or "").upper()
    executed = (
        verdicts.get("closure.dispatch_binding.v1") == "supported"
        or verdicts.get("closure.signature.v1") == "supported"
    )

    violated = [name for name in violation_claims if verdicts.get(name) == "disproved"]
    deny_but_executed = decision == "DENY" and executed
    if violated or deny_but_executed:
        if "permit.dispatch_absence_after_revocation.v1" in violated:
            reason = "dispatch occurred after the permit was revoked"
        elif "closure.dispatch_binding.v1" in violated:
            reason = "the recorded dispatch did not match the permit"
        else:
            reason = "an action executed under a denied permit"
        return f"⚠ VIOLATION — {reason}"

    parts: list[str] = []
    if decision in ("ALLOW", "DENY"):
        parts.append(f"Permit decision {decision}.")
    if verdicts.get("closure.dispatch_binding.v1") == "supported":
        parts.append("Recorded action matched the permit.")
    if verdicts.get("permit.revoked.v1") == "supported":
        if verdicts.get("permit.dispatch_absence_after_revocation.v1") == "supported":
            parts.append("Revoked; no dispatch after revocation.")
        else:
            parts.append("Revoked.")
    if not parts:
        parts.append("See checks below.")
    return " ".join(parts)


def _next_step(
    evidence_state: str,
    qualifier: str | None,
    trust_mode: dict[str, Any] | None,
    verdicts: dict[str, str],
) -> str | None:
    if trust_mode and trust_mode.get("id") == "self_attested":
        return "Re-run without --self-attested to verify against the Keel trust root."
    if verdicts.get("checkpoint.tsa_imprint.v1") == "insufficient_evidence":
        return "Provide the timestamp receipt to enable timestamp verification."
    if evidence_state == "INCOMPLETE":
        return "Provide the missing evidence listed under the incomplete checks."
    if qualifier == "partial coverage":
        return (
            "Upgrade keel-verifier; one or more claims are newer than this build "
            "understands."
        )
    return None


def _claim_family(name: str) -> str | None:
    """Group the permit-v2 slot claim versions so they render as one line.

    operator_approval v1/v2/approved, counter_signature v1/v2/signed, and
    audit_attestation v1/v2/attested are the same assurance at different
    strengths; showing all of them at once reads as contradictory.
    """
    if name.startswith("permit.operator_approv"):
        return "operator_approval"
    if name.startswith("permit.counter_sign"):
        return "counter_signature"
    if name.startswith("permit.audit_attest"):
        return "audit_attestation"
    return None


def _collapse_verdict(verdicts: list[str]) -> str:
    """Pick the representative verdict for a collapsed family / coverage row.

    A failure dominates (show it), then success, then the can't-tell states.
    """
    for verdict in ("disproved", "supported", "insufficient_evidence", "unverifiable_scope"):
        if verdict in verdicts:
            return verdict
    return verdicts[0] if verdicts else "insufficient_evidence"


def _lookup(source: dict[str, Any], names: tuple[str, ...]) -> Any:
    for name in names:
        value = source.get(name)
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)) or (isinstance(value, str) and value):
            return value
    return None


def _artifact_identity_lines(
    report: dict[str, Any], presentation: dict[str, Any]
) -> list[ReportLine]:
    artifact = report.get("artifact") or {}

    # Checkpoint identity reads from artifact or the top-level live shape.
    if artifact.get("kind") in _CHECKPOINT_KINDS:
        lines: list[ReportLine] = []
        for key, label in (
            ("checkpoint_id", "Checkpoint"),
            ("computed_at", "Computed at"),
            ("composite_hash", "Composite"),
        ):
            value = artifact.get(key)
            if value in (None, ""):
                value = report.get(key)
            if value not in (None, ""):
                lines.append(
                    ReportLine(f"  {label}: {value}", provenance="SIGNED_FIELD")
                )
        return lines

    # Permit identity + authorized action. Signed fields are lifted into
    # artifact["permit"] at verification time (only when the signature over
    # them verified); fall back to top-level artifact for older shapes.
    permit = artifact.get("permit")
    source = {**artifact, **(permit if isinstance(permit, dict) else {})}

    lines = []
    for label, names in _IDENTITY_LINES:
        value = _lookup(source, names)
        if value is not None:
            lines.append(ReportLine(f"  {label}: {value}", provenance="SIGNED_FIELD"))

    action_lines = [
        ReportLine(f"  {label}: {value}", provenance="SIGNED_FIELD")
        for label, names in _ACTION_LINES
        if (value := _lookup(source, names)) is not None
    ]
    if action_lines:
        lines.append(ReportLine("", structural=True))
        lines.append(ReportLine("Authorized action", structural=True))
        lines.extend(action_lines)
    return lines


def _coverage_lines(verdicts: dict[str, str]) -> list[ReportLine]:
    """Explicit negative space: which evidence types were present vs absent.

    Returns [] when nothing was present, so trivially-failed reports stay terse.
    """
    lines: list[ReportLine] = []
    any_present = False
    for label, names in _COVERAGE:
        present = [verdicts[name] for name in names if name in verdicts]
        if present:
            status = _COVERAGE_STATUS.get(_collapse_verdict(present), "not provided")
            if status != "not provided":
                any_present = True
        else:
            status = "not provided"
        lines.append(
            ReportLine(f"  {label}: {status}", provenance="DERIVED_VERIFICATION_RESULT")
        )
    return lines if any_present else []


def build_report_lines(
    report: dict[str, Any],
    *,
    presentation: dict[str, Any] | None = None,
    session: dict[str, Any] | None = None,
) -> list[ReportLine]:
    """Render the report as structured lines (text + provenance).

    Every non-structural line carries a provenance class; this is what the
    provenance-coverage test asserts.
    """
    presentation = presentation or load_presentation_registry()
    verdicts = _verdicts_by_claim(report)
    artifact = report.get("artifact") or {}
    trust_mode = _trust_mode(report, session, presentation)

    evidence_state, qualifier = _evidence_state(report, presentation, trust_mode)
    finding = _finding(report, presentation, verdicts)

    is_checkpoint = artifact.get("kind") in _CHECKPOINT_KINDS
    title = "AUDIT CHECKPOINT" if is_checkpoint else "AI PERMIT — Verification Report"

    lines: list[ReportLine] = [ReportLine(title, structural=True)]

    # Header: Evidence + Finding.
    evidence_text = f"Evidence:  {evidence_state}"
    if qualifier:
        evidence_text += f" — {qualifier} ⚠"
    if trust_mode:
        evidence_text += f" ({trust_mode['label']})"
    lines.append(ReportLine(evidence_text, provenance="DERIVED_VERIFICATION_RESULT"))
    if not is_checkpoint:
        lines.append(
            ReportLine(
                f"Finding:   {finding}", provenance="DERIVED_VERIFICATION_RESULT"
            )
        )
    if trust_mode and not trust_mode.get("trusted") and trust_mode.get("warning"):
        lines.append(
            ReportLine(
                f"  ⚠ {trust_mode['warning']}", provenance="SESSION_VALUE"
            )
        )

    # Artifact identity.
    identity = _artifact_identity_lines(report, presentation)
    if identity:
        lines.append(ReportLine("", structural=True))
        lines.extend(identity)

    # Per-dimension checks (operator/counter/audit slot families collapse to one).
    for dimension in presentation["dimensions"]:
        dim_id = dimension["id"]
        present = [
            entry
            for entry in presentation["assertions"]
            if entry["dimension"] == dim_id and entry["claim"] in verdicts
        ]
        dim_lines: list[ReportLine] = []
        handled_families: set[str] = set()
        for entry in present:
            family = _claim_family(entry["claim"])
            if family:
                if family in handled_families:
                    continue
                handled_families.add(family)
                members = [e for e in present if _claim_family(e["claim"]) == family]
                chosen = _collapse_verdict([verdicts[e["claim"]] for e in members])
                entry = next(e for e in members if verdicts[e["claim"]] == chosen)
            else:
                chosen = verdicts[entry["claim"]]
            marker = _VERDICT_MARKERS.get(chosen, "?")
            label = entry["labels"].get(chosen, entry["claim"])
            dim_lines.append(
                ReportLine(f"  {marker} {label}", provenance=entry["provenance"])
            )
        if dim_lines:
            lines.append(ReportLine("", structural=True))
            lines.append(ReportLine(dimension["title"], structural=True))
            lines.extend(dim_lines)

    # Evidence coverage (explicit negative space) -- permit reports only.
    if not is_checkpoint:
        coverage = _coverage_lines(verdicts)
        if coverage:
            lines.append(ReportLine("", structural=True))
            lines.append(ReportLine("Evidence coverage", structural=True))
            lines.extend(coverage)

    # Next step (mechanical; evidence/session deficiencies only).
    next_step = _next_step(evidence_state, qualifier, trust_mode, verdicts)
    if next_step:
        lines.append(ReportLine("", structural=True))
        lines.append(ReportLine("Next step", structural=True))
        lines.append(
            ReportLine(f"  {next_step}", provenance="DERIVED_VERIFICATION_RESULT")
        )

    # Session / provenance footer.
    lines.append(ReportLine("", structural=True))
    footer = _footer_lines(report, session, trust_mode)
    lines.extend(footer)

    return lines


def _footer_lines(
    report: dict[str, Any],
    session: dict[str, Any] | None,
    trust_mode: dict[str, Any] | None,
) -> list[ReportLine]:
    session = session or {}
    version = session.get("verifier_version")
    if not version:
        for claim in report.get("claims", []):
            if claim.get("verifier_version"):
                version = claim["verifier_version"]
                break
    lines: list[ReportLine] = []
    lines.append(
        ReportLine(
            f"Verifier {version or '(unknown)'}", provenance="SESSION_VALUE"
        )
    )
    lines.append(
        ReportLine(
            f"Trust mode: {trust_mode['label'] if trust_mode else '(not determined)'}",
            provenance="SESSION_VALUE",
        )
    )
    semantics = report.get("semantics") or {}
    if semantics.get("profile_id"):
        lines.append(
            ReportLine(
                f"Semantics profile: {semantics['profile_id']}",
                provenance="SESSION_VALUE",
            )
        )
    for key, label in (
        ("verified_at", "Verified at"),
        ("input_digest", "Input"),
        ("trust_root_digest", "Trust root"),
    ):
        if session.get(key):
            lines.append(
                ReportLine(f"{label}: {session[key]}", provenance="SESSION_VALUE")
            )
    return lines


def render_human(
    report: dict[str, Any],
    *,
    presentation: dict[str, Any] | None = None,
    session: dict[str, Any] | None = None,
) -> str:
    """Render the verification report as a human-readable string."""
    return "\n".join(
        line.text
        for line in build_report_lines(
            report, presentation=presentation, session=session
        )
    )
