"""Standing-approval coverage: vocabulary, receipt parsing, and wording.

A standing approval is a bounded, passkey-confirmed pre-approval that can
satisfy Keel's default admin review for a narrow class of managed-MCP actions
(earned-autonomy spec v4, sections 1.10 and 1.13). A covered permit carries the
signed reason ``platform_safety_floor.standing_approval_covered`` on every
binding version, and binding ``v8`` additionally signs the covering approval's
``standing_approval_version_id`` and ``terms_digest``.

The receipt block ``permit_receipt.standing_approval`` is an unsigned
projection. This module validates its shape and checks it against the signed
binding; it never lets the block upgrade a decision, and it never describes a
covered permit as human-reviewed.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

STANDING_APPROVAL_COVERED_REASON = "platform_safety_floor.standing_approval_covered"
STANDING_APPROVAL_BINDING_VERSION = "v8"
STANDING_APPROVAL_RECEIPT_KEY = "standing_approval"
STANDING_APPROVAL_ADMIN_REVIEW = "satisfied_by_standing_approval"
STANDING_APPROVAL_FACTS_TRUST = "gateway_asserted_keel_authenticated"
STANDING_APPROVAL_ASSURANCE_LEVELS = frozenset({"A2"})
# Only a human user can authorize or co-approve a standing approval: API keys
# and agent credentials can do neither (spec section 1.9).
STANDING_APPROVAL_AUTHORIZER_KINDS = frozenset({"user"})

STANDING_APPROVAL_NOT_HUMAN_REVIEWED = "that a human reviewed this individual action"
STANDING_APPROVAL_TERMS_NOT_ESTABLISHED = (
    "the standing approval's terms or the approver's passkey assertion over "
    "terms_digest"
)
STANDING_APPROVAL_VERSION_UNSIGNED = (
    "which standing approval version covered this permit "
    "(binding versions below v8 do not sign it)"
)
STANDING_APPROVAL_FACTS_NOT_ESTABLISHED = (
    "the identity-provider facts the coverage relied on "
    "(gateway-asserted, Keel-authenticated)"
)

_TERMS_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

RECEIPT_REQUIRED_FIELDS: tuple[str, ...] = (
    "admin_review",
    "per_action_review",
    "facts_trust",
    "id",
    "approval_version",
    "standing_approval_version_id",
    "terms_digest",
    "authorized_by",
    "co_approved_by",
    "authorized_at",
    "expires_at",
    "origin",
    "assurance_level",
    "usage",
)


class StandingApprovalError(ValueError):
    """A standing-approval receipt block or binding is invalid or inconsistent."""

    def __init__(self, reason_code: str, message: str, evidence: tuple[str, ...]) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message
        self.evidence = evidence


@dataclass(frozen=True)
class StandingApprovalReceipt:
    approval_id: str
    approval_version: int
    standing_approval_version_id: str
    terms_digest: str
    authorized_by: dict[str, str]
    co_approved_by: dict[str, str] | None
    authorized_at: str
    expires_at: str
    origin: str
    assurance_level: str
    usage: dict[str, Any]
    facts_trust: str


def is_covered_reason(reason: Any) -> bool:
    return isinstance(reason, str) and reason.strip() == STANDING_APPROVAL_COVERED_REASON


def is_terms_digest(value: Any) -> bool:
    return isinstance(value, str) and _TERMS_DIGEST_RE.fullmatch(value) is not None


def _is_uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _invalid(message: str, field: str) -> StandingApprovalError:
    return StandingApprovalError(
        "STANDING_APPROVAL_RECEIPT_INVALID",
        f"permit_receipt.standing_approval {message}",
        (f"permit_receipt.standing_approval.{field}",),
    )


def _principal(value: Any, field: str, *, nullable: bool) -> dict[str, str] | None:
    if value is None and nullable:
        return None
    if not isinstance(value, Mapping):
        raise _invalid(
            f"{field} must be an object with kind and id"
            + (" or null" if nullable else ""),
            field,
        )
    kind = value.get("kind")
    principal_id = value.get("id")
    if kind not in STANDING_APPROVAL_AUTHORIZER_KINDS:
        raise _invalid(f"{field}.kind must be user", f"{field}.kind")
    if not isinstance(principal_id, str) or not principal_id.strip():
        raise _invalid(f"{field}.id must be a non-empty string", f"{field}.id")
    return {"kind": str(kind), "id": principal_id}


def parse_receipt_block(block: Any) -> StandingApprovalReceipt:
    """Validate ``permit_receipt.standing_approval`` and return it typed.

    Unknown extra keys are ignored: they can never change what is reported,
    because only the fields validated here are read.
    """

    if not isinstance(block, Mapping):
        raise _invalid("must be an object", "")
    missing = [field for field in RECEIPT_REQUIRED_FIELDS if field not in block]
    if missing:
        raise StandingApprovalError(
            "STANDING_APPROVAL_RECEIPT_INVALID",
            "permit_receipt.standing_approval lacks required field(s): "
            + ", ".join(missing),
            tuple(f"permit_receipt.standing_approval.{field}" for field in missing),
        )
    if block["admin_review"] != STANDING_APPROVAL_ADMIN_REVIEW:
        raise _invalid(
            f"admin_review must be {STANDING_APPROVAL_ADMIN_REVIEW}", "admin_review"
        )
    # A covered permit never had a per-action review. Anything but literal
    # false would let the receipt describe it as human-reviewed.
    if block["per_action_review"] is not False:
        raise _invalid("per_action_review must be false", "per_action_review")
    if block["facts_trust"] != STANDING_APPROVAL_FACTS_TRUST:
        raise _invalid(
            f"facts_trust must be {STANDING_APPROVAL_FACTS_TRUST}", "facts_trust"
        )
    if not _is_uuid(block["id"]):
        raise _invalid("id must be a lowercase UUID string", "id")
    approval_version = block["approval_version"]
    if not _is_int(approval_version) or approval_version < 1:
        raise _invalid("approval_version must be an integer >= 1", "approval_version")
    if not _is_uuid(block["standing_approval_version_id"]):
        raise _invalid(
            "standing_approval_version_id must be a lowercase UUID string",
            "standing_approval_version_id",
        )
    if not is_terms_digest(block["terms_digest"]):
        raise _invalid("terms_digest must be sha256:<64 lowercase hex>", "terms_digest")
    authorized_by = _principal(block["authorized_by"], "authorized_by", nullable=False)
    assert authorized_by is not None
    co_approved_by = _principal(block["co_approved_by"], "co_approved_by", nullable=True)
    authorized_at = _parse_time(block["authorized_at"])
    if authorized_at is None:
        raise _invalid("authorized_at must be an RFC 3339 timestamp with offset", "authorized_at")
    expires_at = _parse_time(block["expires_at"])
    if expires_at is None:
        raise _invalid("expires_at must be an RFC 3339 timestamp with offset", "expires_at")
    if expires_at <= authorized_at:
        raise _invalid("expires_at must be after authorized_at", "expires_at")
    origin = block["origin"]
    if not isinstance(origin, str) or not origin.strip():
        raise _invalid("origin must be a non-empty string", "origin")
    assurance_level = block["assurance_level"]
    if assurance_level not in STANDING_APPROVAL_ASSURANCE_LEVELS:
        raise _invalid("assurance_level must be A2", "assurance_level")
    usage = block["usage"]
    if not isinstance(usage, Mapping):
        raise _invalid("usage must be an object with window, used, cap", "usage")
    window = usage.get("window")
    used = usage.get("used")
    cap = usage.get("cap")
    if not isinstance(window, str) or not window.strip():
        raise _invalid("usage.window must be a non-empty string", "usage.window")
    if not _is_int(cap) or cap < 1:
        raise _invalid("usage.cap must be an integer >= 1", "usage.cap")
    if not _is_int(used) or used < 0 or used > cap:
        raise _invalid("usage.used must be an integer from 0 to usage.cap", "usage.used")
    return StandingApprovalReceipt(
        approval_id=str(block["id"]),
        approval_version=int(approval_version),
        standing_approval_version_id=str(block["standing_approval_version_id"]),
        terms_digest=str(block["terms_digest"]),
        authorized_by=authorized_by,
        co_approved_by=co_approved_by,
        authorized_at=str(block["authorized_at"]),
        expires_at=str(block["expires_at"]),
        origin=str(origin),
        assurance_level=str(assurance_level),
        usage={"window": window, "used": used, "cap": cap},
        facts_trust=str(block["facts_trust"]),
    )


def signed_binding_error(canonical_payload: Mapping[str, Any]) -> str | None:
    """Return why a signed v8 payload is not a valid covered binding, if it isn't."""

    if canonical_payload.get("binding_version") != STANDING_APPROVAL_BINDING_VERSION:
        return None
    if not _is_uuid(canonical_payload.get("standing_approval_version_id")):
        return (
            "canonical_payload.standing_approval_version_id must be a lowercase "
            "UUID string on v8"
        )
    if not is_terms_digest(canonical_payload.get("terms_digest")):
        return "canonical_payload.terms_digest must be sha256:<64 lowercase hex> on v8"
    if canonical_payload.get("reason") != STANDING_APPROVAL_COVERED_REASON:
        return (
            "canonical_payload.reason must be "
            f"{STANDING_APPROVAL_COVERED_REASON} on v8"
        )
    if canonical_payload.get("decision") != "allow":
        return "canonical_payload.decision must be allow on v8"
    return None


def receipt_block(document: Mapping[str, Any]) -> tuple[bool, Any]:
    """Return ``(present, block)`` for ``permit_receipt.standing_approval``.

    Older receipts have no block, and a receipt model with an optional block
    serializes an uncovered permit as ``"standing_approval": null``. Both mean
    "absent", which is never an error by itself.
    """

    receipt = document.get("permit_receipt")
    if not isinstance(receipt, Mapping):
        return False, None
    block = receipt.get(STANDING_APPROVAL_RECEIPT_KEY)
    if block is None:
        return False, None
    return True, block


def check_against_signed(
    canonical_payload: Mapping[str, Any],
    document: Mapping[str, Any],
) -> StandingApprovalReceipt | None:
    """Validate the receipt block against the signed binding.

    Returns the parsed block (or ``None`` when absent). Raises
    ``StandingApprovalError`` when the block is malformed, when it claims
    coverage the signed reason does not carry, or when a v8 binding's signed
    version id or terms digest disagrees with the block.
    """

    present, block = receipt_block(document)
    if not present:
        return None
    if not is_covered_reason(canonical_payload.get("reason")):
        raise StandingApprovalError(
            "STANDING_APPROVAL_RECEIPT_UNSIGNED_COVERAGE",
            "permit_receipt.standing_approval claims standing-approval coverage "
            "but the signed reason is not "
            f"{STANDING_APPROVAL_COVERED_REASON}",
            (
                "permit_receipt.standing_approval",
                "canonical_payload.reason",
            ),
        )
    parsed = parse_receipt_block(block)
    if canonical_payload.get("binding_version") == STANDING_APPROVAL_BINDING_VERSION:
        for field, signed_value, receipt_value in (
            (
                "standing_approval_version_id",
                canonical_payload.get("standing_approval_version_id"),
                parsed.standing_approval_version_id,
            ),
            (
                "terms_digest",
                canonical_payload.get("terms_digest"),
                parsed.terms_digest,
            ),
        ):
            if signed_value != receipt_value:
                raise StandingApprovalError(
                    "STANDING_APPROVAL_RECEIPT_MISMATCH",
                    f"permit_receipt.standing_approval.{field} does not match "
                    f"the signed v8 canonical_payload.{field}",
                    (
                        f"permit_receipt.standing_approval.{field}",
                        f"canonical_payload.{field}",
                    ),
                )
    issued_at = _parse_time(canonical_payload.get("issued_at"))
    authorized_at = _parse_time(parsed.authorized_at)
    expires_at = _parse_time(parsed.expires_at)
    if (
        issued_at is not None
        and authorized_at is not None
        and expires_at is not None
        and not (authorized_at <= issued_at < expires_at)
    ):
        raise StandingApprovalError(
            "STANDING_APPROVAL_RECEIPT_MISMATCH",
            "signed canonical_payload.issued_at is outside the standing "
            "approval's [authorized_at, expires_at) window",
            (
                "canonical_payload.issued_at",
                "permit_receipt.standing_approval.authorized_at",
                "permit_receipt.standing_approval.expires_at",
            ),
        )
    return parsed


def coverage_statement(
    *,
    receipt: StandingApprovalReceipt | None,
    signed_version_id: str | None,
) -> str:
    """The one sentence the verifier uses for a covered permit.

    It never says a human reviewed the action.
    """

    if receipt is not None:
        return (
            f"pre-approved by standing approval {receipt.approval_id} "
            f"v{receipt.approval_version}; no per-action review"
        )
    if signed_version_id is not None:
        return (
            f"pre-approved by standing approval version {signed_version_id}; "
            "no per-action review"
        )
    return "pre-approved by a standing approval; no per-action review"


def does_not_establish(
    canonical_payload: Mapping[str, Any],
    receipt: StandingApprovalReceipt | None,
) -> list[str]:
    values = [STANDING_APPROVAL_NOT_HUMAN_REVIEWED, STANDING_APPROVAL_TERMS_NOT_ESTABLISHED]
    if canonical_payload.get("binding_version") != STANDING_APPROVAL_BINDING_VERSION:
        values.append(STANDING_APPROVAL_VERSION_UNSIGNED)
    values.append(STANDING_APPROVAL_FACTS_NOT_ESTABLISHED)
    return values


def coverage_view(
    canonical_payload: Mapping[str, Any],
    receipt: StandingApprovalReceipt | None,
) -> dict[str, Any]:
    """Verifier-safe projection for ``artifact["permit"]["standing_approval"]``.

    ``signed`` holds only values covered by the binding signature;
    ``receipt_reported`` holds unsigned receipt values that passed validation
    (and, on v8, matched the signed ones).
    """

    is_v8 = canonical_payload.get("binding_version") == STANDING_APPROVAL_BINDING_VERSION
    signed_version_id = (
        str(canonical_payload.get("standing_approval_version_id")) if is_v8 else None
    )
    view: dict[str, Any] = {
        "admin_review": STANDING_APPROVAL_ADMIN_REVIEW,
        "per_action_review": False,
        "statement": coverage_statement(
            receipt=receipt, signed_version_id=signed_version_id
        ),
        "signed": {
            "reason": STANDING_APPROVAL_COVERED_REASON,
            "standing_approval_version_id": signed_version_id,
            "terms_digest": (
                str(canonical_payload.get("terms_digest")) if is_v8 else None
            ),
        },
        "receipt_reported": None,
    }
    if receipt is not None:
        view["receipt_reported"] = {
            "id": receipt.approval_id,
            "approval_version": receipt.approval_version,
            "standing_approval_version_id": receipt.standing_approval_version_id,
            "terms_digest": receipt.terms_digest,
            "authorized_by": dict(receipt.authorized_by),
            "co_approved_by": (
                dict(receipt.co_approved_by) if receipt.co_approved_by else None
            ),
            "authorized_at": receipt.authorized_at,
            "expires_at": receipt.expires_at,
            "origin": receipt.origin,
            "assurance_level": receipt.assurance_level,
            "facts_trust": receipt.facts_trust,
            "usage": dict(receipt.usage),
        }
    return view


#: Summary sentence for a covered permit. It lives here, not in
#: ``semantics/permit/human_summary_v1.json``: that file is keel-permit's
#: canonical artifact and must stay byte-identical to its pinned digest.
STANDING_APPROVAL_COVERAGE_SENTENCE = (
    "No human reviewed this individual action: the admin review was satisfied "
    "by {coverage}."
)


def coverage_subject(view: Mapping[str, Any]) -> str:
    """Name the covering approval from a ``coverage_view`` dict, for renderers."""

    receipt = view.get("receipt_reported")
    if isinstance(receipt, Mapping):
        approval_id = receipt.get("id")
        approval_version = receipt.get("approval_version")
        if isinstance(approval_id, str) and _is_int(approval_version):
            return f"standing approval {approval_id} v{approval_version}"
    signed = view.get("signed")
    if isinstance(signed, Mapping):
        version_id = signed.get("standing_approval_version_id")
        if isinstance(version_id, str) and version_id:
            return f"standing approval version {version_id}"
    return "a standing approval"


__all__ = [
    "RECEIPT_REQUIRED_FIELDS",
    "STANDING_APPROVAL_ADMIN_REVIEW",
    "STANDING_APPROVAL_ASSURANCE_LEVELS",
    "STANDING_APPROVAL_BINDING_VERSION",
    "STANDING_APPROVAL_COVERED_REASON",
    "STANDING_APPROVAL_FACTS_TRUST",
    "STANDING_APPROVAL_NOT_HUMAN_REVIEWED",
    "STANDING_APPROVAL_RECEIPT_KEY",
    "StandingApprovalError",
    "StandingApprovalReceipt",
    "check_against_signed",
    "coverage_statement",
    "coverage_subject",
    "coverage_view",
    "does_not_establish",
    "is_covered_reason",
    "is_terms_digest",
    "parse_receipt_block",
    "receipt_block",
    "signed_binding_error",
]
