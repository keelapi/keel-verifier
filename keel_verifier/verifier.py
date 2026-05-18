#!/usr/bin/env python3
"""Standalone Keel trust artifact verifier.

This is a self-contained verifier you can run WITHOUT cloning keel-api.
It depends only on:
    pip install cryptography

Three modes:

  1. Compliance export (manifest + payload):
       keel_verify.py export --export-file export.jsonl.gz --manifest manifest.json \\
           [--key-manifest keys.json]
           [--key-manifest-url https://api.keelapi.com/v1/compliance/keys]
           [--expected-public-key ed25519:...]

  2. Integrity checkpoint (raw JSON downloaded from external anchor):
       keel_verify.py checkpoint \\
           --checkpoint-file checkpoint.json \\
           [--key-manifest keys.json]
           [--key-manifest-url https://api.keelapi.com/v1/compliance/keys]
           [--expected-public-key ed25519:...] \\
           [--public-key-url https://api.keelapi.com/v1/integrity/checkpoint-public-key]

     If neither --expected-public-key, --public-key-url, nor --key-manifest is
     given, the verifier uses the public_key embedded in the artifact and
     reports this as a self-attested verification only.

  3. TSA receipt embedded in a checkpoint:
     Performed automatically inside ``checkpoint`` mode whenever the
     checkpoint includes a ``tsa.receipt_b64`` field. The verifier checks
     that the receipt's MessageImprint equals the checkpoint's
     composite_hash (RFC 3161 §2.4.2). For full trust-chain verification
     against the TSA's CA bundle, see --tsa-ca-bundle.

Key resolution order (when verifying signatures):

  1. ``--expected-public-key`` (explicit pin) — highest priority.
  2. ``--public-key-url`` (single-key fetch, checkpoint mode only).
  3. ``--key-manifest`` / ``--key-manifest-url`` resolved by ``key_id``.
  4. Embedded ``public_key`` in the artifact (self-attested).

If the artifact carries a ``key_id`` and a key manifest is supplied, the
verifier requires the manifest to contain a matching entry with the correct
purpose. If the artifact has no ``key_id`` (legacy artifact), the manifest
must contain a single matching legacy public key for the relevant purpose;
otherwise verification fails with a clear message.

Exit codes: 0 = verified, 1 = failed, 2 = bad usage.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import gzip
import hashlib
import io
import json
import re
import sys
import urllib.request
import zipfile
from datetime import datetime, timezone
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path
from typing import Any

from keel_verifier.verdicts import (
    ClaimVerdict,
    VERDICT_SCHEMA_ID,
    VerificationReport,
    VerdictSubject,
    legacy_semantics,
    verdict_value,
)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:
    print(
        "ERROR: 'cryptography' is required.  Install with: pip install cryptography",
        file=sys.stderr,
    )
    sys.exit(2)


DEFAULT_TRUST_ROOT_PATH = Path(__file__).resolve().parent / "data" / "trust_root.json"
CACHED_TRUST_ROOT_PATH = Path.home() / ".keel-verifier" / "trust-root.json"
KEELAPI_COMPLIANCE_KEYS_URL = "https://api.keelapi.com/v1/compliance/keys"
KEELAPI_CHECKPOINT_PUBLIC_KEY_URL = (
    "https://api.keelapi.com/v1/integrity/checkpoint-public-key"
)
GITHUB_TRUST_ROOT_URL = (
    "https://raw.githubusercontent.com/keelapi/keel-verifier/main/"
    "keel_verifier/data/trust_root.json"
)
REFRESH_KEYS_SOURCES: tuple[tuple[str, str, str], ...] = (
    # (slug, display_name, url)
    ("api", "Keel API", KEELAPI_COMPLIANCE_KEYS_URL),
    ("github", "GitHub", GITHUB_TRUST_ROOT_URL),
)


def _content_hash(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _subject(
    *,
    subject_type: str,
    subject_id: str | None,
    verdict: str,
    reason_code: str,
    message: str,
    evidence: list[str] | None = None,
) -> VerdictSubject:
    return VerdictSubject(
        type=subject_type,
        id=subject_id,
        verdict=verdict_value(verdict),
        reason_code=reason_code,
        message=message,
        evidence=list(evidence or []),
    )


def _single_subject_claim(
    name: str,
    *,
    subject_type: str,
    subject_id: str | None,
    verdict: str,
    reason_code: str,
    message: str,
    evidence: list[str] | None = None,
    required: bool = True,
) -> ClaimVerdict:
    return ClaimVerdict(
        name=name,
        required=required,
        subjects=[
            _subject(
                subject_type=subject_type,
                subject_id=subject_id,
                verdict=verdict,
                reason_code=reason_code,
                message=message,
                evidence=evidence,
            )
        ],
        reason_code=reason_code,
        message=message,
        evidence=list(evidence or []),
    )


def _merge_claims(claims: list[ClaimVerdict]) -> list[ClaimVerdict]:
    merged: dict[str, ClaimVerdict] = {}
    order: list[str] = []
    for claim in claims:
        existing = merged.get(claim.name)
        if existing is None:
            merged[claim.name] = claim
            order.append(claim.name)
            continue
        merged[claim.name] = ClaimVerdict(
            name=claim.name,
            subjects=[*existing.subjects, *claim.subjects],
            required=existing.required or claim.required,
            semantics=existing.semantics if existing.semantics is not None else claim.semantics,
            evidence=[*existing.evidence, *claim.evidence],
            reason_code=existing.reason_code or claim.reason_code,
            message=existing.message or claim.message,
            diagnostics=[*existing.diagnostics, *claim.diagnostics],
        )
    return [merged[name] for name in order]


WALK_RECORD_HASH_MISMATCH = "WALK_RECORD_HASH_MISMATCH"
WALK_PREV_HASH_DISCONTINUITY = "WALK_PREV_HASH_DISCONTINUITY"
WALK_SEQUENCE_INVERSION = "WALK_SEQUENCE_INVERSION"
WALK_UNKNOWN_CHAIN_FORMAT = "WALK_UNKNOWN_CHAIN_FORMAT"
WALK_CLOSURE_SIGNATURE_INVALID = "WALK_CLOSURE_SIGNATURE_INVALID"
WALK_CLOSURE_DIGEST_MISMATCH = "WALK_CLOSURE_DIGEST_MISMATCH"
WALK_CLOSURE_DIGEST_MISSING = "WALK_CLOSURE_DIGEST_MISSING"
WALK_CLOSURE_DISPATCH_DIGEST_MISMATCH = "WALK_CLOSURE_DISPATCH_DIGEST_MISMATCH"
WALK_UNKNOWN_CLOSURE_FORMAT = "WALK_UNKNOWN_CLOSURE_FORMAT"
WORKFLOW_EVIDENCE_SCHEMA_INVALID = "WORKFLOW_EVIDENCE_SCHEMA_INVALID"
WORKFLOW_SIGNATURE_INVALID = "WORKFLOW_SIGNATURE_INVALID"
WORKFLOW_AMENDMENT_ORDER_INVALID = "WORKFLOW_AMENDMENT_ORDER_INVALID"
WORKFLOW_EFFECTIVE_INTENT_HASH_MISMATCH = "WORKFLOW_EFFECTIVE_INTENT_HASH_MISMATCH"
INCIDENT_MANIFEST_SCHEMA_INVALID = "INCIDENT_MANIFEST_SCHEMA_INVALID"
INCIDENT_UNKNOWN_MANIFEST_VERSION = "INCIDENT_UNKNOWN_MANIFEST_VERSION"

PERMIT_BINDING_SIGNING_PURPOSE = "permit_binding_signing"
WORKFLOW_DECLARATION_BINDING_VERSION = "workflow_declaration.v1"
WORKFLOW_AMENDMENT_BINDING_VERSION = "workflow_amendment.v1"
VANTA_WORKFLOW_EVIDENCE_SCHEMA = "keel.vanta.workflow_evidence/v1"
INCIDENT_WORKFLOW_DECLARATIONS_SCHEMA = "keel.workflow_declarations/v1"
INCIDENT_WORKFLOW_AMENDMENTS_SCHEMA = "keel.workflow_amendments/v1"
INCIDENT_V2_REQUIRED_FILES = {
    "admin_actions.jsonl": "keel.admin_actions/v1",
    "bracket_checkpoints.json": "keel.bracket_checkpoints/v1",
    "governance_events.jsonl": "keel.governance_events/v1",
    "incident_metadata.json": "keel.incident_metadata/v1",
    "permits.jsonl": "keel.permits/v1",
    "workflow_declarations.jsonl": "keel.workflow_declarations/v1",
    "workflow_amendments.jsonl": "keel.workflow_amendments/v1",
    "mcp_tool_decisions.jsonl": "keel.mcp_tool_decisions/v1",
}
DISPATCH_REQUEST_DIGEST_SEMANTICS = "approved_request_body_bytes_at_dispatch_time"
PROVIDER_RESPONSE_DIGEST_SEMANTICS = "provider_bytes_received_by_keel"
CLIENT_RESPONSE_DIGEST_SEMANTICS = "response_bytes_handed_to_asgi_not_tcp_receipt"
CLOSURE_STATUS_CLOSED = "closed"
CLOSURE_STATUS_MISSING_CLOSURE = "missing_closure"

_SIGNED_CLOSURE_V1_REQUIRED_KEYS = (
    "binding_version",
    "permit_id",
    "execution_id",
    "correlation_id",
    "provider",
    "model",
    "provider_response_digest_v1",
    "client_response_digest_v1",
    "closure_status",
    "status_code",
    "provider_response_id",
    "provider_response_digest_semantics",
    "client_response_digest_semantics",
    "request_created_at",
    "started_at",
    "completed_at",
    "provider_response_received_at",
    "client_response_delivered_at",
    "closure_signed_at",
    "binding_key_id",
)
_SIGNED_CLOSURE_V1_OPTIONAL_KEYS = ("usage_reported_at",)
_SIGNED_CLOSURE_V2_REQUIRED_KEYS = (
    "binding_version",
    "permit_id",
    "execution_id",
    "correlation_id",
    "provider",
    "model",
    "dispatch_request_digest_v1",
    "provider_response_digest_v1",
    "client_response_digest_v1",
    "closure_status",
    "status_code",
    "provider_response_id",
    "dispatch_request_digest_semantics",
    "provider_response_digest_semantics",
    "client_response_digest_semantics",
    "request_created_at",
    "started_at",
    "completed_at",
    "provider_response_received_at",
    "client_response_delivered_at",
    "closure_signed_at",
    "binding_key_id",
)
_SIGNED_CLOSURE_V2_OPTIONAL_KEYS = ("usage_reported_at",)


def _verify_ed25519(pub_b64: str, signed_message: bytes, sig_b64: str) -> bool:
    try:
        pub_bytes = base64.b64decode(pub_b64.removeprefix("ed25519:"))
        sig_bytes = base64.b64decode(sig_b64.removeprefix("ed25519:"))
        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub_key.verify(sig_bytes, signed_message)
        return True
    except Exception:
        return False


def _public_key_fingerprint(pub_b64: str) -> str:
    raw = base64.b64decode(pub_b64.removeprefix("ed25519:"))
    return f"sha256:{hashlib.sha256(raw).hexdigest()[:32]}"


def _parse_record_hash_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        raise TypeError("created_at must be an ISO-8601 string")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


def _compute_record_hash_v1(
    *,
    event_id: str,
    event_type: str,
    resource_type: str | None,
    resource_id: str | None,
    outcome: str | None,
    severity: str,
    created_at: Any,
    prev_hash: str,
    sequence_number: int,
) -> str:
    normalized_ts = _parse_record_hash_timestamp(created_at)
    normalized_ts = (
        normalized_ts.replace(tzinfo=None)
        if normalized_ts.tzinfo
        else normalized_ts
    )
    ts_str = normalized_ts.strftime("%Y-%m-%dT%H:%M:%S.%f")
    parts = "|".join(
        [
            event_id,
            event_type,
            resource_type or "",
            resource_id or "",
            outcome or "",
            severity,
            ts_str,
            prev_hash,
            str(sequence_number),
        ]
    )
    return hashlib.sha256(parts.encode("utf-8")).hexdigest()


CHAIN_FORMAT_HASHERS = {"v1": _compute_record_hash_v1}


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _compute_canonical_binding_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _binding_key_id_from_public_key(public_key: str) -> str:
    raw = base64.b64decode(public_key.removeprefix("ed25519:"))
    return hashlib.sha256(raw).hexdigest()[:16]


# ─── Key manifest loading ──────────────────────────────────────────


def _parse_iso_or_none(value: Any) -> datetime | None:
    """Parse an ISO-8601 timestamp. Returns None if missing or unparseable.

    Accepts ``Z`` and ``+00:00`` suffixes; bare strings without an
    explicit zone are assumed UTC. Used for both artifact signing times
    (``signed_at`` / ``computed_at``) and manifest entry windows
    (``valid_from`` / ``valid_to``).
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _filter_by_active_window(
    entries: list[dict[str, Any]],
    signing_time: datetime,
) -> list[dict[str, Any]]:
    """Keep entries whose [valid_from, valid_to] window covers signing_time.

    Either bound being None means "open-ended" on that side. Entries
    whose timestamp fields fail to parse are excluded conservatively.
    """
    matches: list[dict[str, Any]] = []
    for entry in entries:
        valid_from = _parse_iso_or_none(entry.get("valid_from"))
        valid_to = _parse_iso_or_none(entry.get("valid_to"))
        if valid_from is not None and signing_time < valid_from:
            continue
        if valid_to is not None and signing_time > valid_to:
            continue
        matches.append(entry)
    return matches


def _load_key_manifest(source: str) -> list[dict[str, Any]]:
    """Load a Keel public key manifest from a local file path or URL."""
    if source.startswith(("http://", "https://")):
        with urllib.request.urlopen(source, timeout=10) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    else:
        body = json.loads(Path(source).read_text(encoding="utf-8"))

    if not isinstance(body, dict) or not isinstance(body.get("keys"), list):
        raise ValueError(
            f"Key manifest at {source!r} must be a JSON object with a 'keys' list"
        )

    default_purpose = (
        body.get("purpose") if isinstance(body.get("purpose"), str) else None
    )
    entries: list[dict[str, Any]] = []
    for entry in body["keys"]:
        if not isinstance(entry, dict):
            continue
        normalized = dict(entry)
        if default_purpose is not None and not isinstance(
            normalized.get("purpose"), str
        ):
            normalized["purpose"] = default_purpose
        public_key_b64 = normalized.get("public_key_b64")
        if not isinstance(normalized.get("public_key"), str) and isinstance(
            public_key_b64, str
        ):
            public_key_material = public_key_b64.removeprefix("ed25519:")
            normalized["public_key"] = f"ed25519:{public_key_material}"
        if "valid_from" not in normalized and "active_from" in normalized:
            normalized["valid_from"] = normalized.get("active_from")
        if "valid_to" not in normalized and "active_to" in normalized:
            normalized["valid_to"] = normalized.get("active_to")
        if "status" not in normalized and (
            "active_to" in normalized or "valid_to" in normalized
        ):
            normalized["status"] = (
                "active" if normalized.get("valid_to") is None else "retired"
            )
        entries.append(normalized)

    return entries


def _resolve_from_manifest(
    manifest_entries: list[dict[str, Any]],
    *,
    key_id: str | None,
    purpose: str,
    signing_time: datetime | None = None,
) -> tuple[str | None, dict[str, Any] | None, str | None]:
    """Pick the right entry from the manifest.

    Returns ``(public_key, entry, error)``.  Error is a human-readable string
    if no resolution is possible; ``public_key`` and ``entry`` are None in
    that case.

    When the artifact has no ``key_id`` and the manifest has multiple
    candidates for the purpose, ``signing_time`` (parsed from the artifact's
    ``signed_at`` or ``computed_at`` field) filters candidates to those
    whose ``[valid_from, valid_to]`` window covers it. If signing_time is
    None, the verifier falls back to the legacy "single candidate" rule
    so older artifacts without a signing timestamp remain verifiable.
    """
    purpose_entries = [e for e in manifest_entries if e.get("purpose") == purpose]
    if not purpose_entries:
        return (
            None,
            None,
            f"key manifest contains no entry with purpose={purpose!r}",
        )

    if key_id is not None:
        matches = [e for e in purpose_entries if e.get("key_id") == key_id]
        if not matches:
            return (
                None,
                None,
                f"key_id {key_id!r} not found in key manifest for purpose={purpose!r}",
            )
        # Prefer an exact unique match
        entry = matches[0]
        pub = entry.get("public_key")
        if not isinstance(pub, str):
            return None, None, "matched manifest entry has no public_key"
        return pub, entry, None

    # Legacy artifact (no key_id). When the artifact carries no parseable
    # signing timestamp, retain the single-candidate rule for back-compat
    # with older artifacts.
    if signing_time is None:
        if len(purpose_entries) != 1:
            return (
                None,
                None,
                (
                    "artifact has no key_id and the key manifest does not contain a "
                    "single legacy fallback for purpose="
                    + repr(purpose)
                    + f" ({len(purpose_entries)} candidates)"
                ),
            )
        entry = purpose_entries[0]
        pub = entry.get("public_key")
        if not isinstance(pub, str):
            return None, None, "legacy fallback manifest entry has no public_key"
        return pub, entry, None

    # Filter manifest candidates by their active window vs. signing_time.
    active = _filter_by_active_window(purpose_entries, signing_time)
    if len(active) == 1:
        entry = active[0]
        pub = entry.get("public_key")
        if not isinstance(pub, str):
            return None, None, "matching manifest entry has no public_key"
        return pub, entry, None

    if len(active) == 0:
        return (
            None,
            None,
            (
                f"no manifest entries for purpose={purpose!r} were active at "
                f"signing time {signing_time.isoformat()} "
                f"({len(purpose_entries)} candidates evaluated); manifest may "
                "be missing key history"
            ),
        )

    return (
        None,
        None,
        (
            f"multiple manifest entries for purpose={purpose!r} were active at "
            f"signing time {signing_time.isoformat()} "
            f"({len(active)} candidates); manifest is ambiguous within active window"
        ),
    )


def _resolve_trust_key(
    *,
    artifact_pub: str | None,
    artifact_key_id: str | None,
    purpose: str,
    expected_public_key: str | None,
    public_key_url: str | None,
    key_manifest_source: str | None,
    signing_time: datetime | None = None,
) -> tuple[str | None, str, str | None]:
    """Resolve which public key to trust for verifying an artifact.

    Returns ``(trusted_public_key, trust_source, error)``.  When ``error`` is
    not None, the trusted key is None and verification must abort.

    ``signing_time`` (parsed from the artifact) lets the manifest path
    filter retired candidates by their active window. None falls back to
    the legacy single-candidate rule.
    """
    if expected_public_key is not None:
        return expected_public_key, "user-supplied", None

    if public_key_url is not None:
        try:
            with urllib.request.urlopen(public_key_url, timeout=10) as resp:
                body = json.loads(resp.read().decode("utf-8"))
            pub = body.get("public_key")
            if not isinstance(pub, str) or not pub.startswith("ed25519:"):
                return None, "", f"unexpected response shape from {public_key_url}"
            return pub, f"fetched from {public_key_url}", None
        except Exception as exc:
            return None, "", f"could not fetch public key: {exc}"

    if key_manifest_source is not None:
        try:
            entries = _load_key_manifest(key_manifest_source)
        except Exception as exc:
            return None, "", f"could not load key manifest: {exc}"
        pub, entry, err = _resolve_from_manifest(
            entries,
            key_id=artifact_key_id,
            purpose=purpose,
            signing_time=signing_time,
        )
        if err is not None:
            return None, "", err
        assert pub is not None and entry is not None
        return pub, (
            f"key manifest ({key_manifest_source}) "
            f"key_id={entry.get('key_id')} status={entry.get('status')}"
        ), None

    if artifact_pub is not None:
        return artifact_pub, "embedded", None

    return None, "", "no trust key available (artifact is unsigned)"


def _bundled_key_manifest_source() -> str | None:
    return str(DEFAULT_TRUST_ROOT_PATH) if DEFAULT_TRUST_ROOT_PATH.exists() else None


def _cached_key_manifest_source() -> str | None:
    """Path to the user-refreshed manifest at ``~/.keel-verifier/trust-root.json`` if present."""
    return str(CACHED_TRUST_ROOT_PATH) if CACHED_TRUST_ROOT_PATH.exists() else None


def _key_manifest_source_for_args(args: argparse.Namespace) -> str | None:
    """Resolve which trust-root source to use for a verification run.

    Resolution order:
      1. Explicit ``--key-manifest`` / ``--key-manifest-url`` argument.
      2. Self-attested mode short-circuits to no manifest.
      3. Cached manifest at ``~/.keel-verifier/trust-root.json`` (populated by
         ``keel-verify refresh-keys``).
      4. Bundled trust root shipped with the wheel.
    """
    explicit = getattr(args, "key_manifest", None) or getattr(args, "key_manifest_url", None)
    if explicit:
        return explicit
    if getattr(args, "self_attested", False):
        return None
    cached = _cached_key_manifest_source()
    if cached is not None:
        return cached
    return _bundled_key_manifest_source()


def _composite_hash(chain_heads: dict[str, dict[str, Any]]) -> str:
    parts: list[str] = []
    for scope_key in sorted(chain_heads.keys()):
        head = chain_heads[scope_key]
        parts.append(
            f"{scope_key}:{head['sequence_number']}:{head['last_record_hash']}"
        )
    combined = "\n".join(parts)
    return f"sha256:{hashlib.sha256(combined.encode('utf-8')).hexdigest()}"


# ─── Mode 1: export ────────────────────────────────────────────────


def _walk_fail(code: str, message: str) -> int:
    print(f"FAILED: {code}: {message}", file=sys.stderr)
    return 1


def _walk_structure_fail(message: str) -> int:
    print(f"FAILED: {message}", file=sys.stderr)
    return 1


def _scope_label(chain_scope: Any) -> str:
    return "<none>" if chain_scope is None else str(chain_scope)


def _entry_id(entry: dict[str, Any]) -> str:
    event_id = entry.get("event_id")
    return event_id if isinstance(event_id, str) and event_id else "<unknown>"


def _required_str(entry: dict[str, Any], field: str) -> str:
    value = entry.get(field)
    if not isinstance(value, str) or value == "":
        raise TypeError(f"{field} must be a non-empty string")
    return value


def _optional_str(entry: dict[str, Any], field: str) -> str | None:
    value = entry.get(field)
    if value is None or isinstance(value, str):
        return value
    raise TypeError(f"{field} must be a string or null")


def _required_int(entry: dict[str, Any], field: str) -> int:
    value = entry.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field} must be an integer")
    return value


def _optional_sequence_number(entry: dict[str, Any]) -> int | None:
    if entry.get("sequence_number") is None:
        return None
    return _required_int(entry, "sequence_number")


def _sequence_sort_key(entry: dict[str, Any]) -> tuple[bool, int]:
    sequence_number = _optional_sequence_number(entry)
    return (
        sequence_number is None,
        sequence_number if sequence_number is not None else 0,
    )


def _walk_array_order_fail(
    chain_scope: Any,
    entries: list[dict[str, Any]],
) -> int | None:
    for index in range(1, len(entries)):
        previous = entries[index - 1]
        current = entries[index]
        try:
            previous_sequence = _optional_sequence_number(previous)
            current_sequence = _optional_sequence_number(current)
        except (TypeError, ValueError) as exc:
            return _walk_fail(
                WALK_SEQUENCE_INVERSION,
                f"event_id={_entry_id(current)} {exc}",
            )
        if previous_sequence is None or current_sequence is None:
            continue
        if current_sequence < previous_sequence:
            return _walk_fail(
                WALK_SEQUENCE_INVERSION,
                (
                    f"chain_scope={_scope_label(chain_scope)} "
                    f"prev_event_id={_entry_id(previous)} "
                    f"prev_sequence_number={previous_sequence} "
                    f"event_id={_entry_id(current)} "
                    f"sequence_number={current_sequence}"
                ),
            )
    return None


def _walk_duplicate_sequence_fail(
    chain_scope: Any,
    entries: list[dict[str, Any]],
) -> int | None:
    seen: dict[int, dict[str, Any]] = {}
    for entry in entries:
        try:
            sequence_number = _optional_sequence_number(entry)
        except (TypeError, ValueError) as exc:
            return _walk_fail(
                WALK_SEQUENCE_INVERSION,
                f"event_id={_entry_id(entry)} {exc}",
            )
        if sequence_number is None:
            continue
        if sequence_number in seen:
            return _walk_fail(
                WALK_SEQUENCE_INVERSION,
                (
                    f"chain_scope={_scope_label(chain_scope)} "
                    f"event_id={_entry_id(entry)} "
                    f"previous_event_id={_entry_id(seen[sequence_number])} "
                    f"duplicate_sequence_number={sequence_number}"
                ),
            )
        seen[sequence_number] = entry
    return None


def _decode_export_json_payload(export_data: bytes) -> bytes:
    if export_data.startswith(b"\x1f\x8b"):
        try:
            return gzip.decompress(export_data)
        except OSError as exc:
            raise ValueError(f"gzip decompression failed: {exc}") from exc
    return export_data


def _load_export_json_document(export_data: bytes) -> Any:
    decoded = _decode_export_json_payload(export_data).decode("utf-8")
    try:
        return json.loads(decoded)
    except json.JSONDecodeError as exc:
        records: list[dict[str, Any]] = []
        for line_number, line in enumerate(decoded.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as line_exc:
                raise ValueError(
                    f"JSONL line {line_number} is not valid JSON: {line_exc}"
                ) from line_exc
            if not isinstance(record, dict):
                raise ValueError(f"JSONL line {line_number} must be a JSON object")
            records.append(record)
        if not records:
            raise exc
        project_id = next(
            (
                record.get("project_id")
                for record in records
                if isinstance(record.get("project_id"), str)
                and record.get("project_id")
            ),
            None,
        )
        return {
            "schema": "keel.governance_events/v1",
            "project_id": project_id,
            "record_count": len(records),
            "records": records,
        }


def _load_audit_export_bundle_for_optional_check(
    export_data: bytes,
    *,
    label: str,
) -> tuple[dict[str, Any] | None, int | None]:
    try:
        bundle = _load_export_json_document(export_data)
    except Exception as exc:
        return None, _walk_structure_fail(f"export is not JSON: {exc}")

    if not isinstance(bundle, dict):
        return None, _walk_structure_fail("bundle must be a JSON object")
    if bundle.get("bundle_type") != "audit_export_bundle":
        return None, _walk_structure_fail(
            "bundle_type must be 'audit_export_bundle'",
        )

    schema_version = bundle.get("schema_version")
    if schema_version not in {1, 2}:
        return None, _walk_structure_fail(
            "schema_version must be 1 or 2",
        )
    if schema_version == 1:
        print(
            f"{label}: bundle has no chain entries (schema_version=1, "
            "request with ?include_chain_entries=true to enable verification)"
        )
        return None, 0
    if bundle.get("include_chain_entries") is not True:
        return None, _walk_structure_fail(
            "schema_version=2 requires include_chain_entries=true",
        )
    return bundle, None


def _record_permit_id(record: dict[str, Any]) -> str | None:
    permit = record.get("permit")
    if not isinstance(permit, dict):
        return None
    permit_id = permit.get("id")
    return permit_id if isinstance(permit_id, str) and permit_id else None


def _record_permit_binding_request_hash(record: dict[str, Any]) -> str | None:
    permit = record.get("permit")
    if not isinstance(permit, dict):
        return None
    value = permit.get("binding_request_hash")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _entry_inline_permit_id(entry: dict[str, Any]) -> str | None:
    value = entry.get("permit_id")
    if isinstance(value, str) and value:
        return value
    payload = _entry_payload(entry)
    value = payload.get("permit_id")
    if isinstance(value, str) and value:
        return value
    if entry.get("resource_type") == "permit":
        value = entry.get("resource_id")
        if isinstance(value, str) and value:
            return value
    return None


def _entry_payload(entry: dict[str, Any]) -> dict[str, Any]:
    payload = entry.get("payload_json")
    if isinstance(payload, dict):
        return payload
    return {}


def _flatten_chain_entries(
    bundle: dict[str, Any],
) -> tuple[list[dict[str, Any]] | None, int | None]:
    records = bundle.get("records")
    if not isinstance(records, list):
        return None, _walk_structure_fail("records must be a list")

    record_binding_by_permit: dict[str, str] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        record_permit_id = _record_permit_id(record)
        record_binding_request_hash = _record_permit_binding_request_hash(record)
        if record_permit_id is not None and record_binding_request_hash is not None:
            record_binding_by_permit[record_permit_id] = record_binding_request_hash

    bundle_chain_entries = bundle.get("chain_entries")
    if bundle_chain_entries is not None:
        if not isinstance(bundle_chain_entries, list):
            return None, _walk_structure_fail("chain_entries must be a list")
        flattened: list[dict[str, Any]] = []
        for entry_index, entry in enumerate(bundle_chain_entries):
            if not isinstance(entry, dict):
                return None, _walk_structure_fail(
                    f"chain_entries[{entry_index}] must be an object",
                )
            permit_id = _entry_inline_permit_id(entry)
            flattened.append(
                {
                    "entry": entry,
                    "record_index": None,
                    "entry_index": entry_index,
                    "record_permit_id": permit_id,
                    "record_binding_request_hash": record_binding_by_permit.get(
                        permit_id or "",
                    ),
                }
            )
        return flattened, None

    flattened: list[dict[str, Any]] = []
    for record_index, record in enumerate(records):
        if not isinstance(record, dict):
            return None, _walk_structure_fail(
                f"records[{record_index}] must be an object",
            )
        record_permit_id = _record_permit_id(record)
        record_binding_request_hash = _record_permit_binding_request_hash(record)
        chain_entries = record.get("chain_entries")
        if chain_entries is None:
            return None, _walk_structure_fail(
                f"records[{record_index}].chain_entries missing",
            )
        if not isinstance(chain_entries, list):
            return None, _walk_structure_fail(
                f"records[{record_index}].chain_entries must be a list",
            )
        for entry_index, entry in enumerate(chain_entries):
            if not isinstance(entry, dict):
                return None, _walk_structure_fail(
                    f"records[{record_index}].chain_entries[{entry_index}] "
                    "must be an object",
                )
            flattened.append(
                {
                    "entry": entry,
                    "record_index": record_index,
                    "entry_index": entry_index,
                    "record_permit_id": record_permit_id,
                    "record_binding_request_hash": record_binding_request_hash,
                }
            )
    return flattened, None


def _governance_events_export_as_walk_bundle(
    bundle: dict[str, Any],
) -> tuple[dict[str, Any] | None, int | None]:
    records = bundle.get("records")
    if not isinstance(records, list):
        return None, _walk_structure_fail("records must be a list")

    chain_entries: list[dict[str, Any]] = []
    project_id = bundle.get("project_id")
    derived_chain_scope = (
        f"project:{project_id}" if isinstance(project_id, str) and project_id else None
    )
    for record_index, record in enumerate(records):
        if not isinstance(record, dict):
            return None, _walk_structure_fail(
                f"records[{record_index}] must be an object",
            )
        entry = dict(record)
        entry["chain_format_version"] = str(record.get("chain_format_version") or "v1")
        entry["created_at"] = record.get("occurred_at") or record.get("created_at")
        if "payload_json" not in entry and isinstance(record.get("payload"), dict):
            entry["payload_json"] = record["payload"]
        if not entry.get("chain_scope") and derived_chain_scope is not None:
            entry["chain_scope"] = derived_chain_scope
        chain_entries.append(entry)

    return {
        "bundle_type": "audit_export_bundle",
        "schema_version": 2,
        "include_chain_entries": True,
        "chain_entries": chain_entries,
        "records": [],
    }, None


def _walk_export_events(export_data: bytes) -> int:
    try:
        bundle = _load_export_json_document(export_data)
    except Exception as exc:
        return _walk_structure_fail(f"export is not JSON: {exc}")

    if not isinstance(bundle, dict):
        return _walk_structure_fail("bundle must be a JSON object")
    if bundle.get("schema") == "keel.governance_events/v1":
        bundle, conversion_result = _governance_events_export_as_walk_bundle(bundle)
        if conversion_result is not None:
            return conversion_result
        if bundle is None:
            return _walk_structure_fail("could not load governance events export")
    elif bundle.get("bundle_type") != "audit_export_bundle":
        return _walk_structure_fail(
            "bundle_type must be 'audit_export_bundle'",
        )

    schema_version = bundle.get("schema_version")
    if schema_version not in {1, 2}:
        return _walk_structure_fail(
            "schema_version must be 1 or 2",
        )
    if schema_version == 1:
        print(
            "WALK-EVENTS: bundle has no chain entries (schema_version=1, "
            "request with ?include_chain_entries=true to enable walk)"
        )
        return 0
    if bundle.get("include_chain_entries") is not True:
        return _walk_structure_fail(
            "schema_version=2 requires include_chain_entries=true",
        )

    by_scope: dict[Any, list[dict[str, Any]]] = {}
    entries_walked = 0

    bundle_chain_entries = bundle.get("chain_entries")
    if bundle_chain_entries is not None:
        if not isinstance(bundle_chain_entries, list):
            return _walk_structure_fail("chain_entries must be a list")
        bundle_entries_by_scope: dict[Any, list[dict[str, Any]]] = {}
        for entry_index, entry in enumerate(bundle_chain_entries):
            if not isinstance(entry, dict):
                return _walk_structure_fail(
                    f"chain_entries[{entry_index}] must be an object",
                )
            version = entry.get("chain_format_version")
            if version not in CHAIN_FORMAT_HASHERS:
                return _walk_fail(
                    WALK_UNKNOWN_CHAIN_FORMAT,
                    (
                        f"event_id={_entry_id(entry)} "
                        f"chain_format_version={version!r}"
                    ),
                )
            try:
                _optional_sequence_number(entry)
            except (TypeError, ValueError) as exc:
                return _walk_fail(
                    WALK_SEQUENCE_INVERSION,
                    f"event_id={_entry_id(entry)} {exc}",
                )
            chain_scope = entry.get("chain_scope")
            by_scope.setdefault(chain_scope, []).append(entry)
            bundle_entries_by_scope.setdefault(chain_scope, []).append(entry)
            entries_walked += 1
        for chain_scope, scope_entries in bundle_entries_by_scope.items():
            sequence_failure = _walk_array_order_fail(chain_scope, scope_entries)
            if sequence_failure is not None:
                return sequence_failure
    else:
        records = bundle.get("records")
        if not isinstance(records, list):
            return _walk_structure_fail("records must be a list")

        for record_index, record in enumerate(records):
            if not isinstance(record, dict):
                return _walk_structure_fail(
                    f"records[{record_index}] must be an object",
                )
            chain_entries = record.get("chain_entries")
            if chain_entries is None:
                return _walk_structure_fail(
                    f"records[{record_index}].chain_entries missing",
                )
            if not isinstance(chain_entries, list):
                return _walk_structure_fail(
                    f"records[{record_index}].chain_entries must be a list",
                )
            record_entries_by_scope: dict[Any, list[dict[str, Any]]] = {}
            for entry_index, entry in enumerate(chain_entries):
                if not isinstance(entry, dict):
                    return _walk_structure_fail(
                        f"records[{record_index}].chain_entries[{entry_index}] "
                        "must be an object",
                    )
                version = entry.get("chain_format_version")
                if version not in CHAIN_FORMAT_HASHERS:
                    return _walk_fail(
                        WALK_UNKNOWN_CHAIN_FORMAT,
                        (
                            f"event_id={_entry_id(entry)} "
                            f"chain_format_version={version!r}"
                        ),
                    )
                try:
                    _optional_sequence_number(entry)
                except (TypeError, ValueError) as exc:
                    return _walk_fail(
                        WALK_SEQUENCE_INVERSION,
                        f"event_id={_entry_id(entry)} {exc}",
                    )
                chain_scope = entry.get("chain_scope")
                by_scope.setdefault(chain_scope, []).append(entry)
                record_entries_by_scope.setdefault(chain_scope, []).append(entry)
                entries_walked += 1
            for chain_scope, scope_entries in record_entries_by_scope.items():
                sequence_failure = _walk_array_order_fail(chain_scope, scope_entries)
                if sequence_failure is not None:
                    return sequence_failure

    record_hash_checks = 0
    prev_hash_checks = 0
    sequence_checks = 0
    for chain_scope, entries in sorted(
        by_scope.items(),
        key=lambda item: _scope_label(item[0]),
    ):
        sequence_failure = _walk_duplicate_sequence_fail(chain_scope, entries)
        if sequence_failure is not None:
            return sequence_failure
        entries.sort(key=_sequence_sort_key)
        first = entries[0]
        print(
            "WALK-EVENTS: "
            f"chain_scope={_scope_label(chain_scope)} "
            f"first sequence_number={first['sequence_number']}, "
            "prev_hash unverifiable from this bundle "
            "(continuity prior to window requires server-side "
            "verify_chain_integrity)"
        )

        previous: dict[str, Any] | None = None
        for entry in entries:
            event_id = _entry_id(entry)
            try:
                sequence_number = _required_int(entry, "sequence_number")
                record_hash = _required_str(entry, "record_hash")
                prev_hash = _required_str(entry, "prev_hash")
                hasher = CHAIN_FORMAT_HASHERS[entry["chain_format_version"]]
                expected_hash = hasher(
                    event_id=_required_str(entry, "event_id"),
                    event_type=_required_str(entry, "event_type"),
                    resource_type=_optional_str(entry, "resource_type"),
                    resource_id=_optional_str(entry, "resource_id"),
                    outcome=_optional_str(entry, "outcome"),
                    severity=_required_str(entry, "severity"),
                    created_at=entry.get("created_at"),
                    prev_hash=prev_hash,
                    sequence_number=sequence_number,
                )
            except (TypeError, ValueError) as exc:
                return _walk_fail(
                    WALK_RECORD_HASH_MISMATCH,
                    f"event_id={event_id} could not recompute hash: {exc}",
                )

            record_hash_checks += 1
            if record_hash != expected_hash:
                return _walk_fail(
                    WALK_RECORD_HASH_MISMATCH,
                    (
                        f"event_id={event_id} "
                        f"expected={expected_hash} actual={record_hash}"
                    ),
                )

            if previous is not None:
                prev_hash_checks += 1
                expected_prev = _required_str(previous, "record_hash")
                if prev_hash != expected_prev:
                    return _walk_fail(
                        WALK_PREV_HASH_DISCONTINUITY,
                        (
                            f"chain_scope={_scope_label(chain_scope)} "
                            f"event_id={event_id} "
                            f"sequence_number={sequence_number} "
                            f"expected_prev={expected_prev} actual_prev={prev_hash}"
                        ),
                    )

                sequence_checks += 1
                previous_sequence = _required_int(previous, "sequence_number")
                if sequence_number <= previous_sequence:
                    return _walk_fail(
                        WALK_SEQUENCE_INVERSION,
                        (
                            f"chain_scope={_scope_label(chain_scope)} "
                            f"event_id={event_id} "
                            f"previous_sequence_number={previous_sequence} "
                            f"sequence_number={sequence_number}"
                        ),
                    )

            previous = entry

    print("WALK-EVENTS: VERIFIED")
    print(f"  chain_scopes:        {len(by_scope)}")
    print(f"  entries_walked:      {entries_walked}")
    print(f"  record_hash_checks:  {record_hash_checks} PASS")
    print(
        f"  prev_hash_checks:    {prev_hash_checks} PASS "
        "(excludes window-edge entries)"
    )
    print(f"  sequence_checks:     {sequence_checks} PASS")
    return 0


def _closure_signature_value(payload: dict[str, Any]) -> str | None:
    value = payload.get("closure_signature_b64")
    if isinstance(value, str) and value.strip():
        return value.strip()
    value = payload.get("binding_signature")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _closure_canonical_hash_value(payload: dict[str, Any]) -> str | None:
    value = payload.get("closure_canonical_hash")
    if isinstance(value, str) and value.strip():
        return value.strip()
    value = payload.get("binding_canonical_hash")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _closure_v1_signed_payload(payload: dict[str, Any]) -> dict[str, Any]:
    missing = [key for key in _SIGNED_CLOSURE_V1_REQUIRED_KEYS if key not in payload]
    if missing:
        raise ValueError(f"closure payload missing signed field(s): {', '.join(missing)}")
    signed = {key: payload.get(key) for key in _SIGNED_CLOSURE_V1_REQUIRED_KEYS}
    for key in _SIGNED_CLOSURE_V1_OPTIONAL_KEYS:
        if key in payload:
            signed[key] = payload.get(key)
    return signed


def _closure_v2_signed_payload(payload: dict[str, Any]) -> dict[str, Any]:
    missing = [key for key in _SIGNED_CLOSURE_V2_REQUIRED_KEYS if key not in payload]
    if missing:
        raise ValueError(f"closure payload missing signed field(s): {', '.join(missing)}")
    signed = {key: payload.get(key) for key in _SIGNED_CLOSURE_V2_REQUIRED_KEYS}
    for key in _SIGNED_CLOSURE_V2_OPTIONAL_KEYS:
        if key in payload:
            signed[key] = payload.get(key)
    return signed


def _verify_closure_v1_signature(
    *,
    payload: dict[str, Any],
    args: argparse.Namespace,
) -> tuple[bool, str]:
    try:
        signed_payload = _closure_v1_signed_payload(payload)
    except ValueError as exc:
        return False, str(exc)

    canonical_hash = _closure_canonical_hash_value(payload)
    signature = _closure_signature_value(payload)
    permit_id = signed_payload.get("permit_id")
    if not isinstance(canonical_hash, str) or not canonical_hash:
        return False, f"permit_id={permit_id} closure_canonical_hash missing"
    if not isinstance(signature, str) or not signature:
        return False, f"permit_id={permit_id} closure_signature_b64 missing"

    recomputed = _compute_canonical_binding_hash(signed_payload)
    if recomputed != canonical_hash:
        return (
            False,
            (
                f"permit_id={permit_id} canonical_hash mismatch "
                f"expected={recomputed} actual={canonical_hash}"
            ),
        )

    closure_signed_at = _parse_iso_or_none(signed_payload.get("closure_signed_at"))
    trusted_pub, trust_source, err = _resolve_trust_key(
        artifact_pub=None,
        artifact_key_id=None,
        purpose=PERMIT_BINDING_SIGNING_PURPOSE,
        expected_public_key=None,
        public_key_url=None,
        key_manifest_source=_key_manifest_source_for_args(args),
        signing_time=closure_signed_at,
    )
    if err is not None or trusted_pub is None:
        return False, f"permit_id={permit_id} {err}"

    binding_key_id = signed_payload.get("binding_key_id")
    if isinstance(binding_key_id, str) and binding_key_id:
        try:
            actual_key_id = _binding_key_id_from_public_key(trusted_pub)
        except Exception as exc:
            return False, f"permit_id={permit_id} invalid trusted public key: {exc}"
        if actual_key_id != binding_key_id:
            return (
                False,
                (
                    f"permit_id={permit_id} binding_key_id mismatch "
                    f"expected={binding_key_id} actual={actual_key_id}"
                ),
            )

    if not _verify_ed25519(trusted_pub, canonical_hash.encode("utf-8"), signature):
        return (
            False,
            f"permit_id={permit_id} Ed25519 signature invalid ({trust_source})",
        )
    return True, trust_source


def _verify_closure_v2_signature(
    *,
    payload: dict[str, Any],
    args: argparse.Namespace,
) -> tuple[bool, str]:
    try:
        signed_payload = _closure_v2_signed_payload(payload)
    except ValueError as exc:
        return False, str(exc)

    canonical_hash = _closure_canonical_hash_value(payload)
    signature = _closure_signature_value(payload)
    permit_id = signed_payload.get("permit_id")
    if not isinstance(canonical_hash, str) or not canonical_hash:
        return False, f"permit_id={permit_id} closure_canonical_hash missing"
    if not isinstance(signature, str) or not signature:
        return False, f"permit_id={permit_id} closure_signature_b64 missing"

    recomputed = _compute_canonical_binding_hash(signed_payload)
    if recomputed != canonical_hash:
        return (
            False,
            (
                f"permit_id={permit_id} canonical_hash mismatch "
                f"expected={recomputed} actual={canonical_hash}"
            ),
        )

    closure_signed_at = _parse_iso_or_none(signed_payload.get("closure_signed_at"))
    trusted_pub, trust_source, err = _resolve_trust_key(
        artifact_pub=None,
        artifact_key_id=None,
        purpose=PERMIT_BINDING_SIGNING_PURPOSE,
        expected_public_key=None,
        public_key_url=None,
        key_manifest_source=_key_manifest_source_for_args(args),
        signing_time=closure_signed_at,
    )
    if err is not None or trusted_pub is None:
        return False, f"permit_id={permit_id} {err}"

    binding_key_id = signed_payload.get("binding_key_id")
    if isinstance(binding_key_id, str) and binding_key_id:
        try:
            actual_key_id = _binding_key_id_from_public_key(trusted_pub)
        except Exception as exc:
            return False, f"permit_id={permit_id} invalid trusted public key: {exc}"
        if actual_key_id != binding_key_id:
            return (
                False,
                (
                    f"permit_id={permit_id} binding_key_id mismatch "
                    f"expected={binding_key_id} actual={actual_key_id}"
                ),
            )

    if not _verify_ed25519(trusted_pub, canonical_hash.encode("utf-8"), signature):
        return (
            False,
            f"permit_id={permit_id} Ed25519 signature invalid ({trust_source})",
        )
    return True, trust_source


def _entry_permit_id(context: dict[str, Any]) -> str | None:
    entry = context["entry"]
    payload = _entry_payload(entry)
    permit_id = payload.get("permit_id")
    if isinstance(permit_id, str) and permit_id:
        return permit_id
    return context.get("record_permit_id")


def _digest_value(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _digest_candidates(
    contexts: list[dict[str, Any]],
    *,
    permit_id: str,
    event_types: tuple[str, ...],
) -> list[dict[str, Any]]:
    accepted = set(event_types)
    return [
        context
        for context in contexts
        if _entry_permit_id(context) == permit_id
        and context["entry"].get("event_type") in accepted
    ]


def _verify_closure_digest_reference(
    *,
    closure_payload: dict[str, Any],
    contexts: list[dict[str, Any]],
    permit_id: str,
    field: str,
    event_types: tuple[str, ...],
) -> int | None:
    closure_status = str(closure_payload.get("closure_status") or "").strip().lower()
    if closure_status == CLOSURE_STATUS_MISSING_CLOSURE:
        return None

    closure_digest = _digest_value(closure_payload.get(field))
    if closure_digest is None:
        if closure_status == CLOSURE_STATUS_CLOSED:
            return _walk_fail(
                WALK_CLOSURE_DIGEST_MISSING,
                f"permit_id={permit_id} closure_status=closed missing {field}",
            )
        return None

    candidates = _digest_candidates(
        contexts,
        permit_id=permit_id,
        event_types=event_types,
    )
    if not candidates:
        return _walk_fail(
            WALK_CLOSURE_DIGEST_MISSING,
            (
                f"permit_id={permit_id} missing "
                f"{'/'.join(event_types)} evidence for {field}"
            ),
        )

    candidate_values = [
        _digest_value(_entry_payload(context["entry"]).get(field))
        for context in candidates
    ]
    present_values = [value for value in candidate_values if value is not None]
    if not present_values:
        return _walk_fail(
            WALK_CLOSURE_DIGEST_MISSING,
            (
                f"permit_id={permit_id} {'/'.join(event_types)} evidence "
                f"missing {field}"
            ),
        )
    if closure_digest not in present_values:
        return _walk_fail(
            WALK_CLOSURE_DIGEST_MISMATCH,
            (
                f"permit_id={permit_id} {field} mismatch "
                f"closure={closure_digest} events={present_values}"
            ),
        )
    return None


def _verify_closure_dispatch_digest_reference(
    *,
    closure_payload: dict[str, Any],
    closure_context: dict[str, Any],
    permit_id: str,
) -> int | None:
    closure_status = str(closure_payload.get("closure_status") or "").strip().lower()
    if closure_status == CLOSURE_STATUS_MISSING_CLOSURE:
        return None

    closure_digest = _digest_value(
        closure_payload.get("dispatch_request_digest_v1")
    )
    if closure_digest is None:
        if closure_status == CLOSURE_STATUS_CLOSED:
            return _walk_fail(
                WALK_CLOSURE_DIGEST_MISSING,
                (
                    f"permit_id={permit_id} closure_status=closed missing "
                    "dispatch_request_digest_v1"
                ),
            )
        print(
            "WARNING: "
            f"permit_id={permit_id} closure_status={closure_status or 'unknown'} "
            "missing dispatch_request_digest_v1; abnormal closures should carry "
            "the dispatch-time request digest when dispatch occurred.",
            file=sys.stderr,
        )
        return None

    record_digest = _digest_value(
        closure_context.get("record_binding_request_hash")
    )
    if record_digest is None:
        return _walk_fail(
            WALK_CLOSURE_DIGEST_MISSING,
            (
                f"permit_id={permit_id} export permit missing binding_request_hash "
                "for dispatch_request_digest_v1"
            ),
        )
    if closure_digest != record_digest:
        return _walk_fail(
            WALK_CLOSURE_DISPATCH_DIGEST_MISMATCH,
            (
                "permit_id="
                f"{permit_id} dispatch_request_digest_v1 mismatch "
                f"closure={closure_digest} binding_request_hash={record_digest}"
            ),
        )
    return None


def _verify_closure_v1(
    *,
    closure_context: dict[str, Any],
    contexts: list[dict[str, Any]],
    args: argparse.Namespace,
) -> int | None:
    closure_entry = closure_context["entry"]
    closure_payload = _entry_payload(closure_entry)
    permit_id = closure_payload.get("permit_id")
    if not isinstance(permit_id, str) or not permit_id:
        return _walk_fail(
            WALK_CLOSURE_SIGNATURE_INVALID,
            f"event_id={_entry_id(closure_entry)} permit_id missing",
        )

    ok, reason = _verify_closure_v1_signature(payload=closure_payload, args=args)
    if not ok:
        return _walk_fail(
            WALK_CLOSURE_SIGNATURE_INVALID,
            f"permit_id={permit_id} event_id={_entry_id(closure_entry)} {reason}",
        )

    if closure_payload.get("provider_response_digest_semantics") not in {
        PROVIDER_RESPONSE_DIGEST_SEMANTICS,
        None,
    }:
        return _walk_fail(
            WALK_CLOSURE_DIGEST_MISMATCH,
            f"permit_id={permit_id} provider_response_digest_semantics mismatch",
        )
    if closure_payload.get("client_response_digest_semantics") not in {
        CLIENT_RESPONSE_DIGEST_SEMANTICS,
        None,
    }:
        return _walk_fail(
            WALK_CLOSURE_DIGEST_MISMATCH,
            f"permit_id={permit_id} client_response_digest_semantics mismatch",
        )

    for field, event_types in (
        (
            "provider_response_digest_v1",
            ("provider.response.received", "execution.completed"),
        ),
        (
            "client_response_digest_v1",
            ("client.response.delivered", "execution.completed"),
        ),
    ):
        failure = _verify_closure_digest_reference(
            closure_payload=closure_payload,
            contexts=contexts,
            permit_id=permit_id,
            field=field,
            event_types=event_types,
        )
        if failure is not None:
            return failure
    return None


def _verify_closure_v2(
    *,
    closure_context: dict[str, Any],
    contexts: list[dict[str, Any]],
    args: argparse.Namespace,
) -> int | None:
    closure_entry = closure_context["entry"]
    closure_payload = _entry_payload(closure_entry)
    permit_id = closure_payload.get("permit_id")
    if not isinstance(permit_id, str) or not permit_id:
        return _walk_fail(
            WALK_CLOSURE_SIGNATURE_INVALID,
            f"event_id={_entry_id(closure_entry)} permit_id missing",
        )

    ok, reason = _verify_closure_v2_signature(payload=closure_payload, args=args)
    if not ok:
        return _walk_fail(
            WALK_CLOSURE_SIGNATURE_INVALID,
            f"permit_id={permit_id} event_id={_entry_id(closure_entry)} {reason}",
        )

    if (
        closure_payload.get("dispatch_request_digest_semantics")
        != DISPATCH_REQUEST_DIGEST_SEMANTICS
    ):
        return _walk_fail(
            WALK_CLOSURE_DIGEST_MISMATCH,
            f"permit_id={permit_id} dispatch_request_digest_semantics mismatch",
        )
    if closure_payload.get("provider_response_digest_semantics") not in {
        PROVIDER_RESPONSE_DIGEST_SEMANTICS,
        None,
    }:
        return _walk_fail(
            WALK_CLOSURE_DIGEST_MISMATCH,
            f"permit_id={permit_id} provider_response_digest_semantics mismatch",
        )
    if closure_payload.get("client_response_digest_semantics") not in {
        CLIENT_RESPONSE_DIGEST_SEMANTICS,
        None,
    }:
        return _walk_fail(
            WALK_CLOSURE_DIGEST_MISMATCH,
            f"permit_id={permit_id} client_response_digest_semantics mismatch",
        )

    failure = _verify_closure_dispatch_digest_reference(
        closure_payload=closure_payload,
        closure_context=closure_context,
        permit_id=permit_id,
    )
    if failure is not None:
        return failure

    for field, event_types in (
        (
            "provider_response_digest_v1",
            ("provider.response.received", "execution.completed"),
        ),
        (
            "client_response_digest_v1",
            ("client.response.delivered", "execution.completed"),
        ),
    ):
        failure = _verify_closure_digest_reference(
            closure_payload=closure_payload,
            contexts=contexts,
            permit_id=permit_id,
            field=field,
            event_types=event_types,
        )
        if failure is not None:
            return failure
    return None


CLOSURE_FORMAT_VERIFIERS = {
    "closure_v1": _verify_closure_v1,
    "closure_v2": _verify_closure_v2,
}


def _verify_export_closures(export_data: bytes, args: argparse.Namespace) -> int:
    bundle, bundle_result = _load_audit_export_bundle_for_optional_check(
        export_data,
        label="VERIFY-CLOSURE",
    )
    if bundle_result is not None:
        return bundle_result
    assert bundle is not None

    contexts, flatten_result = _flatten_chain_entries(bundle)
    if flatten_result is not None:
        return flatten_result
    assert contexts is not None

    closures_checked = 0
    digest_checks = 0
    dispatch_digest_checks = 0
    dispatch_digest_warnings = 0
    chain_scopes: set[str] = set()
    for context in contexts:
        entry = context["entry"]
        if entry.get("event_type") != "permit.closed":
            continue
        payload = _entry_payload(entry)
        binding_version = payload.get("binding_version")
        verifier = CLOSURE_FORMAT_VERIFIERS.get(binding_version)
        if verifier is None:
            return _walk_fail(
                WALK_UNKNOWN_CLOSURE_FORMAT,
                (
                    f"event_id={_entry_id(entry)} "
                    f"permit_id={payload.get('permit_id')} "
                    f"binding_version={binding_version!r}"
                ),
            )
        failure = verifier(closure_context=context, contexts=contexts, args=args)
        if failure is not None:
            return failure
        closures_checked += 1
        chain_scopes.add(_scope_label(entry.get("chain_scope")))
        closure_status = str(payload.get("closure_status") or "").strip().lower()
        if closure_status != CLOSURE_STATUS_MISSING_CLOSURE:
            if _digest_value(payload.get("provider_response_digest_v1")) is not None:
                digest_checks += 1
            if _digest_value(payload.get("client_response_digest_v1")) is not None:
                digest_checks += 1
            if binding_version == "closure_v2":
                if _digest_value(payload.get("dispatch_request_digest_v1")) is not None:
                    dispatch_digest_checks += 1
                elif closure_status != CLOSURE_STATUS_CLOSED:
                    dispatch_digest_warnings += 1

    print("VERIFY-CLOSURE: VERIFIED")
    print(f"  chain_scopes:        {len(chain_scopes)}")
    print(f"  closures_verified:   {closures_checked}")
    print(f"  signature_checks:    {closures_checked} PASS")
    print(f"  digest_checks:       {digest_checks} PASS")
    if dispatch_digest_checks:
        print("  dispatch_digest_check: PASS")
    else:
        print("  dispatch_digest_check: SKIPPED")
    if dispatch_digest_warnings:
        print(f"  dispatch_digest_warnings: {dispatch_digest_warnings}")
    return 0


@dataclass(frozen=True)
class _WorkflowEvidenceIndex:
    declarations: dict[str, dict[str, Any]]
    amendments_by_declaration: dict[str, list[dict[str, Any]]]


def _workflow_fail(code: str, message: str) -> int:
    print(f"FAILED: {code}: {message}", file=sys.stderr)
    return 1


def _strip_none(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _strip_none(item)
            for key, item in value.items()
            if item is not None
        }
    if isinstance(value, list):
        return [_strip_none(item) for item in value]
    return value


def _canonical_workflow_json(value: Any) -> str:
    return json.dumps(
        _strip_none(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _normalize_sha256_hex(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.startswith("sha256:"):
        text = text.removeprefix("sha256:")
    return text or None


def _required_workflow_str(record: dict[str, Any], field: str) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def _optional_workflow_str(record: dict[str, Any], field: str) -> str | None:
    value = record.get(field)
    if value is None:
        return None
    if isinstance(value, str):
        return value
    raise ValueError(f"{field} must be a string or null")


def _optional_workflow_int(record: dict[str, Any], field: str) -> int | None:
    value = record.get(field)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer or null")
    if value < 0:
        raise ValueError(f"{field} must be non-negative")
    return value


def _required_workflow_int(record: dict[str, Any], field: str) -> int:
    value = _optional_workflow_int(record, field)
    if value is None:
        raise ValueError(f"{field} must be an integer")
    return value


def _workflow_declaration_id(record: dict[str, Any]) -> str:
    value = record.get("workflow_declaration_id", record.get("id"))
    if not isinstance(value, str) or not value.strip():
        raise ValueError("workflow_declaration_id must be a non-empty string")
    return value.strip()


def _workflow_amendment_id(record: dict[str, Any]) -> str:
    value = record.get("workflow_amendment_id", record.get("id"))
    if not isinstance(value, str) or not value.strip():
        raise ValueError("workflow_amendment_id must be a non-empty string")
    return value.strip()


def _workflow_project_id(record: dict[str, Any]) -> str:
    return _required_workflow_str(record, "project_id")


def _workflow_datetime_sort_key(record: dict[str, Any], field: str) -> datetime:
    parsed = _parse_iso_or_none(record.get(field))
    if parsed is None:
        raise ValueError(f"{field} must be an ISO-8601 timestamp")
    return parsed


def _workflow_issued_at_candidates(value: Any) -> list[str]:
    candidates: list[str] = []
    if isinstance(value, str) and value.strip():
        candidates.append(value.strip())
    parsed = _parse_iso_or_none(value)
    if parsed is not None:
        normalized = parsed.astimezone(timezone.utc).isoformat()
        if normalized not in candidates:
            candidates.append(normalized)
    return candidates


def _workflow_principal_payload(
    record: dict[str, Any],
    *,
    object_field: str,
    api_key_field: str,
    dashboard_session_field: str,
) -> dict[str, Any]:
    principal = record.get(object_field)
    if isinstance(principal, dict):
        principal_type = principal.get("type")
        principal_id = principal.get("id")
        if principal_type == "api_key" and isinstance(principal_id, str):
            return {"api_key_id": principal_id}
        if principal_type == "dashboard_session" and isinstance(principal_id, str):
            return {"dashboard_session_id": principal_id}

    return _strip_none(
        {
            "api_key_id": record.get(api_key_field),
            "dashboard_session_id": record.get(dashboard_session_field),
        }
    )


def _workflow_declaration_intent(record: dict[str, Any]) -> dict[str, Any]:
    for field in ("intent_json", "intent"):
        value = record.get(field)
        if isinstance(value, dict):
            return _strip_none(dict(value))

    intent = _strip_none(
        {
            "expected_calls": record.get("expected_calls"),
            "max_calls": record.get("max_calls"),
            "expected_model": record.get("expected_model"),
            "expected_input_tokens_per_call": record.get(
                "expected_input_tokens_per_call"
            ),
            "expected_output_tokens_per_call": record.get(
                "expected_output_tokens_per_call"
            ),
            "max_duration_seconds": record.get("max_duration_seconds"),
        }
    )
    if not isinstance(intent, dict):
        raise ValueError("workflow intent must be an object")
    return intent


def _validate_workflow_intent(intent: dict[str, Any]) -> None:
    expected_calls = intent.get("expected_calls")
    max_calls = intent.get("max_calls")
    for field, value in (
        ("expected_calls", expected_calls),
        ("max_calls", max_calls),
        ("expected_input_tokens_per_call", intent.get("expected_input_tokens_per_call")),
        ("expected_output_tokens_per_call", intent.get("expected_output_tokens_per_call")),
        ("max_duration_seconds", intent.get("max_duration_seconds")),
    ):
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"intent.{field} must be a non-negative integer")
    if expected_calls is None and max_calls is None:
        raise ValueError("intent requires expected_calls or max_calls")
    if expected_calls is not None and max_calls is not None and expected_calls > max_calls:
        raise ValueError("intent.expected_calls must be <= intent.max_calls")
    expected_model = intent.get("expected_model")
    if expected_model is not None and not isinstance(expected_model, str):
        raise ValueError("intent.expected_model must be a string or null")


def _workflow_projected_cost(record: dict[str, Any]) -> dict[str, Any]:
    projected = record.get("projected_cost")
    if isinstance(projected, dict):
        return _strip_none(dict(projected))
    return _strip_none(
        {
            "amount_micros": record.get("projection_amount_micros"),
            "currency": record.get("projection_currency", "USD"),
            "methodology": record.get("projection_methodology"),
        }
    )


def _workflow_declaration_payload_candidates(
    record: dict[str, Any],
    *,
    binding_key_id: str,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    signed_payload = record.get("signed_payload")
    if isinstance(signed_payload, dict):
        payload = dict(signed_payload)
        payload.setdefault("binding_key_id", binding_key_id)
        candidates.append(payload)

    intent = _workflow_declaration_intent(record)
    declared_by = _workflow_principal_payload(
        record,
        object_field="declared_by",
        api_key_field="declared_by_api_key_id",
        dashboard_session_field="declared_by_dashboard_session_id",
    )
    issued_at_values = _workflow_issued_at_candidates(
        record.get("declaration_signed_at")
        or record.get("declared_at")
        or record.get("created_at")
    )
    for issued_at in issued_at_values:
        candidates.append(
            {
                "binding_version": WORKFLOW_DECLARATION_BINDING_VERSION,
                "project_id": _workflow_project_id(record),
                "workflow_id": _required_workflow_str(record, "workflow_id"),
                "intent": intent,
                "budget_envelope_id": record.get("budget_envelope_id"),
                "declared_by": declared_by,
                "projected_cost": _workflow_projected_cost(record),
                "status": _required_workflow_str(record, "status"),
                "issued_at": issued_at,
                "binding_key_id": binding_key_id,
            }
        )
    return candidates


def _workflow_amendment_delta(record: dict[str, Any]) -> dict[str, Any]:
    delta = record.get("delta")
    if isinstance(delta, dict):
        return _strip_none(dict(delta))
    return _strip_none(
        {
            "applied_against_version": record.get("applied_against_version"),
            "previous_max_calls": record.get("previous_max_calls"),
            "new_max_calls": record.get("new_max_calls"),
            "previous_expected_calls": record.get("previous_expected_calls"),
            "new_expected_calls": record.get("new_expected_calls"),
            "reason_provided": record.get("reason_provided"),
        }
    )


def _workflow_amendment_payload_candidates(
    record: dict[str, Any],
    *,
    binding_key_id: str,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    signed_payload = record.get("signed_payload")
    if isinstance(signed_payload, dict):
        payload = dict(signed_payload)
        payload.setdefault("binding_key_id", binding_key_id)
        candidates.append(payload)

    amendment_id = _workflow_amendment_id(record)
    declaration_id = _workflow_declaration_id(record)
    project_id = _workflow_project_id(record)
    delta = _workflow_amendment_delta(record)
    amended_by = _workflow_principal_payload(
        record,
        object_field="amended_by",
        api_key_field="amended_by_api_key_id",
        dashboard_session_field="amended_by_dashboard_session_id",
    )
    issued_at_values = _workflow_issued_at_candidates(
        record.get("amendment_signed_at") or record.get("created_at")
    )
    for issued_at in issued_at_values:
        base = {
            "binding_version": WORKFLOW_AMENDMENT_BINDING_VERSION,
            "project_id": project_id,
            "workflow_declaration_id": declaration_id,
            "amended_by": amended_by,
            "issued_at": issued_at,
            "binding_key_id": binding_key_id,
        }
        candidates.append({**base, "delta": delta})
        candidates.append({**base, "workflow_amendment_id": amendment_id, "delta": delta})
        candidates.append({**base, **delta})
        candidates.append({**base, "workflow_amendment_id": amendment_id, **delta})
    return candidates


def _verify_workflow_signed_record(
    *,
    record: dict[str, Any],
    canonical_hash_field: str,
    signature_field: str,
    signing_time_field: str,
    args: argparse.Namespace,
    payload_candidates,
    record_label: str,
) -> int | None:
    canonical_hash = _normalize_sha256_hex(record.get(canonical_hash_field))
    signature = record.get(signature_field)
    if canonical_hash is None:
        return _workflow_fail(
            WORKFLOW_SIGNATURE_INVALID,
            f"{record_label} missing {canonical_hash_field}",
        )
    if not isinstance(signature, str) or not signature.strip():
        return _workflow_fail(
            WORKFLOW_SIGNATURE_INVALID,
            f"{record_label} missing {signature_field}",
        )

    artifact_key_id = (
        record.get("binding_key_id")
        if isinstance(record.get("binding_key_id"), str)
        else record.get("key_id")
        if isinstance(record.get("key_id"), str)
        else None
    )
    signing_time = _parse_iso_or_none(record.get(signing_time_field))
    trusted_pub, trust_source, err = _resolve_trust_key(
        artifact_pub=None,
        artifact_key_id=artifact_key_id,
        purpose=PERMIT_BINDING_SIGNING_PURPOSE,
        expected_public_key=None,
        public_key_url=None,
        key_manifest_source=_key_manifest_source_for_args(args),
        signing_time=signing_time,
    )
    if err is not None or trusted_pub is None:
        return _workflow_fail(
            WORKFLOW_SIGNATURE_INVALID,
            f"{record_label} {err}",
        )

    try:
        binding_key_id = _binding_key_id_from_public_key(trusted_pub)
    except Exception as exc:
        return _workflow_fail(
            WORKFLOW_SIGNATURE_INVALID,
            f"{record_label} invalid permit-binding public key: {exc}",
        )
    if artifact_key_id is not None and artifact_key_id != binding_key_id:
        return _workflow_fail(
            WORKFLOW_SIGNATURE_INVALID,
            (
                f"{record_label} binding_key_id mismatch "
                f"expected={artifact_key_id} actual={binding_key_id}"
            ),
        )

    candidates = payload_candidates(record, binding_key_id=binding_key_id)
    recomputed_hashes = [
        _compute_canonical_binding_hash(candidate) for candidate in candidates
    ]
    if canonical_hash not in recomputed_hashes:
        return _workflow_fail(
            WORKFLOW_SIGNATURE_INVALID,
            (
                f"{record_label} canonical_hash mismatch "
                f"actual={canonical_hash}"
            ),
        )

    if not _verify_ed25519(trusted_pub, canonical_hash.encode("utf-8"), signature):
        return _workflow_fail(
            WORKFLOW_SIGNATURE_INVALID,
            f"{record_label} Ed25519 signature invalid ({trust_source})",
        )
    return None


def _validate_workflow_declaration_record(
    record: dict[str, Any],
    *,
    require_effective_hash: bool,
) -> None:
    _required_workflow_str(record, "workflow_id")
    _workflow_declaration_id(record)
    _workflow_project_id(record)
    status = _required_workflow_str(record, "status")
    if status not in {"active", "completed", "expired", "rejected"}:
        raise ValueError("status must be active, completed, expired, or rejected")
    intent = _workflow_declaration_intent(record)
    _validate_workflow_intent(intent)
    _required_workflow_int(record, "version")
    _optional_workflow_int(record, "cached_actual_calls")
    _optional_workflow_int(record, "projection_amount_micros")
    _optional_workflow_str(record, "declaration_canonical_hash")
    _optional_workflow_str(record, "declaration_signature_b64")
    if _parse_iso_or_none(record.get("declaration_signed_at")) is None:
        raise ValueError("declaration_signed_at must be an ISO-8601 timestamp")
    if require_effective_hash and _normalize_sha256_hex(record.get("effective_intent_hash")) is None:
        raise ValueError("effective_intent_hash must be a non-empty string")


def _validate_workflow_amendment_record(record: dict[str, Any]) -> None:
    _workflow_amendment_id(record)
    _workflow_declaration_id(record)
    _workflow_project_id(record)
    _required_workflow_int(record, "applied_against_version")
    _optional_workflow_int(record, "previous_max_calls")
    _optional_workflow_int(record, "new_max_calls")
    _optional_workflow_int(record, "previous_expected_calls")
    _optional_workflow_int(record, "new_expected_calls")
    reason = record.get("reason_provided")
    if reason is not None and not isinstance(reason, str):
        raise ValueError("reason_provided must be a string or null")
    if _parse_iso_or_none(record.get("created_at")) is None:
        raise ValueError("created_at must be an ISO-8601 timestamp")
    _optional_workflow_str(record, "amendment_canonical_hash")
    _optional_workflow_str(record, "amendment_signature_b64")


def _compute_effective_intent_hash_from_records(
    declaration: dict[str, Any],
    amendments: list[dict[str, Any]],
    *,
    before_created_at: datetime | None = None,
) -> str:
    selected: list[dict[str, Any]] = []
    for amendment in amendments:
        created_at = _workflow_datetime_sort_key(amendment, "created_at")
        if before_created_at is not None and created_at >= before_created_at:
            continue
        selected.append(amendment)

    selected.sort(
        key=lambda item: (
            _workflow_datetime_sort_key(item, "created_at"),
            _workflow_amendment_id(item),
        )
    )
    hasher = hashlib.sha256()
    hasher.update(
        _canonical_workflow_json(_workflow_declaration_intent(declaration)).encode(
            "utf-8"
        )
    )
    for amendment in selected:
        hasher.update(
            _canonical_workflow_json(_workflow_amendment_delta(amendment)).encode(
                "utf-8"
            )
        )
    return hasher.hexdigest()


def _verify_workflow_amendment_chains(
    declarations: dict[str, dict[str, Any]],
    amendments_by_declaration: dict[str, list[dict[str, Any]]],
) -> int | None:
    for declaration_id, amendments in sorted(amendments_by_declaration.items()):
        if declaration_id not in declarations:
            return _workflow_fail(
                WORKFLOW_AMENDMENT_ORDER_INVALID,
                f"workflow_declaration_id={declaration_id} has no declaration record",
            )
        previous_sort_key: tuple[datetime, str] | None = None
        expected_version = 1
        for amendment in amendments:
            amendment_id = _workflow_amendment_id(amendment)
            sort_key = (
                _workflow_datetime_sort_key(amendment, "created_at"),
                amendment_id,
            )
            if previous_sort_key is not None and sort_key < previous_sort_key:
                return _workflow_fail(
                    WORKFLOW_AMENDMENT_ORDER_INVALID,
                    (
                        f"workflow_declaration_id={declaration_id} "
                        f"workflow_amendment_id={amendment_id} is out of order"
                    ),
                )
            applied_against_version = _required_workflow_int(
                amendment,
                "applied_against_version",
            )
            if applied_against_version != expected_version:
                return _workflow_fail(
                    WORKFLOW_AMENDMENT_ORDER_INVALID,
                    (
                        f"workflow_declaration_id={declaration_id} "
                        f"workflow_amendment_id={amendment_id} "
                        f"expected_applied_against_version={expected_version} "
                        f"actual={applied_against_version}"
                    ),
                )
            previous_sort_key = sort_key
            expected_version += 1

        declaration_version = _required_workflow_int(
            declarations[declaration_id],
            "version",
        )
        if declaration_version != expected_version:
            return _workflow_fail(
                WORKFLOW_AMENDMENT_ORDER_INVALID,
                (
                    f"workflow_declaration_id={declaration_id} "
                    f"declaration version={declaration_version} does not match "
                    f"amendment history version={expected_version}"
                ),
            )
    return None


def _verify_workflow_effective_hashes(
    declarations: dict[str, dict[str, Any]],
    amendments_by_declaration: dict[str, list[dict[str, Any]]],
) -> int | None:
    for declaration_id, declaration in sorted(declarations.items()):
        expected = _compute_effective_intent_hash_from_records(
            declaration,
            amendments_by_declaration.get(declaration_id, []),
        )
        actual = _normalize_sha256_hex(declaration.get("effective_intent_hash"))
        if actual is None:
            continue
        if actual != expected:
            return _workflow_fail(
                WORKFLOW_EFFECTIVE_INTENT_HASH_MISMATCH,
                (
                    f"workflow_declaration_id={declaration_id} "
                    f"expected={expected} actual={actual}"
                ),
            )
    return None


def _verify_workflow_records(
    *,
    declarations: list[dict[str, Any]],
    amendments: list[dict[str, Any]],
    args: argparse.Namespace,
    require_declaration_effective_hash: bool,
) -> tuple[_WorkflowEvidenceIndex | None, int | None]:
    declarations_by_id: dict[str, dict[str, Any]] = {}
    amendments_by_declaration: dict[str, list[dict[str, Any]]] = {}

    for index, declaration in enumerate(declarations):
        if not isinstance(declaration, dict):
            return None, _workflow_fail(
                WORKFLOW_EVIDENCE_SCHEMA_INVALID,
                f"declarations[{index}] must be an object",
            )
        try:
            _validate_workflow_declaration_record(
                declaration,
                require_effective_hash=require_declaration_effective_hash,
            )
            declaration_id = _workflow_declaration_id(declaration)
        except ValueError as exc:
            return None, _workflow_fail(
                WORKFLOW_EVIDENCE_SCHEMA_INVALID,
                f"declarations[{index}] {exc}",
            )
        if declaration_id in declarations_by_id:
            return None, _workflow_fail(
                WORKFLOW_EVIDENCE_SCHEMA_INVALID,
                f"duplicate workflow_declaration_id={declaration_id}",
            )
        failure = _verify_workflow_signed_record(
            record=declaration,
            canonical_hash_field="declaration_canonical_hash",
            signature_field="declaration_signature_b64",
            signing_time_field="declaration_signed_at",
            args=args,
            payload_candidates=_workflow_declaration_payload_candidates,
            record_label=f"workflow_declaration_id={declaration_id}",
        )
        if failure is not None:
            return None, failure
        declarations_by_id[declaration_id] = declaration

    for index, amendment in enumerate(amendments):
        if not isinstance(amendment, dict):
            return None, _workflow_fail(
                WORKFLOW_EVIDENCE_SCHEMA_INVALID,
                f"amendments[{index}] must be an object",
            )
        try:
            _validate_workflow_amendment_record(amendment)
            declaration_id = _workflow_declaration_id(amendment)
            amendment_id = _workflow_amendment_id(amendment)
        except ValueError as exc:
            return None, _workflow_fail(
                WORKFLOW_EVIDENCE_SCHEMA_INVALID,
                f"amendments[{index}] {exc}",
            )
        failure = _verify_workflow_signed_record(
            record=amendment,
            canonical_hash_field="amendment_canonical_hash",
            signature_field="amendment_signature_b64",
            signing_time_field="created_at",
            args=args,
            payload_candidates=_workflow_amendment_payload_candidates,
            record_label=f"workflow_amendment_id={amendment_id}",
        )
        if failure is not None:
            return None, failure
        amendments_by_declaration.setdefault(declaration_id, []).append(amendment)

    chain_failure = _verify_workflow_amendment_chains(
        declarations_by_id,
        amendments_by_declaration,
    )
    if chain_failure is not None:
        return None, chain_failure
    hash_failure = _verify_workflow_effective_hashes(
        declarations_by_id,
        amendments_by_declaration,
    )
    if hash_failure is not None:
        return None, hash_failure

    return (
        _WorkflowEvidenceIndex(
            declarations=declarations_by_id,
            amendments_by_declaration=amendments_by_declaration,
        ),
        None,
    )


def _verify_workflow_evidence_document(
    document: dict[str, Any],
    *,
    args: argparse.Namespace,
    label: str,
) -> tuple[_WorkflowEvidenceIndex | None, int | None]:
    if document.get("schema") != VANTA_WORKFLOW_EVIDENCE_SCHEMA:
        return None, _workflow_fail(
            WORKFLOW_EVIDENCE_SCHEMA_INVALID,
            f"{label} schema must be {VANTA_WORKFLOW_EVIDENCE_SCHEMA!r}",
        )
    declarations = document.get("declarations")
    amendments = document.get("amendments")
    if not isinstance(declarations, list):
        return None, _workflow_fail(
            WORKFLOW_EVIDENCE_SCHEMA_INVALID,
            f"{label} declarations must be a list",
        )
    if not isinstance(amendments, list):
        return None, _workflow_fail(
            WORKFLOW_EVIDENCE_SCHEMA_INVALID,
            f"{label} amendments must be a list",
        )
    if document.get("declaration_count") != len(declarations):
        return None, _workflow_fail(
            WORKFLOW_EVIDENCE_SCHEMA_INVALID,
            (
                f"{label} declaration_count={document.get('declaration_count')} "
                f"does not match declarations length={len(declarations)}"
            ),
        )
    if document.get("amendment_count") != len(amendments):
        return None, _workflow_fail(
            WORKFLOW_EVIDENCE_SCHEMA_INVALID,
            (
                f"{label} amendment_count={document.get('amendment_count')} "
                f"does not match amendments length={len(amendments)}"
            ),
        )
    index, failure = _verify_workflow_records(
        declarations=declarations,
        amendments=amendments,
        args=args,
        require_declaration_effective_hash=True,
    )
    if failure is not None:
        return None, failure
    assert index is not None
    print(f"{label}: VERIFIED")
    print(f"  declarations_verified: {len(declarations)}")
    print(f"  amendments_verified:   {len(amendments)}")
    return index, None


def _extract_permit_workflow_snapshot(record: dict[str, Any]) -> dict[str, Any] | None:
    for key in ("workflow_state_json", "workflow_state"):
        value = record.get(key)
        if isinstance(value, dict):
            return value
    permit = record.get("permit")
    if isinstance(permit, dict):
        for key in ("workflow_state_json", "workflow_state"):
            value = permit.get(key)
            if isinstance(value, dict):
                return value
    return None


def _permit_created_at(record: dict[str, Any]) -> datetime | None:
    for key in ("created_at", "timestamp", "permit_created_at"):
        parsed = _parse_iso_or_none(record.get(key))
        if parsed is not None:
            return parsed
    permit = record.get("permit")
    if isinstance(permit, dict):
        for key in ("created_at", "timestamp", "permit_created_at"):
            parsed = _parse_iso_or_none(permit.get(key))
            if parsed is not None:
                return parsed
    return None


def _verify_permit_workflow_snapshots(
    permit_records: list[dict[str, Any]],
    index: _WorkflowEvidenceIndex,
    *,
    label: str,
) -> int | None:
    checked = 0
    for record_index, record in enumerate(permit_records):
        if not isinstance(record, dict):
            return _workflow_fail(
                WORKFLOW_EVIDENCE_SCHEMA_INVALID,
                f"{label} permit_records[{record_index}] must be an object",
            )
        snapshot = _extract_permit_workflow_snapshot(record)
        if snapshot is None:
            continue
        declaration_id = snapshot.get("workflow_declaration_id") or record.get(
            "workflow_declaration_id"
        )
        if not isinstance(declaration_id, str) or not declaration_id.strip():
            if snapshot.get("admission_state") == "unknown_or_inactive":
                continue
            return _workflow_fail(
                WORKFLOW_EFFECTIVE_INTENT_HASH_MISMATCH,
                f"{label} permit_records[{record_index}] missing workflow_declaration_id",
            )
        declaration_id = declaration_id.strip()
        declaration = index.declarations.get(declaration_id)
        if declaration is None:
            return _workflow_fail(
                WORKFLOW_EFFECTIVE_INTENT_HASH_MISMATCH,
                (
                    f"{label} permit_records[{record_index}] "
                    f"workflow_declaration_id={declaration_id} missing declaration"
                ),
            )
        created_at = _permit_created_at(record)
        if created_at is None:
            return _workflow_fail(
                WORKFLOW_EFFECTIVE_INTENT_HASH_MISMATCH,
                f"{label} permit_records[{record_index}] missing permit created_at",
            )
        expected_hash = _compute_effective_intent_hash_from_records(
            declaration,
            index.amendments_by_declaration.get(declaration_id, []),
            before_created_at=created_at,
        )
        actual_hash = _normalize_sha256_hex(snapshot.get("effective_intent_hash"))
        if actual_hash != expected_hash:
            return _workflow_fail(
                WORKFLOW_EFFECTIVE_INTENT_HASH_MISMATCH,
                (
                    f"{label} permit_records[{record_index}] "
                    f"workflow_declaration_id={declaration_id} "
                    f"expected={expected_hash} actual={actual_hash}"
                ),
            )
        expected_version = (
            len(
                [
                    amendment
                    for amendment in index.amendments_by_declaration.get(
                        declaration_id,
                        [],
                    )
                    if _workflow_datetime_sort_key(amendment, "created_at")
                    < created_at
                ]
            )
            + 1
        )
        snapshot_version = snapshot.get("declaration_version_at_decision")
        if snapshot_version != expected_version:
            return _workflow_fail(
                WORKFLOW_EFFECTIVE_INTENT_HASH_MISMATCH,
                (
                    f"{label} permit_records[{record_index}] "
                    f"workflow_declaration_id={declaration_id} "
                    f"expected_version={expected_version} actual={snapshot_version}"
                ),
            )
        checked += 1
    if checked:
        print(f"{label}: workflow_state_json checks: {checked} PASS")
    return None


def _json_document_or_none(data: bytes) -> dict[str, Any] | None:
    try:
        value = json.loads(data.decode("utf-8"))
    except Exception:
        return None
    return value if isinstance(value, dict) else None


def _resolve_sibling_path(
    *,
    manifest: dict[str, Any],
    manifest_path: Path,
    export_path: Path,
    sibling: dict[str, Any],
) -> Path | None:
    descriptor = sibling.get("workflow_evidence")
    file_name = "workflow_evidence.json"
    if isinstance(descriptor, dict) and isinstance(descriptor.get("file_name"), str):
        file_name = descriptor["file_name"]

    candidates: list[Path] = []
    explicit = sibling.get("workflow_evidence_file")
    if isinstance(explicit, str) and explicit:
        explicit_path = Path(explicit)
        candidates.append(explicit_path)
        if not explicit_path.is_absolute():
            candidates.append(manifest_path.parent / explicit_path)

    bundle_dir = sibling.get("bundle_dir")
    if isinstance(bundle_dir, str) and bundle_dir:
        bundle_path = Path(bundle_dir)
        candidates.append(bundle_path / file_name)
        if not bundle_path.is_absolute():
            candidates.append(manifest_path.parent / bundle_path / file_name)

    export_id = manifest.get("export_id")
    candidates.extend(
        [
            manifest_path.parent / file_name,
            export_path.parent / file_name,
        ]
    )
    if isinstance(export_id, str) and export_id:
        candidates.extend(
            [
                manifest_path.parent / export_id / file_name,
                export_path.parent / export_id / file_name,
            ]
        )

    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.expanduser()
        if resolved in seen:
            continue
        seen.add(resolved)
        if resolved.exists():
            return resolved
    return None


def _verify_signed_workflow_sibling(
    *,
    workflow_path: Path,
    descriptor: dict[str, Any],
    args: argparse.Namespace,
) -> tuple[dict[str, Any] | None, int | None]:
    workflow_data = workflow_path.read_bytes()
    expected_hash = descriptor.get("content_hash")
    actual_hash = _content_hash(workflow_data)
    if expected_hash != actual_hash:
        return None, _workflow_fail(
            WORKFLOW_EVIDENCE_SCHEMA_INVALID,
            (
                f"workflow_evidence content_hash mismatch "
                f"expected={expected_hash} actual={actual_hash}"
            ),
        )
    signature = descriptor.get("signature")
    if not isinstance(signature, str) or not signature.strip():
        return None, _workflow_fail(
            WORKFLOW_SIGNATURE_INVALID,
            "workflow_evidence sibling manifest is unsigned",
        )
    embedded_pub = descriptor.get("public_key")
    artifact_key_id = (
        descriptor.get("key_id") if isinstance(descriptor.get("key_id"), str) else None
    )
    signing_time = _parse_iso_or_none(descriptor.get("signed_at"))
    trusted_pub, _trust_source, err = _resolve_trust_key(
        artifact_pub=embedded_pub if isinstance(embedded_pub, str) else None,
        artifact_key_id=artifact_key_id,
        purpose="export_signing",
        expected_public_key=getattr(args, "expected_public_key", None),
        public_key_url=None,
        key_manifest_source=_key_manifest_source_for_args(args),
        signing_time=signing_time,
    )
    if err is not None or trusted_pub is None:
        return None, _workflow_fail(WORKFLOW_SIGNATURE_INVALID, str(err))
    if isinstance(embedded_pub, str) and embedded_pub != trusted_pub:
        return None, _workflow_fail(
            WORKFLOW_SIGNATURE_INVALID,
            "workflow_evidence public_key does not match trusted key",
        )
    if not _verify_ed25519(trusted_pub, actual_hash.encode("utf-8"), signature):
        return None, _workflow_fail(
            WORKFLOW_SIGNATURE_INVALID,
            "workflow_evidence sibling signature invalid",
        )
    document = _json_document_or_none(workflow_data)
    if document is None:
        return None, _workflow_fail(
            WORKFLOW_EVIDENCE_SCHEMA_INVALID,
            "workflow_evidence sibling is not a JSON object",
        )
    return document, None


def _verify_vanta_workflow_extension(
    *,
    export_document: dict[str, Any] | None,
    export_path: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
    args: argparse.Namespace,
) -> int | None:
    sibling_artifacts = manifest.get("sibling_artifacts")
    if not isinstance(sibling_artifacts, dict):
        return None
    sibling = sibling_artifacts.get("workflow_evidence")
    if not isinstance(sibling, dict):
        return None
    if sibling.get("schema") != VANTA_WORKFLOW_EVIDENCE_SCHEMA:
        return _workflow_fail(
            WORKFLOW_EVIDENCE_SCHEMA_INVALID,
            "workflow_evidence sibling schema is invalid",
        )
    descriptor = sibling.get("workflow_evidence")
    if not isinstance(descriptor, dict):
        return _workflow_fail(
            WORKFLOW_EVIDENCE_SCHEMA_INVALID,
            "workflow_evidence sibling descriptor missing",
        )
    workflow_path = _resolve_sibling_path(
        manifest=manifest,
        manifest_path=manifest_path,
        export_path=export_path,
        sibling=sibling,
    )
    if workflow_path is None:
        return _workflow_fail(
            WORKFLOW_EVIDENCE_SCHEMA_INVALID,
            "workflow_evidence file could not be found next to export/manifest",
        )
    workflow_document, failure = _verify_signed_workflow_sibling(
        workflow_path=workflow_path,
        descriptor=descriptor,
        args=args,
    )
    if failure is not None:
        return failure
    assert workflow_document is not None
    index, failure = _verify_workflow_evidence_document(
        workflow_document,
        args=args,
        label="WORKFLOW-EVIDENCE",
    )
    if failure is not None:
        return failure
    assert index is not None
    if isinstance(export_document, dict) and isinstance(export_document.get("records"), list):
        snapshot_failure = _verify_permit_workflow_snapshots(
            export_document["records"],
            index,
            label="WORKFLOW-EVIDENCE",
        )
        if snapshot_failure is not None:
            return snapshot_failure
    return None


def _read_jsonl_from_zip(
    zip_file: zipfile.ZipFile,
    name: str,
) -> list[dict[str, Any]]:
    raw = zip_file.read(name).decode("utf-8")
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{name}:{line_number} must be a JSON object")
        records.append(value)
    return records


def _incident_manifest_from_zip(zip_file: zipfile.ZipFile) -> dict[str, Any] | None:
    for name in ("manifest.json", "bundle_manifest.json"):
        if name not in zip_file.namelist():
            continue
        value = json.loads(zip_file.read(name).decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"{name} must be a JSON object")
        return value
    return None


def _manifest_file_schemas(bundle_manifest: dict[str, Any]) -> dict[str, str | None]:
    files = bundle_manifest.get("files")
    if not isinstance(files, list):
        raise ValueError("files must be a list")
    schemas: dict[str, str | None] = {}
    for index, entry in enumerate(files):
        if not isinstance(entry, dict):
            raise ValueError(f"files[{index}] must be an object")
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"files[{index}].name must be a non-empty string")
        schema = entry.get("schema")
        if schema is not None and not isinstance(schema, str):
            raise ValueError(f"files[{index}].schema must be a string or null")
        schemas[name] = schema
    return schemas


def _verify_incident_bundle(
    *,
    export_path: Path,
    manifest: dict[str, Any],
    args: argparse.Namespace,
) -> int | None:
    if not zipfile.is_zipfile(export_path):
        if manifest.get("export_type") == "incident_evidence":
            return _workflow_fail(
                INCIDENT_MANIFEST_SCHEMA_INVALID,
                "incident_evidence export payload must be a zip bundle",
            )
        return None

    with zipfile.ZipFile(export_path) as zip_file:
        try:
            bundle_manifest = (
                manifest
                if "manifest_version" in manifest
                else _incident_manifest_from_zip(zip_file)
            )
        except Exception as exc:
            return _workflow_fail(
                INCIDENT_MANIFEST_SCHEMA_INVALID,
                f"could not read incident bundle manifest: {exc}",
            )
        if bundle_manifest is None:
            return None

        manifest_version = bundle_manifest.get("manifest_version")
        if manifest_version == 1:
            return None
        if manifest_version != 2:
            return _workflow_fail(
                INCIDENT_UNKNOWN_MANIFEST_VERSION,
                f"unsupported incident bundle manifest_version={manifest_version!r}",
            )

        try:
            schemas = _manifest_file_schemas(bundle_manifest)
        except ValueError as exc:
            return _workflow_fail(INCIDENT_MANIFEST_SCHEMA_INVALID, str(exc))

        for name, schema in INCIDENT_V2_REQUIRED_FILES.items():
            if schemas.get(name) != schema:
                return _workflow_fail(
                    INCIDENT_MANIFEST_SCHEMA_INVALID,
                    f"{name} manifest schema must be {schema!r}",
                )
            if name not in zip_file.namelist():
                return _workflow_fail(
                    INCIDENT_MANIFEST_SCHEMA_INVALID,
                    f"{name} listed in manifest but missing from zip",
                )
        if "permits.jsonl" not in schemas or "permits.jsonl" not in zip_file.namelist():
            return _workflow_fail(
                INCIDENT_MANIFEST_SCHEMA_INVALID,
                "manifest_version=2 requires permits.jsonl",
            )

        try:
            metadata = json.loads(zip_file.read("incident_metadata.json").decode("utf-8"))
            if not isinstance(metadata, dict):
                raise ValueError("incident_metadata.json must be an object")
            if metadata.get("schema") != "keel.incident_evidence/v1":
                raise ValueError(
                    "incident_metadata.json schema must be keel.incident_evidence/v1"
                )
            declarations = _read_jsonl_from_zip(
                zip_file,
                "workflow_declarations.jsonl",
            )
            amendments = _read_jsonl_from_zip(zip_file, "workflow_amendments.jsonl")
            permits = _read_jsonl_from_zip(zip_file, "permits.jsonl")
            _read_jsonl_from_zip(zip_file, "mcp_tool_decisions.jsonl")
        except Exception as exc:
            return _workflow_fail(
                INCIDENT_MANIFEST_SCHEMA_INVALID,
                f"could not read incident bundle jsonl: {exc}",
            )

    index, failure = _verify_workflow_records(
        declarations=declarations,
        amendments=amendments,
        args=args,
        require_declaration_effective_hash=False,
    )
    if failure is not None:
        return failure
    assert index is not None
    snapshot_failure = _verify_permit_workflow_snapshots(
        permits,
        index,
        label="INCIDENT-BUNDLE",
    )
    if snapshot_failure is not None:
        return snapshot_failure
    print("INCIDENT-BUNDLE: VERIFIED")
    print("  manifest_version:    2")
    print(f"  declarations_verified: {len(declarations)}")
    print(f"  amendments_verified:   {len(amendments)}")
    return None


def _verify_export_workflow_extensions(
    *,
    export_data: bytes,
    export_path: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
    args: argparse.Namespace,
) -> int | None:
    export_document = _json_document_or_none(export_data)
    if isinstance(export_document, dict) and export_document.get("schema") == VANTA_WORKFLOW_EVIDENCE_SCHEMA:
        _index, failure = _verify_workflow_evidence_document(
            export_document,
            args=args,
            label="WORKFLOW-EVIDENCE",
        )
        return failure

    sibling_failure = _verify_vanta_workflow_extension(
        export_document=export_document,
        export_path=export_path,
        manifest_path=manifest_path,
        manifest=manifest,
        args=args,
    )
    if sibling_failure is not None:
        return sibling_failure

    incident_failure = _verify_incident_bundle(
        export_path=export_path,
        manifest=manifest,
        args=args,
    )
    if incident_failure is not None:
        return incident_failure
    return None


def _fetch_manifest_bytes(url: str) -> bytes:
    """Fetch raw manifest bytes from a URL with a short timeout."""
    with urllib.request.urlopen(url, timeout=10) as resp:
        return resp.read()


def _validate_manifest_payload(payload: dict[str, Any]) -> int:
    """Validate that ``payload`` looks like a Keel public-key manifest.

    Returns the number of keys when valid; raises ``ValueError`` otherwise. A
    valid manifest is a JSON object with a non-empty ``keys`` list, where each
    entry has at minimum a ``public_key`` (or ``public_key_b64``) string.
    """
    if not isinstance(payload, dict):
        raise ValueError("manifest is not a JSON object")
    keys = payload.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ValueError("manifest has no 'keys' list or it is empty")
    for entry in keys:
        if not isinstance(entry, dict):
            raise ValueError("manifest 'keys' entries must be JSON objects")
        pub = entry.get("public_key")
        pub_b64 = entry.get("public_key_b64")
        if not (isinstance(pub, str) and pub.strip()) and not (
            isinstance(pub_b64, str) and pub_b64.strip()
        ):
            raise ValueError("manifest 'keys' entries must include 'public_key'")
    return len(keys)


def _captured_check(callable_, *args, **kwargs) -> tuple[int | None, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        result = callable_(*args, **kwargs)
    return result, stdout.getvalue(), stderr.getvalue()


def _failure_from_output(stdout: str, stderr: str) -> tuple[str, str]:
    text = f"{stderr}\n{stdout}"
    match = re.search(r"FAILED:\s+([A-Z][A-Z0-9_]+):\s*(.*)", text)
    if match:
        return match.group(1), match.group(2).strip()
    lowered = text.lower()
    if "content hash mismatch" in lowered:
        return "CONTENT_HASH_MISMATCH", "content hash mismatch"
    if "signature verification failed" in lowered:
        return "SIGNATURE_VERIFICATION_FAILED", "signature verification failed"
    if "export manifest is unsigned" in lowered:
        return "MANIFEST_SIGNATURE_MISSING", "export manifest is unsigned"
    if "export is not json" in lowered:
        return "EXPORT_STRUCTURE_INVALID", "export is not JSON"
    match = re.search(r"FAILED:\s*(.*)", text)
    return "VERIFICATION_FAILED", (match.group(1).strip() if match else text.strip())


def _export_artifact_dict(
    *,
    export_path: Path,
    manifest_path: Path,
    export_data: bytes | None = None,
    manifest_data: bytes | None = None,
) -> dict[str, Any]:
    artifact: dict[str, Any] = {
        "kind": "export",
        "manifest_path": str(manifest_path),
        "payload_path": str(export_path),
    }
    if manifest_data is not None:
        artifact["manifest_hash"] = _content_hash(manifest_data)
    if export_data is not None:
        artifact["payload_hash"] = _content_hash(export_data)
    return artifact


def _export_report(
    *,
    ok: bool,
    exit_code: int,
    artifact: dict[str, Any],
    claims: list[ClaimVerdict],
    error: str | None = None,
    diagnostics: list[str] | None = None,
) -> VerificationReport:
    return VerificationReport(
        ok=ok,
        exit_code=exit_code,
        artifact=artifact,
        claims=_merge_claims(claims),
        error=error,
        diagnostics=list(diagnostics or []),
        semantics=legacy_semantics(),
    )


def _export_integrity_claim(
    *,
    export_path: Path,
    manifest_path: Path,
    content_verdict: str,
    signature_verdict: str,
    reason_code: str,
    message: str,
    signature_message: str | None = None,
) -> ClaimVerdict:
    return ClaimVerdict(
        name="export.integrity.v1",
        subjects=[
            _subject(
                subject_type="payload_content_hash",
                subject_id=export_path.name,
                verdict=content_verdict,
                reason_code=(
                    "CONTENT_HASH_MATCH"
                    if content_verdict == "supported"
                    else reason_code
                ),
                message=(
                    "export bytes match manifest content_hash"
                    if content_verdict == "supported"
                    else message
                ),
                evidence=["manifest.content_hash", str(export_path)],
            ),
            _subject(
                subject_type="manifest_signature",
                subject_id=manifest_path.name,
                verdict=signature_verdict,
                reason_code=reason_code,
                message=signature_message or message,
                evidence=["manifest.signature", "manifest.public_key", "manifest.key_id"],
            ),
        ],
        reason_code=reason_code,
        message=message,
        evidence=["manifest.content_hash", "manifest.signature", str(export_path)],
    )


def _payload_record_count(export_data: bytes) -> int | None:
    try:
        document = _load_export_json_document(export_data)
    except Exception:
        return None
    if not isinstance(document, dict):
        return None
    records = document.get("records")
    if isinstance(records, list):
        return len(records)
    return None


def _evaluate_export_scope_identity(
    *,
    manifest: dict[str, Any],
    export_data: bytes,
) -> ClaimVerdict | None:
    identity_fields = (
        "export_id",
        "project_id",
        "export_type",
        "format",
        "compressed",
        "record_count",
    )
    if not any(field in manifest for field in identity_fields):
        return None
    missing = [field for field in identity_fields if field not in manifest]
    if missing:
        return _single_subject_claim(
            "export.scope_identity.v1",
            subject_type="manifest_identity",
            subject_id=str(manifest.get("export_id") or "<unknown>"),
            verdict="insufficient_evidence",
            reason_code="EXPORT_SCOPE_IDENTITY_INCOMPLETE",
            message=f"manifest identity fields missing: {', '.join(missing)}",
            evidence=["manifest"],
            required=False,
        )

    record_count = _payload_record_count(export_data)
    if record_count is None:
        return _single_subject_claim(
            "export.scope_identity.v1",
            subject_type="manifest_identity",
            subject_id=str(manifest.get("export_id") or "<unknown>"),
            verdict="unverifiable_scope",
            reason_code="EXPORT_SCOPE_IDENTITY_UNVERIFIABLE",
            message="export payload shape does not expose a verifiable record_count",
            evidence=["manifest", "export.records"],
            required=False,
        )
    if record_count != manifest.get("record_count"):
        return _single_subject_claim(
            "export.scope_identity.v1",
            subject_type="manifest_identity",
            subject_id=str(manifest.get("export_id") or "<unknown>"),
            verdict="disproved",
            reason_code="EXPORT_SCOPE_RECORD_COUNT_MISMATCH",
            message=(
                f"manifest record_count={manifest.get('record_count')} "
                f"does not match payload records={record_count}"
            ),
            evidence=["manifest.record_count", "export.records"],
            required=False,
        )

    try:
        document = _load_export_json_document(export_data)
    except Exception:
        document = None
    project_id = document.get("project_id") if isinstance(document, dict) else None
    if (
        isinstance(manifest.get("project_id"), str)
        and isinstance(project_id, str)
        and manifest["project_id"] != project_id
    ):
        return _single_subject_claim(
            "export.scope_identity.v1",
            subject_type="manifest_identity",
            subject_id=str(manifest.get("export_id") or "<unknown>"),
            verdict="disproved",
            reason_code="EXPORT_SCOPE_PROJECT_ID_MISMATCH",
            message="manifest project_id does not match payload project_id",
            evidence=["manifest.project_id", "export.project_id"],
            required=False,
        )

    return _single_subject_claim(
        "export.scope_identity.v1",
        subject_type="manifest_identity",
        subject_id=str(manifest.get("export_id") or "<unknown>"),
        verdict="supported",
        reason_code="EXPORT_SCOPE_IDENTITY_SUPPORTED",
        message="manifest identity fields match the export payload shape",
        evidence=["manifest", "export.records"],
        required=False,
    )


def _count_from_output(stdout: str, label: str) -> int | None:
    match = re.search(rf"{re.escape(label)}:\s+(\d+)", stdout)
    if not match:
        return None
    return int(match.group(1))


def _workflow_claims_from_output(
    *,
    manifest: dict[str, Any],
    stdout: str,
    stderr: str,
    result: int | None,
) -> list[ClaimVerdict]:
    claims: list[ClaimVerdict] = []
    sibling_artifacts = manifest.get("sibling_artifacts")
    sibling_present = (
        isinstance(sibling_artifacts, dict)
        and isinstance(sibling_artifacts.get("workflow_evidence"), dict)
    )
    if sibling_present and "WORKFLOW-EVIDENCE: VERIFIED" in stdout:
        claims.append(
            _single_subject_claim(
                "workflow_evidence.sibling_integrity.v1",
                subject_type="workflow_evidence_sibling",
                subject_id="workflow_evidence",
                verdict="supported",
                reason_code="WORKFLOW_SIBLING_INTEGRITY_SUPPORTED",
                message="workflow evidence sibling content hash and signature are valid",
                evidence=["manifest.sibling_artifacts.workflow_evidence"],
            )
        )

    declarations = _count_from_output(stdout, "declarations_verified")
    amendments = _count_from_output(stdout, "amendments_verified")
    if declarations is not None and declarations > 0:
        claims.extend(
            [
                _single_subject_claim(
                    "workflow.declaration_signature.v1",
                    subject_type="workflow_declarations",
                    subject_id="declarations",
                    verdict="supported",
                    reason_code="WORKFLOW_DECLARATION_SIGNATURE_SUPPORTED",
                    message=f"{declarations} workflow declaration signature(s) verified",
                    evidence=["workflow_evidence.declarations"],
                ),
                _single_subject_claim(
                    "workflow.effective_intent_hash.v1",
                    subject_type="workflow_declarations",
                    subject_id="declarations",
                    verdict="supported",
                    reason_code="WORKFLOW_EFFECTIVE_INTENT_HASH_SUPPORTED",
                    message="workflow effective intent hash checks verified",
                    evidence=["workflow_evidence.declarations", "workflow_evidence.amendments"],
                ),
            ]
        )
    if amendments is not None and amendments > 0:
        claims.append(
            _single_subject_claim(
                "workflow.amendment_signature.v1",
                subject_type="workflow_amendments",
                subject_id="amendments",
                verdict="supported",
                reason_code="WORKFLOW_AMENDMENT_SIGNATURE_SUPPORTED",
                message=f"{amendments} workflow amendment signature(s) verified",
                evidence=["workflow_evidence.amendments"],
            )
        )
    snapshot_checks = _count_from_output(stdout, "workflow_state_json checks")
    if snapshot_checks is not None and snapshot_checks > 0:
        claims.append(
            _single_subject_claim(
                "workflow.permit_snapshot.v1",
                subject_type="permit_workflow_snapshot",
                subject_id="workflow_state_json",
                verdict="supported",
                reason_code="WORKFLOW_PERMIT_SNAPSHOT_SUPPORTED",
                message=f"{snapshot_checks} permit workflow snapshot(s) verified",
                evidence=["export.records.workflow_state_json"],
            )
        )
    if "INCIDENT-BUNDLE: VERIFIED" in stdout:
        claims.append(
            _single_subject_claim(
                "incident.bundle_manifest.v1",
                subject_type="incident_bundle",
                subject_id="incident.zip",
                verdict="supported",
                reason_code="INCIDENT_BUNDLE_MANIFEST_SUPPORTED",
                message="incident bundle manifest v2 file set and schemas verified",
                evidence=["incident.zip", "manifest"],
            )
        )

    if result is None:
        return claims
    if result == 0:
        return claims

    reason_code, message = _failure_from_output(stdout, stderr)
    lowered = message.lower()
    if reason_code == WORKFLOW_EVIDENCE_SCHEMA_INVALID:
        if "workflow_evidence content_hash mismatch" in lowered:
            claim_name = "workflow_evidence.sibling_integrity.v1"
            verdict = "disproved"
        elif "declaration_signed_at" in lowered or "declarations[" in lowered:
            claim_name = "workflow.declaration_signature.v1"
            verdict = "insufficient_evidence"
        else:
            claim_name = "workflow.effective_intent_hash.v1"
            verdict = "insufficient_evidence"
    elif reason_code == WORKFLOW_SIGNATURE_INVALID:
        if "amendment" in lowered:
            claim_name = "workflow.amendment_signature.v1"
        elif "workflow_evidence" in lowered:
            claim_name = "workflow_evidence.sibling_integrity.v1"
        else:
            claim_name = "workflow.declaration_signature.v1"
        verdict = "disproved"
    elif reason_code == WORKFLOW_AMENDMENT_ORDER_INVALID:
        claim_name = "workflow.effective_intent_hash.v1"
        verdict = "disproved"
    elif reason_code == WORKFLOW_EFFECTIVE_INTENT_HASH_MISMATCH:
        claim_name = (
            "workflow.permit_snapshot.v1"
            if "permit_records[" in lowered
            else "workflow.effective_intent_hash.v1"
        )
        verdict = "disproved"
    elif reason_code in {INCIDENT_MANIFEST_SCHEMA_INVALID, INCIDENT_UNKNOWN_MANIFEST_VERSION}:
        claim_name = "incident.bundle_manifest.v1"
        verdict = "disproved"
    else:
        claim_name = "workflow.effective_intent_hash.v1"
        verdict = "unverifiable_scope"
    claims.append(
        _single_subject_claim(
            claim_name,
            subject_type="workflow_or_incident",
            subject_id=None,
            verdict=verdict,
            reason_code=reason_code,
            message=message,
            evidence=["export", "manifest"],
        )
    )
    return claims


def _walk_claim_from_output(
    *,
    stdout: str,
    stderr: str,
    result: int,
) -> ClaimVerdict:
    if result == 0 and "WALK-EVENTS: VERIFIED" in stdout:
        entries = _count_from_output(stdout, "entries_walked")
        if entries is not None and entries == 0:
            verdict = "insufficient_evidence"
            reason_code = "WALK_NO_EVALUABLE_SUBJECTS"
            message = "walk-events found zero evaluable chain entries"
        else:
            verdict = "supported"
            reason_code = "WALK_EVENTS_SUPPORTED"
            message = "governance chain local continuity verified"
        return _single_subject_claim(
            "governance_chain.local_continuity.v1",
            subject_type="governance_chain",
            subject_id="chain_entries",
            verdict=verdict,
            reason_code=reason_code,
            message=message,
            evidence=["export.chain_entries", "export.records.chain_entries"],
        )

    reason_code, message = _failure_from_output(stdout, stderr)
    verdict = (
        "unverifiable_scope"
        if reason_code in {"EXPORT_STRUCTURE_INVALID", WALK_UNKNOWN_CHAIN_FORMAT}
        else "disproved"
    )
    return _single_subject_claim(
        "governance_chain.local_continuity.v1",
        subject_type="governance_chain",
        subject_id="chain_entries",
        verdict=verdict,
        reason_code=reason_code,
        message=message,
        evidence=["export.chain_entries", "export.records.chain_entries"],
    )


def _closure_claims_from_output(
    *,
    stdout: str,
    stderr: str,
    result: int,
) -> list[ClaimVerdict]:
    claims: list[ClaimVerdict] = []
    if result == 0 and "VERIFY-CLOSURE: VERIFIED" in stdout:
        closures = _count_from_output(stdout, "closures_verified") or 0
        digest_checks = _count_from_output(stdout, "digest_checks") or 0
        if closures > 0:
            claims.append(
                _single_subject_claim(
                    "closure.signature.v1",
                    subject_type="closure",
                    subject_id="permit.closed",
                    verdict="supported",
                    reason_code="CLOSURE_SIGNATURE_SUPPORTED",
                    message=f"{closures} closure signature(s) verified",
                    evidence=["export.chain_entries[permit.closed]"],
                )
            )
        else:
            claims.append(
                _single_subject_claim(
                    "closure.signature.v1",
                    subject_type="closure",
                    subject_id="permit.closed",
                    verdict="insufficient_evidence",
                    reason_code="CLOSURE_NO_EVALUABLE_SUBJECTS",
                    message="verify-closure found zero evaluable closure subjects",
                    evidence=["export.chain_entries[permit.closed]"],
                )
            )
        if digest_checks > 0:
            claims.append(
                _single_subject_claim(
                    "closure.digest_consistency.v1",
                    subject_type="closure_digest",
                    subject_id="provider_client_response",
                    verdict="supported",
                    reason_code="CLOSURE_DIGEST_CONSISTENCY_SUPPORTED",
                    message=f"{digest_checks} closure digest reference(s) verified",
                    evidence=["export.chain_entries[permit.closed]"],
                )
            )
        if "dispatch_digest_check: PASS" in stdout:
            claims.append(
                _single_subject_claim(
                    "closure.dispatch_binding.v1",
                    subject_type="closure_dispatch_digest",
                    subject_id="dispatch_request_digest_v1",
                    verdict="supported",
                    reason_code="CLOSURE_DISPATCH_BINDING_SUPPORTED",
                    message="closure dispatch request digest matches permit binding hash",
                    evidence=[
                        "export.records.permit.binding_request_hash",
                        "export.chain_entries[permit.closed]",
                    ],
                )
            )
        return claims

    reason_code, message = _failure_from_output(stdout, stderr)
    if reason_code == WALK_CLOSURE_SIGNATURE_INVALID:
        claim_name = "closure.signature.v1"
        verdict = "disproved"
    elif reason_code == WALK_CLOSURE_DISPATCH_DIGEST_MISMATCH:
        claims.append(
            _single_subject_claim(
                "closure.signature.v1",
                subject_type="closure",
                subject_id="permit.closed",
                verdict="supported",
                reason_code="CLOSURE_SIGNATURE_SUPPORTED",
                message="closure signature checks passed before dispatch binding failure",
                evidence=["export.chain_entries[permit.closed]"],
            )
        )
        claim_name = "closure.dispatch_binding.v1"
        verdict = "disproved"
    elif reason_code == WALK_CLOSURE_DIGEST_MISSING:
        claims.append(
            _single_subject_claim(
                "closure.signature.v1",
                subject_type="closure",
                subject_id="permit.closed",
                verdict="supported",
                reason_code="CLOSURE_SIGNATURE_SUPPORTED",
                message="closure signature checks passed before digest evidence failure",
                evidence=["export.chain_entries[permit.closed]"],
            )
        )
        claim_name = (
            "closure.dispatch_binding.v1"
            if "dispatch_request_digest_v1" in message
            else "closure.digest_consistency.v1"
        )
        verdict = "insufficient_evidence"
    elif reason_code == WALK_CLOSURE_DIGEST_MISMATCH:
        claims.append(
            _single_subject_claim(
                "closure.signature.v1",
                subject_type="closure",
                subject_id="permit.closed",
                verdict="supported",
                reason_code="CLOSURE_SIGNATURE_SUPPORTED",
                message="closure signature checks passed before digest consistency failure",
                evidence=["export.chain_entries[permit.closed]"],
            )
        )
        claim_name = "closure.digest_consistency.v1"
        verdict = "disproved"
    else:
        claim_name = "closure.signature.v1"
        verdict = "unverifiable_scope"
    claims.append(
        _single_subject_claim(
            claim_name,
            subject_type="closure",
            subject_id="permit.closed",
            verdict=verdict,
            reason_code=reason_code,
            message=message,
            evidence=["export.chain_entries[permit.closed]"],
        )
    )
    return claims


def verify_export_structured(args: argparse.Namespace) -> VerificationReport:
    export_path = Path(args.export_file)
    manifest_path = Path(args.manifest)
    artifact = _export_artifact_dict(
        export_path=export_path,
        manifest_path=manifest_path,
    )

    if not export_path.exists():
        return _export_report(
            ok=False,
            exit_code=1,
            artifact=artifact,
            claims=[],
            error=f"Export file not found: {export_path}",
        )
    if not manifest_path.exists():
        return _export_report(
            ok=False,
            exit_code=1,
            artifact=artifact,
            claims=[],
            error=f"Manifest file not found: {manifest_path}",
        )

    manifest_data = manifest_path.read_bytes()
    export_data = export_path.read_bytes()
    artifact = _export_artifact_dict(
        export_path=export_path,
        manifest_path=manifest_path,
        export_data=export_data,
        manifest_data=manifest_data,
    )
    try:
        manifest = json.loads(manifest_data.decode("utf-8"))
    except Exception as exc:
        return _export_report(
            ok=False,
            exit_code=1,
            artifact=artifact,
            claims=[
                _single_subject_claim(
                    "export.integrity.v1",
                    subject_type="manifest",
                    subject_id=manifest_path.name,
                    verdict="insufficient_evidence",
                    reason_code="MANIFEST_JSON_INVALID",
                    message=f"manifest is not valid JSON: {exc}",
                    evidence=[str(manifest_path)],
                )
            ],
            error=f"manifest is not valid JSON: {exc}",
        )
    if not isinstance(manifest, dict):
        return _export_report(
            ok=False,
            exit_code=1,
            artifact=artifact,
            claims=[
                _single_subject_claim(
                    "export.integrity.v1",
                    subject_type="manifest",
                    subject_id=manifest_path.name,
                    verdict="insufficient_evidence",
                    reason_code="MANIFEST_JSON_INVALID",
                    message="manifest top-level JSON must be an object",
                    evidence=[str(manifest_path)],
                )
            ],
            error="manifest top-level JSON must be an object",
        )

    claims: list[ClaimVerdict] = []
    diagnostics: list[str] = []
    expected = manifest.get("content_hash")
    actual = _content_hash(export_data)
    if expected != actual:
        message = f"content hash mismatch: expected={expected} actual={actual}"
        return _export_report(
            ok=False,
            exit_code=1,
            artifact=artifact,
            claims=[
                _export_integrity_claim(
                    export_path=export_path,
                    manifest_path=manifest_path,
                    content_verdict="disproved",
                    signature_verdict="insufficient_evidence",
                    reason_code="CONTENT_HASH_MISMATCH",
                    message=message,
                    signature_message="signature was not evaluated after content hash mismatch",
                )
            ],
            error=message,
        )

    sig = manifest.get("signature")
    embedded_pub = manifest.get("public_key")
    artifact_key_id = (
        manifest.get("key_id") if isinstance(manifest.get("key_id"), str) else None
    )

    if not sig:
        message = "Export manifest is unsigned (no signature in manifest)."
        signature_verdict = "insufficient_evidence"
        claims.append(
            _export_integrity_claim(
                export_path=export_path,
                manifest_path=manifest_path,
                content_verdict="supported",
                signature_verdict=signature_verdict,
                reason_code="MANIFEST_SIGNATURE_MISSING",
                message=message,
                signature_message=(
                    "--allow-unsigned compatibility: manifest has no signature; "
                    "content hash verified but signature evidence is missing"
                    if getattr(args, "allow_unsigned", False)
                    else message
                ),
            )
        )
        if getattr(args, "allow_unsigned", False):
            diagnostics.append(
                "--allow-unsigned compatibility mode: content hash verified, "
                "but export.integrity.v1 remains insufficient_evidence because "
                "the manifest signature is missing"
            )
            return _export_report(
                ok=True,
                exit_code=0,
                artifact=artifact,
                claims=claims,
                diagnostics=diagnostics,
            )
        return _export_report(
            ok=False,
            exit_code=1,
            artifact=artifact,
            claims=claims,
            error=message,
            diagnostics=diagnostics,
        )

    signing_time = _parse_iso_or_none(manifest.get("signed_at"))
    trusted_pub, trust_source, err = _resolve_trust_key(
        artifact_pub=embedded_pub if isinstance(embedded_pub, str) else None,
        artifact_key_id=artifact_key_id,
        purpose="export_signing",
        expected_public_key=args.expected_public_key,
        public_key_url=None,
        key_manifest_source=_key_manifest_source_for_args(args),
        signing_time=signing_time,
    )
    if err is not None or trusted_pub is None:
        message = str(err or "could not resolve trust root")
        claims.append(
            _export_integrity_claim(
                export_path=export_path,
                manifest_path=manifest_path,
                content_verdict="supported",
                signature_verdict="insufficient_evidence",
                reason_code="TRUST_ROOT_UNRESOLVABLE",
                message=message,
            )
        )
        return _export_report(
            ok=False,
            exit_code=1,
            artifact=artifact,
            claims=claims,
            error=message,
        )

    if isinstance(embedded_pub, str) and embedded_pub != trusted_pub:
        message = "Manifest public_key does not match trusted key."
        claims.append(
            _export_integrity_claim(
                export_path=export_path,
                manifest_path=manifest_path,
                content_verdict="supported",
                signature_verdict="disproved",
                reason_code="MANIFEST_PUBLIC_KEY_MISMATCH",
                message=message,
            )
        )
        return _export_report(
            ok=False,
            exit_code=1,
            artifact=artifact,
            claims=claims,
            error=message,
        )

    if not _verify_ed25519(trusted_pub, expected.encode("utf-8"), sig):
        message = "Signature verification failed."
        claims.append(
            _export_integrity_claim(
                export_path=export_path,
                manifest_path=manifest_path,
                content_verdict="supported",
                signature_verdict="disproved",
                reason_code="SIGNATURE_VERIFICATION_FAILED",
                message=message,
            )
        )
        return _export_report(
            ok=False,
            exit_code=1,
            artifact=artifact,
            claims=claims,
            error=message,
        )

    claims.append(
        _export_integrity_claim(
            export_path=export_path,
            manifest_path=manifest_path,
            content_verdict="supported",
            signature_verdict="supported",
            reason_code="EXPORT_INTEGRITY_SUPPORTED",
            message="export content hash and manifest signature verified",
        )
    )
    scope_claim = _evaluate_export_scope_identity(
        manifest=manifest,
        export_data=export_data,
    )
    if scope_claim is not None:
        claims.append(scope_claim)

    workflow_result, workflow_stdout, workflow_stderr = _captured_check(
        _verify_export_workflow_extensions,
        export_data=export_data,
        export_path=export_path,
        manifest_path=manifest_path,
        manifest=manifest,
        args=args,
    )
    claims.extend(
        _workflow_claims_from_output(
            manifest=manifest,
            stdout=workflow_stdout,
            stderr=workflow_stderr,
            result=workflow_result,
        )
    )
    if workflow_result is not None:
        return _export_report(
            ok=False,
            exit_code=workflow_result,
            artifact=artifact,
            claims=claims,
            error=_failure_from_output(workflow_stdout, workflow_stderr)[1],
        )

    if args.walk_events:
        walk_result, walk_stdout, walk_stderr = _captured_check(
            _walk_export_events,
            export_data,
        )
        assert walk_result is not None
        claims.append(
            _walk_claim_from_output(
                stdout=walk_stdout,
                stderr=walk_stderr,
                result=walk_result,
            )
        )
        if walk_result != 0:
            return _export_report(
                ok=False,
                exit_code=walk_result,
                artifact=artifact,
                claims=claims,
                error=_failure_from_output(walk_stdout, walk_stderr)[1],
            )
    if args.verify_closure:
        closure_result, closure_stdout, closure_stderr = _captured_check(
            _verify_export_closures,
            export_data,
            args,
        )
        assert closure_result is not None
        claims.extend(
            _closure_claims_from_output(
                stdout=closure_stdout,
                stderr=closure_stderr,
                result=closure_result,
            )
        )
        if closure_result != 0:
            return _export_report(
                ok=False,
                exit_code=closure_result,
                artifact=artifact,
                claims=claims,
                error=_failure_from_output(closure_stdout, closure_stderr)[1],
            )

    return _export_report(
        ok=True,
        exit_code=0,
        artifact=artifact,
        claims=claims,
        diagnostics=diagnostics,
    )


def cmd_refresh_keys(args: argparse.Namespace) -> int:
    """Pull a fresh Keel public-key manifest into ``~/.keel-verifier/trust-root.json``.

    Tries the configured channels in order (Keel API, then GitHub) and writes
    the first valid response to the cache. Subsequent verifications prefer the
    cache over the wheel-bundled trust root, so the bundled snapshot does not
    need to be regenerated when Keel rotates a signing key.
    """
    requested_source = (getattr(args, "source", "auto") or "auto").lower()
    candidates: list[tuple[str, str, str]] = []
    for slug, name, url in REFRESH_KEYS_SOURCES:
        if requested_source in {"auto", slug}:
            candidates.append((slug, name, url))
        if requested_source != "auto" and slug == requested_source:
            break
    if not candidates:
        valid = ", ".join(slug for slug, _, _ in REFRESH_KEYS_SOURCES)
        print(
            f"FAILED: unknown --source value {requested_source!r}; "
            f"valid choices: auto, {valid}",
            file=sys.stderr,
        )
        return 2

    last_error: str | None = None
    for _slug, name, url in candidates:
        print(f"trying {name} ({url})...", file=sys.stderr)
        try:
            raw = _fetch_manifest_bytes(url)
        except Exception as exc:  # network or HTTP failure
            last_error = f"{name}: fetch failed: {exc}"
            print(f"  fetch failed: {exc}", file=sys.stderr)
            continue
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            last_error = f"{name}: invalid JSON: {exc}"
            print(f"  invalid JSON: {exc}", file=sys.stderr)
            continue
        try:
            key_count = _validate_manifest_payload(payload)
        except ValueError as exc:
            last_error = f"{name}: invalid manifest: {exc}"
            print(f"  invalid manifest: {exc}", file=sys.stderr)
            continue

        try:
            CACHED_TRUST_ROOT_PATH.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = CACHED_TRUST_ROOT_PATH.with_suffix(".json.tmp")
            tmp_path.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            tmp_path.replace(CACHED_TRUST_ROOT_PATH)
        except OSError as exc:
            print(f"FAILED: could not write cache: {exc}", file=sys.stderr)
            return 1

        print(f"refreshed from {name}")
        print(f"  cache:     {CACHED_TRUST_ROOT_PATH}")
        print(f"  key count: {key_count}")
        generated_at = (
            payload.get("generated_at") if isinstance(payload, dict) else None
        )
        if isinstance(generated_at, str):
            print(f"  generated: {generated_at}")
        return 0

    print(
        "FAILED: no channel returned a valid manifest" + (
            f" (last error: {last_error})" if last_error else ""
        ),
        file=sys.stderr,
    )
    return 1


def cmd_export(args: argparse.Namespace) -> int:
    if getattr(args, "as_json", False):
        report = verify_export_structured(args)
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        return report.exit_code

    export_path = Path(args.export_file)
    manifest_path = Path(args.manifest)

    if not export_path.exists():
        print(f"FAILED: Export file not found: {export_path}", file=sys.stderr)
        return 1
    if not manifest_path.exists():
        print(f"FAILED: Manifest file not found: {manifest_path}", file=sys.stderr)
        return 1

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    export_data = export_path.read_bytes()

    expected = manifest.get("content_hash")
    actual = _content_hash(export_data)
    if expected != actual:
        print(
            f"FAILED: Content hash mismatch.\n"
            f"  Expected: {expected}\n"
            f"  Actual:   {actual}",
            file=sys.stderr,
        )
        return 1

    sig = manifest.get("signature")
    embedded_pub = manifest.get("public_key")
    artifact_key_id = (
        manifest.get("key_id") if isinstance(manifest.get("key_id"), str) else None
    )

    if not sig:
        if not getattr(args, "allow_unsigned", False):
            print(
                "FAILED: Export manifest is unsigned (no signature in manifest).",
                file=sys.stderr,
            )
            return 1
        print(
            "WARNING: Export manifest is unsigned (no signature in manifest).",
            file=sys.stderr,
        )
        print(f"Content hash verified: {actual}")
        return 0

    signing_time = _parse_iso_or_none(manifest.get("signed_at"))

    trusted_pub, trust_source, err = _resolve_trust_key(
        artifact_pub=embedded_pub if isinstance(embedded_pub, str) else None,
        artifact_key_id=artifact_key_id,
        purpose="export_signing",
        expected_public_key=args.expected_public_key,
        public_key_url=None,  # export mode does not support single-key URL
        key_manifest_source=_key_manifest_source_for_args(args),
        signing_time=signing_time,
    )
    if err is not None or trusted_pub is None:
        print(f"FAILED: {err}", file=sys.stderr)
        return 1

    if isinstance(embedded_pub, str) and embedded_pub != trusted_pub:
        print(
            "FAILED: Manifest public_key does not match trusted key.\n"
            f"  Trusted:  {trusted_pub}\n"
            f"  In file:  {embedded_pub}",
            file=sys.stderr,
        )
        return 1

    if not _verify_ed25519(trusted_pub, expected.encode("utf-8"), sig):
        print("FAILED: Signature verification failed.", file=sys.stderr)
        return 1

    print("VERIFIED")
    print(f"  Export:       {export_path.name}")
    print(f"  Content hash: {expected}")
    print(f"  Signature:    {sig[:40]}...")
    print(f"  Public key:   {trusted_pub}")
    print(f"  Key id:       {artifact_key_id or _public_key_fingerprint(trusted_pub)}")
    print(f"  Trust source: {trust_source}")
    workflow_result = _verify_export_workflow_extensions(
        export_data=export_data,
        export_path=export_path,
        manifest_path=manifest_path,
        manifest=manifest,
        args=args,
    )
    if workflow_result is not None:
        return workflow_result
    if args.walk_events:
        walk_result = _walk_export_events(export_data)
        if walk_result != 0:
            return walk_result
    if args.verify_closure:
        return _verify_export_closures(export_data, args)
    return 0


# ─── Mode 2/3: checkpoint (+ optional TSA) ─────────────────────────


class _DerNode:
    def __init__(self, tag_class: int, constructed: bool, tag_number: int, value: bytes):
        self.tag_class = tag_class
        self.constructed = constructed
        self.tag_number = tag_number
        self.value = value

    @property
    def universal_sequence(self) -> bool:
        return self.tag_class == 0 and self.constructed and self.tag_number == 16

    @property
    def universal_octet_string(self) -> bool:
        return self.tag_class == 0 and not self.constructed and self.tag_number == 4

    def children(self) -> list["_DerNode"]:
        if not self.constructed:
            return []
        out: list[_DerNode] = []
        offset = 0
        while offset < len(self.value):
            child, offset = _read_der_node(self.value, offset)
            out.append(child)
        if offset != len(self.value):
            raise ValueError("DER child parse did not consume value")
        return out


def _read_der_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("truncated DER length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0:
        raise ValueError("indefinite DER length is not allowed")
    if count > 4 or offset + count > len(data):
        raise ValueError("invalid DER length")
    length = int.from_bytes(data[offset : offset + count], "big")
    if length < 0x80:
        raise ValueError("non-minimal DER length")
    return length, offset + count


def _read_der_node(data: bytes, offset: int = 0) -> tuple[_DerNode, int]:
    if offset >= len(data):
        raise ValueError("truncated DER tag")
    tag = data[offset]
    offset += 1
    tag_class = tag >> 6
    constructed = bool(tag & 0x20)
    tag_number = tag & 0x1F
    if tag_number == 0x1F:
        raise ValueError("high-tag-number DER is not supported")
    length, offset = _read_der_length(data, offset)
    end = offset + length
    if end > len(data):
        raise ValueError("truncated DER value")
    return _DerNode(tag_class, constructed, tag_number, data[offset:end]), end


def _unwrap_explicit_context(node: _DerNode) -> _DerNode:
    if node.tag_class != 2 or not node.constructed:
        raise ValueError("expected explicit context-specific node")
    children = node.children()
    if len(children) != 1:
        raise ValueError("explicit context node must contain one child")
    return children[0]


def _extract_rfc3161_message_imprint(receipt_der: bytes) -> bytes:
    content_info, end = _read_der_node(receipt_der)
    if end != len(receipt_der) or not content_info.universal_sequence:
        raise ValueError("receipt is not a DER ContentInfo sequence")
    ci_children = content_info.children()
    if len(ci_children) < 2:
        raise ValueError("ContentInfo missing signedData content")

    signed_data = _unwrap_explicit_context(ci_children[1])
    if not signed_data.universal_sequence:
        raise ValueError("signedData content is not a sequence")
    sd_children = signed_data.children()
    if len(sd_children) < 3:
        raise ValueError("SignedData missing encapContentInfo")

    encap = sd_children[2]
    if not encap.universal_sequence:
        raise ValueError("encapContentInfo is not a sequence")
    encap_children = encap.children()
    content_node = next(
        (
            child
            for child in encap_children[1:]
            if child.tag_class == 2 and child.constructed and child.tag_number == 0
        ),
        None,
    )
    if content_node is None:
        raise ValueError("encapContentInfo missing TSTInfo content")
    octets = _unwrap_explicit_context(content_node)
    if not octets.universal_octet_string:
        raise ValueError("TSTInfo content is not an octet string")

    tst_info, tst_end = _read_der_node(octets.value)
    if tst_end != len(octets.value) or not tst_info.universal_sequence:
        raise ValueError("TSTInfo is not a DER sequence")
    tst_children = tst_info.children()
    if len(tst_children) < 3 or not tst_children[2].universal_sequence:
        raise ValueError("TSTInfo missing messageImprint")
    imprint_children = tst_children[2].children()
    if len(imprint_children) < 2 or not imprint_children[1].universal_octet_string:
        raise ValueError("messageImprint missing hashedMessage")
    return imprint_children[1].value


def _verify_tsa_receipt(receipt_b64: str, content_hash_hex: str) -> tuple[bool, str]:
    """Verify the embedded TSA receipt against the checkpoint composite_hash.

    This intentionally performs the verifier's historical offline check only:
    it parses the RFC 3161 TimeStampToken and confirms the MessageImprint
    equals the checkpoint composite hash. Full TSA certificate-chain validation
    remains out of scope; use ``openssl ts -verify`` for that step.
    """
    try:
        raw_der = base64.b64decode(receipt_b64)
        imprint = _extract_rfc3161_message_imprint(raw_der)
        expected = bytes.fromhex(content_hash_hex)
        if imprint != expected:
            return False, "TSA message imprint does not match composite_hash"
        return True, "TSA message imprint matches composite_hash"
    except Exception as exc:
        return False, f"TSA parse/verify failed: {exc}"


def _checkpoint_tsa_receipts(cp: dict[str, Any]) -> list[dict[str, Any]]:
    """Return TSA receipt payloads, preferring multi-receipt checkpoints."""
    raw_receipts = cp.get("tsa_receipts")
    if isinstance(raw_receipts, list):
        receipts: list[dict[str, Any]] = []
        for index, receipt in enumerate(raw_receipts, start=1):
            if isinstance(receipt, dict):
                receipts.append(receipt)
            else:
                receipts.append(
                    {
                        "_invalid": f"tsa_receipts[{index}] is not an object",
                    }
                )
        if receipts:
            return receipts

    tsa = cp.get("tsa")
    if isinstance(tsa, dict) and isinstance(tsa.get("receipt_b64"), str):
        return [tsa]
    return []


def cmd_checkpoint(args: argparse.Namespace) -> int:
    result = verify_checkpoint(
        args.checkpoint_file,
        expected_public_key=args.expected_public_key,
        public_key_url=args.public_key_url,
        key_manifest=_key_manifest_source_for_args(args),
        self_attested=getattr(args, "self_attested", False),
        check_tsa=True,
    )
    result.exit_code = 0 if result.ok else 1
    if getattr(args, "as_json", False):
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return result.exit_code
    if not result.ok:
        print(f"FAILED: {result.error}", file=sys.stderr)
        return 1

    print("VERIFIED")
    print(f"  Checkpoint:   {result.checkpoint_id}")
    print(f"  Computed at:  {result.computed_at}")
    print(f"  Composite:    {result.composite_hash}")
    print(f"  Public key:   {result.public_key}")
    print(f"  Key id:       {result.key_id}")
    print(f"  Trust source: {result.trust_source}")
    print(f"  Chain heads:  {result.chain_heads_count} scope(s)")

    if result.tsa_receipts:
        for index, receipt in enumerate(result.tsa_receipts, start=1):
            label = receipt.get("provider") or receipt.get("url") or f"receipt {index}"
            if receipt.get("verified") is True:
                print(f"  TSA[{index}]:      OK ({label}: {receipt.get('reason')})")
                print(f"    URL:        {receipt.get('url')}")
                print(f"    Stamped at: {receipt.get('requested_at')}")
            elif receipt.get("checked") is False:
                print(f"  TSA[{index}]:      present (skipped)")
            else:
                print(
                    f"  TSA[{index}]:      FAILED ({label}: {receipt.get('reason')})",
                    file=sys.stderr,
                )
                return 1
        if args.tsa_ca_bundle:
            print(
                "  NOTE: full RFC 3161 trust-chain validation against "
                f"{args.tsa_ca_bundle} is out of scope for this verifier; "
                "use openssl ts -verify for that step.",
            )
    elif result.tsa_present:
        print("  TSA:          present but receipt_b64 missing - skipped")

    return 0


# ─── Programmatic and legacy checkpoint API ─────────────────────────


@dataclass
class VerifyResult:
    ok: bool
    error: str | None = None
    exit_code: int | None = None
    artifact: dict[str, Any] = dataclass_field(default_factory=lambda: {"kind": "checkpoint"})

    checkpoint_id: str | None = None
    computed_at: str | None = None
    composite_hash: str | None = None
    chain_heads_count: int = 0

    public_key: str | None = None
    key_id: str | None = None
    trust_source: str | None = None
    self_attested: bool = False

    tsa_present: bool = False
    tsa_checked: bool = False
    tsa_verified: bool | None = None
    tsa_reason: str | None = None
    tsa_url: str | None = None
    tsa_requested_at: str | None = None
    tsa_receipts: list[dict[str, Any]] = dataclass_field(default_factory=list)

    diagnostics: list[str] = dataclass_field(default_factory=list)
    semantics: dict[str, Any] = dataclass_field(default_factory=legacy_semantics)
    claims: list[ClaimVerdict] = dataclass_field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": VERDICT_SCHEMA_ID,
            "ok": self.ok,
            "exit_code": (
                self.exit_code if self.exit_code is not None else 0 if self.ok else 1
            ),
            "error": self.error,
            "artifact": dict(self.artifact),
            "semantics": dict(self.semantics),
            "claims": [claim.to_dict() for claim in self.claims],
            "checkpoint_id": self.checkpoint_id,
            "computed_at": self.computed_at,
            "composite_hash": self.composite_hash,
            "chain_heads_count": self.chain_heads_count,
            "public_key": self.public_key,
            "key_id": self.key_id,
            "trust_source": self.trust_source,
            "self_attested": self.self_attested,
            "tsa": {
                "present": self.tsa_present,
                "checked": self.tsa_checked,
                "verified": self.tsa_verified,
                "reason": self.tsa_reason,
                "url": self.tsa_url,
                "requested_at": self.tsa_requested_at,
            },
            "tsa_receipts": list(self.tsa_receipts),
            "diagnostics": list(self.diagnostics),
        }


def _fetch_single_public_key(url: str) -> tuple[str | None, str | None]:
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        return None, f"could not fetch trust root from {url}: {exc}"
    pub = body.get("public_key") if isinstance(body, dict) else None
    if not isinstance(pub, str) or not pub.startswith("ed25519:"):
        return None, f"unexpected response shape from {url} (missing ed25519 public_key)"
    return pub, None


def _checkpoint_artifact_dict(path: Path, data: bytes | None = None) -> dict[str, Any]:
    artifact: dict[str, Any] = {
        "kind": "checkpoint",
        "checkpoint_path": str(path),
    }
    if data is not None:
        artifact["checkpoint_hash"] = _content_hash(data)
    return artifact


def _checkpoint_composite_claim(
    *,
    verdict: str,
    reason_code: str,
    message: str,
    checkpoint_id: str | None = None,
) -> ClaimVerdict:
    return _single_subject_claim(
        "checkpoint.composite_hash.v1",
        subject_type="checkpoint",
        subject_id=checkpoint_id,
        verdict=verdict,
        reason_code=reason_code,
        message=message,
        evidence=["checkpoint.chain_heads", "checkpoint.composite_hash"],
    )


def _checkpoint_signature_claim(
    *,
    verdict: str,
    reason_code: str,
    message: str,
    key_id: str | None = None,
) -> ClaimVerdict:
    return _single_subject_claim(
        "checkpoint.signature.v1",
        subject_type="checkpoint_signature",
        subject_id=key_id,
        verdict=verdict,
        reason_code=reason_code,
        message=message,
        evidence=["checkpoint.signature", "checkpoint.public_key", "checkpoint.key_id"],
    )


def _checkpoint_tsa_claim(receipts: list[dict[str, Any]]) -> ClaimVerdict:
    subjects: list[VerdictSubject] = []
    for index, receipt in enumerate(receipts, start=1):
        label = receipt.get("provider") or receipt.get("url") or f"receipt {index}"
        ok = receipt.get("verified") is True
        reason = str(receipt.get("reason") or "")
        subjects.append(
            _subject(
                subject_type="tsa_receipt",
                subject_id=str(label),
                verdict="supported" if ok else "disproved",
                reason_code=(
                    "CHECKPOINT_TSA_IMPRINT_SUPPORTED"
                    if ok
                    else "CHECKPOINT_TSA_IMPRINT_MISMATCH"
                ),
                message=reason
                or (
                    "TSA receipt message imprint matches composite_hash"
                    if ok
                    else "TSA receipt message imprint does not match composite_hash"
                ),
                evidence=["checkpoint.tsa", "checkpoint.tsa_receipts"],
            )
        )
    verdict = "supported" if all(subject.verdict == verdict_value("supported") for subject in subjects) else None
    return ClaimVerdict(
        name="checkpoint.tsa_imprint.v1",
        subjects=subjects,
        verdict=verdict,
        reason_code=(
            "CHECKPOINT_TSA_IMPRINT_SUPPORTED"
            if verdict == "supported"
            else "CHECKPOINT_TSA_IMPRINT_MISMATCH"
        ),
        message=(
            "TSA receipt message imprint matches composite_hash"
            if verdict == "supported"
            else "one or more TSA receipt message imprints do not match composite_hash"
        ),
        evidence=["checkpoint.tsa", "checkpoint.tsa_receipts"],
    )


def _checkpoint_base_result(
    body: dict[str, Any] | None,
    *,
    ok: bool,
    error: str | None = None,
    artifact: dict[str, Any] | None = None,
    claims: list[ClaimVerdict] | None = None,
    diagnostics: list[str] | None = None,
    composite_hash: str | None = None,
    chain_heads_count: int = 0,
    public_key: str | None = None,
    key_id: str | None = None,
    trust_source: str | None = None,
    self_attested: bool = False,
    tsa_present: bool = False,
    tsa_checked: bool = False,
    tsa_verified: bool | None = None,
    tsa_reason: str | None = None,
    tsa_url: str | None = None,
    tsa_requested_at: str | None = None,
    tsa_receipts: list[dict[str, Any]] | None = None,
) -> VerifyResult:
    return VerifyResult(
        ok=ok,
        error=error,
        exit_code=0 if ok else 1,
        artifact=artifact or {"kind": "checkpoint"},
        checkpoint_id=(
            str(body.get("checkpoint_id") or "") or None
            if isinstance(body, dict)
            else None
        ),
        computed_at=(
            str(body.get("computed_at") or "") or None
            if isinstance(body, dict)
            else None
        ),
        composite_hash=composite_hash,
        chain_heads_count=chain_heads_count,
        public_key=public_key,
        key_id=key_id,
        trust_source=trust_source,
        self_attested=self_attested,
        tsa_present=tsa_present,
        tsa_checked=tsa_checked,
        tsa_verified=tsa_verified,
        tsa_reason=tsa_reason,
        tsa_url=tsa_url,
        tsa_requested_at=tsa_requested_at,
        tsa_receipts=list(tsa_receipts or []),
        diagnostics=list(diagnostics or []),
        claims=_merge_claims(list(claims or [])),
    )


def _checkpoint_receipt_label(receipt: dict[str, Any], index: int) -> str:
    value = receipt.get("provider") or receipt.get("url")
    return value if isinstance(value, str) and value else f"receipt {index}"


def _verify_checkpoint_core(
    checkpoint_path: str | Path,
    *,
    expected_public_key: str | None = None,
    public_key_url: str | None = None,
    key_manifest_source: str | None = None,
    self_attested: bool = False,
    check_tsa: bool = True,
) -> VerifyResult:
    path = Path(checkpoint_path)
    artifact = _checkpoint_artifact_dict(path)

    try:
        raw = path.read_bytes()
        artifact = _checkpoint_artifact_dict(path, raw)
        body = json.loads(raw.decode("utf-8"))
    except FileNotFoundError:
        return VerifyResult(ok=False, error=f"file not found: {path}", artifact=artifact)
    except json.JSONDecodeError as exc:
        return VerifyResult(ok=False, error=f"invalid JSON: {exc}", artifact=artifact)
    except Exception as exc:
        return VerifyResult(ok=False, error=f"could not read {path}: {exc}", artifact=artifact)

    if not isinstance(body, dict):
        return VerifyResult(
            ok=False,
            error="top-level JSON must be an object",
            artifact=artifact,
        )

    composite = body.get("composite_hash")
    signature = body.get("signature")
    embedded_pub = body.get("public_key")
    chain_heads_raw = body.get("chain_heads") or {}
    artifact_key_id = body.get("key_id") if isinstance(body.get("key_id"), str) else None
    checkpoint_id = str(body.get("checkpoint_id") or "") or None

    if not isinstance(composite, str) or not composite.startswith("sha256:"):
        return _checkpoint_base_result(
            body,
            ok=False,
            error="missing or malformed composite_hash",
            artifact=artifact,
            claims=[
                _checkpoint_composite_claim(
                    verdict="insufficient_evidence",
                    reason_code="CHECKPOINT_COMPOSITE_HASH_MISSING",
                    message="missing or malformed composite_hash",
                    checkpoint_id=checkpoint_id,
                )
            ],
        )
    if not isinstance(chain_heads_raw, dict):
        return _checkpoint_base_result(
            body,
            ok=False,
            error="chain_heads must be an object",
            artifact=artifact,
            claims=[
                _checkpoint_composite_claim(
                    verdict="insufficient_evidence",
                    reason_code="CHECKPOINT_CHAIN_HEADS_INVALID",
                    message="chain_heads must be an object",
                    checkpoint_id=checkpoint_id,
                )
            ],
            composite_hash=composite,
        )

    for scope_key, head in chain_heads_raw.items():
        if not isinstance(head, dict):
            return _checkpoint_base_result(
                body,
                ok=False,
                error=f"chain_heads[{scope_key}] must be an object",
                artifact=artifact,
                claims=[
                    _checkpoint_composite_claim(
                        verdict="insufficient_evidence",
                        reason_code="CHECKPOINT_CHAIN_HEADS_INVALID",
                        message=f"chain_heads[{scope_key}] must be an object",
                        checkpoint_id=checkpoint_id,
                    )
                ],
                composite_hash=composite,
                chain_heads_count=len(chain_heads_raw),
            )
        if not isinstance(head.get("sequence_number"), int):
            return _checkpoint_base_result(
                body,
                ok=False,
                error=f"chain_heads[{scope_key}].sequence_number must be an int",
                artifact=artifact,
                claims=[
                    _checkpoint_composite_claim(
                        verdict="insufficient_evidence",
                        reason_code="CHECKPOINT_CHAIN_HEADS_INVALID",
                        message=f"chain_heads[{scope_key}].sequence_number must be an int",
                        checkpoint_id=checkpoint_id,
                    )
                ],
                composite_hash=composite,
                chain_heads_count=len(chain_heads_raw),
            )
        if not isinstance(head.get("last_record_hash"), str):
            return _checkpoint_base_result(
                body,
                ok=False,
                error=f"chain_heads[{scope_key}].last_record_hash must be a string",
                artifact=artifact,
                claims=[
                    _checkpoint_composite_claim(
                        verdict="insufficient_evidence",
                        reason_code="CHECKPOINT_CHAIN_HEADS_INVALID",
                        message=f"chain_heads[{scope_key}].last_record_hash must be a string",
                        checkpoint_id=checkpoint_id,
                    )
                ],
                composite_hash=composite,
                chain_heads_count=len(chain_heads_raw),
            )

    try:
        recomputed = _composite_hash(chain_heads_raw)
    except Exception as exc:
        return _checkpoint_base_result(
            body,
            ok=False,
            error=f"could not recompute composite_hash: {exc}",
            artifact=artifact,
            claims=[
                _checkpoint_composite_claim(
                    verdict="insufficient_evidence",
                    reason_code="CHECKPOINT_COMPOSITE_HASH_RECOMPUTE_FAILED",
                    message=f"could not recompute composite_hash: {exc}",
                    checkpoint_id=checkpoint_id,
                )
            ],
            composite_hash=composite,
            chain_heads_count=len(chain_heads_raw),
        )
    if recomputed != composite:
        return _checkpoint_base_result(
            body,
            ok=False,
            error=(
                "composite_hash mismatch - chain_heads have been altered\n"
                f"  stored:     {composite}\n"
                f"  recomputed: {recomputed}"
            ),
            artifact=artifact,
            claims=[
                _checkpoint_composite_claim(
                    verdict="disproved",
                    reason_code="CHECKPOINT_COMPOSITE_HASH_MISMATCH",
                    message="composite_hash mismatch - chain_heads have been altered",
                    checkpoint_id=checkpoint_id,
                )
            ],
            composite_hash=composite,
            chain_heads_count=len(chain_heads_raw),
        )

    if not isinstance(signature, str):
        return _checkpoint_base_result(
            body,
            ok=False,
            error="export is unsigned (no signature field)",
            artifact=artifact,
            claims=[
                _checkpoint_composite_claim(
                    verdict="supported",
                    reason_code="CHECKPOINT_COMPOSITE_HASH_SUPPORTED",
                    message="checkpoint composite_hash matches chain_heads",
                    checkpoint_id=checkpoint_id,
                ),
                _checkpoint_signature_claim(
                    verdict="insufficient_evidence",
                    reason_code="CHECKPOINT_SIGNATURE_MISSING",
                    message="checkpoint is unsigned (no signature field)",
                    key_id=artifact_key_id,
                ),
            ],
            composite_hash=composite,
            chain_heads_count=len(chain_heads_raw),
        )

    if expected_public_key is not None and not expected_public_key.startswith("ed25519:"):
        return _checkpoint_base_result(
            body,
            ok=False,
            error="--public-key must start with 'ed25519:'",
            artifact=artifact,
            claims=[
                _checkpoint_composite_claim(
                    verdict="supported",
                    reason_code="CHECKPOINT_COMPOSITE_HASH_SUPPORTED",
                    message="checkpoint composite_hash matches chain_heads",
                    checkpoint_id=checkpoint_id,
                ),
                _checkpoint_signature_claim(
                    verdict="insufficient_evidence",
                    reason_code="CHECKPOINT_PUBLIC_KEY_INVALID",
                    message="--public-key must start with 'ed25519:'",
                    key_id=artifact_key_id,
                ),
            ],
            composite_hash=composite,
            chain_heads_count=len(chain_heads_raw),
        )

    signing_time = _parse_iso_or_none(body.get("computed_at"))
    trusted_pub, trust_source, err = _resolve_trust_key(
        artifact_pub=embedded_pub if self_attested and isinstance(embedded_pub, str) else None,
        artifact_key_id=artifact_key_id,
        purpose="integrity_checkpoint",
        expected_public_key=expected_public_key,
        public_key_url=public_key_url,
        key_manifest_source=key_manifest_source,
        signing_time=signing_time,
    )
    if self_attested and trust_source == "embedded":
        trust_source = "self-attested (embedded public_key)"
    if err is not None or trusted_pub is None:
        return _checkpoint_base_result(
            body,
            ok=False,
            error=err or "could not resolve trust root",
            artifact=artifact,
            claims=[
                _checkpoint_composite_claim(
                    verdict="supported",
                    reason_code="CHECKPOINT_COMPOSITE_HASH_SUPPORTED",
                    message="checkpoint composite_hash matches chain_heads",
                    checkpoint_id=checkpoint_id,
                ),
                _checkpoint_signature_claim(
                    verdict="insufficient_evidence",
                    reason_code="TRUST_ROOT_UNRESOLVABLE",
                    message=err or "could not resolve trust root",
                    key_id=artifact_key_id,
                ),
            ],
            composite_hash=composite,
            chain_heads_count=len(chain_heads_raw),
        )

    if isinstance(embedded_pub, str) and embedded_pub != trusted_pub:
        return _checkpoint_base_result(
            body,
            ok=False,
            error=(
                "embedded public_key does not match resolved trust root\n"
                f"  trust root: {trusted_pub}\n"
                f"  embedded:   {embedded_pub}"
            ),
            artifact=artifact,
            claims=[
                _checkpoint_composite_claim(
                    verdict="supported",
                    reason_code="CHECKPOINT_COMPOSITE_HASH_SUPPORTED",
                    message="checkpoint composite_hash matches chain_heads",
                    checkpoint_id=checkpoint_id,
                ),
                _checkpoint_signature_claim(
                    verdict="disproved",
                    reason_code="CHECKPOINT_PUBLIC_KEY_MISMATCH",
                    message="embedded public_key does not match resolved trust root",
                    key_id=artifact_key_id or _public_key_fingerprint(trusted_pub),
                ),
            ],
            composite_hash=composite,
            chain_heads_count=len(chain_heads_raw),
        )

    if not _verify_ed25519(trusted_pub, composite.encode("utf-8"), signature):
        return _checkpoint_base_result(
            body,
            ok=False,
            error="signature verification failed",
            artifact=artifact,
            claims=[
                _checkpoint_composite_claim(
                    verdict="supported",
                    reason_code="CHECKPOINT_COMPOSITE_HASH_SUPPORTED",
                    message="checkpoint composite_hash matches chain_heads",
                    checkpoint_id=checkpoint_id,
                ),
                _checkpoint_signature_claim(
                    verdict="disproved",
                    reason_code="SIGNATURE_VERIFICATION_FAILED",
                    message="signature verification failed",
                    key_id=artifact_key_id or _public_key_fingerprint(trusted_pub),
                ),
            ],
            composite_hash=composite,
            chain_heads_count=len(chain_heads_raw),
            public_key=trusted_pub,
            key_id=artifact_key_id or _public_key_fingerprint(trusted_pub),
            trust_source=trust_source,
            self_attested=trust_source.startswith("self-attested"),
        )

    tsa_inputs = _checkpoint_tsa_receipts(body)
    tsa_receipts: list[dict[str, Any]] = []
    hex_hash = composite.removeprefix("sha256:")
    for index, receipt in enumerate(tsa_inputs, start=1):
        label = _checkpoint_receipt_label(receipt, index)
        receipt_result = {
            "provider": receipt.get("provider") if isinstance(receipt.get("provider"), str) else None,
            "url": receipt.get("url") if isinstance(receipt.get("url"), str) else None,
            "requested_at": receipt.get("requested_at") if isinstance(receipt.get("requested_at"), str) else None,
            "checked": check_tsa,
            "verified": None,
            "reason": None,
        }
        if not check_tsa:
            receipt_result["reason"] = "skipped"
            tsa_receipts.append(receipt_result)
            continue
        if not isinstance(receipt.get("receipt_b64"), str):
            reason = receipt.get("_invalid") or "receipt_b64 missing"
            receipt_result["verified"] = False
            receipt_result["reason"] = f"{label}: {reason}"
            tsa_receipts.append(receipt_result)
            return _checkpoint_base_result(
                body,
                ok=False,
                error=f"TSA: {receipt_result['reason']}",
                artifact=artifact,
                claims=[
                    _checkpoint_composite_claim(
                        verdict="supported",
                        reason_code="CHECKPOINT_COMPOSITE_HASH_SUPPORTED",
                        message="checkpoint composite_hash matches chain_heads",
                        checkpoint_id=checkpoint_id,
                    ),
                    _checkpoint_signature_claim(
                        verdict="supported",
                        reason_code="CHECKPOINT_SIGNATURE_SUPPORTED",
                        message="checkpoint signature verified",
                        key_id=artifact_key_id or _public_key_fingerprint(trusted_pub),
                    ),
                    _checkpoint_tsa_claim(tsa_receipts),
                ],
                composite_hash=composite,
                chain_heads_count=len(chain_heads_raw),
                public_key=trusted_pub,
                key_id=artifact_key_id or _public_key_fingerprint(trusted_pub),
                trust_source=trust_source,
                self_attested=trust_source.startswith("self-attested"),
                tsa_present=True,
                tsa_checked=True,
                tsa_verified=False,
                tsa_reason=receipt_result["reason"],
                tsa_url=receipt_result["url"],
                tsa_requested_at=receipt_result["requested_at"],
                tsa_receipts=tsa_receipts,
            )
        ok, reason = _verify_tsa_receipt(receipt["receipt_b64"], hex_hash)
        receipt_result["verified"] = ok
        receipt_result["reason"] = reason
        tsa_receipts.append(receipt_result)
        if not ok:
            return _checkpoint_base_result(
                body,
                ok=False,
                error=f"TSA: {label}: {reason}",
                artifact=artifact,
                claims=[
                    _checkpoint_composite_claim(
                        verdict="supported",
                        reason_code="CHECKPOINT_COMPOSITE_HASH_SUPPORTED",
                        message="checkpoint composite_hash matches chain_heads",
                        checkpoint_id=checkpoint_id,
                    ),
                    _checkpoint_signature_claim(
                        verdict="supported",
                        reason_code="CHECKPOINT_SIGNATURE_SUPPORTED",
                        message="checkpoint signature verified",
                        key_id=artifact_key_id or _public_key_fingerprint(trusted_pub),
                    ),
                    _checkpoint_tsa_claim(tsa_receipts),
                ],
                composite_hash=composite,
                chain_heads_count=len(chain_heads_raw),
                public_key=trusted_pub,
                key_id=artifact_key_id or _public_key_fingerprint(trusted_pub),
                trust_source=trust_source,
                self_attested=trust_source.startswith("self-attested"),
                tsa_present=True,
                tsa_checked=True,
                tsa_verified=False,
                tsa_reason=reason,
                tsa_url=receipt_result["url"],
                tsa_requested_at=receipt_result["requested_at"],
                tsa_receipts=tsa_receipts,
            )

    first_receipt = tsa_receipts[0] if tsa_receipts else None
    tsa_present = bool(tsa_receipts)
    tsa_checked = tsa_present and check_tsa
    tsa_verified = (
        all(receipt.get("verified") is True for receipt in tsa_receipts)
        if tsa_checked
        else None
    )
    tsa_reason = None
    if tsa_checked:
        tsa_reason = (
            f"{len(tsa_receipts)} TSA receipt(s) match composite_hash"
            if len(tsa_receipts) != 1
            else str(first_receipt.get("reason"))
        )

    success_claims = [
        _checkpoint_composite_claim(
            verdict="supported",
            reason_code="CHECKPOINT_COMPOSITE_HASH_SUPPORTED",
            message="checkpoint composite_hash matches chain_heads",
            checkpoint_id=checkpoint_id,
        ),
        _checkpoint_signature_claim(
            verdict="supported",
            reason_code="CHECKPOINT_SIGNATURE_SUPPORTED",
            message="checkpoint signature verified",
            key_id=artifact_key_id or _public_key_fingerprint(trusted_pub),
        ),
    ]
    if tsa_checked:
        success_claims.append(_checkpoint_tsa_claim(tsa_receipts))

    return _checkpoint_base_result(
        body,
        ok=True,
        artifact=artifact,
        claims=success_claims,
        composite_hash=composite,
        chain_heads_count=len(chain_heads_raw),
        public_key=trusted_pub,
        key_id=artifact_key_id or _public_key_fingerprint(trusted_pub),
        trust_source=trust_source,
        self_attested=trust_source.startswith("self-attested"),
        tsa_present=tsa_present,
        tsa_checked=tsa_checked,
        tsa_verified=tsa_verified,
        tsa_reason=tsa_reason,
        tsa_url=(
            first_receipt.get("url")
            if isinstance(first_receipt, dict)
            and isinstance(first_receipt.get("url"), str)
            else None
        ),
        tsa_requested_at=(
            first_receipt.get("requested_at")
            if isinstance(first_receipt, dict)
            and isinstance(first_receipt.get("requested_at"), str)
            else None
        ),
        tsa_receipts=tsa_receipts,
    )


def verify_checkpoint(
    checkpoint_path: str | Path,
    *,
    expected_public_key: str | None = None,
    public_key_url: str | None = None,
    key_manifest: str | None = None,
    self_attested: bool = False,
    check_tsa: bool = True,
) -> VerifyResult:
    key_manifest_source = key_manifest
    if (
        key_manifest_source is None
        and not self_attested
        and expected_public_key is None
        and public_key_url is None
    ):
        key_manifest_source = _cached_key_manifest_source() or _bundled_key_manifest_source()
    return _verify_checkpoint_core(
        checkpoint_path,
        expected_public_key=expected_public_key,
        public_key_url=public_key_url,
        key_manifest_source=key_manifest_source,
        self_attested=self_attested,
        check_tsa=check_tsa,
    )


def verify(
    export_path: str | Path,
    *,
    public_key: str | None = None,
    public_key_url: str | None = None,
    self_attested: bool = False,
    check_tsa: bool = True,
) -> VerifyResult:
    """Verify a v0.2-compatible integrity checkpoint JSON artifact.

    This preserves the historical ``python -m keel_verifier <artifact>`` and
    programmatic ``verify(path)`` surface. New signed compliance exports should
    use ``keel-verify export`` so ``--walk-events`` and ``--verify-closure`` can
    validate bundled lifecycle evidence.
    """
    return verify_checkpoint(
        export_path,
        expected_public_key=public_key,
        public_key_url=public_key_url,
        self_attested=self_attested,
        check_tsa=check_tsa,
    )


def verify_export_walk_events(export_data: bytes | str | Path) -> int:
    if isinstance(export_data, bytes):
        data = export_data
    elif isinstance(export_data, Path) or (isinstance(export_data, str) and Path(export_data).exists()):
        data = Path(export_data).read_bytes()
    else:
        data = str(export_data).encode("utf-8")
    return _walk_export_events(data)


def verify_closure_record(export_data: bytes | str | Path, *, key_manifest: str | None = None) -> int:
    if isinstance(export_data, bytes):
        data = export_data
    elif isinstance(export_data, Path) or (isinstance(export_data, str) and Path(export_data).exists()):
        data = Path(export_data).read_bytes()
    else:
        data = str(export_data).encode("utf-8")
    args = argparse.Namespace(
        key_manifest=key_manifest,
        key_manifest_url=None,
        self_attested=False,
    )
    return _verify_export_closures(data, args)


# ─── CLI plumbing ──────────────────────────────────────────────────


def _add_key_manifest_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--key-manifest",
        help=(
            "Local path to a Keel public key manifest JSON file "
            "(as returned by GET /v1/compliance/keys)."
        ),
    )
    p.add_argument(
        "--key-manifest-url",
        help=(
            "URL to fetch the key manifest from "
            "(e.g. https://api.keelapi.com/v1/compliance/keys)."
        ),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Standalone verifier for Keel trust artifacts.",
        epilog=(
            "Export mode can also walk bundled governance chain entries with "
            "--walk-events and verify permit closure records with --verify-closure."
        ),
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_export = sub.add_parser("export", help="Verify a signed compliance export.")
    p_export.add_argument("--export-file", required=True)
    p_export.add_argument("--manifest", required=True)
    p_export.add_argument("--json", action="store_true", dest="as_json")
    p_export.add_argument(
        "--walk-events",
        action="store_true",
        help=(
            "After export content hash and signature verification, parse an "
            "audit export bundle and walk bundled chain_entries."
        ),
    )
    p_export.add_argument(
        "--verify-closure",
        action="store_true",
        help=(
            "After export content hash and signature verification, verify "
            "permit.closed closure signatures and dispatch/provider/client digest "
            "consistency from bundled chain_entries."
        ),
    )
    p_export.add_argument(
        "--allow-unsigned",
        action="store_true",
        help=(
            "Allow legacy unsigned manifests after content-hash verification. "
            "Prints a warning and exits 0."
        ),
    )
    p_export.add_argument(
        "--expected-public-key",
        help="ed25519:<base64> public key the export must be signed with.",
    )
    _add_key_manifest_args(p_export)
    p_export.set_defaults(func=cmd_export)

    p_cp = sub.add_parser(
        "checkpoint", help="Verify an integrity checkpoint JSON file."
    )
    p_cp.add_argument("--checkpoint-file", required=True)
    p_cp.add_argument("--json", action="store_true", dest="as_json")
    p_cp.add_argument(
        "--expected-public-key",
        help="ed25519:<base64> public key the checkpoint must be signed with.",
    )
    p_cp.add_argument(
        "--public-key-url",
        help=(
            "URL to fetch the trust-root public key "
            "(e.g. .../v1/integrity/checkpoint-public-key)."
        ),
    )
    _add_key_manifest_args(p_cp)
    p_cp.add_argument(
        "--tsa-ca-bundle",
        help="Optional CA bundle for TSA trust-chain validation (note only).",
    )
    p_cp.set_defaults(func=cmd_checkpoint)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
