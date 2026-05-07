#!/usr/bin/env python3
"""Standalone Keel trust artifact verifier.

This is a self-contained verifier you can run WITHOUT cloning keel-api.
It depends only on:
    pip install cryptography

Three modes:

  1. Compliance export (manifest + payload):
       keel_verify.py export --export-file export.jsonl.gz --manifest manifest.json \\
           [--key-manifest keys.json]
           [--key-manifest-url https://api.keel.com/v1/compliance/keys]
           [--expected-public-key ed25519:...]

  2. Integrity checkpoint (raw JSON downloaded from external anchor):
       keel_verify.py checkpoint \\
           --checkpoint-file checkpoint.json \\
           [--key-manifest keys.json]
           [--key-manifest-url https://api.keel.com/v1/compliance/keys]
           [--expected-public-key ed25519:...] \\
           [--public-key-url https://api.keel.com/v1/integrity/checkpoint-public-key]

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
import hashlib
import json
import sys
import urllib.request
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:
    print(
        "ERROR: 'cryptography' is required.  Install with: pip install cryptography",
        file=sys.stderr,
    )
    sys.exit(2)


DEFAULT_TRUST_ROOT_PATH = Path(__file__).resolve().parent / "data" / "trust_root.json"
KEELAPI_COMPLIANCE_KEYS_URL = "https://api.keelapi.com/v1/compliance/keys"
KEELAPI_CHECKPOINT_PUBLIC_KEY_URL = (
    "https://api.keelapi.com/v1/integrity/checkpoint-public-key"
)


def _content_hash(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


WALK_RECORD_HASH_MISMATCH = "WALK_RECORD_HASH_MISMATCH"
WALK_PREV_HASH_DISCONTINUITY = "WALK_PREV_HASH_DISCONTINUITY"
WALK_SEQUENCE_INVERSION = "WALK_SEQUENCE_INVERSION"
WALK_UNKNOWN_CHAIN_FORMAT = "WALK_UNKNOWN_CHAIN_FORMAT"
WALK_CLOSURE_SIGNATURE_INVALID = "WALK_CLOSURE_SIGNATURE_INVALID"
WALK_CLOSURE_DIGEST_MISMATCH = "WALK_CLOSURE_DIGEST_MISMATCH"
WALK_CLOSURE_DIGEST_MISSING = "WALK_CLOSURE_DIGEST_MISSING"
WALK_CLOSURE_DISPATCH_DIGEST_MISMATCH = "WALK_CLOSURE_DISPATCH_DIGEST_MISMATCH"
WALK_UNKNOWN_CLOSURE_FORMAT = "WALK_UNKNOWN_CLOSURE_FORMAT"

PERMIT_BINDING_SIGNING_PURPOSE = "permit_binding_signing"
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


def _key_manifest_source_for_args(args: argparse.Namespace) -> str | None:
    explicit = getattr(args, "key_manifest", None) or getattr(args, "key_manifest_url", None)
    if explicit:
        return explicit
    if getattr(args, "self_attested", False):
        return None
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


def _load_audit_export_bundle_for_optional_check(
    export_data: bytes,
    *,
    label: str,
) -> tuple[dict[str, Any] | None, int | None]:
    try:
        bundle = json.loads(export_data.decode("utf-8"))
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


def _walk_export_events(export_data: bytes) -> int:
    try:
        bundle = json.loads(export_data.decode("utf-8"))
    except Exception as exc:
        return _walk_structure_fail(f"export is not JSON: {exc}")

    if not isinstance(bundle, dict):
        return _walk_structure_fail("bundle must be a JSON object")
    if bundle.get("bundle_type") != "audit_export_bundle":
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

    records = bundle.get("records")
    if not isinstance(records, list):
        return _walk_structure_fail("records must be a list")

    by_scope: dict[Any, list[dict[str, Any]]] = {}
    entries_walked = 0
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
    event_type: str,
) -> list[dict[str, Any]]:
    return [
        context
        for context in contexts
        if _entry_permit_id(context) == permit_id
        and context["entry"].get("event_type") == event_type
    ]


def _verify_closure_digest_reference(
    *,
    closure_payload: dict[str, Any],
    contexts: list[dict[str, Any]],
    permit_id: str,
    field: str,
    event_type: str,
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
        event_type=event_type,
    )
    if not candidates:
        return _walk_fail(
            WALK_CLOSURE_DIGEST_MISSING,
            f"permit_id={permit_id} missing {event_type} evidence for {field}",
        )

    candidate_values = [
        _digest_value(_entry_payload(context["entry"]).get(field))
        for context in candidates
    ]
    present_values = [value for value in candidate_values if value is not None]
    if not present_values:
        return _walk_fail(
            WALK_CLOSURE_DIGEST_MISSING,
            f"permit_id={permit_id} {event_type} evidence missing {field}",
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

    for field, event_type in (
        ("provider_response_digest_v1", "provider.response.received"),
        ("client_response_digest_v1", "client.response.delivered"),
    ):
        failure = _verify_closure_digest_reference(
            closure_payload=closure_payload,
            contexts=contexts,
            permit_id=permit_id,
            field=field,
            event_type=event_type,
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

    for field, event_type in (
        ("provider_response_digest_v1", "provider.response.received"),
        ("client_response_digest_v1", "client.response.delivered"),
    ):
        failure = _verify_closure_digest_reference(
            closure_payload=closure_payload,
            contexts=contexts,
            permit_id=permit_id,
            field=field,
            event_type=event_type,
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


def cmd_export(args: argparse.Namespace) -> int:
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
        print("WARNING: Export is unsigned (no signature in manifest).")
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


def cmd_checkpoint(args: argparse.Namespace) -> int:
    checkpoint_path = Path(args.checkpoint_file)
    if not checkpoint_path.exists():
        print(f"FAILED: Checkpoint file not found: {checkpoint_path}", file=sys.stderr)
        return 1

    cp: dict[str, Any] = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    composite_hash = cp.get("composite_hash")
    signature = cp.get("signature")
    embedded_pub = cp.get("public_key")
    chain_heads = cp.get("chain_heads") or {}
    tsa = cp.get("tsa")
    artifact_key_id = cp.get("key_id") if isinstance(cp.get("key_id"), str) else None

    if not isinstance(composite_hash, str) or not composite_hash.startswith("sha256:"):
        print("FAILED: Checkpoint missing or malformed composite_hash.", file=sys.stderr)
        return 1

    # Recompute composite_hash from chain_heads — proves the file isn't tampered
    parts = []
    for scope_key in sorted(chain_heads.keys()):
        head = chain_heads[scope_key]
        parts.append(
            f"{scope_key}:{head['sequence_number']}:{head['last_record_hash']}"
        )
    recomputed = f"sha256:{hashlib.sha256(chr(10).join(parts).encode()).hexdigest()}"
    if recomputed != composite_hash:
        print(
            f"FAILED: composite_hash does not match chain_heads.\n"
            f"  Stored:     {composite_hash}\n"
            f"  Recomputed: {recomputed}",
            file=sys.stderr,
        )
        return 1

    if not isinstance(signature, str):
        print("FAILED: Checkpoint is unsigned.", file=sys.stderr)
        return 1

    signing_time = _parse_iso_or_none(cp.get("computed_at"))

    trusted_pub, trust_source, err = _resolve_trust_key(
        artifact_pub=embedded_pub if isinstance(embedded_pub, str) else None,
        artifact_key_id=artifact_key_id,
        purpose="integrity_checkpoint",
        expected_public_key=args.expected_public_key,
        public_key_url=args.public_key_url,
        key_manifest_source=_key_manifest_source_for_args(args),
        signing_time=signing_time,
    )
    if err is not None or trusted_pub is None:
        print(f"FAILED: {err}", file=sys.stderr)
        return 1

    if isinstance(embedded_pub, str) and embedded_pub != trusted_pub:
        print(
            "FAILED: Checkpoint public_key does not match trusted key.\n"
            f"  Trusted:  {trusted_pub}\n"
            f"  In file:  {embedded_pub}",
            file=sys.stderr,
        )
        return 1

    if not _verify_ed25519(trusted_pub, composite_hash.encode("utf-8"), signature):
        print("FAILED: Checkpoint signature verification failed.", file=sys.stderr)
        return 1

    print("VERIFIED")
    print(f"  Checkpoint:   {cp.get('checkpoint_id')}")
    print(f"  Computed at:  {cp.get('computed_at')}")
    print(f"  Composite:    {composite_hash}")
    print(f"  Public key:   {trusted_pub}")
    print(f"  Key id:       {artifact_key_id or _public_key_fingerprint(trusted_pub)}")
    print(f"  Trust source: {trust_source}")
    print(f"  Chain heads:  {len(chain_heads)} scope(s)")

    # Optional TSA verification
    if isinstance(tsa, dict) and isinstance(tsa.get("receipt_b64"), str):
        hex_hash = composite_hash.removeprefix("sha256:")
        ok, reason = _verify_tsa_receipt(tsa["receipt_b64"], hex_hash)
        if ok:
            print(f"  TSA:          OK ({reason})")
            print(f"    URL:        {tsa.get('url')}")
            print(f"    Stamped at: {tsa.get('requested_at')}")
        else:
            print(f"  TSA:          FAILED ({reason})", file=sys.stderr)
            return 1
        if args.tsa_ca_bundle:
            print(
                "  NOTE: full RFC 3161 trust-chain validation against "
                f"{args.tsa_ca_bundle} is out of scope for this verifier; "
                "use openssl ts -verify for that step.",
            )
    elif tsa is not None:
        print("  TSA:          present but receipt_b64 missing — skipped")

    return 0


# ─── Programmatic and legacy checkpoint API ─────────────────────────


@dataclass
class VerifyResult:
    ok: bool
    error: str | None = None

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

    diagnostics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "error": self.error,
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
    path = Path(export_path)

    try:
        body = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return VerifyResult(ok=False, error=f"file not found: {path}")
    except json.JSONDecodeError as exc:
        return VerifyResult(ok=False, error=f"invalid JSON: {exc}")
    except Exception as exc:
        return VerifyResult(ok=False, error=f"could not read {path}: {exc}")

    if not isinstance(body, dict):
        return VerifyResult(ok=False, error="top-level JSON must be an object")

    composite = body.get("composite_hash")
    signature = body.get("signature")
    embedded_pub = body.get("public_key")
    chain_heads_raw = body.get("chain_heads") or {}
    tsa = body.get("tsa")
    artifact_key_id = body.get("key_id") if isinstance(body.get("key_id"), str) else None

    if not isinstance(composite, str) or not composite.startswith("sha256:"):
        return VerifyResult(ok=False, error="missing or malformed composite_hash")
    if not isinstance(chain_heads_raw, dict):
        return VerifyResult(ok=False, error="chain_heads must be an object")

    for scope_key, head in chain_heads_raw.items():
        if not isinstance(head, dict):
            return VerifyResult(ok=False, error=f"chain_heads[{scope_key}] must be an object")
        if not isinstance(head.get("sequence_number"), int):
            return VerifyResult(
                ok=False,
                error=f"chain_heads[{scope_key}].sequence_number must be an int",
            )
        if not isinstance(head.get("last_record_hash"), str):
            return VerifyResult(
                ok=False,
                error=f"chain_heads[{scope_key}].last_record_hash must be a string",
            )

    try:
        recomputed = _composite_hash(chain_heads_raw)
    except Exception as exc:
        return VerifyResult(ok=False, error=f"could not recompute composite_hash: {exc}")
    if recomputed != composite:
        return VerifyResult(
            ok=False,
            error=(
                "composite_hash mismatch — chain_heads have been altered\n"
                f"  stored:     {composite}\n"
                f"  recomputed: {recomputed}"
            ),
            checkpoint_id=str(body.get("checkpoint_id") or "") or None,
            composite_hash=composite,
            chain_heads_count=len(chain_heads_raw),
        )

    if not isinstance(signature, str):
        return VerifyResult(
            ok=False,
            error="export is unsigned (no signature field)",
            checkpoint_id=str(body.get("checkpoint_id") or "") or None,
            composite_hash=composite,
            chain_heads_count=len(chain_heads_raw),
        )

    if public_key is not None:
        if not public_key.startswith("ed25519:"):
            return VerifyResult(ok=False, error="--public-key must start with 'ed25519:'")
        trusted_pub = public_key
        trust_source = "user-supplied (--public-key)"
    elif public_key_url is not None:
        trusted_pub, err = _fetch_single_public_key(public_key_url)
        if err is not None or trusted_pub is None:
            return VerifyResult(
                ok=False,
                error=err or "could not resolve trust root",
                checkpoint_id=str(body.get("checkpoint_id") or "") or None,
                composite_hash=composite,
                chain_heads_count=len(chain_heads_raw),
            )
        trust_source = f"fetched from {public_key_url}"
    elif self_attested:
        if not isinstance(embedded_pub, str):
            return VerifyResult(
                ok=False,
                error="--self-attested requested but the artifact has no embedded public_key field",
            )
        trusted_pub = embedded_pub
        trust_source = "self-attested (embedded public_key)"
    else:
        signing_time = _parse_iso_or_none(body.get("computed_at"))
        trusted_pub, trust_source, err = _resolve_trust_key(
            artifact_pub=None,
            artifact_key_id=artifact_key_id,
            purpose="integrity_checkpoint",
            expected_public_key=None,
            public_key_url=None,
            key_manifest_source=_bundled_key_manifest_source(),
            signing_time=signing_time,
        )
        if err is not None or trusted_pub is None:
            return VerifyResult(
                ok=False,
                error=(err or "could not resolve bundled trust root"),
                checkpoint_id=str(body.get("checkpoint_id") or "") or None,
                composite_hash=composite,
                chain_heads_count=len(chain_heads_raw),
            )
        trust_source = trust_source.replace(
            f"key manifest ({_bundled_key_manifest_source()})", "bundled trust root"
        )

    if isinstance(embedded_pub, str) and embedded_pub != trusted_pub:
        return VerifyResult(
            ok=False,
            error=(
                "embedded public_key does not match resolved trust root\n"
                f"  trust root: {trusted_pub}\n"
                f"  embedded:   {embedded_pub}"
            ),
            checkpoint_id=str(body.get("checkpoint_id") or "") or None,
            composite_hash=composite,
            chain_heads_count=len(chain_heads_raw),
        )

    if not _verify_ed25519(trusted_pub, composite.encode("utf-8"), signature):
        return VerifyResult(
            ok=False,
            error="signature verification failed",
            checkpoint_id=str(body.get("checkpoint_id") or "") or None,
            composite_hash=composite,
            chain_heads_count=len(chain_heads_raw),
            public_key=trusted_pub,
            key_id=artifact_key_id or _public_key_fingerprint(trusted_pub),
            trust_source=trust_source,
        )

    tsa_present = isinstance(tsa, dict) and isinstance(tsa.get("receipt_b64"), str)
    tsa_checked = False
    tsa_verified: bool | None = None
    tsa_reason: str | None = None
    tsa_url: str | None = None
    tsa_requested_at: str | None = None

    if tsa_present:
        tsa_url = tsa.get("url") if isinstance(tsa.get("url"), str) else None
        tsa_requested_at = tsa.get("requested_at") if isinstance(tsa.get("requested_at"), str) else None
        if check_tsa:
            tsa_checked = True
            hex_hash = composite.removeprefix("sha256:")
            tsa_verified, tsa_reason = _verify_tsa_receipt(tsa["receipt_b64"], hex_hash)
            if not tsa_verified:
                return VerifyResult(
                    ok=False,
                    error=f"TSA: {tsa_reason}",
                    checkpoint_id=str(body.get("checkpoint_id") or "") or None,
                    computed_at=str(body.get("computed_at") or "") or None,
                    composite_hash=composite,
                    chain_heads_count=len(chain_heads_raw),
                    public_key=trusted_pub,
                    key_id=artifact_key_id or _public_key_fingerprint(trusted_pub),
                    trust_source=trust_source,
                    self_attested=trust_source.startswith("self-attested"),
                    tsa_present=True,
                    tsa_checked=True,
                    tsa_verified=False,
                    tsa_reason=tsa_reason,
                    tsa_url=tsa_url,
                    tsa_requested_at=tsa_requested_at,
                )

    return VerifyResult(
        ok=True,
        checkpoint_id=str(body.get("checkpoint_id") or "") or None,
        computed_at=str(body.get("computed_at") or "") or None,
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
        tsa_url=tsa_url,
        tsa_requested_at=tsa_requested_at,
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
            "(e.g. https://api.keel.com/v1/compliance/keys)."
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
        "--expected-public-key",
        help="ed25519:<base64> public key the export must be signed with.",
    )
    _add_key_manifest_args(p_export)
    p_export.set_defaults(func=cmd_export)

    p_cp = sub.add_parser(
        "checkpoint", help="Verify an integrity checkpoint JSON file."
    )
    p_cp.add_argument("--checkpoint-file", required=True)
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
