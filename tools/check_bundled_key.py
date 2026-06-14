"""Verify that the bundled trust root matches live Keel public endpoints."""

from __future__ import annotations

import json
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

COMPLIANCE_KEYS_URL = "https://api.keelapi.com/v1/compliance/keys"
CHECKPOINT_PUBLIC_KEY_URL = "https://api.keelapi.com/v1/integrity/checkpoint-public-key"
PERMIT_BINDING_KEYS_URL = "https://api.keelapi.com/v1/integrity/permit-binding-public-keys"
BUNDLED_PATH = (
    Path(__file__).resolve().parent.parent
    / "keel_verifier"
    / "data"
    / "trust_root.json"
)


def _fetch_json(url: str, *, attempts: int = 3, timeout: int = 20) -> dict[str, Any]:
    last_exc: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            last_exc = exc
            if attempt < attempts:
                time.sleep(attempt)
    assert last_exc is not None
    raise last_exc


def _entries_by_purpose(body: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for entry in body.get("keys", []):
        if isinstance(entry, dict) and isinstance(entry.get("purpose"), str):
            out.setdefault(entry["purpose"], []).append(entry)
    return out


def _active_entry(entries: list[dict[str, Any]]) -> dict[str, Any] | None:
    active = [entry for entry in entries if entry.get("status") == "active" or entry.get("valid_to") is None]
    return active[0] if active else None


def _normalize_permit_binding_entry(entry: dict[str, Any]) -> dict[str, Any] | None:
    key_id = entry.get("key_id")
    public_key = entry.get("public_key")
    public_key_b64 = entry.get("public_key_b64")
    if not isinstance(public_key, str) and isinstance(public_key_b64, str):
        public_key = f"ed25519:{public_key_b64.removeprefix('ed25519:')}"
    if not isinstance(key_id, str) or not isinstance(public_key, str):
        return None

    valid_to = entry.get("valid_to", entry.get("active_to"))
    return {
        "key_id": key_id,
        "public_key": public_key,
        "status": entry.get("status") or ("active" if valid_to is None else "retired"),
        "valid_from": entry.get("valid_from", entry.get("active_from")),
        "valid_to": valid_to,
    }


def _normalized_permit_binding_entries(body: dict[str, Any]) -> list[dict[str, Any]]:
    if body.get("purpose") != "permit_binding_signing":
        return []
    keys = body.get("keys")
    if not isinstance(keys, list):
        return []

    entries: list[dict[str, Any]] = []
    for entry in keys:
        if not isinstance(entry, dict):
            continue
        normalized = _normalize_permit_binding_entry(entry)
        if normalized is not None:
            entries.append(normalized)
    return entries


def main() -> int:
    if not BUNDLED_PATH.exists():
        print(f"FAIL: bundled trust root not found at {BUNDLED_PATH}", file=sys.stderr)
        return 2

    try:
        bundled = json.loads(BUNDLED_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"FAIL: bundled trust root is not valid JSON: {exc}", file=sys.stderr)
        return 2

    try:
        live_compliance = _fetch_json(COMPLIANCE_KEYS_URL)
        live_checkpoint = _fetch_json(CHECKPOINT_PUBLIC_KEY_URL)
    except Exception as exc:
        print(f"FAIL: could not fetch live trust roots: {exc}", file=sys.stderr)
        return 2

    bundled_by_purpose = _entries_by_purpose(bundled)
    live_by_purpose = _entries_by_purpose(live_compliance)

    for purpose in ("export_signing", "integrity_checkpoint"):
        bundled_active = _active_entry(bundled_by_purpose.get(purpose, []))
        live_active = _active_entry(live_by_purpose.get(purpose, []))
        if bundled_active is None or live_active is None:
            print(f"FAIL: missing active {purpose} entry", file=sys.stderr)
            return 1
        for field in ("key_id", "public_key"):
            if bundled_active.get(field) != live_active.get(field):
                print(f"FAIL: bundled {purpose}.{field} does not match live endpoint", file=sys.stderr)
                print(f"  bundled: {bundled_active.get(field)}", file=sys.stderr)
                print(f"  live:    {live_active.get(field)}", file=sys.stderr)
                return 1

    checkpoint = _active_entry(bundled_by_purpose.get("integrity_checkpoint", []))
    if checkpoint is None or checkpoint.get("public_key") != live_checkpoint.get("public_key"):
        print("FAIL: bundled integrity_checkpoint key does not match checkpoint endpoint", file=sys.stderr)
        return 1

    try:
        permit = _fetch_json(PERMIT_BINDING_KEYS_URL)
    except Exception as exc:
        print(f"WARN: could not fetch permit-binding public keys: {exc}")
    else:
        if permit.get("detail") == "Not Found":
            print("WARN: permit-binding public-key endpoint returned 404; bundled manifest has no production permit-binding key")
        elif permit.get("keys"):
            bundled_permit = bundled_by_purpose.get("permit_binding_signing", [])
            if not bundled_permit:
                print("FAIL: live permit-binding keys exist but bundled manifest has none", file=sys.stderr)
                return 1
            live_permit = _normalized_permit_binding_entries(permit)
            if not live_permit:
                print("FAIL: live permit-binding response had no normalizable keys", file=sys.stderr)
                return 1
            for live_entry in live_permit:
                matches = [
                    entry
                    for entry in bundled_permit
                    if entry.get("public_key") == live_entry.get("public_key")
                ]
                if not matches:
                    print("FAIL: live permit-binding public key is missing from bundled manifest", file=sys.stderr)
                    print(f"  live: {live_entry.get('public_key')}", file=sys.stderr)
                    return 1
                bundled_entry = matches[0]
                for field in ("key_id", "status", "valid_from", "valid_to"):
                    if bundled_entry.get(field) != live_entry.get(field):
                        print(f"FAIL: bundled permit_binding_signing.{field} does not match live endpoint", file=sys.stderr)
                        print(f"  bundled: {bundled_entry.get(field)}", file=sys.stderr)
                        print(f"  live:    {live_entry.get(field)}", file=sys.stderr)
                        return 1

    print(f"OK: bundled trust root matches {COMPLIANCE_KEYS_URL}")
    print(f"  path: {BUNDLED_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
