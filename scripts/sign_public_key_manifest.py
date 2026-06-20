#!/usr/bin/env python3
"""Sign the GitHub-served public-key manifest.

Production releases must run this with ``KEEL_EXPORT_SIGNING_KEY`` set by the
Christian/key-ops export-signing flow.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import urllib.request
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keel_verifier import verifier

REKOR_ENTRY_KIND = "hashedrekord"
REKOR_WITNESS_VERSION = "keel.rekor_witness.v1"


def _error(message: str) -> SystemExit:
    return SystemExit(f"error: {message}")


def _public_key(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "ed25519:" + base64.b64encode(raw).decode("ascii")


def _signature(private_key: Ed25519PrivateKey, message: bytes) -> str:
    return "ed25519:" + base64.b64encode(private_key.sign(message)).decode("ascii")


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _private_key_from_env() -> Ed25519PrivateKey:
    raw = os.getenv("KEEL_EXPORT_SIGNING_KEY")
    if not raw:
        raise _error("KEEL_EXPORT_SIGNING_KEY is required")
    try:
        seed = base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise _error("KEEL_EXPORT_SIGNING_KEY must be base64 Ed25519 seed bytes") from exc
    if len(seed) != 32:
        raise _error("KEEL_EXPORT_SIGNING_KEY must decode to exactly 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(seed)


def _load_manifest(path: Path) -> dict[str, Any]:
    body = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(body, dict):
        raise _error(f"{path} must contain a JSON object")
    keys = body.get("keys")
    if not isinstance(keys, list) or not keys:
        raise _error(f"{path} must contain a non-empty keys list")
    return body


def _signer_key_id_for_public_key(manifest: dict[str, Any], public_key: str) -> str:
    matches = [
        entry
        for entry in manifest["keys"]
        if isinstance(entry, dict)
        and entry.get("purpose") == "export_signing"
        and entry.get("public_key") == public_key
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("key_id"), str):
        raise _error(
            "manifest must contain exactly one export_signing key matching "
            "KEEL_EXPORT_SIGNING_KEY"
        )
    return matches[0]["key_id"]


def _remove_scaffold_keys(manifest: dict[str, Any]) -> None:
    manifest["keys"] = [
        entry
        for entry in manifest["keys"]
        if not (
            isinstance(entry, dict)
            and entry.get("metadata", {}).get("release_scaffold_only") is True
        )
    ]


def _signed_manifest(
    manifest: dict[str, Any],
    *,
    private_key: Ed25519PrivateKey,
    signer_key_id: str,
) -> dict[str, Any]:
    signed = dict(manifest)
    signed["manifest_version"] = "keel.public_key_manifest.v1"
    signed["canonicalization_profile"] = "keel.canonical_json.payload.v1"
    signed["publication_note"] = (
        "GitHub trust-root publications must be signed by export_signing. "
        "Before production publish, Christian/key-ops re-runs "
        "scripts/sign_public_key_manifest.py with the real KEEL_EXPORT_SIGNING_KEY."
    )
    signed.pop("publication_scaffold", None)

    signed.pop("manifest_signature", None)
    content_hash = verifier._content_hash(
        verifier._manifest_signature_payload_bytes(signed)
    )
    signed["manifest_signature"] = {
        "signature_type": "ed25519.content_hash.v1",
        "purpose": "export_signing",
        "key_id": signer_key_id,
        "content_hash": content_hash,
        "signature": _signature(private_key, content_hash.encode("utf-8")),
    }
    return signed


def _rekor_enabled() -> bool:
    return os.getenv("KEEL_REKOR_ENABLED", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _rekor_url() -> str:
    return (os.getenv("KEEL_REKOR_URL") or "https://rekor.sigstore.dev").rstrip("/")


def _rekor_entry_for_hash(content_hash: str) -> dict[str, Any]:
    return {
        "apiVersion": "0.0.1",
        "kind": REKOR_ENTRY_KIND,
        "spec": {
            "data": {
                "hash": {
                    "algorithm": "sha256",
                    "value": content_hash.removeprefix("sha256:"),
                }
            }
        },
    }


def _anchor_manifest_in_rekor(signed: dict[str, Any]) -> dict[str, Any] | None:
    if not _rekor_enabled():
        return None
    content_hash = signed["manifest_signature"]["content_hash"]
    entry = _rekor_entry_for_hash(content_hash)
    request = urllib.request.Request(
        f"{_rekor_url()}/api/v1/log/entries",
        data=_canonical_json_bytes(entry),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    timeout = float(os.getenv("KEEL_REKOR_TIMEOUT_S") or "10")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict) or not payload:
        raise _error("Rekor response must be a non-empty JSON object")
    rekor_uuid, rekor_entry = next(iter(payload.items()))
    if not isinstance(rekor_entry, dict):
        raise _error("Rekor response entry must be a JSON object")
    verification = rekor_entry.get("verification")
    inclusion_proof = (
        verification.get("inclusionProof") if isinstance(verification, dict) else None
    )
    witness: dict[str, Any] = {
        "witness_version": REKOR_WITNESS_VERSION,
        "witness_type": "rekor",
        "status": "included",
        "log_url": _rekor_url(),
        "entry_kind": REKOR_ENTRY_KIND,
        "artifact_type": "keel.public_key_manifest.v1",
        "artifact_hash": content_hash,
        "rekor_uuid": str(rekor_uuid),
        "log_index": rekor_entry.get("logIndex"),
        "integrated_time": rekor_entry.get("integratedTime"),
        "log_id": rekor_entry.get("logID"),
    }
    if isinstance(inclusion_proof, dict):
        witness["inclusion_proof"] = inclusion_proof
    return witness


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sign a keel.public_key_manifest.v1 trust-root manifest."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("keel_verifier/data/trust_root.json"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("keel_verifier/data/trust_root.json"),
    )
    args = parser.parse_args()

    manifest = _load_manifest(args.input)
    _remove_scaffold_keys(manifest)
    private_key = _private_key_from_env()
    public_key = _public_key(private_key)
    signer_key_id = _signer_key_id_for_public_key(manifest, public_key)

    signed = _signed_manifest(
        manifest,
        private_key=private_key,
        signer_key_id=signer_key_id,
    )
    witness = _anchor_manifest_in_rekor(signed)
    if witness is not None:
        signed["transparency"] = witness
    verification_source = (
        str(verifier.DEFAULT_TRUST_ROOT_PATH)
        if args.output.resolve() == verifier.DEFAULT_TRUST_ROOT_PATH.resolve()
        else str(args.output)
    )
    verifier._verify_public_key_manifest_signature(signed, source=verification_source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(signed, indent=2, sort_keys=True) + "\n")
    print(f"wrote signed public-key manifest: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
