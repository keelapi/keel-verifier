"""Tests for the ``refresh-keys`` subcommand and cache-aware trust resolution."""

from __future__ import annotations

import argparse
import base64
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keel_verifier import verifier


VALID_MANIFEST_BYTES = json.dumps(
    {
        "schema_version": 1,
        "generated_at": "2026-05-10T00:00:00Z",
        "keys": [
            {
                "key_id": "test-export-key",
                "purpose": "export_signing",
                "public_key": "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_to": None,
            },
            {
                "key_id": "test-checkpoint-key",
                "purpose": "integrity_checkpoint",
                "public_key": "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_to": None,
            },
        ],
    },
    sort_keys=True,
).encode("utf-8")


@pytest.fixture
def cache_path(tmp_path, monkeypatch):
    """Redirect the cached trust-root path into a per-test tmpdir."""
    target = tmp_path / "cache" / "trust-root.json"
    monkeypatch.setattr(verifier, "CACHED_TRUST_ROOT_PATH", target)
    return target


def _fetch_returning(payloads: dict[str, Any]):
    """Build a fake _fetch_manifest_bytes that returns per-URL bytes or raises."""

    def fake_fetch(url: str) -> bytes:
        result = payloads.get(url)
        if result is None:
            raise RuntimeError(f"unexpected URL: {url}")
        if isinstance(result, BaseException):
            raise result
        return result

    return fake_fetch


def _public_key(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "ed25519:" + base64.b64encode(raw).decode("ascii")


def _signature(private_key: Ed25519PrivateKey, message: bytes) -> str:
    return "ed25519:" + base64.b64encode(private_key.sign(message)).decode("ascii")


def _signed_api_manifest_bytes(tmp_path, monkeypatch) -> bytes:
    export_key = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)
    checkpoint_key = Ed25519PrivateKey.from_private_bytes(bytes([8]) * 32)
    export_public = _public_key(export_key)
    checkpoint_public = _public_key(checkpoint_key)
    export_key_id = verifier._public_key_fingerprint(export_public)
    keys = [
        {
            "key_id": export_key_id,
            "purpose": "export_signing",
            "public_key": export_public,
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": None,
            "status": "active",
        },
        {
            "key_id": verifier._public_key_fingerprint(checkpoint_public),
            "purpose": "integrity_checkpoint",
            "public_key": checkpoint_public,
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": None,
            "status": "active",
        },
    ]
    trust_root = {
        "schema_version": 1,
        "generated_at": "2026-05-10T00:00:00Z",
        "keys": keys,
    }
    trust_path = tmp_path / "pinned-trust-root.json"
    trust_path.parent.mkdir(parents=True, exist_ok=True)
    trust_path.write_text(json.dumps(trust_root, sort_keys=True), encoding="utf-8")
    monkeypatch.setattr(verifier, "DEFAULT_TRUST_ROOT_PATH", trust_path)

    manifest = {
        "manifest_version": "keel.public_key_manifest.v1",
        "canonicalization_profile": "keel.canonical_json.payload.v1",
        "generated_at": "2026-05-10T00:00:00Z",
        "keys": keys,
    }
    content_hash = verifier._content_hash(
        verifier._manifest_signature_payload_bytes(manifest)
    )
    manifest["manifest_signature"] = {
        "signature_type": "ed25519.content_hash.v1",
        "purpose": "export_signing",
        "key_id": export_key_id,
        "content_hash": content_hash,
        "signature": _signature(export_key, content_hash.encode("utf-8")),
    }
    return json.dumps(manifest, sort_keys=True).encode("utf-8")


def test_refresh_keys_writes_cache_from_api(monkeypatch, cache_path):
    signed_manifest = _signed_api_manifest_bytes(cache_path.parent, monkeypatch)
    monkeypatch.setattr(
        verifier,
        "_fetch_manifest_bytes",
        _fetch_returning({verifier.KEELAPI_COMPLIANCE_KEYS_URL: signed_manifest}),
    )

    rc = verifier.cmd_refresh_keys(argparse.Namespace(source="auto"))

    assert rc == 0
    assert cache_path.exists()
    body = json.loads(cache_path.read_text(encoding="utf-8"))
    assert len(body["keys"]) == 2
    assert {k["purpose"] for k in body["keys"]} == {"export_signing", "integrity_checkpoint"}


def test_refresh_keys_rejects_unsigned_api_manifest(monkeypatch, cache_path):
    monkeypatch.setattr(
        verifier,
        "_fetch_manifest_bytes",
        _fetch_returning({verifier.KEELAPI_COMPLIANCE_KEYS_URL: VALID_MANIFEST_BYTES}),
    )

    rc = verifier.cmd_refresh_keys(argparse.Namespace(source="api"))

    assert rc == 1
    assert not cache_path.exists()


def test_refresh_keys_falls_back_to_github_when_api_fails(monkeypatch, cache_path):
    signed_manifest = _signed_api_manifest_bytes(cache_path.parent, monkeypatch)
    monkeypatch.setattr(
        verifier,
        "_fetch_manifest_bytes",
        _fetch_returning(
            {
                verifier.KEELAPI_COMPLIANCE_KEYS_URL: ConnectionError("api down"),
                verifier.GITHUB_TRUST_ROOT_URL: signed_manifest,
            }
        ),
    )

    rc = verifier.cmd_refresh_keys(argparse.Namespace(source="auto"))

    assert rc == 0
    assert cache_path.exists()


def test_refresh_keys_rejects_unsigned_github_manifest(monkeypatch, cache_path):
    monkeypatch.setattr(
        verifier,
        "_fetch_manifest_bytes",
        _fetch_returning({verifier.GITHUB_TRUST_ROOT_URL: VALID_MANIFEST_BYTES}),
    )

    rc = verifier.cmd_refresh_keys(argparse.Namespace(source="github"))

    assert rc == 1
    assert not cache_path.exists()


def test_bundled_trust_root_requires_signed_github_publication_before_refresh():
    assert verifier._remote_key_manifest_requires_signature(
        verifier.GITHUB_TRUST_ROOT_URL
    )
    body = json.loads(verifier.DEFAULT_TRUST_ROOT_PATH.read_text(encoding="utf-8"))
    assert body.get("manifest_version") != "keel.public_key_manifest.v1"

    with pytest.raises(
        ValueError,
        match="public key manifests must use keel.public_key_manifest.v1",
    ):
        verifier._verify_public_key_manifest_signature(
            body,
            source=verifier.GITHUB_TRUST_ROOT_URL,
        )


def test_refresh_keys_fails_when_all_channels_fail(monkeypatch, cache_path):
    monkeypatch.setattr(
        verifier,
        "_fetch_manifest_bytes",
        _fetch_returning(
            {
                verifier.KEELAPI_COMPLIANCE_KEYS_URL: ConnectionError("api down"),
                verifier.GITHUB_TRUST_ROOT_URL: ConnectionError("github down"),
            }
        ),
    )

    rc = verifier.cmd_refresh_keys(argparse.Namespace(source="auto"))

    assert rc == 1
    assert not cache_path.exists()


def test_refresh_keys_explicit_source_github(monkeypatch, cache_path):
    signed_manifest = _signed_api_manifest_bytes(cache_path.parent, monkeypatch)
    monkeypatch.setattr(
        verifier,
        "_fetch_manifest_bytes",
        _fetch_returning({verifier.GITHUB_TRUST_ROOT_URL: signed_manifest}),
    )

    rc = verifier.cmd_refresh_keys(argparse.Namespace(source="github"))

    assert rc == 0
    assert cache_path.exists()


def test_refresh_keys_rejects_invalid_manifest(monkeypatch, cache_path):
    bad_payload = json.dumps({"keys": [{"no_public_key_here": True}]}).encode("utf-8")
    monkeypatch.setattr(
        verifier,
        "_fetch_manifest_bytes",
        _fetch_returning(
            {
                verifier.KEELAPI_COMPLIANCE_KEYS_URL: bad_payload,
                verifier.GITHUB_TRUST_ROOT_URL: bad_payload,
            }
        ),
    )

    rc = verifier.cmd_refresh_keys(argparse.Namespace(source="auto"))

    assert rc == 1
    assert not cache_path.exists()


def test_refresh_keys_rejects_empty_keys_list(monkeypatch, cache_path):
    empty = json.dumps({"keys": []}).encode("utf-8")
    monkeypatch.setattr(
        verifier,
        "_fetch_manifest_bytes",
        _fetch_returning(
            {
                verifier.KEELAPI_COMPLIANCE_KEYS_URL: empty,
                verifier.GITHUB_TRUST_ROOT_URL: empty,
            }
        ),
    )

    rc = verifier.cmd_refresh_keys(argparse.Namespace(source="auto"))

    assert rc == 1
    assert not cache_path.exists()


def test_cache_takes_precedence_over_bundled(monkeypatch, cache_path):
    """When a refreshed cache exists, _key_manifest_source_for_args returns it."""
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(VALID_MANIFEST_BYTES.decode("utf-8"), encoding="utf-8")

    ns = argparse.Namespace(key_manifest=None, key_manifest_url=None, self_attested=False)
    resolved = verifier._key_manifest_source_for_args(ns)

    assert resolved == str(cache_path)


def test_explicit_manifest_overrides_cache(monkeypatch, cache_path, tmp_path):
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(VALID_MANIFEST_BYTES.decode("utf-8"), encoding="utf-8")

    explicit = tmp_path / "pinned.json"
    explicit.write_text(VALID_MANIFEST_BYTES.decode("utf-8"), encoding="utf-8")

    ns = argparse.Namespace(
        key_manifest=str(explicit), key_manifest_url=None, self_attested=False
    )
    resolved = verifier._key_manifest_source_for_args(ns)

    assert resolved == str(explicit)


def test_self_attested_skips_cache_and_bundled(monkeypatch, cache_path):
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(VALID_MANIFEST_BYTES.decode("utf-8"), encoding="utf-8")

    ns = argparse.Namespace(key_manifest=None, key_manifest_url=None, self_attested=True)
    resolved = verifier._key_manifest_source_for_args(ns)

    assert resolved is None


def test_unknown_source_returns_usage_error(monkeypatch, cache_path):
    monkeypatch.setattr(
        verifier,
        "_fetch_manifest_bytes",
        _fetch_returning({verifier.KEELAPI_COMPLIANCE_KEYS_URL: VALID_MANIFEST_BYTES}),
    )
    rc = verifier.cmd_refresh_keys(argparse.Namespace(source="not-a-channel"))
    assert rc == 2
    assert not cache_path.exists()
