from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from keel_verifier import verifier
from scripts.check_release_trust_root import validate_release_trust_root


ROOT = Path(__file__).resolve().parents[1]
TRUST_ROOT = ROOT / "keel_verifier" / "data" / "trust_root.json"


def _bundled_trust_root() -> dict:
    return json.loads(TRUST_ROOT.read_text(encoding="utf-8"))


def _unsigned_manifest() -> dict:
    manifest = copy.deepcopy(_bundled_trust_root())
    manifest.pop("manifest_version", None)
    manifest.pop("manifest_signature", None)
    return manifest


def _test_signed_manifest() -> dict:
    manifest = copy.deepcopy(_bundled_trust_root())
    manifest["manifest_version"] = "keel.public_key_manifest.v1"
    manifest["canonicalization_profile"] = "keel.canonical_json.payload.v1"
    manifest["keys"].append(
        {
            "key_id": "sha256:defe6330f78fcc11efd0fb28614f0d29",
            "algorithm": "ed25519",
            "public_key": "ed25519:kaKKC3Q4FZOk2UaVeSCJJq/IrYLIg5t2RDWbnrqaSzo=",
            "purpose": "export_signing",
            "status": "retired",
            "valid_from": "2026-05-08T00:00:00Z",
            "valid_to": "2026-05-08T00:10:00Z",
        }
    )
    content_hash = verifier._content_hash(
        verifier._manifest_signature_payload_bytes(manifest)
    )
    manifest["manifest_signature"] = {
        "signature_type": "ed25519.content_hash.v1",
        "purpose": "export_signing",
        "key_id": "sha256:defe6330f78fcc11efd0fb28614f0d29",
        "content_hash": content_hash,
        "signature": "ed25519:" + "A" * 88,
    }
    return manifest


def test_release_trust_root_gate_rejects_unsigned_bundled_anchor() -> None:
    with pytest.raises(ValueError, match="keel.public_key_manifest.v1"):
        validate_release_trust_root(
            _unsigned_manifest(),
            source=verifier.GITHUB_TRUST_ROOT_URL,
        )


def test_release_trust_root_gate_rejects_test_signed_manifest() -> None:
    with pytest.raises(ValueError, match="allowlisted real export_signing key"):
        validate_release_trust_root(
            _test_signed_manifest(),
            source=verifier.GITHUB_TRUST_ROOT_URL,
        )
