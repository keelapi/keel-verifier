from __future__ import annotations

import hashlib

import rfc8785

from keel_verifier.canonical import permit_binding


def test_replay_recompute_uses_stored_binding_version_not_environment_default(
    monkeypatch,
) -> None:
    monkeypatch.setenv("KEEL_BINDING_VERSION_DEFAULT", "v5")
    payload = {"binding_version": "v4", "temperature": 1.0}

    legacy_hash = hashlib.sha256(
        permit_binding._legacy_canonical_json_v1_to_v4(payload)
    ).hexdigest()
    rfc8785_hash = hashlib.sha256(rfc8785.dumps(payload)).hexdigest()

    assert legacy_hash != rfc8785_hash
    assert permit_binding.compute_canonical_binding_hash(payload) == legacy_hash
