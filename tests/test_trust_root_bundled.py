from __future__ import annotations

import json
import re
from pathlib import Path

from keel_verifier.verifier import DEFAULT_TRUST_ROOT_PATH, _load_key_manifest


PERMIT_BINDING_FIXTURE_PATH = Path(__file__).parent / "fixtures" / "permit_binding_public_keys.json"


def _recorded_live_permit_binding_key_id() -> str:
    body = json.loads(PERMIT_BINDING_FIXTURE_PATH.read_text(encoding="utf-8"))

    assert body.get("purpose") == "permit_binding_signing"
    active_keys = [
        key
        for key in body.get("keys", [])
        if isinstance(key, dict) and key.get("active_to") is None
    ]

    assert len(active_keys) == 1
    key_id = active_keys[0].get("key_id")
    assert isinstance(key_id, str)
    return key_id


def test_bundled_trust_root_includes_active_permit_binding_key():
    entries = _load_key_manifest(str(DEFAULT_TRUST_ROOT_PATH))

    active_permit_keys = [
        entry
        for entry in entries
        if entry.get("purpose") == "permit_binding_signing"
        and entry.get("status") == "active"
    ]

    assert active_permit_keys
    for entry in active_permit_keys:
        assert entry.get("public_key", "").startswith("ed25519:")
        assert re.fullmatch(r"[0-9a-f]{16}", entry.get("key_id", ""))


def test_bundled_permit_binding_key_id_matches_recorded_wire_response():
    entries = _load_key_manifest(str(DEFAULT_TRUST_ROOT_PATH))

    active_permit_keys = [
        entry
        for entry in entries
        if entry.get("purpose") == "permit_binding_signing"
        and entry.get("status") == "active"
    ]

    assert len(active_permit_keys) == 1
    assert active_permit_keys[0].get("key_id") == _recorded_live_permit_binding_key_id()
