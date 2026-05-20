from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keel_verifier.verifier import (
    _adjudicate_checkpoint_scope_state_v1,
    _canonical_json_bytes,
    _legacy_dispatch,
)


ROOT = Path(__file__).resolve().parent / "fixtures" / "scope_faithfulness_corpus"
FIXTURE = ROOT / "fixtures" / "scope-faithfulness-edge-bridge-records-not-members"
SIDECAR = FIXTURE / "sidecars" / "scope-faithfulness-edge-bridge-records-not-members-checkpoint-scope-state-v1.json"
CHECKPOINT = FIXTURE / "pack" / "checkpoint.json"
TRUST_ROOT = ROOT / "trust_roots" / "step2-scope-faithfulness-trust-root.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _claim(sidecar: dict | None, checkpoint: dict | None = None):
    return _adjudicate_checkpoint_scope_state_v1(
        sidecar,
        checkpoint=checkpoint or _load(CHECKPOINT),
        key_manifest_source=str(TRUST_ROOT),
        semantics_dispatch=_legacy_dispatch(),
    ).claim


def _resign_sidecar(sidecar: dict) -> None:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("22" * 32))
    payload = json.loads(json.dumps(sidecar, sort_keys=True))
    del payload["signature"]["signature"]
    signature = key.sign(_canonical_json_bytes(payload))
    sidecar["signature"]["signature"] = "ed25519:" + base64.b64encode(signature).decode("ascii")


def test_scope_state_sidecar_signature_and_checkpoint_binding_supported() -> None:
    claim = _claim(_load(SIDECAR))
    assert claim.aggregate_verdict == "supported"
    assert claim.reason_code == "CHECKPOINT_SCOPE_STATE_SUPPORTED"


def test_scope_state_sidecar_schema_invalid_is_disproved() -> None:
    sidecar = _load(SIDECAR)
    sidecar["tree_size"] = "8"
    claim = _claim(sidecar)
    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "CHECKPOINT_SCOPE_STATE_SCHEMA_INVALID"


def test_scope_state_sidecar_signature_invalid_after_signed_field_tamper() -> None:
    sidecar = _load(SIDECAR)
    sidecar["tree_size"] += 1
    claim = _claim(sidecar)
    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "CHECKPOINT_SCOPE_STATE_SIGNATURE_INVALID"


def test_scope_state_checkpoint_mismatch_is_disproved() -> None:
    checkpoint = _load(CHECKPOINT)
    checkpoint["checkpoint_id"] = "aaaaaaaa-3333-4444-5555-666666666666"
    claim = _claim(_load(SIDECAR), checkpoint=checkpoint)
    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "CHECKPOINT_SCOPE_STATE_CHECKPOINT_MISMATCH"


def test_scope_state_key_outside_active_window_is_disproved(tmp_path: Path) -> None:
    trust = _load(TRUST_ROOT)
    for key in trust["keys"]:
        if key["purpose"] == "scope_state":
            key["valid_to"] = "2026-05-19T11:59:59Z"
    trust_path = tmp_path / "trust-root.json"
    trust_path.write_text(json.dumps(trust), encoding="utf-8")
    result = _adjudicate_checkpoint_scope_state_v1(
        _load(SIDECAR),
        checkpoint=_load(CHECKPOINT),
        key_manifest_source=str(trust_path),
        semantics_dispatch=_legacy_dispatch(),
    )
    assert result.claim.aggregate_verdict == "disproved"
    assert result.claim.reason_code == "CHECKPOINT_SCOPE_STATE_KEY_NOT_ACTIVE"


def test_scope_state_predicate_hash_mismatch_is_disproved() -> None:
    sidecar = _load(SIDECAR)
    sidecar["scope_commitments"][0]["predicate_value_hash"] = "sha256:" + "0" * 64
    _resign_sidecar(sidecar)
    claim = _claim(sidecar)
    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "CHECKPOINT_SCOPE_STATE_PREDICATE_HASH_MISMATCH"


def test_scope_state_duplicate_commitment_rejected_when_signature_valid() -> None:
    sidecar = _load(
        ROOT
        / "fixtures"
        / "scope-faithfulness-neg-sidecar-duplicate-predicate-commitment"
        / "sidecars"
        / "scope-faithfulness-neg-sidecar-duplicate-predicate-commitment-checkpoint-scope-state-v1.json"
    )
    claim = _claim(sidecar)
    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "CHECKPOINT_SCOPE_STATE_COMMITMENT_PREDICATE_DUPLICATE"
