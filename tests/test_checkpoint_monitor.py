from __future__ import annotations

import hashlib

from conftest import write_json
from keel_verifier.monitor import (
    merkle_root_from_leaf_hashes,
    verify_consistency_surface,
)


def _leaf(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _witness() -> dict:
    return {
        "witness_type": "rekor",
        "status": "included",
        "artifact_hash": "sha256:" + "a" * 64,
        "rekor_uuid": "rekor_uuid",
        "log_index": 7,
    }


def _surface(*, with_rekor: bool = True) -> dict:
    leaves = [_leaf("one"), _leaf("two")]
    from_root = merkle_root_from_leaf_hashes(leaves[:1])
    to_root = merkle_root_from_leaf_hashes(leaves)
    entries = [
        {
            "checkpoint_id": "ckpt_1",
            "leaf_hash": leaves[0],
            "transparency": _witness() if with_rekor else None,
        },
        {
            "checkpoint_id": "ckpt_2",
            "leaf_hash": leaves[1],
            "transparency": _witness() if with_rekor else None,
        },
    ]
    return {
        "surface_version": "keel.checkpoint_consistency_surface.v1",
        "tree_head": {
            "version": "keel.checkpoint_log.v1",
            "tree_size": 2,
            "root_hash": to_root,
        },
        "requested_tree_head": {
            "version": "keel.checkpoint_log.v1",
            "tree_size": 2,
            "root_hash": to_root,
        },
        "proof": {
            "proof_type": "keel.checkpoint_log.full_prefix_merkle.v1",
            "from_size": 1,
            "to_size": 2,
            "from_root_hash": from_root,
            "to_root_hash": to_root,
            "leaf_hashes": leaves,
        },
        "entries": entries,
    }


def test_consistency_surface_verifies_full_prefix_merkle_proof() -> None:
    result = verify_consistency_surface(_surface(), require_rekor=True)

    assert result["ok"] is True
    assert result["errors"] == []


def test_consistency_surface_rejects_forked_root() -> None:
    surface = _surface()
    surface["proof"]["to_root_hash"] = "sha256:" + "0" * 64

    result = verify_consistency_surface(surface)

    assert result["ok"] is False
    assert "to_root_hash mismatch" in result["errors"]


def test_consistency_surface_requires_rekor_when_requested() -> None:
    result = verify_consistency_surface(_surface(with_rekor=False), require_rekor=True)

    assert result["ok"] is False
    assert any("missing Rekor witness" in error for error in result["errors"])


def test_customer_pin_rejects_downgraded_or_forked_view() -> None:
    surface = _surface()
    pin = {
        "schema": "keel.customer_checkpoint_pin.v1",
        "checkpoint_log_tree_size": 1,
        "checkpoint_log_root_hash": "sha256:" + "f" * 64,
    }

    result = verify_consistency_surface(surface, customer_pin=pin)

    assert result["ok"] is False
    assert "customer-pinned checkpoint root mismatch" in result["errors"]


def test_monitor_cli_fetches_surface_and_writes_customer_pin_state(
    tmp_path,
    run_cli,
) -> None:
    surface_path = write_json(tmp_path / "surface.json", _surface())
    state_path = tmp_path / "state.json"

    result = run_cli(
        "monitor",
        "--consistency-url",
        surface_path.as_uri(),
        "--state-file",
        str(state_path),
        "--cycles",
        "1",
        "--interval",
        "0",
        "--require-rekor",
        "--json",
    )

    assert result.returncode == 0, result.stderr
    assert state_path.exists()
    assert "checkpoint_log_root_hash" in state_path.read_text(encoding="utf-8")
