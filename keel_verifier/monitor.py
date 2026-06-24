"""Checkpoint consistency monitor for Tier-B public surfaces."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Mapping

DEFAULT_CONSISTENCY_URL = (
    "https://api.keelapi.com/v1/integrity/checkpoints/consistency"
)
DEFAULT_STATE_PATH = Path.home() / ".keel-verifier" / "checkpoint-monitor-state.json"
PIN_SCHEMA = "keel.customer_checkpoint_pin.v1"
PROOF_TYPE = "keel.checkpoint_log.full_prefix_merkle.v1"
EMPTY_MERKLE_ROOT = (
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _hash_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _merkle_root_bytes(nodes: list[bytes]) -> bytes:
    if not nodes:
        return bytes.fromhex(EMPTY_MERKLE_ROOT.removeprefix("sha256:"))
    if len(nodes) == 1:
        return nodes[0]
    split = 1 << ((len(nodes) - 1).bit_length() - 1)
    return _hash_node(
        _merkle_root_bytes(nodes[:split]),
        _merkle_root_bytes(nodes[split:]),
    )


def merkle_root_from_leaf_hashes(leaf_hashes: list[str]) -> str:
    nodes: list[bytes] = []
    for item in leaf_hashes:
        if not isinstance(item, str) or not item.startswith("sha256:"):
            raise ValueError("leaf_hashes must be sha256-prefixed strings")
        nodes.append(bytes.fromhex(item.removeprefix("sha256:")))
    return f"sha256:{_merkle_root_bytes(nodes).hex()}"


def verify_rekor_witness(
    witness: Mapping[str, Any] | None,
    *,
    expected_artifact_hash: str | None = None,
) -> list[str]:
    if not isinstance(witness, Mapping):
        return ["missing Rekor witness"]
    errors: list[str] = []
    if witness.get("witness_type") != "rekor":
        errors.append("witness_type is not rekor")
    if witness.get("status") != "included":
        errors.append("Rekor witness is not included")
    if expected_artifact_hash is not None and witness.get("artifact_hash") != expected_artifact_hash:
        errors.append("Rekor witness artifact_hash mismatch")
    if not witness.get("rekor_uuid"):
        errors.append("Rekor witness missing uuid")
    if witness.get("log_index") is None:
        errors.append("Rekor witness missing log_index")
    return errors


def _pin_root_hash(pin: Mapping[str, Any]) -> str | None:
    value = pin.get("checkpoint_log_root_hash") or pin.get("root_hash")
    return value if isinstance(value, str) and value.startswith("sha256:") else None


def _pin_tree_size(pin: Mapping[str, Any]) -> int | None:
    value = pin.get("checkpoint_log_tree_size") or pin.get("tree_size")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def verify_consistency_surface(
    surface: Mapping[str, Any],
    *,
    customer_pin: Mapping[str, Any] | None = None,
    require_rekor: bool = False,
) -> dict[str, Any]:
    errors: list[str] = []
    proof = surface.get("proof")
    if not isinstance(proof, Mapping):
        return {"ok": False, "errors": ["missing consistency proof"]}
    if proof.get("proof_type") != PROOF_TYPE:
        errors.append("unsupported consistency proof type")
    from_size = proof.get("from_size")
    to_size = proof.get("to_size")
    leaf_hashes = proof.get("leaf_hashes")
    if (
        isinstance(from_size, bool)
        or isinstance(to_size, bool)
        or not isinstance(from_size, int)
        or not isinstance(to_size, int)
        or from_size < 0
        or to_size < from_size
    ):
        errors.append("invalid consistency proof window")
        from_size = 0
        to_size = 0
    if not isinstance(leaf_hashes, list) or len(leaf_hashes) != to_size:
        errors.append("leaf_hashes length does not match to_size")
        leaf_hashes = []

    try:
        from_root = merkle_root_from_leaf_hashes(list(leaf_hashes[:from_size]))
        to_root = merkle_root_from_leaf_hashes(list(leaf_hashes[:to_size]))
    except Exception as exc:
        errors.append(f"could not recompute Merkle roots: {exc}")
        from_root = None
        to_root = None

    if from_root is not None and proof.get("from_root_hash") != from_root:
        errors.append("from_root_hash mismatch")
    if to_root is not None and proof.get("to_root_hash") != to_root:
        errors.append("to_root_hash mismatch")

    requested_head = surface.get("requested_tree_head")
    if isinstance(requested_head, Mapping):
        if requested_head.get("tree_size") != to_size:
            errors.append("requested tree_size mismatch")
        if to_root is not None and requested_head.get("root_hash") != to_root:
            errors.append("requested root_hash mismatch")

    if customer_pin is not None:
        pinned_root = _pin_root_hash(customer_pin)
        pinned_size = _pin_tree_size(customer_pin)
        if pinned_root is None or pinned_size is None:
            errors.append("customer pin is missing checkpoint log root/size")
        elif to_size < pinned_size:
            errors.append("checkpoint log tree_size is below customer pin")
        else:
            try:
                recomputed_pin = merkle_root_from_leaf_hashes(
                    list(leaf_hashes[:pinned_size])
                )
            except Exception as exc:
                errors.append(f"could not recompute pinned root: {exc}")
            else:
                if recomputed_pin != pinned_root:
                    errors.append("customer-pinned checkpoint root mismatch")

    entries = surface.get("entries")
    if require_rekor:
        if not isinstance(entries, list):
            errors.append("entries are required for Rekor enforcement")
        else:
            for index, entry in enumerate(entries):
                if not isinstance(entry, Mapping):
                    errors.append(f"entry {index} is not an object")
                    continue
                witness = entry.get("transparency")
                errors.extend(
                    f"entry {index}: {error}"
                    for error in verify_rekor_witness(witness)
                )

    return {
        "ok": not errors,
        "errors": errors,
        "from_size": from_size,
        "to_size": to_size,
        "from_root_hash": from_root,
        "to_root_hash": to_root,
    }


def fetch_json(url: str, *, timeout: float = 10.0) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("monitor endpoint returned non-object JSON")
    return payload


def load_customer_pin(path: str | None) -> dict[str, Any] | None:
    if path is None:
        return None
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("customer pin must be a JSON object")
    if payload.get("schema") not in (None, PIN_SCHEMA):
        raise ValueError("customer pin schema is unsupported")
    return payload


def _load_state(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    if not isinstance(payload, dict):
        raise ValueError("monitor state must be a JSON object")
    return payload


def _write_state(path: Path, surface: Mapping[str, Any]) -> None:
    head = surface.get("tree_head")
    if not isinstance(head, Mapping):
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema": PIN_SCHEMA,
                "checkpoint_log_tree_size": head.get("tree_size"),
                "checkpoint_log_root_hash": head.get("root_hash"),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _state_as_pin(state: Mapping[str, Any] | None) -> Mapping[str, Any] | None:
    if state is None:
        return None
    if _pin_root_hash(state) is None or _pin_tree_size(state) is None:
        return None
    return state


def cmd_monitor(args: argparse.Namespace) -> int:
    state_path = Path(args.state_file or DEFAULT_STATE_PATH)
    customer_pin = load_customer_pin(args.pin_file)
    cycles = max(int(args.cycles), 1)
    interval = max(float(args.interval), 0.0)
    last_result: dict[str, Any] | None = None

    for cycle in range(cycles):
        previous_state = _load_state(state_path)
        previous_pin = _state_as_pin(previous_state)
        active_pin = customer_pin or previous_pin
        try:
            surface = fetch_json(args.consistency_url, timeout=float(args.timeout))
            result = verify_consistency_surface(
                surface,
                customer_pin=active_pin,
                require_rekor=bool(args.require_rekor),
            )
        except Exception as exc:
            result = {"ok": False, "errors": [str(exc)]}
            surface = None
        last_result = result
        if not result["ok"]:
            if args.as_json:
                print(json.dumps(result, indent=2, sort_keys=True))
            else:
                print("ALERT: checkpoint monitor detected divergence", file=sys.stderr)
                for error in result["errors"]:
                    print(f"  - {error}", file=sys.stderr)
            return 1
        if isinstance(surface, Mapping):
            _write_state(state_path, surface)
        if cycle != cycles - 1 and interval > 0:
            time.sleep(interval)

    if args.as_json:
        print(json.dumps(last_result or {"ok": True}, indent=2, sort_keys=True))
    else:
        print("checkpoint monitor ok")
    return 0
