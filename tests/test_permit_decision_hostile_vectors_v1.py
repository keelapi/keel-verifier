"""Adversarial vectors for the permit decision-binding surface.

The golden vectors in ``permit_decision_binding_golden_vectors_v1_v7.json`` are
all positive: they show the binding being accepted. This module exercises the
refusal half from a published corpus, so a third party can watch the binding
fail without reading the test suite.

Each record derives from a golden vector by declared mutation. The corpus
distinguishes four verdict tiers, and the distinction is the point: ``disproved``
says the artifact is bad, while ``insufficient_evidence`` and
``unverifiable_scope`` say the verifier cannot decide. A relying party must not
collapse the latter two into either a pass or an accusation.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from conftest import write_json
from keel_verifier.canonical import permit_binding
from keel_verifier.verifier import (
    _adjudicate_permit_decision_v1,
    _binding_key_id_from_public_key,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
GOLDEN_PATH = FIXTURES_DIR / "permit_decision_binding_golden_vectors_v1_v7.json"
HOSTILE_PATH = FIXTURES_DIR / "permit_decision_binding_hostile_vectors_v1.json"

GOLDEN = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
HOSTILE = json.loads(HOSTILE_PATH.read_text(encoding="utf-8"))


def _published_keys() -> list[str]:
    return [GOLDEN["binding_public_key"], *GOLDEN["additional_binding_public_keys"]]


def _trust_root(tmp_path: Path, mode: str) -> str:
    if mode == "absent":
        return str(tmp_path / "trust-root-does-not-exist.json")
    if mode == "all_published_keys":
        keys = _published_keys()
    elif mode == "primary_key_only":
        keys = [GOLDEN["binding_public_key"]]
    elif mode == "empty":
        keys = []
    else:  # pragma: no cover - guards fixture typos
        raise AssertionError(f"unknown trust_root mode: {mode}")
    return str(
        write_json(
            tmp_path / f"trust-root-{mode}.json",
            {
                "keys": [
                    {
                        "key_id": _binding_key_id_from_public_key(public_key),
                        "algorithm": "ed25519",
                        "public_key": public_key,
                        "purpose": "permit_binding_signing",
                        "status": "active",
                        "valid_from": "2026-01-01T00:00:00Z",
                        "valid_to": None,
                    }
                    for public_key in keys
                ]
            },
        )
    )


def _golden_artifact(binding_version: str) -> dict[str, Any]:
    for item in GOLDEN["vectors"]:
        if item["binding_version"] == binding_version:
            return copy.deepcopy(item["artifact"])
    raise AssertionError(f"no golden vector for binding_version {binding_version}")


def _resolve_parent(artifact: dict[str, Any], path: str) -> tuple[dict[str, Any], str]:
    node: Any = artifact
    parts = path.split(".")
    for part in parts[:-1]:
        node = node[part]
    return node, parts[-1]


def _apply(artifact: dict[str, Any], mutation: dict[str, Any]) -> dict[str, Any]:
    op = mutation["op"]
    if op == "set":
        parent, leaf = _resolve_parent(artifact, mutation["path"])
        parent[leaf] = mutation["value"]
    elif op == "delete":
        parent, leaf = _resolve_parent(artifact, mutation["path"])
        del parent[leaf]
    elif op == "recompute_binding_hash":
        artifact["binding_canonical_hash"] = hashlib.sha256(
            permit_binding.canonical_binding_bytes(
                artifact["binding_version"], artifact["canonical_payload"]
            )
        ).hexdigest()
    elif op == "copy_field_from_vector":
        donor = _golden_artifact(mutation["from_binding_version"])
        parent, leaf = _resolve_parent(artifact, mutation["path"])
        donor_parent, donor_leaf = _resolve_parent(donor, mutation["path"])
        parent[leaf] = donor_parent[donor_leaf]
    elif op == "flip_signature_byte":
        raw = bytearray(
            base64.b64decode(
                artifact["binding_signature"].removeprefix("ed25519:"), validate=True
            )
        )
        raw[mutation["index"]] ^= 0xFF
        artifact["binding_signature"] = "ed25519:" + base64.b64encode(bytes(raw)).decode()
    else:  # pragma: no cover - guards fixture typos
        raise AssertionError(f"unknown mutation op: {op}")
    return artifact


def _build(record: dict[str, Any]) -> dict[str, Any]:
    artifact = _golden_artifact(record["base_binding_version"])
    for mutation in record["mutations"]:
        artifact = _apply(artifact, mutation)
    return artifact


@pytest.mark.parametrize(
    "record", HOSTILE["records"], ids=[r["id"] for r in HOSTILE["records"]]
)
def test_decision_binding_hostile_vector(record: dict[str, Any], tmp_path: Path) -> None:
    claim = _adjudicate_permit_decision_v1(
        export_document={"permit_decision": _build(record)},
        key_manifest_source=_trust_root(tmp_path, record["trust_root"]),
    )
    assert claim.aggregate_verdict == record["expected_verdict"], record["note"]
    assert claim.reason_code == record["expected_code"], record["note"]


def test_hostile_corpus_covers_every_verdict_tier() -> None:
    """Guard against the corpus silently degrading back to all-positive.

    The gap this module closes was not missing enforcement — it was a published
    corpus in which every record passed. If a future edit removes the refusal or
    the cannot-decide records, that regression must fail loudly here.
    """

    verdicts = {record["expected_verdict"] for record in HOSTILE["records"]}
    assert verdicts == set(HOSTILE["verdict_tiers"])
    assert {record["expected_code"] for record in HOSTILE["records"]} >= {
        "PERMIT_DECISION_CANONICAL_HASH_MISMATCH",
        "PERMIT_DECISION_SIGNATURE_INVALID",
        "PERMIT_DECISION_TRUST_ROOT_UNRESOLVABLE",
        "PERMIT_DECISION_UNSUPPORTED_BINDING_VERSION",
    }


def test_cannot_decide_is_not_reported_as_tampering(tmp_path: Path) -> None:
    """The SYNC-style distinction, asserted directly.

    An intact artifact with no trust root must not be reported the same way as a
    forged one. Collapsing the two is how a verifier either fails open or
    slanders a good artifact.
    """

    intact = _golden_artifact("v1")
    forged = _apply(_golden_artifact("v1"), {"op": "flip_signature_byte", "index": 0})

    no_trust = _adjudicate_permit_decision_v1(
        export_document={"permit_decision": intact},
        key_manifest_source=_trust_root(tmp_path, "absent"),
    )
    tampered = _adjudicate_permit_decision_v1(
        export_document={"permit_decision": forged},
        key_manifest_source=_trust_root(tmp_path, "all_published_keys"),
    )

    assert no_trust.aggregate_verdict == "insufficient_evidence"
    assert tampered.aggregate_verdict == "disproved"
    assert no_trust.aggregate_verdict != tampered.aggregate_verdict


def _discover_decision_artifacts() -> list[tuple[str, dict[str, Any]]]:
    """Every permit_decision_binding artifact shipped in the repo's fixtures."""

    found: list[tuple[str, dict[str, Any]]] = []

    def walk(node: Any, source: str) -> None:
        if isinstance(node, dict):
            if node.get("artifact_type") == "permit_decision_binding" and isinstance(
                node.get("canonical_payload"), dict
            ):
                found.append((source, node))
            for value in node.values():
                walk(value, source)
        elif isinstance(node, list):
            for value in node:
                walk(value, source)

    for path in sorted(FIXTURES_DIR.rglob("*.json")):
        try:
            walk(json.loads(path.read_text(encoding="utf-8")), str(path.name))
        except (ValueError, UnicodeDecodeError):
            continue
    return found


def test_every_envelope_payload_duplicate_is_enforced() -> None:
    """The check must track the artifact format, not a hand-picked pair of fields.

    If a future binding version restates another signed field in the envelope, that
    field is unauthenticated the moment it exists. This fails then, rather than after
    someone notices in review.
    """

    from keel_verifier.verifier import _PERMIT_DECISION_ENVELOPE_PAYLOAD_DUPLICATES

    duplicated: set[str] = set()
    for _source, artifact in _discover_decision_artifacts():
        payload = artifact["canonical_payload"]
        duplicated |= {
            key
            for key in set(artifact) & set(payload)
            if key != "canonical_payload"
        }

    unenforced = duplicated - set(_PERMIT_DECISION_ENVELOPE_PAYLOAD_DUPLICATES)
    assert not unenforced, (
        "envelope fields restate signed canonical_payload values but are not "
        f"checked for agreement: {sorted(unenforced)}"
    )


def test_shipped_artifacts_satisfy_the_new_invariant() -> None:
    """Backward-compatibility gate.

    Tightening acceptance is only safe if no legitimate artifact already violates the
    rule. This asserts that over every fixture in the repo, including the SHA-pinned
    historical compatibility corpus.
    """

    from keel_verifier.verifier import _PERMIT_DECISION_ENVELOPE_PAYLOAD_DUPLICATES

    violations = [
        (source, field, artifact.get(field), artifact["canonical_payload"].get(field))
        for source, artifact in _discover_decision_artifacts()
        for field in _PERMIT_DECISION_ENVELOPE_PAYLOAD_DUPLICATES
        if artifact.get(field) is not None
        and artifact.get(field) != artifact["canonical_payload"].get(field)
    ]
    assert not violations, f"pre-existing artifacts violate the new invariant: {violations}"
