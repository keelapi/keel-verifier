"""Execute the publicly shipped, synthetic Work conformance corpus.

Committed negative packs authenticate unaffected layers before exercising the
declared failure. No verifier fallback, production key, or customer evidence is
used. Canonical authoring lives in keel-permit; vendored bytes must be identical.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from importlib import resources
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from keel_verifier.work_chain import verify_work_chain_pack

_CORPUS_RESOURCE = "permit_to_x/test_vectors/permit_to_work/v1/corpus.json"


def _load_corpus() -> dict[str, Any]:
    return json.loads(resources.files("keel_verifier.data").joinpath(_CORPUS_RESOURCE).read_text())


def _assemble_pack(corpus: dict[str, Any]) -> dict[str, Any]:
    working = copy.deepcopy(corpus)
    pack = working["valid"]["pack"]
    for target, source in working["assembly"].items():

        def resolve(ref: str) -> Any:
            value = working
            for part in ref.split("."):
                value = value[int(part)] if isinstance(value, list) else value[part]
            return copy.deepcopy(value)

        value = [resolve(ref) for ref in source] if isinstance(source, list) else resolve(source)
        node = pack
        parts = target.removeprefix("pack.").split(".")
        for part in parts[:-1]:
            node = node[part]
        node[parts[-1]] = value
    return pack


def _trust_root(tmp_path: Path) -> Path:
    # Select from disclosed fixture seed independently of untrusted pack keys.
    private = Ed25519PrivateKey.from_private_bytes(bytes([49]) * 32)
    raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    entry = {
        "key_id": "sha256:" + hashlib.sha256(raw).hexdigest()[:32],
        "algorithm": "ed25519",
        "public_key": "ed25519:" + base64.b64encode(raw).decode(),
        "purpose": "export_signing",
        "status": "active",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_to": None,
    }
    root = {"version": "keel.trust_root.v1", "keys": [entry]}
    assert root == _load_corpus()["test_trust"]["trust_root"]
    path = tmp_path / "synthetic-independent-root.json"
    path.write_text(json.dumps(root))
    return path


def _failure_codes(pack: dict[str, Any], trust_root: Path) -> tuple[bool, set[str]]:
    document = verify_work_chain_pack(pack, trust_root=trust_root).to_dict()
    return bool(document["ok"]), {
        subject["reason_code"]
        for claim in document["claims"]
        for subject in claim["subjects"]
        if subject.get("reason_code")
    }


def test_corpus_registers_exactly_the_expected_mutations() -> None:
    corpus = _load_corpus()
    assert {entry["id"] for entry in corpus["negative_mutations"]} == {
        "required-authority-missing",
        "authority-hash-mismatch",
        "child-binding-mismatch",
        "settlement-evidence-missing",
        "scope-population-count-mismatch",
        "scope-commitment-signature-missing",
        "scope-commitment-signature-hash-mismatch",
        "embedded-artifact-tampered",
    }
    assert corpus["canonicalization_profile"] == "keel.canonical_json.payload.v1"


def test_assembled_valid_corpus_pack_is_supported(tmp_path: Path) -> None:
    pack = _assemble_pack(_load_corpus())
    ok, codes = _failure_codes(pack, _trust_root(tmp_path))
    assert ok, sorted(codes)


@pytest.mark.parametrize(
    "mutation", _load_corpus()["negative_mutations"], ids=lambda item: item["id"]
)
def test_corpus_mutation_reproduces_expected_failure_code(mutation: dict, tmp_path: Path) -> None:
    ok, codes = _failure_codes(mutation["pack"], _trust_root(tmp_path))
    assert not ok
    assert mutation["expected_failure_code"] in codes, sorted(codes)
    if mutation["id"] in {
        "required-authority-missing",
        "authority-hash-mismatch",
        "child-binding-mismatch",
        "settlement-evidence-missing",
    }:
        assert "WORK_SCOPE_POPULATION_MISMATCH" not in codes
        assert "WORK_SCOPE_COMMITMENT_SIGNATURE_INVALID" not in codes


def test_wrong_root_never_verifies_valid_corpus(tmp_path: Path) -> None:
    path = tmp_path / "wrong-root.json"
    path.write_text(json.dumps({"version": "keel.trust_root.v1", "keys": []}))
    ok, _ = _failure_codes(_assemble_pack(_load_corpus()), path)
    assert not ok


@pytest.mark.parametrize("part", ["scope", "permit", "key_manifest"])
def test_signature_tamper_never_verifies_corpus(part: str, tmp_path: Path) -> None:
    pack = _assemble_pack(_load_corpus())
    if part == "scope":
        pack["scope_commitment_signature"]["signature"] = (
            "ed25519:" + base64.b64encode(bytes(64)).decode()
        )
    else:
        item = next(
            artifact
            for artifact in pack["artifacts"]
            if artifact["artifact_type"]
            == (
                "keel.work_permit_evidence.v1"
                if part == "permit"
                else "keel.public_key_manifest.v1"
            )
        )
        if part == "permit":
            item["payload"]["permit_decision_binding"]["binding_signature"] = "ed25519:AAAA"
        else:
            item["payload"]["manifest_signature"]["signature"] = "ed25519:AAAA"
    ok, _ = _failure_codes(pack, _trust_root(tmp_path))
    assert not ok
