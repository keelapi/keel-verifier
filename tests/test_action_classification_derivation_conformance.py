"""Conformance: the production derivation module matches the vendored corpus.

The corpus (keel.permit.action_classification_derivation.test_vectors.v1) is the
normative contract. This test executes keel_verifier.action_classification_derivation
against every vector and asserts the corpus outcome. It is the reference verifier
the four-round contract review was converged toward: the corpus decides, this
proves the implementation conforms.
"""
from __future__ import annotations

import hashlib
import json
from importlib import resources

import pytest

from keel_verifier.action_classification_derivation import (
    TrustConfig,
    canonical_pinned_registry,
    derive,
)

_CORPUS = "permit_to_x/test_vectors/action_classification_derivation/v1/corpus.json"


def _load_corpus() -> dict:
    raw = resources.files("keel_verifier").joinpath(f"data/{_CORPUS}").read_text()
    return json.loads(raw)


def _pinned_bytes() -> bytes:
    return resources.files("keel_verifier").joinpath(
        "data/permit_to_x/semantics/permit/value_movement_classification_v1.json"
    ).read_bytes()


def _trust_from_given(given: dict) -> TrustConfig:
    """Build the immutable trust store the vector describes.

    The verifier always has the pinned registry's real bytes for its own digest;
    `store` supplies byte-concrete extras for the integrity vectors.
    """
    pinned = _pinned_bytes()
    pinned_digest = "sha256:" + hashlib.sha256(pinned).hexdigest()
    resolved: dict[str, bytes] = {}
    store = {e["digest"]: e["content_utf8"].encode() for e in given.get("store", [])}
    for digest in given.get("trusted_registry_digests", []):
        if digest == pinned_digest:
            resolved[digest] = pinned
        elif digest in store:
            resolved[digest] = store[digest]
        else:
            # Trusted digest with no bytes available -> absent from the store,
            # which the algorithm treats as unavailable at resolution.
            pass
    return TrustConfig(trusted_registry_digests=resolved)


def _vector_ids():
    return [pytest.param(v, id=v["id"]) for v in _load_corpus()["vectors"]]


@pytest.mark.parametrize("vector", _vector_ids())
def test_vector_conforms(vector: dict) -> None:
    result = derive(vector["facts"], _trust_from_given(vector["given"]))
    expected = vector["expected"]["outcome"]
    assert result.outcome == expected, (
        f"{vector['id']}: got {result.outcome} ({result.reason}), want {expected}\n"
        f"trace: {result.trace}"
    )
    if expected == "valid":
        assert result.authorized_action == vector["expected"]["authorized_action"]


def test_corpus_registry_digest_matches_vendored_pinned() -> None:
    _, pinned_digest = canonical_pinned_registry()
    assert _load_corpus()["classification_registry_digest"] == pinned_digest


def test_all_four_outcomes_covered() -> None:
    outcomes = {v["expected"]["outcome"] for v in _load_corpus()["vectors"]}
    assert outcomes == {"valid", "no_derivation", "invalid", "unverifiable"}
