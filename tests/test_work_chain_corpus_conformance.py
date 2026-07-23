"""Execute the canonical Permit-to-Work conformance corpus against the verifier.

The vendored corpus (``keel_verifier/data/permit_to_x/test_vectors/permit_to_work/v1``)
is the canonical cross-repo conformance surface: third parties implement against
its ``expected_failure_code`` entries. Until this module existed nothing executed
it, so implementation and corpus could drift silently.

Current empirical state (2026-07-22 review follow-up):

==============================================  ==================================  =========
case                                            shipped-verifier outcome            parity
==============================================  ==================================  =========
assembled ``valid`` pack                        WORK_SCOPE_COMMITMENT_MISSING       divergent
required-authority-missing                      WORK_SCOPE_COMMITMENT_MISSING       divergent
authority-hash-mismatch                         WORK_SCOPE_POPULATION_MISMATCH      divergent
child-binding-mismatch                          WORK_SCOPE_POPULATION_MISMATCH      divergent
settlement-evidence-missing                     WORK_SCOPE_POPULATION_MISMATCH      divergent
scope-population-count-mismatch                 as expected                         parity
scope-commitment-signature-missing              as expected                         parity
scope-commitment-signature-hash-mismatch        as expected                         parity
embedded-artifact-tampered                      as expected                         parity
==============================================  ==================================  =========

The five divergences are corpus authoring defects, not verifier bugs:

1. The corpus ships no embedded public-key manifest artifact and only
   placeholder signatures, so the assembled ``valid`` pack can never verify
   (the verifier requires exactly one key manifest and real Ed25519
   signatures — see ``tests/test_work_chain_v1.py::_build_pack`` for the
   required generation shape).
2. Mutations that alter members of a committed population do not re-commit
   the population hash, so ``WORK_SCOPE_POPULATION_MISMATCH`` fires before
   the deeper check each expectation names.

The divergent cases below assert the CORPUS expectation under
``xfail(strict=True)``: the moment keel-permit regenerates the corpus with a
key manifest, real test-key signatures, and population-consistent mutations,
these flip to XPASS and fail the suite — forcing this module to be promoted
to full-parity assertions. Do not relax ``strict``.
"""

from __future__ import annotations

import copy
import json
from importlib import resources
from pathlib import Path
from typing import Any

import pytest

from keel_verifier.work_chain import verify_work_chain_pack

_CORPUS_RESOURCE = "permit_to_x/test_vectors/permit_to_work/v1/corpus.json"

_CORPUS_REGEN_REASON = (
    "canonical corpus lacks an embedded public key manifest and real "
    "signatures, and its population-member mutations are not re-committed; "
    "keel-permit corpus regeneration required (review finding P2-1/P2-2). "
    "strict=True is the ratchet: a regenerated corpus must flip this case "
    "to a plain assertion."
)


def _load_corpus() -> dict[str, Any]:
    data = (
        resources.files("keel_verifier.data")
        .joinpath(_CORPUS_RESOURCE)
        .read_text(encoding="utf-8")
    )
    return json.loads(data)


def _resolve_ref(corpus: dict[str, Any], ref: str) -> Any:
    current: Any = corpus
    for part in ref.split("."):
        current = current[int(part)] if isinstance(current, list) else current[part]
    return copy.deepcopy(current)


def _assemble_pack(corpus: dict[str, Any]) -> dict[str, Any]:
    """Splice the ``valid`` components into the pack per the ``assembly`` map."""

    working = copy.deepcopy(corpus)
    pack = working["valid"]["pack"]
    for target, source in working["assembly"].items():
        if isinstance(source, list):
            value: Any = [_resolve_ref(working, item) for item in source]
        else:
            value = _resolve_ref(working, source)
        assert target.startswith("pack."), target
        node: Any = pack
        parts = target[len("pack.") :].split(".")
        for part in parts[:-1]:
            node = node[part]
        node[parts[-1]] = value
    return pack


_MUTATION_ROOTS = (
    "pack.",
    "work_package.",
    "authority.",
    "child_permit.",
    "value_events.",
)


def _apply_mutation(pack: dict[str, Any], mutation: dict[str, Any]) -> None:
    target = mutation["target"]
    for prefix in _MUTATION_ROOTS:
        if target.startswith(prefix):
            relative = target[len(prefix) :]
            break
    else:  # pragma: no cover - corpus contract violation
        raise AssertionError(f"unknown mutation target root: {target}")

    base: Any = {
        "pack.": pack,
        "work_package.": pack["root"]["work_package"],
        "authority.": pack["authorities"][0],
        "child_permit.": pack["child_permits"][0],
        "value_events.": pack["value_events"],
    }[prefix]

    parts = relative.split(".")
    current: Any = base
    for part in parts[:-1]:
        current = current[int(part)] if isinstance(current, list) else current[part]
    last = parts[-1]
    if mutation.get("operation") == "delete":
        if isinstance(current, list):
            current.pop(int(last))
        else:
            current.pop(last, None)
    else:
        if isinstance(current, list):
            current[int(last)] = mutation["value"]
        else:
            current[last] = mutation["value"]


def _empty_trust_root(tmp_path: Path) -> Path:
    trust_root = tmp_path / "corpus-trust-root.json"
    trust_root.write_text(
        json.dumps({"version": "keel.trust_root.v1", "keys": []}),
        encoding="utf-8",
    )
    return trust_root


def _failure_codes(pack: dict[str, Any], trust_root: Path) -> tuple[bool, set[str]]:
    report = verify_work_chain_pack(pack, trust_root=trust_root)
    document = report.to_dict() if hasattr(report, "to_dict") else dict(report.__dict__)
    codes: set[str] = set()
    for claim in document.get("claims", []):
        for subject in claim.get("subjects", []):
            code = subject.get("reason_code")
            if code:
                codes.add(code)
    return bool(document.get("ok")), codes


_PARITY_MUTATIONS = frozenset(
    {
        "scope-population-count-mismatch",
        "scope-commitment-signature-missing",
        "scope-commitment-signature-hash-mismatch",
        "embedded-artifact-tampered",
    }
)


def _mutation_params() -> list[Any]:
    corpus = _load_corpus()
    params: list[Any] = []
    for mutation in corpus["negative_mutations"]:
        mutation_id = mutation["id"]
        if mutation_id in _PARITY_MUTATIONS:
            params.append(pytest.param(mutation_id, id=mutation_id))
        else:
            params.append(
                pytest.param(
                    mutation_id,
                    id=mutation_id,
                    marks=pytest.mark.xfail(
                        strict=True, reason=_CORPUS_REGEN_REASON
                    ),
                )
            )
    return params


def test_corpus_registers_exactly_the_expected_mutations() -> None:
    corpus = _load_corpus()
    ids = {mutation["id"] for mutation in corpus["negative_mutations"]}
    assert _PARITY_MUTATIONS <= ids
    assert len(corpus["negative_mutations"]) == 8
    assert corpus["canonicalization_profile"] == "keel.canonical_json.payload.v1"


@pytest.mark.xfail(strict=True, reason=_CORPUS_REGEN_REASON)
def test_assembled_valid_corpus_pack_is_supported(tmp_path: Path) -> None:
    corpus = _load_corpus()
    pack = _assemble_pack(corpus)
    ok, codes = _failure_codes(pack, _empty_trust_root(tmp_path))
    assert ok, f"valid corpus pack must verify; got failure codes {sorted(codes)}"


@pytest.mark.parametrize("mutation_id", _mutation_params())
def test_corpus_mutation_reproduces_expected_failure_code(
    mutation_id: str, tmp_path: Path
) -> None:
    corpus = _load_corpus()
    mutation = next(
        entry
        for entry in corpus["negative_mutations"]
        if entry["id"] == mutation_id
    )
    pack = _assemble_pack(corpus)
    _apply_mutation(pack, mutation)
    ok, codes = _failure_codes(pack, _empty_trust_root(tmp_path))
    assert not ok, f"mutation {mutation_id} must not verify"
    assert mutation["expected_failure_code"] in codes, (
        f"mutation {mutation_id} expected {mutation['expected_failure_code']}, "
        f"observed {sorted(codes)}"
    )


def test_every_mutation_fails_closed(tmp_path: Path) -> None:
    """Regardless of expectation parity, no mutation may ever verify."""

    corpus = _load_corpus()
    trust_root = _empty_trust_root(tmp_path)
    for mutation in corpus["negative_mutations"]:
        pack = _assemble_pack(corpus)
        _apply_mutation(pack, mutation)
        ok, _ = _failure_codes(pack, trust_root)
        assert not ok, f"mutation {mutation['id']} unexpectedly verified"
