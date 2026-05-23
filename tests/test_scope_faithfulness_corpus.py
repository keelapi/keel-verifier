from __future__ import annotations

import argparse
import json

import pytest

from scope_faithfulness_public import (
    PROMOTED_SCOPE_FAITHFULNESS_IDS,
    PUBLIC_CORPUS_AVAILABLE,
    PUBLIC_CORPUS_ROOT,
    PUBLIC_CORPUS_SKIP_REASON,
)
from keel_verifier.verifier import verify_export_structured


pytestmark = pytest.mark.skipif(
    not PUBLIC_CORPUS_AVAILABLE,
    reason=PUBLIC_CORPUS_SKIP_REASON,
)

CORPUS_ROOT = PUBLIC_CORPUS_ROOT


def _args(record: dict) -> argparse.Namespace:
    pack = record["pack"]
    return argparse.Namespace(
        export_file=str(CORPUS_ROOT / pack["export_file"]),
        manifest=str(CORPUS_ROOT / pack["manifest"]),
        key_manifest=str(CORPUS_ROOT / pack["key_manifest"]),
        key_manifest_url=None,
        expected_public_key=None,
        public_key=None,
        self_attested=False,
        offline=False,
        allow_unsigned=False,
        walk_events=False,
        verify_closure=False,
        as_json=True,
    )


def _claim(report, name: str) -> dict:
    for claim in report.to_dict()["claims"]:
        if claim["name"] == name:
            return claim
    raise AssertionError(f"missing claim {name}")


def _promoted_records() -> list[dict]:
    corpus = json.loads((CORPUS_ROOT / "corpus.json").read_text(encoding="utf-8"))
    assert len(corpus["records"]) == 99
    records = [
        record
        for record in corpus["records"]
        if record["id"] in PROMOTED_SCOPE_FAITHFULNESS_IDS
    ]
    assert len(records) == 19
    assert {record["id"] for record in records} == PROMOTED_SCOPE_FAITHFULNESS_IDS
    return records


def test_scope_faithfulness_public_corpus_matches_spec_expectations() -> None:
    records = _promoted_records()
    for record in records:
        report = verify_export_structured(_args(record))
        expected_exit = 0 if record["expected_verdict"] == "supported" else 1
        assert report.exit_code == expected_exit, record["id"]
        claim = _claim(report, "export.scope_faithfulness.v1")
        assert claim["verdict"] == record["expected_verdict"], record["id"]
        if record["expected_code"] is not None:
            assert claim["reason_code"] == record["expected_code"], record["id"]


def test_soundness_predictions_for_three_attack_shapes_are_recorded_before_execution() -> None:
    records = _promoted_records()
    expected = {
        "scope-faithfulness-neg-head-truncate": (
            "disproved",
            "EXPORT_BOUNDARY_START_MISMATCH",
        ),
        "scope-faithfulness-neg-sidecar-duplicate-predicate-commitment": (
            "disproved",
            "CHECKPOINT_SCOPE_STATE_COMMITMENT_PREDICATE_DUPLICATE",
        ),
        "scope-faithfulness-edge-empty-scope-cardinality-zero": (
            "supported",
            None,
        ),
    }
    by_id = {record["id"]: record for record in records}
    for fixture_id, (verdict, code) in expected.items():
        record = by_id[fixture_id]
        assert record["expected_verdict"] == verdict
        assert record["expected_code"] == code
        report = verify_export_structured(_args(record))
        claim = _claim(report, "export.scope_faithfulness.v1")
        assert claim["verdict"] == verdict
        if code is not None:
            assert claim["reason_code"] == code
