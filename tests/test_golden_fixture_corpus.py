from __future__ import annotations

import json
import os
import sys

import pytest

from tools.run_golden_corpus import DEFAULT_CORPUS, REPO_ROOT, run_corpus


def test_public_verifier_matches_golden_fixture_corpus():
    if not DEFAULT_CORPUS.exists():
        message = (
            "keel-permit verifier-claim golden corpus is not checked out next "
            f"to keel-verifier: {DEFAULT_CORPUS}"
        )
        if os.getenv("KEEL_REQUIRE_GOLDEN_CORPUS"):
            raise FileNotFoundError(message)
        pytest.skip(message)

    report = run_corpus(
        corpus_path=DEFAULT_CORPUS,
        verifier="public",
        python_executable=sys.executable,
        verifier_root=REPO_ROOT,
    )

    mismatches = [
        result for result in report["results"] if result["status"] != "PASS"
    ]
    assert not mismatches, json.dumps(mismatches, indent=2, sort_keys=True)
    assert all(result["used_structured_verdicts"] for result in report["results"])
    assert all(not result["claim_mismatches"] for result in report["results"])
