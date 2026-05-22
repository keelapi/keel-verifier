from __future__ import annotations

import json
import os
import sys

import pytest

from tools.run_golden_corpus import DEFAULT_CORPUS, REPO_ROOT, run_corpus

PROMOTED_STEP4_PERMIT_IDS = {
    "permit-decision-neg-bad-signature",
    "permit-decision-neg-tampered-decision",
    "permit-decision-neg-untrusted-key",
    "permit-decision-neg-canonical-payload-mismatch",
    "permit-revoked-neg-bad-signature",
    "permit-revoked-neg-project-mismatch",
    "permit-revoked-neg-effective-at-mismatch",
    "permit-revoked-neg-missing-field",
    "permit-revoked-neg-actor-pii-detected",
    "dispatch-absence-after-revocation-neg-post-revocation-dispatch-present",
    "dispatch-absence-after-revocation-neg-bridge-record-matches-predicate",
    "dispatch-absence-after-revocation-neg-predicate-out-of-grammar",
    "dispatch-absence-after-revocation-neg-missing-checkpoint",
    "dispatch-absence-after-revocation-neg-missing-sidecar",
    "dispatch-absence-after-revocation-edge-pre-revocation-dispatch-supported",
    "dispatch-absence-after-revocation-edge-empty-scope-supported",
    "dispatch-absence-after-revocation-neg-occurred-at-equals-effective-at",
}


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
    assert report["total"] == 99

    mismatches = [
        result for result in report["results"] if result["status"] != "PASS"
    ]
    assert not mismatches, json.dumps(mismatches, indent=2, sort_keys=True)
    assert all(result["used_structured_verdicts"] for result in report["results"])
    assert all(not result["claim_mismatches"] for result in report["results"])


def test_step4_permit_corpus_promotion_is_present():
    if not DEFAULT_CORPUS.exists():
        message = (
            "keel-permit verifier-claim golden corpus is not checked out next "
            f"to keel-verifier: {DEFAULT_CORPUS}"
        )
        if os.getenv("KEEL_REQUIRE_GOLDEN_CORPUS"):
            raise FileNotFoundError(message)
        pytest.skip(message)

    corpus = json.loads(DEFAULT_CORPUS.read_text(encoding="utf-8"))
    ids = {record["id"] for record in corpus["records"]}
    assert PROMOTED_STEP4_PERMIT_IDS <= ids
