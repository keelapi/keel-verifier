from __future__ import annotations

import json
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
CORPUS_ROOT = (
    REPO_ROOT.parent
    / "keel-permit"
    / "test-vectors"
    / "verifier_claims"
    / "v0"
)
FIXTURE_ID = "neg-evaluated-tamper-vs-execution-completed"


def test_public_verifier_rejects_evaluated_tamper_vs_execution_completed(run_cli):
    fixture_root = CORPUS_ROOT / "fixtures" / FIXTURE_ID / "pack"
    export_path = fixture_root / "export.json"
    manifest_path = fixture_root / "manifest.json"
    key_manifest_path = CORPUS_ROOT / "trust_roots" / "step1-cross-event-trust-root.json"
    if not export_path.exists():
        pytest.skip(
            "keel-permit verifier-claim golden corpus is not checked out next "
            f"to keel-verifier: {CORPUS_ROOT}"
        )

    result = run_cli(
        "export",
        "--json",
        "--export-file",
        str(export_path),
        "--manifest",
        str(manifest_path),
        "--key-manifest",
        str(key_manifest_path),
        "--walk-events",
    )

    assert result.returncode == 1, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["ok"] is False

    chain_claim = next(
        claim
        for claim in report["claims"]
        if claim["name"] == "governance_chain.local_continuity.v1"
    )
    assert chain_claim["verdict"] == "disproved"
    assert chain_claim["reason_code"] == "WALK_PREV_HASH_DISCONTINUITY"
    assert "event_id=evt_003" in chain_claim["message"]
