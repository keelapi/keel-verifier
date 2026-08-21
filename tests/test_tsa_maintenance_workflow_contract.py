from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
AUTHORITATIVE_WORKFLOW = WORKFLOWS / "tsa-trust-maintenance.yml"
LEGACY_WORKFLOW = WORKFLOWS / "refresh-tsa-trust.yml"


def test_only_proof_complete_tsa_refresh_workflow_remains() -> None:
    assert AUTHORITATIVE_WORKFLOW.is_file()
    assert not LEGACY_WORKFLOW.exists()

    workflow = AUTHORITATIVE_WORKFLOW.read_text(encoding="utf-8")
    required_proofs = (
        "repository: keelapi/keel-permit",
        "refresh_tsa_trust_bundle.py --dry-run",
        "generate_release_manifest.py embedded",
        "ruff check .",
        "check_historical_compatibility_corpus.py --run",
        "pytest -q tests/test_tsa_trust.py -rs",
        "pytest -q",
        "gh pr create --base main",
        "This job never merges. A human merges trust material.",
    )
    assert all(proof in workflow for proof in required_proofs)


def test_tsa_refresh_workflow_has_required_pr_permissions() -> None:
    workflow = AUTHORITATIVE_WORKFLOW.read_text(encoding="utf-8")
    assert "contents: write" in workflow
    assert "pull-requests: write" in workflow
