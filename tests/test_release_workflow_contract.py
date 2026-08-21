from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


def test_release_checks_out_pinned_permit_contract_before_compatibility_gate() -> None:
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    checkout = workflow.index("- name: Checkout released Permit contract")
    commit_gate = workflow.index("- name: Verify released Permit commit")
    compatibility_gate = workflow.index("- name: Gate historical compatibility corpus")

    assert checkout < commit_gate < compatibility_gate
    checkout_block = workflow[checkout:compatibility_gate]
    assert "repository: keelapi/keel-permit" in checkout_block
    assert "path: keel-permit" in checkout_block
    assert "ref: v1.21.1" in checkout_block
    assert "34f5d84f6d4a901e3b9e6e586028d1db89942817" in checkout_block
    assert '["git", "-C", "keel-permit", "rev-parse", "HEAD"]' in checkout_block
