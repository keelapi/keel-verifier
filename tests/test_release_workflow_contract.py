from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


def test_release_checks_out_pinned_permit_contract_before_compatibility_gate() -> None:
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    checkout = workflow.index("- name: Checkout released Permit contract")
    compatibility_gate = workflow.index("- name: Gate historical compatibility corpus")

    assert checkout < compatibility_gate
    checkout_block = workflow[checkout:compatibility_gate]
    assert "repository: keelapi/keel-permit" in checkout_block
    assert "path: keel-permit" in checkout_block
    assert "ref: v1.10.0" in checkout_block
