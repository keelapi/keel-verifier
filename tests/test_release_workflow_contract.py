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
    assert "ref: v1.24.0" in checkout_block
    assert "e6c12a1c82bce85e1a906b031dbb30d61a9c2c26" in checkout_block
    assert '["git", "-C", "keel-permit", "rev-parse", "HEAD"]' in checkout_block


def test_release_pins_the_qualification_corpus_to_the_vendored_permit_commit() -> None:
    """The corpus parity gate must compare against the commit the bytes came from.

    keel-permit fcf1176d (PR #68) adds presentation registry v25 and review
    document templates v2 and v3 on top of 9d72119f (PR #67: review document
    templates v1) and 8016036f (PR #65: selector v23, fact profiles v20 and the
    Aidbox exact-facts schema); v1.24.0 contains none of them.
    """

    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    checkout = workflow.index("- name: Checkout coordinated Permit qualification corpus")
    commit_gate = workflow.index("- name: Verify qualification corpus commit")
    corpus_gate = workflow.index("- name: Gate historical compatibility corpus")

    assert checkout < commit_gate < corpus_gate
    block = workflow[checkout:corpus_gate]
    assert "path: keel-permit-corpus" in block
    assert block.count("fcf1176d11d78099c474543ce615993eb5ecff3b") == 2
    assert "9d72119f661b33351da64d967da0b252b0384cbc" not in block
    assert "8016036f6d8da968a02de47179e4dbc7975b988b" not in block
    assert "f0af32228f9b7a9c61d575d7cbf3716462b9fe87" not in block
