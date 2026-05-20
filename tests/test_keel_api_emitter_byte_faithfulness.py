from __future__ import annotations

import argparse

import pytest

from scope_faithfulness_public import (
    PUBLIC_CORPUS_AVAILABLE,
    PUBLIC_CORPUS_ROOT,
    PUBLIC_CORPUS_SKIP_REASON,
)
from keel_verifier.verifier import verify_export_structured


pytestmark = pytest.mark.skipif(
    not PUBLIC_CORPUS_AVAILABLE,
    reason=PUBLIC_CORPUS_SKIP_REASON,
)

ROOT = PUBLIC_CORPUS_ROOT


def test_pr2_emitter_shape_fixture_adjudicates_through_verifier() -> None:
    fixture = ROOT / "fixtures" / "scope-faithfulness-edge-bridge-records-not-members"
    report = verify_export_structured(
        argparse.Namespace(
            export_file=str(fixture / "pack" / "export.json"),
            manifest=str(fixture / "pack" / "manifest.json"),
            key_manifest=str(ROOT / "trust_roots" / "step2-scope-faithfulness-trust-root.json"),
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
    )
    claims = {claim.name: claim.aggregate_verdict for claim in report.claims}
    assert claims["checkpoint.scope_state.v1"] == "supported"
    assert claims["export.scope_faithfulness.v1"] == "supported"
