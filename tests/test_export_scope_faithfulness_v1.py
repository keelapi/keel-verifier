from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from scope_faithfulness_public import (
    PUBLIC_CORPUS_AVAILABLE,
    PUBLIC_CORPUS_ROOT,
    PUBLIC_CORPUS_SKIP_REASON,
)
from keel_verifier.verifier import (
    _adjudicate_export_scope_faithfulness_v1,
    _legacy_dispatch,
    verify_export_structured,
)


pytestmark = pytest.mark.skipif(
    not PUBLIC_CORPUS_AVAILABLE,
    reason=PUBLIC_CORPUS_SKIP_REASON,
)

ROOT = PUBLIC_CORPUS_ROOT


def _report(fixture_id: str):
    pack = ROOT / "fixtures" / fixture_id / "pack"
    return verify_export_structured(
        argparse.Namespace(
            export_file=str(pack / "export.json"),
            manifest=str(pack / "manifest.json"),
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
    ).to_dict()


def _scope_claim(report: dict) -> dict:
    return next(
        claim
        for claim in report["claims"]
        if claim["name"] == "export.scope_faithfulness.v1"
    )


def test_export_scope_faithfulness_boundary_start_failure() -> None:
    claim = _scope_claim(_report("scope-faithfulness-neg-head-truncate"))
    assert claim["verdict"] == "disproved"
    assert claim["reason_code"] == "EXPORT_BOUNDARY_START_MISMATCH"


def test_export_scope_faithfulness_scope_state_short_circuit() -> None:
    report = _report("scope-faithfulness-edge-unknown-commitment-profile")
    checkpoint_claim = next(
        claim for claim in report["claims"] if claim["name"] == "checkpoint.scope_state.v1"
    )
    scope_claim = _scope_claim(report)
    assert checkpoint_claim["verdict"] == "unverifiable_scope"
    assert scope_claim["verdict"] == "unverifiable_scope"
    assert scope_claim["reason_code"] == "CHECKPOINT_SCOPE_STATE_COMMITMENT_PROFILE_UNKNOWN"


def test_export_scope_faithfulness_predicate_violation() -> None:
    claim = _scope_claim(_report("scope-faithfulness-neg-forged-predicate"))
    assert claim["verdict"] == "disproved"
    assert claim["reason_code"] == "EXPORT_SCOPE_PREDICATE_VIOLATED"


def test_export_scope_faithfulness_cardinality_preempts_root_mismatch() -> None:
    claim = _scope_claim(_report("scope-faithfulness-neg-cardinality-mismatch"))
    assert claim["verdict"] == "disproved"
    assert claim["reason_code"] == "EXPORT_SCOPE_CARDINALITY_MISMATCH"


def test_export_scope_faithfulness_recomputes_membership_root() -> None:
    claim = _scope_claim(_report("scope-faithfulness-neg-membership-root-mismatch"))
    assert claim["verdict"] == "disproved"
    assert claim["reason_code"] == "EXPORT_SCOPE_MEMBERSHIP_ROOT_MISMATCH"


def test_export_scope_faithfulness_bridge_records_are_not_members() -> None:
    claim = _scope_claim(_report("scope-faithfulness-edge-bridge-records-not-members"))
    assert claim["verdict"] == "supported"
    assert claim["reason_code"] == "EXPORT_SCOPE_FAITHFULNESS_SUPPORTED"


def test_export_scope_faithfulness_latest_policy_detects_stale_checkpoint() -> None:
    claim = _scope_claim(_report("scope-faithfulness-neg-stale-checkpoint-latest-policy"))
    assert claim["verdict"] == "disproved"
    assert claim["reason_code"] == "EXPORT_BOUNDARY_STALE_CHECKPOINT"


def test_manifest_auto_require_only_when_scope_block_present(tmp_path: Path) -> None:
    fixture = ROOT / "fixtures" / "scope-faithfulness-edge-bridge-records-not-members"
    pack = fixture / "pack"
    export_payload = json.loads((pack / "export.json").read_text(encoding="utf-8"))
    export_payload.pop("scope_faithfulness")
    export_path = tmp_path / "legacy-export.json"
    export_path.write_text(json.dumps(export_payload, sort_keys=True), encoding="utf-8")
    manifest = json.loads((pack / "manifest.json").read_text(encoding="utf-8"))
    manifest.pop("claim_set")
    manifest.pop("semantics_pins")
    manifest["content_hash"] = "sha256:" + __import__("hashlib").sha256(export_path.read_bytes()).hexdigest()
    manifest.pop("signature")
    manifest_path = tmp_path / "legacy-manifest.json"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")

    report = verify_export_structured(
        argparse.Namespace(
            export_file=str(export_path),
            manifest=str(manifest_path),
            key_manifest=str(ROOT / "trust_roots" / "step2-scope-faithfulness-trust-root.json"),
            key_manifest_url=None,
            expected_public_key=None,
            public_key=None,
            self_attested=False,
            offline=False,
            allow_unsigned=True,
            walk_events=False,
            verify_closure=False,
            as_json=True,
        )
    )
    claim_names = {claim.name for claim in report.claims}
    assert "export.scope_faithfulness.v1" not in claim_names
    assert report.ok is True


def test_export_scope_reserved_predicate_kind_is_unverifiable_scope() -> None:
    fixture = ROOT / "fixtures" / "scope-faithfulness-edge-bridge-records-not-members"
    pack = fixture / "pack"
    export_payload = json.loads((pack / "export.json").read_text(encoding="utf-8"))
    export_payload["scope_faithfulness"]["segments"][0]["declared_scope"]["predicate"] = {
        "version": "keel.scope_predicate.v1",
        "operator": "and",
        "equals": {"subject_id": "opaque-subject"},
        "ranges": {},
    }
    claims = _adjudicate_export_scope_faithfulness_v1(
        export_data=json.dumps(export_payload, sort_keys=True).encode("utf-8"),
        manifest=json.loads((pack / "manifest.json").read_text(encoding="utf-8")),
        manifest_path=pack / "manifest.json",
        key_manifest_source=str(ROOT / "trust_roots" / "step2-scope-faithfulness-trust-root.json"),
        semantics_dispatch=_legacy_dispatch(),
    )
    claim = next(claim for claim in claims if claim.name == "export.scope_faithfulness.v1")
    assert claim.aggregate_verdict == "unverifiable_scope"
    assert claim.reason_code == "EXPORT_SCOPE_PREDICATE_UNSUPPORTED"
