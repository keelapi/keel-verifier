from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from keel_verifier import semantics
from keel_verifier.verdicts import verifier_version
from keel_verifier.verifier import (
    _adjudicate_authority_revocation_temporal_v1,
    _adjudicate_permit_authority_chain_v1,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PRODUCT_ROOT = REPO_ROOT.parent
DEFAULT_CAT09_ROOT = (
    PRODUCT_ROOT
    / ".worktrees"
    / "keel-permit-authority-edges"
    / "test-vectors"
    / "vectors"
    / "cat-09-authority-edges"
)


def _cat09_root() -> Path:
    env_root = os.getenv("KEEL_PERMIT_CAT09_ROOT")
    root = Path(env_root).expanduser() if env_root else DEFAULT_CAT09_ROOT
    if not root.exists():
        message = (
            "cat-09 authority corpus is not checked out at "
            f"{root}; set KEEL_PERMIT_CAT09_ROOT to run this local corpus test"
        )
        if os.getenv("KEEL_REQUIRE_GOLDEN_CORPUS"):
            raise FileNotFoundError(message)
        pytest.skip(message)
    return root


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _fixture_dirs(root: Path) -> list[Path]:
    return sorted(path for path in root.iterdir() if path.is_dir() and path.name.startswith("09-"))


def _adjudicate(input_doc: dict[str, Any], trust_root: dict[str, Any]):
    claim_name = input_doc["claim"]["name"]
    if claim_name == "permit.authority_chain.v1":
        return _adjudicate_permit_authority_chain_v1(
            export_document=input_doc,
            trust_root=trust_root,
        )
    if claim_name == "authority.revocation_temporal.v1":
        return _adjudicate_authority_revocation_temporal_v1(
            export_document=input_doc,
            trust_root=trust_root,
        )
    raise AssertionError(f"unexpected claim in cat-09 fixture: {claim_name}")


def _claim_for_fixture(fixture_id: str):
    root = _cat09_root()
    fixture_dir = next(path for path in _fixture_dirs(root) if path.name.startswith(fixture_id))
    trust_root = _load_json(root / "trust-root.json")
    return (
        _adjudicate(_load_json(fixture_dir / "input.json"), trust_root),
        _load_json(fixture_dir / "expected.json"),
    )


def test_authority_chain_corpus_matches_expected_full_adjudication() -> None:
    root = _cat09_root()
    trust_root = _load_json(root / "trust-root.json")
    fixture_dirs = _fixture_dirs(root)

    assert len(fixture_dirs) == 47

    for fixture_dir in fixture_dirs:
        input_doc = _load_json(fixture_dir / "input.json")
        expected = _load_json(fixture_dir / "expected.json")
        claim = _adjudicate(input_doc, trust_root)

        assert expected["structural_level_only"] is False, fixture_dir.name
        assert expected["adjudication_level"] == "full", fixture_dir.name
        assert claim.aggregate_verdict == expected["expected_verdict"], fixture_dir.name
        if expected["expected_failure_code"] is None:
            assert claim.aggregate_verdict == "supported", fixture_dir.name
        else:
            assert claim.reason_code == expected["expected_failure_code"], fixture_dir.name


def test_v10_subject_type_conditioning_and_v11_order_are_pinned() -> None:
    agent_null, expected_agent_null = _claim_for_fixture("09-44")
    system_null, expected_system_null = _claim_for_fixture("09-46")
    digest_and_leaf, expected_digest_and_leaf = _claim_for_fixture("09-45")

    assert expected_agent_null["expected_failure_code"] == "authority_chain.agent_without_chain"
    assert agent_null.aggregate_verdict == "insufficient_evidence"
    assert agent_null.reason_code == "authority_chain.agent_without_chain"

    assert expected_system_null["expected_failure_code"] == "authority_chain.typed_absence"
    assert system_null.aggregate_verdict == "unverifiable_scope"
    assert system_null.reason_code == "authority_chain.typed_absence"

    assert expected_digest_and_leaf["expected_failure_code"] == "authority_chain.chain_digest_mismatch"
    assert digest_and_leaf.aggregate_verdict == "disproved"
    assert digest_and_leaf.reason_code == "authority_chain.chain_digest_mismatch"


def test_authority_chain_semantics_pin_scalar_failure_code_verdicts() -> None:
    authority_chain_path = (
        REPO_ROOT
        / "keel_verifier"
        / "data"
        / semantics.RELEASED_ARTIFACT_PATHS[semantics.PERMIT_AUTHORITY_CHAIN_ID]
    )
    revocation_path = (
        REPO_ROOT
        / "keel_verifier"
        / "data"
        / semantics.RELEASED_ARTIFACT_PATHS[semantics.AUTHORITY_REVOCATION_TEMPORAL_ID]
    )
    authority_chain = _load_json(authority_chain_path)
    revocation = _load_json(revocation_path)

    authority_failures = authority_chain["body"]["failure_codes"]
    revocation_failures = revocation["body"]["failure_codes"]

    assert len(authority_failures) == 25
    assert len(revocation_failures) == 2
    assert {
        item["code"]: item["verdict"]
        for item in authority_failures
    }["authority_chain.agent_without_chain"] == "insufficient_evidence"
    assert all(isinstance(item["verdict"], str) for item in authority_failures)
    assert all(isinstance(item["verdict"], str) for item in revocation_failures)


def test_authority_chain_verdict_outputs_render_verifier_version() -> None:
    claim, _expected = _claim_for_fixture("09-43")
    payload = claim.to_dict()

    assert payload["verifier_version"] == verifier_version()
    assert payload["reason_code"] == "authority_chain.leaf_subject_mismatch"
    assert payload["subjects"]
    assert all(subject["verifier_version"] == verifier_version() for subject in payload["subjects"])
