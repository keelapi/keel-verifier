"""Exit-code precedence and vendored-artifact parity guards for work-chain packs."""

from __future__ import annotations

import hashlib
import os
from importlib import resources
from pathlib import Path

import pytest

from keel_verifier.work_chain import _claim, _report


def _mixed_report(first: str, second: str):
    claims = [
        _claim(
            "permit.work_authority_manifest.v1",
            subject_type="work_root",
            subject_id="00000000-0000-4000-8000-000000000000",
            verdict=first,
            code="WORK_AUTHORITY_SET_HASH_MISMATCH",
            message="synthetic",
        ),
        _claim(
            "permit.work_value_conservation.v1",
            subject_type="work_root",
            subject_id="00000000-0000-4000-8000-000000000000",
            verdict=second,
            code="WORK_VERSION_UNSUPPORTED",
            message="synthetic",
        ),
    ]
    return _report(document={}, artifact={}, claims=claims)


def test_disproved_dominates_unverifiable_scope_exit_code() -> None:
    """A pack containing disproof must exit 1 even when scope is also limited.

    Compliance consumers triage exit 2 as "out of scope / retryable"; a report
    that actually contains a disproved claim must never be masked behind it.
    """

    for order in (("disproved", "unverifiable_scope"), ("unverifiable_scope", "disproved")):
        report = _mixed_report(*order)
        document = report.to_dict()
        assert document["ok"] is False
        assert document["exit_code"] == 1, (
            f"disproved must dominate; got exit {document['exit_code']} for {order}"
        )


def test_unverifiable_scope_alone_still_exits_2() -> None:
    report = _mixed_report("unverifiable_scope", "unverifiable_scope")
    document = report.to_dict()
    assert document["ok"] is False
    assert document["exit_code"] == 2


# --- vendored artifact parity -------------------------------------------------

# vendored resource (under keel_verifier/data/) -> canonical path in keel-permit
_PARITY_MAP = {
    "permit_to_x/semantic_registry/v1.json": "semantic_registry/v1.json",
    "permit_to_x/semantic_registry/v1.schema.json": "semantic_registry/v1.schema.json",
    "permit_to_x/presentation_registry/v1.json": "presentation_registry/v1.json",
    "permit_to_x/presentation_registry/v1.schema.json": "presentation_registry/v1.schema.json",
    "permit_to_x/test_vectors/permit_to_work/v1/corpus.json": "test-vectors/permit_to_work/v1/corpus.json",
    "comparator_registry/work-payment-authority-v1.json": "comparator_registry/work-payment-authority-v1.json",
    "semantics/work/authority_manifest_v1.json": "semantics/work/authority_manifest_v1.json",
    "semantics/work/child_containment_v1.json": "semantics/work/child_containment_v1.json",
    "semantics/work/execution_authorized_at_boundary_v1.json": "semantics/work/execution_authorized_at_boundary_v1.json",
    "semantics/work/value_conservation_v1.json": "semantics/work/value_conservation_v1.json",
}


def _canonical_root() -> Path:
    env_root = os.getenv("KEEL_PERMIT_PTX_ROOT")
    if not env_root:
        message = (
            "set KEEL_PERMIT_PTX_ROOT to a keel-permit checkout to run the "
            "vendored Permit-to-X artifact parity test"
        )
        if os.getenv("KEEL_REQUIRE_GOLDEN_CORPUS"):
            raise RuntimeError(message)
        pytest.skip(message)
    root = Path(env_root).expanduser()
    if not root.exists():
        raise FileNotFoundError(f"KEEL_PERMIT_PTX_ROOT does not exist: {root}")
    return root


def test_vendored_permit_to_x_artifacts_match_canonical_source() -> None:
    """Every vendored registry/recipe/vector byte-matches keel-permit.

    Guards the cross-repo drift seam the internal self-check cannot see: the
    self-check compares installed bytes to the release manifest, so a
    coordinated regeneration of both would pass silently. This test compares
    against the canonical source of truth instead.
    """

    root = _canonical_root()
    mismatches: list[str] = []
    for vendored, canonical in _PARITY_MAP.items():
        vendored_bytes = (
            resources.files("keel_verifier.data").joinpath(vendored).read_bytes()
        )
        canonical_path = root / canonical
        if not canonical_path.is_file():
            mismatches.append(f"missing canonical file: {canonical}")
            continue
        if (
            hashlib.sha256(vendored_bytes).hexdigest()
            != hashlib.sha256(canonical_path.read_bytes()).hexdigest()
        ):
            mismatches.append(f"drift: {vendored} != {canonical}")
    assert not mismatches, "vendored Permit-to-X artifacts drifted:\n" + "\n".join(
        mismatches
    )
