from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
AUDIT_SUBSET = (
    "keel_verifier/canonical/permit_binding.py",
    "keel_verifier/verifier.py",
    "keel_verifier/data/semantics/permit/decision_v1.json",
)


def _load_selector_audit():
    path = REPO_ROOT / "scripts" / "selector_audit.py"
    spec = importlib.util.spec_from_file_location("selector_audit", path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_binding_version_selector_audit_guard() -> None:
    selector_audit = _load_selector_audit()

    result = selector_audit.audit_repo(REPO_ROOT)

    assert not result.failures, selector_audit.format_failures(result)


def test_no_pending_v7_allowlist_entries_remain() -> None:
    selector_audit = _load_selector_audit()

    pending_entries = tuple(
        entry
        for entry in selector_audit.ALLOWLIST
        if entry.reason == "pending_v7_verifier_support"
    )
    assert pending_entries == ()


def test_allowlist_entries_are_required() -> None:
    selector_audit = _load_selector_audit()
    original_allowlist = selector_audit.ALLOWLIST

    for entry in original_allowlist:
        selector_audit.ALLOWLIST = tuple(
            candidate for candidate in original_allowlist if candidate != entry
        )
        try:
            result = selector_audit.audit_repo(REPO_ROOT)
        finally:
            selector_audit.ALLOWLIST = original_allowlist

        assert result.failures, (
            f"removing {entry.path} {entry.qualname or '*'} "
            f"{entry.kind or '*'} should fail selector audit"
        )


@pytest.mark.parametrize(
    ("relative_path", "needle", "replacement"),
    (
        (
            "keel_verifier/canonical/permit_binding.py",
            '"v7": canonical_binding_payload_v7,',
            "",
        ),
        (
            "keel_verifier/verifier.py",
            '"v7": _PERMIT_DECISION_V7_CANONICAL_FIELDS,',
            "",
        ),
        (
            "keel_verifier/data/semantics/permit/decision_v1.json",
            '"v7"',
            '"v6"',
        ),
    ),
)
def test_v7_selector_regressions_fail_audit(
    tmp_path: Path,
    relative_path: str,
    needle: str,
    replacement: str,
) -> None:
    selector_audit = _load_selector_audit()
    for audit_path in AUDIT_SUBSET:
        source = REPO_ROOT / audit_path
        destination = tmp_path / audit_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

    path = tmp_path / relative_path
    source_text = path.read_text(encoding="utf-8")
    assert needle in source_text
    path.write_text(source_text.replace(needle, replacement, 1), encoding="utf-8")

    result = selector_audit.audit_repo(tmp_path)

    assert result.failures
