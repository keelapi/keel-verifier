"""Drift guard for the verifier capability inventory.

Asserts that ``keel_verifier/capability/v1.json`` is consistent with the
verifier's ``CLAIM_SEMANTICS`` mapping in ``semantics.py``, bidirectionally.
"""

from __future__ import annotations

import json
from importlib import resources

import keel_verifier
from keel_verifier.semantics import CLAIM_SEMANTICS


def _load_inventory() -> dict:
    text = resources.files("keel_verifier.capability").joinpath("v1.json").read_text()
    return json.loads(text)


def _claim_names_with_status(inventory: dict, status: str) -> set[str]:
    return {c["name"] for c in inventory["claims"] if c.get("status") == status}


def test_capability_schema_version_present() -> None:
    inv = _load_inventory()
    assert inv.get("capability_schema_version") == "1.0"


def test_verifier_version_matches_package() -> None:
    inv = _load_inventory()
    assert inv["verifier"]["version"] == keel_verifier.__version__


def test_every_code_claim_is_implemented_in_inventory() -> None:
    """Every CLAIM_SEMANTICS key must be marked 'implemented' in the inventory."""
    inv = _load_inventory()
    implemented = _claim_names_with_status(inv, "implemented")
    code_claims = set(CLAIM_SEMANTICS.keys())
    missing = code_claims - implemented
    assert not missing, (
        "CLAIM_SEMANTICS contains claims that the inventory does not mark "
        f"'implemented': {sorted(missing)}"
    )


def test_every_implemented_claim_has_code_implementation() -> None:
    """Every 'implemented' claim in the inventory must exist in CLAIM_SEMANTICS."""
    inv = _load_inventory()
    implemented = _claim_names_with_status(inv, "implemented")
    code_claims = set(CLAIM_SEMANTICS.keys())
    extra = implemented - code_claims
    assert not extra, (
        "Inventory marks these claims 'implemented' but they have no "
        f"CLAIM_SEMANTICS entry: {sorted(extra)}"
    )


def test_planned_claims_have_no_code_implementation() -> None:
    """Entries with status='planned' must NOT exist in CLAIM_SEMANTICS."""
    inv = _load_inventory()
    planned = _claim_names_with_status(inv, "planned")
    code_claims = set(CLAIM_SEMANTICS.keys())
    leaks = planned & code_claims
    assert not leaks, (
        "Inventory marks these claims 'planned' but they have a CLAIM_SEMANTICS "
        "entry (must be 'implemented' or removed from the inventory): "
        f"{sorted(leaks)}"
    )


def test_inventory_claims_have_required_fields() -> None:
    inv = _load_inventory()
    required = {"name", "status", "description", "verdicts"}
    for claim in inv["claims"]:
        missing = required - claim.keys()
        assert not missing, (
            f"Inventory claim {claim.get('name', '<unnamed>')!r} missing: "
            f"{sorted(missing)}"
        )
