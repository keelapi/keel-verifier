"""Drift guard for the verifier capability inventory.

Asserts that ``keel_verifier/capability/v1.json`` is consistent with the
verifier's ``CLAIM_SEMANTICS`` mapping in ``semantics.py``, bidirectionally.
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

import keel_verifier
from keel_verifier.semantics import CLAIM_SEMANTICS, RELEASED_ARTIFACT_HASHES


REPO_ROOT = Path(__file__).resolve().parents[1]
CLAIM_REGISTRY = REPO_ROOT / "keel_verifier" / "data" / "claim_registry" / "v0.json"
STEP4_FAILURE_CODES = {
    "PERMIT_DECISION_EVIDENCE_MISSING",
    "PERMIT_DECISION_SCHEMA_INVALID",
    "PERMIT_DECISION_CANONICAL_HASH_MISMATCH",
    "PERMIT_DECISION_CANONICAL_PAYLOAD_MISMATCH",
    "PERMIT_DECISION_SIGNATURE_INVALID",
    "PERMIT_DECISION_TRUST_ROOT_UNRESOLVABLE",
    "PERMIT_DECISION_KEY_ID_MISMATCH",
    "PERMIT_DECISION_UNTRUSTED_KEY",
    "PERMIT_DECISION_UNSUPPORTED_BINDING_VERSION",
    "PERMIT_REVOKED_EVIDENCE_MISSING",
    "PERMIT_REVOKED_SCHEMA_INVALID",
    "PERMIT_REVOKED_SIGNATURE_INVALID",
    "PERMIT_REVOKED_TRUST_ROOT_UNRESOLVABLE",
    "PERMIT_REVOKED_PROJECT_ID_MISMATCH",
    "PERMIT_REVOKED_PERMIT_ID_MISMATCH",
    "PERMIT_REVOKED_EFFECTIVE_AT_MISMATCH",
    "PERMIT_REVOKED_ACTOR_PII_DETECTED",
    "PERMIT_REVOKED_ACTOR_KIND_UNSUPPORTED",
    "EXPORT_SCOPE_PREDICATE_OUT_OF_GRAMMAR",
    "EXPORT_SCOPE_POST_REVOCATION_DISPATCH_PRESENT",
    "EXPORT_SCOPE_BRIDGE_RECORD_MATCHES_PREDICATE",
}


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


def test_capability_versions() -> None:
    inv = _load_inventory()
    assert inv["verifier"]["version"] == "2.4.0"
    assert inv["spec_compatibility"]["permit_spec_version"] == "1.4.1"


def test_step4_claims_and_failure_codes_advertised() -> None:
    inv = _load_inventory()
    implemented = _claim_names_with_status(inv, "implemented")
    assert {
        "permit.decision.v1",
        "permit.revoked.v1",
        "permit.dispatch_absence_after_revocation.v1",
    } <= implemented
    codes = set(inv["failure_codes"]["implemented_subset"])
    assert STEP4_FAILURE_CODES <= codes


def test_inventory_claims_match_claim_registry() -> None:
    inv = _load_inventory()
    registry = json.loads(CLAIM_REGISTRY.read_text(encoding="utf-8"))
    inventory_claims = {claim["name"] for claim in inv["claims"]}
    registry_claims = {claim["name"] for claim in registry["claims"]}
    assert inventory_claims == registry_claims


def test_inventory_pinned_semantics_match_allowlist_hashes() -> None:
    inv = _load_inventory()
    inventory_pins = {pin["id"]: pin["hash"] for pin in inv["pinned_semantics"]}
    referenced = {
        semantic_id
        for claim in inv["claims"]
        for semantic_id in claim["depends_on_semantics"]
        if semantic_id.startswith("keel.permit.")
        or semantic_id.startswith("keel.scope_state.")
        or semantic_id == "keel.export.scope_faithfulness.v1"
    }
    assert set(inventory_pins) == referenced
    assert inventory_pins == {
        semantic_id: RELEASED_ARTIFACT_HASHES[semantic_id]
        for semantic_id in sorted(referenced)
    }


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
