"""Historical permits resolve against the registry they were issued under.

Every semantic binding embeds `selector_registry_version` plus digests of the
registry and the matched entry. Loading one hardcoded registry meant publishing
a new version silently retitled the whole back catalogue to "specific title
unavailable" — the permits most likely to be under audit are the oldest ones.
"""

from __future__ import annotations

import hashlib
import json
from importlib import resources

import rfc8785

from keel_verifier.permit_presentation import resolve_permit_presentation


def _registry(version_file: str) -> tuple[dict, bytes]:
    raw = (
        resources.files("keel_verifier")
        .joinpath(f"data/permit_to_x/{version_file}")
        .read_bytes()
    )
    return json.loads(raw.decode("utf-8")), raw


def _binding_for(version_file: str, semantic_id: str) -> dict:
    """Build a binding exactly as issuance would stamp it for that registry."""

    registry, raw = _registry(version_file)
    entry = next(e for e in registry["entries"] if e["semantic_id"] == semantic_id)
    profile_id = {
        "keel.action.payment_execute.v1": "permit_to_pay.r1",
    }[semantic_id]
    return {
        "version": "keel.permit_semantic_binding.v1",
        "semantic_id": semantic_id,
        "trusted_source_kind": "action_verb_execute",
        "chain_role": "session_root",
        "action_name": "payment.execute",
        "operation": "payment.execute",
        "governed_surface": "payment_rail",
        "non_authorizing_presentation_profile_id": profile_id,
        "selector_registry_version": registry["version"],
        "selector_registry_digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
        "selector_entry_digest": f"sha256:{hashlib.sha256(rfc8785.dumps(entry)).hexdigest()}",
    }


def test_v1_issued_permit_keeps_its_title_after_v2_exists() -> None:
    """The regression this change prevents: v2 shipping must not retitle v1."""

    resolved = resolve_permit_presentation(
        _binding_for("semantic_registry/v1.json", "keel.action.payment_execute.v1")
    )
    assert resolved["resolution"] == "trusted_signed_semantic"
    assert resolved["customer_title"] == "AI Permit-to-Pay"


def test_v2_issued_permit_resolves_against_v2() -> None:
    resolved = resolve_permit_presentation(
        _binding_for("semantic_registry/v2.json", "keel.action.payment_execute.v1")
    )
    assert resolved["resolution"] == "trusted_signed_semantic"
    assert resolved["customer_title"] == "AI Permit-to-Pay"


def test_unknown_registry_version_never_borrows_a_title() -> None:
    """A registry this build has never seen must not lend its titles."""

    binding = _binding_for("semantic_registry/v1.json", "keel.action.payment_execute.v1")
    binding["selector_registry_version"] = "keel.semantic_selector_registry.v99"
    resolved = resolve_permit_presentation(binding)
    assert resolved["resolution"] == "historical_or_unavailable_registry"
    assert resolved["customer_title"] != "AI Permit-to-Pay"


def test_v1_and_v2_differ_only_by_surface_constraint() -> None:
    """v2 is v1 minus required_surfaces — nothing else may drift between them."""

    v1, _ = _registry("semantic_registry/v1.json")
    v2, _ = _registry("semantic_registry/v2.json")
    assert {e["semantic_id"] for e in v1["entries"]} == {
        e["semantic_id"] for e in v2["entries"]
    }
    for a, b in zip(v1["entries"], v2["entries"]):
        stripped = dict(a)
        stripped["match"] = {
            k: v for k, v in a["match"].items() if k != "required_surfaces"
        }
        assert stripped == b, f"{a['semantic_id']} drifted beyond the surface removal"
