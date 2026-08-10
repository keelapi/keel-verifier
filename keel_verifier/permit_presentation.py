"""Non-authorizing Permit-to-X title and evidence presentation.

Nothing in this module is imported by adjudication code.  It consumes a
completed report plus already-verified signed semantic facts and may only
change labels, ordering, and explanatory text.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from importlib import resources
from typing import Any

import rfc8785


def _load(name: str) -> tuple[dict[str, Any], bytes]:
    resource = resources.files("keel_verifier").joinpath(f"data/permit_to_x/{name}")
    raw = resource.read_bytes()
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Permit presentation artifact {name} is not an object")
    return value, raw


# Every semantic binding embeds the selector registry version it was matched
# against, so a permit must always be resolved against that exact registry — not
# whichever one happens to be current. Loading a single hardcoded file meant
# publishing a new registry silently retitled the entire back catalogue to
# "specific title unavailable".
#
# Vendored versions are byte-identical copies of keel-permit, so a version that
# was valid at issuance stays resolvable for the life of the record. Unknown
# versions are not guessed at: they fall through to the historical fallback,
# which is the honest answer for a permit issued under a registry this build has
# never seen.
_SEMANTIC_REGISTRY_BY_VERSION = {
    "keel.semantic_selector_registry.v1": "semantic_registry/v1.json",
    "keel.semantic_selector_registry.v2": "semantic_registry/v2.json",
    "keel.semantic_selector_registry.v3": "semantic_registry/v3.json",
    "keel.semantic_selector_registry.v4": "semantic_registry/v4.json",
    "keel.semantic_selector_registry.v5": "semantic_registry/v5.json",
    "keel.semantic_selector_registry.v6": "semantic_registry/v6.json",
    "keel.semantic_selector_registry.v7": "semantic_registry/v7.json",
    "keel.semantic_selector_registry.v8": "semantic_registry/v8.json",
    "keel.semantic_selector_registry.v9": "semantic_registry/v9.json",
    "keel.semantic_selector_registry.v10": "semantic_registry/v10.json",
}

# Registry used for permits carrying no version at all (pre-versioning records).
_DEFAULT_SEMANTIC_REGISTRY = "semantic_registry/v1.json"

_PRESENTATION_REGISTRIES = (
    "presentation_registry/v9.json",
    "presentation_registry/v8.json",
    "presentation_registry/v7.json",
    "presentation_registry/v6.json",
    "presentation_registry/v5.json",
    "presentation_registry/v4.json",
    "presentation_registry/v3.json",
    "presentation_registry/v2.json",
    "presentation_registry/v1.json",
)


def _load_semantic_registry_for(
    binding: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], bytes] | None:
    """Load the registry this binding was issued under, or None if unknown."""

    version = None
    if isinstance(binding, Mapping):
        version = binding.get("selector_registry_version")
    if version is None:
        return _load(_DEFAULT_SEMANTIC_REGISTRY)
    name = _SEMANTIC_REGISTRY_BY_VERSION.get(str(version))
    if name is None:
        return None
    return _load(name)


def _digest(value: Any) -> str:
    return f"sha256:{hashlib.sha256(rfc8785.dumps(value)).hexdigest()}"


def _raw_digest(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def load_permit_presentation_registry() -> dict[str, Any]:
    """Return a defensive copy of the non-trust-input presentation registry."""

    registry, _raw = _load("presentation_registry/v9.json")
    return json.loads(json.dumps(registry))


def _presentation_registry_for(
    semantic_binding: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], bytes]:
    """Select the newest bundled registry that exactly names the signed profile.

    Presentation registry v3 intentionally renamed the refund profile.  The
    signed non-authorizing profile identifier therefore doubles as the stable
    historical discriminator: old refund Permits continue to resolve through
    v2, while newly issued refund Permits resolve through v3.  A semantic ID
    alone is not enough to silently retitle the back catalogue.
    """

    semantic_id = (
        semantic_binding.get("semantic_id")
        if isinstance(semantic_binding, Mapping)
        else None
    )
    profile_id = (
        semantic_binding.get("non_authorizing_presentation_profile_id")
        if isinstance(semantic_binding, Mapping)
        else None
    )
    selector_version = (
        semantic_binding.get("selector_registry_version")
        if isinstance(semantic_binding, Mapping)
        else None
    )
    for name in _PRESENTATION_REGISTRIES:
        registry, raw = _load(name)
        if selector_version in {
            "keel.semantic_selector_registry.v4",
            "keel.semantic_selector_registry.v5",
            "keel.semantic_selector_registry.v6",
            "keel.semantic_selector_registry.v7",
            "keel.semantic_selector_registry.v8",
            "keel.semantic_selector_registry.v9",
            "keel.semantic_selector_registry.v10",
        }:
            if registry.get("semantic_registry_version") != selector_version:
                continue
        profiles = registry.get("profiles")
        if not isinstance(profiles, list):
            continue
        if any(
            isinstance(profile, Mapping)
            and profile.get("semantic_id") == semantic_id
            and profile.get("presentation_profile_id") == profile_id
            for profile in profiles
        ):
            return registry, raw
    legacy_name = (
        "presentation_registry/v8.json"
        if selector_version == "keel.semantic_selector_registry.v10"
        else "presentation_registry/v7.json"
        if selector_version == "keel.semantic_selector_registry.v9"
        else "presentation_registry/v6.json"
        if selector_version == "keel.semantic_selector_registry.v8"
        else "presentation_registry/v5.json"
        if selector_version == "keel.semantic_selector_registry.v7"
        else "presentation_registry/v4.json"
        if selector_version == "keel.semantic_selector_registry.v6"
        else "presentation_registry/v3.json"
        if selector_version == "keel.semantic_selector_registry.v5"
        else "presentation_registry/v2.json"
        if selector_version == "keel.semantic_selector_registry.v4"
        else "presentation_registry/v1.json"
    )
    return _load(legacy_name)


def resolve_permit_presentation(
    semantic_binding: Mapping[str, Any] | None,
    *,
    permit_product: str = "permit",
    semantic_registry: Mapping[str, Any] | None = None,
    presentation_registry: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Resolve a title from trusted signed semantic facts or fail generic.

    The optional registries exist for renderer tests.  They never flow into
    verifier verdicts, claim adjudication, cryptographic checks, or exit codes.
    """

    # Resolve the registry this binding was issued under. An unrecognised
    # version deliberately falls back to the default: the version and digest
    # checks below then fail to match, and the permit lands on the historical
    # fallback rather than borrowing a title from a registry it never saw.
    semantics, semantics_raw = _load_semantic_registry_for(semantic_binding) or _load(
        _DEFAULT_SEMANTIC_REGISTRY
    )
    presentations, presentation_raw = _presentation_registry_for(semantic_binding)
    if semantic_registry is not None:
        semantics = dict(semantic_registry)
    if presentation_registry is not None:
        presentations = dict(presentation_registry)
        presentation_raw = rfc8785.dumps(presentations)
    fallbacks = {
        str(item.get("presentation_profile_id")): dict(item)
        for item in presentations.get("fallback_profiles", [])
        if isinstance(item, Mapping)
    }
    generic = fallbacks.get(
        "generic_ai_permit",
        {
            "presentation_profile_id": "generic_ai_permit",
            "customer_title": "AI Permit",
            "type_definition": "Governed authorization record",
            "evidence_sections": ["record_identity", "authorization"],
        },
    )
    if permit_product == "cost_permit":
        return {
            **generic,
            "presentation_registry_version": presentations.get("version"),
            "presentation_registry_digest": _raw_digest(presentation_raw),
            "resolution": "cost_permit_unchanged",
        }
    if not isinstance(semantic_binding, Mapping):
        return {
            **generic,
            "presentation_registry_version": presentations.get("version"),
            "presentation_registry_digest": _raw_digest(presentation_raw),
            "resolution": "generic_no_signed_semantic",
        }
    if semantic_binding.get("version") not in {
        "keel.permit_semantic_binding.v1",
        "keel.permit_semantic_binding.v2",
    }:
        return {
            **generic,
            "presentation_registry_version": presentations.get("version"),
            "presentation_registry_digest": _raw_digest(presentation_raw),
            "resolution": "generic_unsupported_binding",
        }
    semantic_id = semantic_binding.get("semantic_id")
    entries = [
        dict(entry)
        for entry in semantics.get("entries", [])
        if isinstance(entry, Mapping) and entry.get("semantic_id") == semantic_id
    ]
    if (
        len(entries) != 1
        or semantic_binding.get("selector_registry_version") != semantics.get("version")
        or semantic_binding.get("selector_registry_digest") != _raw_digest(semantics_raw)
        or semantic_binding.get("selector_entry_digest") != _digest(entries[0])
    ):
        historical = fallbacks.get("historical_specific_title_unavailable", generic)
        return {
            **historical,
            "presentation_registry_version": presentations.get("version"),
            "presentation_registry_digest": _raw_digest(presentation_raw),
            "resolution": "historical_or_unavailable_registry",
        }
    entry = entries[0]
    match = entry.get("match") if isinstance(entry.get("match"), Mapping) else {}
    if (
        semantic_binding.get("trusted_source_kind") not in entry.get("trusted_source_kinds", [])
        or semantic_binding.get("chain_role") not in match.get("allowed_chain_roles", [])
        # Surface is an identity constraint only where the registry declares one.
        # v1 pins each semantic to a single governed_surface; v2 drops that,
        # because the surface is derived from (source_kind, action, operation) at
        # issuance and so re-checks what the action and operation checks below
        # already establish. Reading a missing key as an empty allow-list would
        # reject every v2 permit, so the check is skipped rather than defaulted.
        or (
            "required_surfaces" in match
            and semantic_binding.get("governed_surface")
            not in match.get("required_surfaces", [])
        )
        or (
            match.get("action_names")
            and semantic_binding.get("action_name") not in match.get("action_names", [])
        )
        or (
            match.get("operations")
            and semantic_binding.get("operation") not in match.get("operations", [])
        )
    ):
        return {
            **generic,
            "presentation_registry_version": presentations.get("version"),
            "presentation_registry_digest": _raw_digest(presentation_raw),
            "resolution": "generic_semantic_fact_mismatch",
        }
    profiles = [
        dict(profile)
        for profile in presentations.get("profiles", [])
        if isinstance(profile, Mapping)
        and profile.get("semantic_id") == semantic_id
        and profile.get("presentation_profile_id")
        == semantic_binding.get("non_authorizing_presentation_profile_id")
    ]
    if len(profiles) != 1:
        return {
            **generic,
            "presentation_registry_version": presentations.get("version"),
            "presentation_registry_digest": _raw_digest(presentation_raw),
            "resolution": "generic_profile_missing",
        }
    profile = profiles[0]
    if profile.get("release_state") not in {"eligible", "generic_qualified"}:
        return {
            **generic,
            "presentation_registry_version": presentations.get("version"),
            "presentation_registry_digest": _raw_digest(presentation_raw),
            "resolution": "generic_profile_not_released",
        }
    return {
        **profile,
        "presentation_registry_version": presentations.get("version"),
        "presentation_registry_digest": _raw_digest(presentation_raw),
        "resolution": "trusted_signed_semantic",
    }


def render_work_chain_human(
    report: Mapping[str, Any],
    document: Mapping[str, Any],
) -> str:
    """Render the customer-readable Work evidence summary."""

    root = document.get("root") if isinstance(document.get("root"), Mapping) else {}
    profile = resolve_permit_presentation(
        root.get("semantic_binding") if isinstance(root.get("semantic_binding"), Mapping) else None
    )
    package = root.get("work_package") if isinstance(root.get("work_package"), Mapping) else {}
    claims = report.get("claims") if isinstance(report.get("claims"), list) else []
    lines = [
        str(profile.get("customer_title") or "AI Permit"),
        str(profile.get("type_definition") or "Governed authorization record"),
        "",
        f"Declared purpose: {package.get('declared_purpose') or 'Not recorded'}",
        f"Job reference: {package.get('job_reference') or 'Not recorded'}",
        f"Root Permit: {document.get('root_permit_id')}",
        f"Recorded through: {(document.get('declared_cutoff') or {}).get('recorded_through') if isinstance(document.get('declared_cutoff'), Mapping) else None}",
        "",
        "Verification",
    ]
    for claim in claims:
        if not isinstance(claim, Mapping):
            continue
        marker = str(claim.get("verdict") or "unknown").upper()
        lines.append(f"  [{marker}] {claim.get('name')}")
        if claim.get("message"):
            lines.append(f"      {claim['message']}")
    lines.extend(
        [
            "",
            "Evidence scope",
            "  Scope-faithful to Keel-recorded Work populations through the cutoff.",
            "  Comprehensive runtime recording is not asserted.",
            "",
            "Does not establish",
            "  Business job completion, provider success, or financial settlement unless separately evidenced.",
        ]
    )
    return "\n".join(lines)


__all__ = [
    "load_permit_presentation_registry",
    "render_work_chain_human",
    "resolve_permit_presentation",
]
