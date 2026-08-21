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


def _payment_binding_for_v21(source_kind: str) -> dict:
    """Build the exact payment binding issued by either trusted server path."""

    registry, raw = _registry("semantic_registry/v21.json")
    entry = next(
        item
        for item in registry["entries"]
        if item["semantic_id"] == "keel.action.payment_execute.v1"
    )
    return {
        "version": "keel.permit_semantic_binding.v2",
        "semantic_id": "keel.action.payment_execute.v1",
        "trusted_source_kind": source_kind,
        "chain_role": "action_child",
        "action_name": "payment.execute",
        "operation": "payment.execute",
        "governed_surface": "keel_action_gateway",
        "non_authorizing_presentation_profile_id": "permit_to_pay.r1",
        "selector_registry_version": registry["version"],
        "selector_registry_digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
        "selector_entry_digest": (
            f"sha256:{hashlib.sha256(rfc8785.dumps(entry)).hexdigest()}"
        ),
    }


def test_v21_action_gateway_payment_resolves_to_pay_title() -> None:
    resolved = resolve_permit_presentation(
        _payment_binding_for_v21("action_gateway_service")
    )

    assert resolved["resolution"] == "trusted_signed_semantic"
    assert resolved["customer_title"] == "AI Permit-to-Pay"
    assert resolved["presentation_registry_version"] == (
        "keel.presentation_registry.v20"
    )


def test_v21_legacy_payment_source_remains_compatible() -> None:
    resolved = resolve_permit_presentation(
        _payment_binding_for_v21("action_verb_execute")
    )

    assert resolved["resolution"] == "trusted_signed_semantic"
    assert resolved["customer_title"] == "AI Permit-to-Pay"


def test_v20_historical_registry_bytes_are_unchanged() -> None:
    _registry_value, semantic_raw = _registry("semantic_registry/v20.json")
    _presentation_value, presentation_raw = _registry(
        "presentation_registry/v19.json"
    )

    assert hashlib.sha256(semantic_raw).hexdigest() == (
        "65af1608fec493a52819c165acfc78e5fc75ed976e76c89e776d1f7682e6f88e"
    )
    assert hashlib.sha256(presentation_raw).hexdigest() == (
        "77e4829d6a46a53fe697873d0d31a66e39930ec7649d18f1a0e3449236cb52ff"
    )


def test_unknown_future_payment_gateway_registry_fails_safe() -> None:
    binding = _payment_binding_for_v21("action_gateway_service")
    binding["selector_registry_version"] = "keel.semantic_selector_registry.v22"

    resolved = resolve_permit_presentation(binding)

    assert resolved["resolution"] == "historical_or_unavailable_registry"
    assert resolved["customer_title"] != "AI Permit-to-Pay"


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


def test_v3_issued_permit_resolves_against_v3() -> None:
    resolved = resolve_permit_presentation(
        _binding_for("semantic_registry/v3.json", "keel.action.payment_execute.v1")
    )
    assert resolved["resolution"] == "trusted_signed_semantic"
    assert resolved["customer_title"] == "AI Permit-to-Pay"


def test_v4_specific_titles_resolve_from_the_v2_presentation_registry() -> None:
    registry, raw = _registry("semantic_registry/v4.json")
    cases = {
        "keel.action.generate_text.v1": (
            "AI Permit-to-Generate Text",
            "permit_to_generate_text.r2",
            "action_verb_execute",
            "ai.generate",
            "generate.text",
            "model_provider",
        ),
        "keel.action.payment_refund.v1": (
            "AI Permit-to-Refund",
            "permit_to_refund.r1",
            "action_verb_execute",
            "payment.refund",
            "payment.refund",
            "payment_rail",
        ),
        "keel.action.agent_delegate.v1": (
            "AI Permit-to-Delegate",
            "permit_to_delegate.r1",
            "agent_delegation_service",
            "authority.grant",
            "agent.delegate",
            "agent_delegation",
        ),
    }
    for semantic_id, (
        title,
        profile_id,
        source_kind,
        action_name,
        operation,
        surface,
    ) in cases.items():
        entry = next(e for e in registry["entries"] if e["semantic_id"] == semantic_id)
        binding = {
            "version": "keel.permit_semantic_binding.v2",
            "semantic_id": semantic_id,
            "trusted_source_kind": source_kind,
            "chain_role": "session_root",
            "action_name": action_name,
            "operation": operation,
            "governed_surface": surface,
            "non_authorizing_presentation_profile_id": profile_id,
            "selector_registry_version": registry["version"],
            "selector_registry_digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
            "selector_entry_digest": (
                f"sha256:{hashlib.sha256(rfc8785.dumps(entry)).hexdigest()}"
            ),
        }
        resolved = resolve_permit_presentation(binding)
        assert resolved["resolution"] == "trusted_signed_semantic"
        assert resolved["customer_title"] == title


def test_new_refund_profile_uses_v3_without_rewriting_historical_title() -> None:
    registry, raw = _registry("semantic_registry/v4.json")
    semantic_id = "keel.action.payment_refund.v1"
    entry = next(e for e in registry["entries"] if e["semantic_id"] == semantic_id)
    common = {
        "version": "keel.permit_semantic_binding.v2",
        "semantic_id": semantic_id,
        "trusted_source_kind": "action_verb_execute",
        "chain_role": "session_root",
        "action_name": "payment.refund",
        "operation": "payment.refund",
        "governed_surface": "payment_rail",
        "selector_registry_version": registry["version"],
        "selector_registry_digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
        "selector_entry_digest": (
            f"sha256:{hashlib.sha256(rfc8785.dumps(entry)).hexdigest()}"
        ),
    }
    historical = resolve_permit_presentation(
        {
            **common,
            "non_authorizing_presentation_profile_id": "permit_to_refund.r1",
        }
    )
    current = resolve_permit_presentation(
        {
            **common,
            "non_authorizing_presentation_profile_id": (
                "permit_to_refund_payment.r1"
            ),
        }
    )
    assert historical["customer_title"] == "AI Permit-to-Refund"
    assert historical["presentation_registry_version"] == (
        "keel.presentation_registry.v2"
    )
    assert current["customer_title"] == "AI Permit-to-Refund-Payment"
    assert current["presentation_registry_version"] == (
        "keel.presentation_registry.v3"
    )


def test_v5_database_consequences_resolve_from_published_vectors() -> None:
    registry, raw = _registry("semantic_registry/v5.json")
    vectors, _ = _registry("test_vectors/consequence_registry/v1.json")
    presentation, _ = _registry("presentation_registry/v4.json")
    profile_by_semantic = {
        item["semantic_id"]: item for item in presentation["profiles"]
    }

    for vector in vectors["vectors"]:
        semantic_id = vector["expected_semantic_id"]
        candidate = vector["candidate"]
        entry = next(
            item for item in registry["entries"] if item["semantic_id"] == semantic_id
        )
        profile = profile_by_semantic[semantic_id]
        binding = {
            "version": "keel.permit_semantic_binding.v2",
            "semantic_id": semantic_id,
            "trusted_source_kind": candidate["trusted_source_kind"],
            "chain_role": candidate["chain_role"],
            "action_name": candidate["action_name"],
            "operation": candidate["operation"],
            "governed_surface": candidate["governed_surface"],
            "non_authorizing_presentation_profile_id": profile[
                "presentation_profile_id"
            ],
            "selector_registry_version": registry["version"],
            "selector_registry_digest": (
                f"sha256:{hashlib.sha256(raw).hexdigest()}"
            ),
            "selector_entry_digest": (
                f"sha256:{hashlib.sha256(rfc8785.dumps(entry)).hexdigest()}"
            ),
        }

        resolved = resolve_permit_presentation(binding)

        assert resolved["resolution"] == "trusted_signed_semantic"
        assert resolved["customer_title"] == vector["expected_title"]
        assert resolved["presentation_registry_version"] == (
            "keel.presentation_registry.v4"
        )


def test_v6_exact_database_profiles_resolve_from_published_vectors() -> None:
    registry, raw = _registry("semantic_registry/v6.json")
    vectors, _ = _registry("test_vectors/consequence_registry/v2.json")
    presentation, _ = _registry("presentation_registry/v5.json")
    profile_by_semantic = {
        item["semantic_id"]: item for item in presentation["profiles"]
    }

    for vector in vectors["vectors"]:
        semantic_id = vector["expected_semantic_id"]
        candidate = vector["candidate"]
        entry = next(
            item for item in registry["entries"] if item["semantic_id"] == semantic_id
        )
        profile = profile_by_semantic[semantic_id]
        binding = {
            "version": "keel.permit_semantic_binding.v2",
            "semantic_id": semantic_id,
            "fact_profile_id": vector["expected_fact_profile_id"],
            "trusted_source_kind": candidate["trusted_source_kind"],
            "chain_role": candidate["chain_role"],
            "action_name": candidate["action_name"],
            "operation": candidate["operation"],
            "governed_surface": candidate["governed_surface"],
            "non_authorizing_presentation_profile_id": profile[
                "presentation_profile_id"
            ],
            "selector_registry_version": registry["version"],
            "selector_registry_digest": (
                f"sha256:{hashlib.sha256(raw).hexdigest()}"
            ),
            "selector_entry_digest": (
                f"sha256:{hashlib.sha256(rfc8785.dumps(entry)).hexdigest()}"
            ),
        }

        resolved = resolve_permit_presentation(binding)

        assert resolved["resolution"] == "trusted_signed_semantic"
        assert resolved["customer_title"] == vector["expected_title"]
        assert resolved["presentation_registry_version"] == (
            "keel.presentation_registry.v5"
        )


def test_v7_payment_ledger_profiles_resolve_from_published_vectors() -> None:
    registry, raw = _registry("semantic_registry/v7.json")
    vectors, _ = _registry("test_vectors/consequence_registry/v3.json")
    presentation, _ = _registry("presentation_registry/v6.json")
    profile_by_semantic = {
        item["semantic_id"]: item for item in presentation["profiles"]
    }

    for vector in vectors["vectors"][-3:]:
        semantic_id = vector["expected_semantic_id"]
        candidate = vector["candidate"]
        entry = next(
            item for item in registry["entries"] if item["semantic_id"] == semantic_id
        )
        profile = profile_by_semantic[semantic_id]
        binding = {
            "version": "keel.permit_semantic_binding.v2",
            "semantic_id": semantic_id,
            "fact_profile_id": vector["expected_fact_profile_id"],
            "trusted_source_kind": candidate["trusted_source_kind"],
            "chain_role": candidate["chain_role"],
            "action_name": candidate["action_name"],
            "operation": candidate["operation"],
            "governed_surface": candidate["governed_surface"],
            "non_authorizing_presentation_profile_id": profile[
                "presentation_profile_id"
            ],
            "selector_registry_version": registry["version"],
            "selector_registry_digest": (
                f"sha256:{hashlib.sha256(raw).hexdigest()}"
            ),
            "selector_entry_digest": (
                f"sha256:{hashlib.sha256(rfc8785.dumps(entry)).hexdigest()}"
            ),
        }

        resolved = resolve_permit_presentation(binding)

        assert resolved["resolution"] == "trusted_signed_semantic"
        assert resolved["customer_title"] == vector["expected_title"]
        assert resolved["presentation_registry_version"] == (
            "keel.presentation_registry.v6"
        )


def test_v8_transactional_cx_profiles_resolve_from_published_vectors() -> None:
    registry, raw = _registry("semantic_registry/v8.json")
    vectors, _ = _registry("test_vectors/consequence_registry/v4.json")
    presentation, _ = _registry("presentation_registry/v7.json")
    profile_by_semantic = {
        item["semantic_id"]: item for item in presentation["profiles"]
    }

    for vector in vectors["vectors"][-5:]:
        semantic_id = vector["expected_semantic_id"]
        candidate = vector["candidate"]
        entry = next(
            item for item in registry["entries"] if item["semantic_id"] == semantic_id
        )
        profile = profile_by_semantic[semantic_id]
        binding = {
            "version": "keel.permit_semantic_binding.v2",
            "semantic_id": semantic_id,
            "fact_profile_id": vector["expected_fact_profile_id"],
            "trusted_source_kind": candidate["trusted_source_kind"],
            "chain_role": candidate["chain_role"],
            "action_name": candidate["action_name"],
            "operation": candidate["operation"],
            "governed_surface": candidate["governed_surface"],
            "non_authorizing_presentation_profile_id": profile[
                "presentation_profile_id"
            ],
            "selector_registry_version": registry["version"],
            "selector_registry_digest": (
                f"sha256:{hashlib.sha256(raw).hexdigest()}"
            ),
            "selector_entry_digest": (
                f"sha256:{hashlib.sha256(rfc8785.dumps(entry)).hexdigest()}"
            ),
        }

        resolved = resolve_permit_presentation(binding)

        assert resolved["resolution"] == "trusted_signed_semantic"
        assert resolved["customer_title"] == vector["expected_title"]
        assert resolved["presentation_registry_version"] == (
            "keel.presentation_registry.v7"
        )


def test_v9_release_profiles_resolve_from_published_vectors() -> None:
    registry, raw = _registry("semantic_registry/v9.json")
    vectors, _ = _registry("test_vectors/consequence_registry/v5.json")
    presentation, _ = _registry("presentation_registry/v8.json")
    profile_by_semantic = {
        item["semantic_id"]: item for item in presentation["profiles"]
    }

    for vector in vectors["vectors"][-3:]:
        semantic_id = vector["expected_semantic_id"]
        candidate = vector["candidate"]
        entry = next(
            item for item in registry["entries"] if item["semantic_id"] == semantic_id
        )
        profile = profile_by_semantic[semantic_id]
        binding = {
            "version": "keel.permit_semantic_binding.v2",
            "semantic_id": semantic_id,
            "fact_profile_id": vector["expected_fact_profile_id"],
            "trusted_source_kind": candidate["trusted_source_kind"],
            "chain_role": candidate["chain_role"],
            "action_name": candidate["action_name"],
            "operation": candidate["operation"],
            "governed_surface": candidate["governed_surface"],
            "non_authorizing_presentation_profile_id": profile[
                "presentation_profile_id"
            ],
            "selector_registry_version": registry["version"],
            "selector_registry_digest": (
                f"sha256:{hashlib.sha256(raw).hexdigest()}"
            ),
            "selector_entry_digest": (
                f"sha256:{hashlib.sha256(rfc8785.dumps(entry)).hexdigest()}"
            ),
        }

        resolved = resolve_permit_presentation(binding)

        assert resolved["resolution"] == "trusted_signed_semantic"
        assert resolved["customer_title"] == vector["expected_title"]
        assert resolved["presentation_registry_version"] == (
            "keel.presentation_registry.v8"
        )


def test_v10_identity_security_profiles_resolve_from_published_vectors() -> None:
    registry, raw = _registry("semantic_registry/v10.json")
    vectors, _ = _registry("test_vectors/consequence_registry/v6.json")
    presentation, _ = _registry("presentation_registry/v9.json")
    profile_by_semantic = {
        item["semantic_id"]: item for item in presentation["profiles"]
    }

    for vector in vectors["vectors"][-6:]:
        semantic_id = vector["expected_semantic_id"]
        candidate = vector["candidate"]
        entry = next(
            item for item in registry["entries"] if item["semantic_id"] == semantic_id
        )
        profile = profile_by_semantic[semantic_id]
        binding = {
            "version": "keel.permit_semantic_binding.v2",
            "semantic_id": semantic_id,
            "fact_profile_id": vector["expected_fact_profile_id"],
            "trusted_source_kind": candidate["trusted_source_kind"],
            "chain_role": candidate["chain_role"],
            "action_name": candidate["action_name"],
            "operation": candidate["operation"],
            "governed_surface": candidate["governed_surface"],
            "non_authorizing_presentation_profile_id": profile[
                "presentation_profile_id"
            ],
            "selector_registry_version": registry["version"],
            "selector_registry_digest": (
                f"sha256:{hashlib.sha256(raw).hexdigest()}"
            ),
            "selector_entry_digest": (
                f"sha256:{hashlib.sha256(rfc8785.dumps(entry)).hexdigest()}"
            ),
        }

        resolved = resolve_permit_presentation(binding)

        assert resolved["resolution"] == "trusted_signed_semantic"
        assert resolved["customer_title"] == vector["expected_title"]
        assert resolved["presentation_registry_version"] == (
            "keel.presentation_registry.v9"
        )


def test_v11_coding_workspace_profiles_resolve_from_published_vectors() -> None:
    registry, raw = _registry("semantic_registry/v11.json")
    vectors, _ = _registry("test_vectors/consequence_registry/v7.json")
    presentation, _ = _registry("presentation_registry/v10.json")
    profile_by_semantic = {
        item["semantic_id"]: item for item in presentation["profiles"]
    }

    for vector in vectors["vectors"][-3:]:
        semantic_id = vector["expected_semantic_id"]
        candidate = vector["candidate"]
        entry = next(
            item for item in registry["entries"] if item["semantic_id"] == semantic_id
        )
        profile = profile_by_semantic[semantic_id]
        binding = {
            "version": "keel.permit_semantic_binding.v2",
            "semantic_id": semantic_id,
            "fact_profile_id": vector["expected_fact_profile_id"],
            "trusted_source_kind": candidate["trusted_source_kind"],
            "chain_role": candidate["chain_role"],
            "action_name": candidate["action_name"],
            "operation": candidate["operation"],
            "governed_surface": candidate["governed_surface"],
            "non_authorizing_presentation_profile_id": profile[
                "presentation_profile_id"
            ],
            "selector_registry_version": registry["version"],
            "selector_registry_digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
            "selector_entry_digest": (
                f"sha256:{hashlib.sha256(rfc8785.dumps(entry)).hexdigest()}"
            ),
        }

        resolved = resolve_permit_presentation(binding)

        assert resolved["resolution"] == "trusted_signed_semantic"
        assert resolved["customer_title"] == vector["expected_title"]
        assert resolved["presentation_registry_version"] == (
            "keel.presentation_registry.v10"
        )


def test_v12_collections_profiles_resolve_from_published_vectors() -> None:
    registry, raw = _registry("semantic_registry/v12.json")
    vectors, _ = _registry("test_vectors/consequence_registry/v8.json")
    presentation, _ = _registry("presentation_registry/v11.json")
    profile_by_semantic = {
        item["semantic_id"]: item for item in presentation["profiles"]
    }

    for vector in vectors["vectors"][-4:]:
        semantic_id = vector["expected_semantic_id"]
        candidate = vector["candidate"]
        entry = next(
            item for item in registry["entries"] if item["semantic_id"] == semantic_id
        )
        profile = profile_by_semantic[semantic_id]
        binding = {
            "version": "keel.permit_semantic_binding.v2",
            "semantic_id": semantic_id,
            "fact_profile_id": vector["expected_fact_profile_id"],
            "trusted_source_kind": candidate["trusted_source_kind"],
            "chain_role": candidate["chain_role"],
            "action_name": candidate["action_name"],
            "operation": candidate["operation"],
            "governed_surface": candidate["governed_surface"],
            "non_authorizing_presentation_profile_id": profile[
                "presentation_profile_id"
            ],
            "selector_registry_version": registry["version"],
            "selector_registry_digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
            "selector_entry_digest": (
                f"sha256:{hashlib.sha256(rfc8785.dumps(entry)).hexdigest()}"
            ),
        }

        resolved = resolve_permit_presentation(binding)

        assert resolved["resolution"] == "trusted_signed_semantic"
        assert resolved["customer_title"] == vector["expected_title"]
        assert resolved["presentation_registry_version"] == (
            "keel.presentation_registry.v11"
        )


def test_v13_insurance_claims_profiles_resolve_from_published_vectors() -> None:
    registry, raw = _registry("semantic_registry/v13.json")
    vectors, _ = _registry("test_vectors/consequence_registry/v9.json")
    presentation, _ = _registry("presentation_registry/v12.json")
    profile_by_semantic = {
        item["semantic_id"]: item for item in presentation["profiles"]
    }

    for vector in vectors["vectors"][-4:]:
        semantic_id = vector["expected_semantic_id"]
        candidate = vector["candidate"]
        entry = next(
            item for item in registry["entries"] if item["semantic_id"] == semantic_id
        )
        profile = profile_by_semantic[semantic_id]
        binding = {
            "version": "keel.permit_semantic_binding.v2",
            "semantic_id": semantic_id,
            "fact_profile_id": vector["expected_fact_profile_id"],
            "trusted_source_kind": candidate["trusted_source_kind"],
            "chain_role": candidate["chain_role"],
            "action_name": candidate["action_name"],
            "operation": candidate["operation"],
            "governed_surface": candidate["governed_surface"],
            "non_authorizing_presentation_profile_id": profile[
                "presentation_profile_id"
            ],
            "selector_registry_version": registry["version"],
            "selector_registry_digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
            "selector_entry_digest": (
                f"sha256:{hashlib.sha256(rfc8785.dumps(entry)).hexdigest()}"
            ),
        }

        resolved = resolve_permit_presentation(binding)

        assert resolved["resolution"] == "trusted_signed_semantic"
        assert resolved["customer_title"] == vector["expected_title"]
        assert resolved["presentation_registry_version"] == (
            "keel.presentation_registry.v12"
        )


def test_v14_erp_crm_profiles_resolve_from_published_vectors() -> None:
    registry, raw = _registry("semantic_registry/v14.json")
    vectors, _ = _registry("test_vectors/consequence_registry/v10.json")
    presentation, _ = _registry("presentation_registry/v13.json")
    profile_by_semantic = {
        item["semantic_id"]: item for item in presentation["profiles"]
    }

    for vector in vectors["vectors"][-3:]:
        semantic_id = vector["expected_semantic_id"]
        candidate = vector["candidate"]
        entry = next(
            item for item in registry["entries"] if item["semantic_id"] == semantic_id
        )
        profile = profile_by_semantic[semantic_id]
        binding = {
            "version": "keel.permit_semantic_binding.v2",
            "semantic_id": semantic_id,
            "fact_profile_id": vector["expected_fact_profile_id"],
            "trusted_source_kind": candidate["trusted_source_kind"],
            "chain_role": candidate["chain_role"],
            "action_name": candidate["action_name"],
            "operation": candidate["operation"],
            "governed_surface": candidate["governed_surface"],
            "non_authorizing_presentation_profile_id": profile[
                "presentation_profile_id"
            ],
            "selector_registry_version": registry["version"],
            "selector_registry_digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
            "selector_entry_digest": (
                f"sha256:{hashlib.sha256(rfc8785.dumps(entry)).hexdigest()}"
            ),
        }

        resolved = resolve_permit_presentation(binding)

        assert resolved["resolution"] == "trusted_signed_semantic"
        assert resolved["customer_title"] == vector["expected_title"]
        assert resolved["presentation_registry_version"] == (
            "keel.presentation_registry.v13"
        )


def test_v15_procurement_ap_profiles_resolve_from_published_vectors() -> None:
    registry, raw = _registry("semantic_registry/v15.json")
    vectors, _ = _registry("test_vectors/consequence_registry/v11.json")
    presentation, _ = _registry("presentation_registry/v14.json")
    profile_by_semantic = {
        item["semantic_id"]: item for item in presentation["profiles"]
    }

    for vector in vectors["vectors"][-6:]:
        semantic_id = vector["expected_semantic_id"]
        candidate = vector["candidate"]
        entry = next(
            item for item in registry["entries"] if item["semantic_id"] == semantic_id
        )
        profile = profile_by_semantic[semantic_id]
        binding = {
            "version": "keel.permit_semantic_binding.v2",
            "semantic_id": semantic_id,
            "fact_profile_id": vector["expected_fact_profile_id"],
            "trusted_source_kind": candidate["trusted_source_kind"],
            "chain_role": candidate["chain_role"],
            "action_name": candidate["action_name"],
            "operation": candidate["operation"],
            "governed_surface": candidate["governed_surface"],
            "non_authorizing_presentation_profile_id": profile[
                "presentation_profile_id"
            ],
            "selector_registry_version": registry["version"],
            "selector_registry_digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
            "selector_entry_digest": (
                f"sha256:{hashlib.sha256(rfc8785.dumps(entry)).hexdigest()}"
            ),
        }

        resolved = resolve_permit_presentation(binding)

        assert resolved["resolution"] == "trusted_signed_semantic"
        assert resolved["customer_title"] == vector["expected_title"]
        assert resolved["presentation_registry_version"] == (
            "keel.presentation_registry.v14"
        )


def test_v16_commerce_regulated_profiles_resolve_from_published_vectors() -> None:
    registry, raw = _registry("semantic_registry/v16.json")
    vectors, _ = _registry("test_vectors/consequence_registry/v12.json")
    presentation, _ = _registry("presentation_registry/v15.json")
    profile_by_semantic = {
        item["semantic_id"]: item for item in presentation["profiles"]
    }

    for vector in vectors["vectors"][-15:]:
        semantic_id = vector["expected_semantic_id"]
        candidate = vector["candidate"]
        entry = next(
            item for item in registry["entries"] if item["semantic_id"] == semantic_id
        )
        profile = profile_by_semantic[semantic_id]
        binding = {
            "version": "keel.permit_semantic_binding.v2",
            "semantic_id": semantic_id,
            "fact_profile_id": vector["expected_fact_profile_id"],
            "trusted_source_kind": candidate["trusted_source_kind"],
            "chain_role": candidate["chain_role"],
            "action_name": candidate["action_name"],
            "operation": candidate["operation"],
            "governed_surface": candidate["governed_surface"],
            "non_authorizing_presentation_profile_id": profile[
                "presentation_profile_id"
            ],
            "selector_registry_version": registry["version"],
            "selector_registry_digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
            "selector_entry_digest": (
                f"sha256:{hashlib.sha256(rfc8785.dumps(entry)).hexdigest()}"
            ),
        }

        resolved = resolve_permit_presentation(binding)
        assert resolved["resolution"] == "trusted_signed_semantic"
        assert resolved["customer_title"] == vector["expected_title"]
        assert resolved["presentation_registry_version"] == (
            "keel.presentation_registry.v15"
        )


def test_v17_wave5_breadth_profiles_resolve_from_published_vectors() -> None:
    registry, raw = _registry("semantic_registry/v17.json")
    vectors, _ = _registry("test_vectors/consequence_registry/v13.json")
    presentation, _ = _registry("presentation_registry/v16.json")
    profile_by_semantic = {
        item["semantic_id"]: item for item in presentation["profiles"]
    }

    for vector in vectors["vectors"][-33:]:
        semantic_id = vector["expected_semantic_id"]
        candidate = vector["candidate"]
        entry = next(
            item for item in registry["entries"] if item["semantic_id"] == semantic_id
        )
        profile = profile_by_semantic[semantic_id]
        binding = {
            "version": "keel.permit_semantic_binding.v2",
            "semantic_id": semantic_id,
            "fact_profile_id": vector["expected_fact_profile_id"],
            "trusted_source_kind": candidate["trusted_source_kind"],
            "chain_role": candidate["chain_role"],
            "action_name": candidate["action_name"],
            "operation": candidate["operation"],
            "governed_surface": candidate["governed_surface"],
            "non_authorizing_presentation_profile_id": profile[
                "presentation_profile_id"
            ],
            "selector_registry_version": registry["version"],
            "selector_registry_digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
            "selector_entry_digest": (
                f"sha256:{hashlib.sha256(rfc8785.dumps(entry)).hexdigest()}"
            ),
        }

        resolved = resolve_permit_presentation(binding)
        assert resolved["resolution"] == "trusted_signed_semantic"
        assert resolved["customer_title"] == vector["expected_title"]
        assert resolved["presentation_registry_version"] == (
            "keel.presentation_registry.v16"
        )


def test_v18_goal3a_portfolio_profiles_resolve_from_published_vectors() -> None:
    registry, raw = _registry("semantic_registry/v18.json")
    vectors, _ = _registry("test_vectors/consequence_registry/v15.json")
    presentation, _ = _registry("presentation_registry/v17.json")
    profile_by_semantic = {
        item["semantic_id"]: item for item in presentation["profiles"]
    }

    assert len(vectors["vectors"]) == 96
    for vector in vectors["vectors"]:
        semantic_id = vector["expected_semantic_id"]
        candidate = vector["candidate"]
        entry = next(
            item for item in registry["entries"] if item["semantic_id"] == semantic_id
        )
        profile = profile_by_semantic[semantic_id]
        binding = {
            "version": "keel.permit_semantic_binding.v2",
            "semantic_id": semantic_id,
            "fact_profile_id": vector["expected_fact_profile_id"],
            "trusted_source_kind": candidate["trusted_source_kind"],
            "chain_role": candidate["chain_role"],
            "action_name": candidate["action_name"],
            "operation": candidate["operation"],
            "governed_surface": candidate["governed_surface"],
            "non_authorizing_presentation_profile_id": profile[
                "presentation_profile_id"
            ],
            "selector_registry_version": registry["version"],
            "selector_registry_digest": f"sha256:{hashlib.sha256(raw).hexdigest()}",
            "selector_entry_digest": (
                f"sha256:{hashlib.sha256(rfc8785.dumps(entry)).hexdigest()}"
            ),
        }

        resolved = resolve_permit_presentation(binding)
        assert resolved["resolution"] == "trusted_signed_semantic"
        assert resolved["customer_title"] == vector["expected_title"]
        assert resolved["presentation_registry_version"] == (
            "keel.presentation_registry.v17"
        )


def test_refund_v1_and_mcp_v2_remain_unambiguous() -> None:
    registry, _ = _registry("semantic_registry/v8.json")
    refund_entries = [
        entry
        for entry in registry["entries"]
        if entry["semantic_id"]
        in {"keel.action.payment_refund.v1", "keel.action.payment_refund.v2"}
    ]
    assert len(refund_entries) == 2
    operations = {
        entry["semantic_id"]: entry["match"]["operations"]
        for entry in refund_entries
    }
    assert operations["keel.action.payment_refund.v1"] == ["payment.refund"]
    assert operations["keel.action.payment_refund.v2"] == ["call.tools"]


def test_signed_unknown_profile_cannot_borrow_a_specific_title() -> None:
    binding = _binding_for(
        "semantic_registry/v4.json", "keel.action.payment_execute.v1"
    )
    binding["non_authorizing_presentation_profile_id"] = "permit_to_drain.r1"
    resolved = resolve_permit_presentation(binding)
    assert resolved["resolution"] == "generic_profile_missing"
    assert resolved["customer_title"] == "AI Permit"


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
