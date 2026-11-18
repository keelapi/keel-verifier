"""Bundled review document templates: loader, digest and non-authorizing scope."""

from __future__ import annotations

import ast
import hashlib
import json
from importlib import resources
from pathlib import Path

import jsonschema
import pytest
import rfc8785

import keel_verifier
from keel_verifier.review_document_templates import (
    LATEST_REGISTRY_VERSION,
    REGISTRY_ARTIFACT_ID,
    REGISTRY_RESOURCE,
    REGISTRY_VERSION,
    REGISTRY_VERSION_V1,
    REGISTRY_VERSION_V2,
    REGISTRY_VERSION_V3,
    REGISTRY_VERSIONS,
    SCHEMA_RESOURCE,
    ReviewDocumentTemplate,
    get_review_document_template,
    load_review_document_templates,
    load_review_document_templates_schema,
    review_document_templates_digest,
    review_document_templates_file_sha256,
)

GROUP_GRANT_TEMPLATE = "identity_group_access_grant.review.r1"

# Pinned so any change to the bundled bytes is a deliberate, reviewed edit.
# A published registry version is never edited; a change is a new version.
V1_FILE_SHA256 = "3cee62b82f79de43c3f2ed557a2d45a10b8483259db3957377a8df68b1239dd9"
V1_SCHEMA_FILE_SHA256 = "76c8b33d7b282f3b7eb08b938c03976d6e90ba565f54e8eb38fa00e21436bdd3"
V1_JCS_DIGEST = "sha256:f501b480e6da1b14ba1a5160663edb18f19ebed550bc8b1b3b2df06dbf1a4eac"


def _data_bytes(relative: str) -> bytes:
    return (
        resources.files("keel_verifier")
        .joinpath(f"data/permit_to_x/{relative}")
        .read_bytes()
    )


def _data_json(relative: str) -> dict:
    return json.loads(_data_bytes(relative).decode("utf-8"))


def _fields(template: dict) -> dict[str, dict]:
    return {
        field["field_id"]: field
        for section in template["sections"]
        for field in section["fields"]
    }


def test_bundled_bytes_are_pinned() -> None:
    assert hashlib.sha256(
        _data_bytes("review_document_templates/v1.json")
    ).hexdigest() == V1_FILE_SHA256
    assert hashlib.sha256(
        _data_bytes("review_document_templates/v1.schema.json")
    ).hexdigest() == V1_SCHEMA_FILE_SHA256


def test_release_manifest_lists_both_files() -> None:
    manifest = json.loads(
        resources.files("keel_verifier")
        .joinpath("_release_manifest.json")
        .read_text(encoding="utf-8")
    )
    digests = manifest["per_file_digests"]
    prefix = "keel_verifier/data/permit_to_x/review_document_templates/"
    assert digests[f"{prefix}v1.json"] == V1_FILE_SHA256
    assert digests[f"{prefix}v1.schema.json"] == V1_SCHEMA_FILE_SHA256


def test_registry_validates_against_its_bundled_schema() -> None:
    schema = load_review_document_templates_schema()
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    ).validate(load_review_document_templates())


def test_schema_rejects_an_authoritative_requester_explanation() -> None:
    registry = load_review_document_templates()
    registry["templates"][0]["requester_explanation"]["authoritative"] = True
    validator = jsonschema.Draft202012Validator(load_review_document_templates_schema())
    assert not validator.is_valid(registry)


def test_schema_rejects_an_agent_reported_field() -> None:
    registry = load_review_document_templates()
    registry["templates"][0]["sections"][0]["fields"][0]["provenance"] = "agent_reported"
    validator = jsonschema.Draft202012Validator(load_review_document_templates_schema())
    assert not validator.is_valid(registry)


def test_get_template_returns_template_and_registry_digest() -> None:
    resolved = get_review_document_template(GROUP_GRANT_TEMPLATE)

    assert isinstance(resolved, ReviewDocumentTemplate)
    assert resolved.template["template_id"] == GROUP_GRANT_TEMPLATE
    assert resolved.template["semantic_id"] == (
        "keel.action.identity_group_access_grant.v1"
    )
    assert resolved.template["fact_profile_id"] == (
        "keel.facts.identity_group_access_grant_exact.v1"
    )
    assert resolved.template["presentation_profile_id"] == (
        "identity_group_access_grant.r1"
    )
    assert resolved.registry_artifact_id == REGISTRY_ARTIFACT_ID
    assert resolved.registry_version == REGISTRY_VERSION
    assert resolved.registry_digest == V1_JCS_DIGEST
    assert resolved.registry_file_sha256 == f"sha256:{V1_FILE_SHA256}"


def test_registry_digest_is_rfc8785_over_the_whole_registry() -> None:
    registry = load_review_document_templates()
    expected = f"sha256:{hashlib.sha256(rfc8785.dumps(registry)).hexdigest()}"
    assert review_document_templates_digest() == expected == V1_JCS_DIGEST


def test_unknown_template_is_refused_not_guessed() -> None:
    with pytest.raises(KeyError):
        get_review_document_template("identity_group_access_grant.review.r2")
    with pytest.raises(KeyError):
        get_review_document_template("")


def test_callers_receive_copies() -> None:
    first = get_review_document_template(GROUP_GRANT_TEMPLATE)
    first.template["sections"].clear()
    first.template["title"] = "changed"
    loaded = load_review_document_templates()
    loaded["templates"].clear()

    again = get_review_document_template(GROUP_GRANT_TEMPLATE)
    assert again.template["sections"]
    assert again.template["title"] == "Add a person to an Okta group"
    assert again.registry_digest == V1_JCS_DIGEST


def test_template_resolves_against_the_bundled_registries() -> None:
    template = get_review_document_template(GROUP_GRANT_TEMPLATE).template

    semantic = next(
        entry
        for entry in _data_json("semantic_registry/v22.json")["entries"]
        if entry["semantic_id"] == template["semantic_id"]
    )
    assert semantic["fact_profile_id"] == template["fact_profile_id"]

    presentation = next(
        profile
        for profile in _data_json("presentation_registry/v24.json")["profiles"]
        if profile["presentation_profile_id"] == template["presentation_profile_id"]
    )
    assert presentation["semantic_id"] == template["semantic_id"]

    fact_profile = next(
        profile
        for profile in _data_json("fact_profiles/v19.json")["profiles"]
        if profile["fact_profile_id"] == template["fact_profile_id"]
    )
    assert template["semantic_id"] in fact_profile["semantic_ids"]
    facts_schema = _data_json(fact_profile["facts_schema"])
    properties = facts_schema["$defs"]["identity_group_access_grant"]["properties"]
    assert properties["fact_profile_id"]["const"] == template["fact_profile_id"]

    fields = _fields(template)
    for field in fields.values():
        if field["source"] == "exact_facts":
            assert field["field_id"] in properties, field["field_id"]
        if "commitment" in field:
            assert properties[field["commitment"]]["$ref"] == "#/$defs/saltedCommitment"
            assert f"/{field['commitment']}" in fact_profile["target_fact_paths"]

    rule = template["protected_class_rule"]
    assert set(rule["protected_values"]) <= set(properties[rule["fact"]]["enum"])
    assert "commitment" in fields[template["beneficiary"]["field_id"]]


def test_status_outside_digest_is_not_a_document_field() -> None:
    template = get_review_document_template(GROUP_GRANT_TEMPLATE).template
    assert set(template["status_outside_digest"]) == {
        "votes",
        "deadline",
        "filing_state",
    }
    assert not set(template["status_outside_digest"]) & set(_fields(template))
    assert template["requester_explanation"]["authoritative"] is False
    assert template["requester_explanation"]["provenance"] == "agent_reported"


def test_no_verifier_module_imports_the_template_loader() -> None:
    """Templates are presentation: adjudication code must never import them."""

    package_root = Path(keel_verifier.__file__).resolve().parent
    importers = []
    for path in sorted(package_root.rglob("*.py")):
        if path.name == "review_document_templates.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""] + [alias.name for alias in node.names]
            if any("review_document_templates" in name for name in names):
                importers.append(str(path.relative_to(package_root)))
    assert importers == []


# --- v2 and v3 (keel-permit fcf1176) ------------------------------------------

# File SHA-256s equal keel-permit's artifact-manifests/permit-to-x-v1.json at
# fcf1176; JCS digests are sha256 over the RFC 8785 form of those bytes.
VERSIONED = {
    REGISTRY_VERSION_V2: {
        "file": "review_document_templates/v2.json",
        "schema": "review_document_templates/v2.schema.json",
        "file_sha256": "38220f891f2a71975ba3a610b045760f121de11fc79b892ce5822dd68bb6d8a0",
        "schema_sha256": "3a864f0d761cfe1a790d49d06a4e99a81db0e4b1282e5e14a9a5c03c04a7c1e3",
        "jcs_digest": "sha256:8a500e45444beb22fbcb69aa8c6099e59f458255bd260e47235715ad67660c8d",
        "document_format": "keel.review_document.v2",
        "presentation_registry": "presentation_registry/v24.json",
    },
    REGISTRY_VERSION_V3: {
        "file": "review_document_templates/v3.json",
        "schema": "review_document_templates/v3.schema.json",
        "file_sha256": "4767754bc0b0bdfd0974e51ddca4af925e8630d2cd5331a4018317061a453a27",
        "schema_sha256": "e9d89cc5395fdbe95028ddd9c9919181e04dc01abcad8b3e30ee6c8e7a32d442",
        "jcs_digest": "sha256:585e9e0fb5cf635b9ebfc80b66e5210f479d806357cff7360e0d3ead9d7e985d",
        "document_format": "keel.review_document.v2",
        "presentation_registry": "presentation_registry/v25.json",
    },
}
V3_TEMPLATE_IDS = [
    "identity_group_access_grant.review.r1",
    "payment_execute.review.r1",
    "healthcare_records_release.review.r1",
    "payment_refund.review.r1",
    "payment_refund.review.r2",
    "invoice_payment_execute.review.r1",
    "stripe_connect_transfer_send.review.r1",
    "ledger_entry_record.review.r1",
    "payment_reconciliation_record.review.r1",
    "customer_credit_issue.review.r1",
    "identity_group_access_remove.review.r1",
    "identity_mfa_reset.review.r1",
    "identity_sessions_revoke.review.r1",
    "identity_disable.review.r1",
    "security_indicator_block.review.r1",
    "generate_text.review.r1",
]


def test_versions_are_listed_oldest_first_and_v1_stays_the_default() -> None:
    assert REGISTRY_VERSIONS == (
        "keel.review_document_templates.v1",
        "keel.review_document_templates.v2",
        "keel.review_document_templates.v3",
    )
    assert LATEST_REGISTRY_VERSION == REGISTRY_VERSION_V3
    # The 3.35.0 constants still name v1.
    assert REGISTRY_VERSION == REGISTRY_VERSION_V1
    assert REGISTRY_RESOURCE == "data/permit_to_x/review_document_templates/v1.json"
    assert SCHEMA_RESOURCE == "data/permit_to_x/review_document_templates/v1.schema.json"
    assert review_document_templates_digest() == V1_JCS_DIGEST
    assert review_document_templates_file_sha256() == f"sha256:{V1_FILE_SHA256}"
    assert load_review_document_templates() == load_review_document_templates(
        REGISTRY_VERSION_V1
    )
    assert get_review_document_template(GROUP_GRANT_TEMPLATE) == (
        get_review_document_template(GROUP_GRANT_TEMPLATE, version=REGISTRY_VERSION_V1)
    )


@pytest.mark.parametrize("version", sorted(VERSIONED))
def test_versioned_bytes_and_digests_are_pinned(version: str) -> None:
    expected = VERSIONED[version]
    raw = _data_bytes(expected["file"])

    assert hashlib.sha256(raw).hexdigest() == expected["file_sha256"]
    assert hashlib.sha256(_data_bytes(expected["schema"])).hexdigest() == (
        expected["schema_sha256"]
    )
    assert review_document_templates_file_sha256(version) == (
        f"sha256:{expected['file_sha256']}"
    )
    registry = load_review_document_templates(version)
    assert f"sha256:{hashlib.sha256(rfc8785.dumps(registry)).hexdigest()}" == (
        expected["jcs_digest"]
    )
    assert review_document_templates_digest(version) == expected["jcs_digest"]
    assert registry["artifact_id"] == REGISTRY_ARTIFACT_ID
    assert registry["version"] == version
    assert registry["document_format"] == expected["document_format"]


@pytest.mark.parametrize("version", sorted(VERSIONED))
def test_release_manifest_lists_versioned_files(version: str) -> None:
    manifest = json.loads(
        resources.files("keel_verifier")
        .joinpath("_release_manifest.json")
        .read_text(encoding="utf-8")
    )
    digests = manifest["per_file_digests"]
    expected = VERSIONED[version]
    prefix = "keel_verifier/data/permit_to_x/"
    assert digests[prefix + expected["file"]] == expected["file_sha256"]
    assert digests[prefix + expected["schema"]] == expected["schema_sha256"]


@pytest.mark.parametrize("version", sorted(VERSIONED))
def test_versioned_registry_validates_against_its_bundled_schema(version: str) -> None:
    schema = load_review_document_templates_schema(version)
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    ).validate(load_review_document_templates(version))
    # Each version's schema is its own: v1's schema refuses v2's generic rules.
    assert not jsonschema.Draft202012Validator(
        load_review_document_templates_schema(REGISTRY_VERSION_V1)
    ).is_valid(load_review_document_templates(version))


@pytest.mark.parametrize("version", sorted(VERSIONED))
def test_source_registry_pins_match_the_bundled_registries(version: str) -> None:
    pins = load_review_document_templates(version)["source_registries"]
    expected_paths = {
        "semantic_registry": "semantic_registry/v23.json",
        "presentation_registry": VERSIONED[version]["presentation_registry"],
        "fact_profiles": "fact_profiles/v20.json",
    }
    assert {name: pin["path"] for name, pin in pins.items()} == expected_paths
    for pin in pins.values():
        raw = _data_bytes(pin["path"])
        assert pin["digest"] == f"sha256:{hashlib.sha256(raw).hexdigest()}"
        assert json.loads(raw)["version"] == pin["version"]


def test_v2_and_v3_carry_v1_template_and_v2_generic_rules_unchanged() -> None:
    v1 = load_review_document_templates(REGISTRY_VERSION_V1)
    v2 = load_review_document_templates(REGISTRY_VERSION_V2)
    v3 = load_review_document_templates(REGISTRY_VERSION_V3)

    assert v2["templates"] == v1["templates"]
    assert v3["templates"][0] == v1["templates"][0]
    assert v3["generic"] == v2["generic"]
    assert [t["template_id"] for t in v3["templates"]] == V3_TEMPLATE_IDS


def test_get_template_by_version_reports_that_version() -> None:
    for version in REGISTRY_VERSIONS:
        resolved = get_review_document_template(GROUP_GRANT_TEMPLATE, version=version)
        assert resolved.registry_version == version
        assert resolved.registry_digest == review_document_templates_digest(version)
        assert resolved.registry_file_sha256 == (
            review_document_templates_file_sha256(version)
        )
        assert resolved.template == get_review_document_template(
            GROUP_GRANT_TEMPLATE
        ).template


def test_v3_only_template_is_refused_from_older_versions() -> None:
    release = "healthcare_records_release.review.r1"
    resolved = get_review_document_template(release, version=REGISTRY_VERSION_V3)
    assert resolved.registry_version == REGISTRY_VERSION_V3
    for version in (REGISTRY_VERSION_V1, REGISTRY_VERSION_V2):
        with pytest.raises(KeyError):
            get_review_document_template(release, version=version)


@pytest.mark.parametrize(
    "version",
    ["keel.review_document_templates.v4", "v2", "", "keel.review_document_templates"],
)
def test_unknown_registry_version_is_refused_not_guessed(version: str) -> None:
    with pytest.raises(KeyError):
        load_review_document_templates(version)
    with pytest.raises(KeyError):
        load_review_document_templates_schema(version)
    with pytest.raises(KeyError):
        review_document_templates_digest(version)
    with pytest.raises(KeyError):
        get_review_document_template(GROUP_GRANT_TEMPLATE, version=version)


def test_v3_templates_resolve_against_the_pinned_v25_and_v20_registries() -> None:
    presentation = {
        profile["presentation_profile_id"]: profile
        for profile in _data_json("presentation_registry/v25.json")["profiles"]
    }
    semantics = {
        entry["semantic_id"]: entry
        for entry in _data_json("semantic_registry/v23.json")["entries"]
    }
    fact_profiles = {
        profile["fact_profile_id"]: profile
        for profile in _data_json("fact_profiles/v20.json")["profiles"]
    }
    for template in load_review_document_templates(REGISTRY_VERSION_V3)["templates"]:
        semantic_id = template["semantic_id"]
        assert semantic_id in semantics, template["template_id"]
        assert template["fact_profile_id"] in fact_profiles, template["template_id"]
        assert semantic_id in fact_profiles[template["fact_profile_id"]]["semantic_ids"]
        profile_id = template["presentation_profile_id"]
        if profile_id is not None:
            assert presentation[profile_id]["semantic_id"] == semantic_id

    release = get_review_document_template(
        "healthcare_records_release.review.r1", version=REGISTRY_VERSION_V3
    ).template
    assert presentation[release["presentation_profile_id"]]["customer_title"] == (
        "AI Permit-to-Release-Records"
    )


def test_versioned_callers_receive_copies() -> None:
    first = get_review_document_template(
        "payment_execute.review.r1", version=REGISTRY_VERSION_V3
    )
    first.template["sections"].clear()
    loaded = load_review_document_templates(REGISTRY_VERSION_V3)
    loaded["generic"].clear()

    again = get_review_document_template(
        "payment_execute.review.r1", version=REGISTRY_VERSION_V3
    )
    assert again.template["sections"]
    assert load_review_document_templates(REGISTRY_VERSION_V3)["generic"]
    assert review_document_templates_digest(REGISTRY_VERSION_V3) == (
        VERSIONED[REGISTRY_VERSION_V3]["jcs_digest"]
    )
