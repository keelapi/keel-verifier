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
    REGISTRY_ARTIFACT_ID,
    REGISTRY_VERSION,
    ReviewDocumentTemplate,
    get_review_document_template,
    load_review_document_templates,
    load_review_document_templates_schema,
    review_document_templates_digest,
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
