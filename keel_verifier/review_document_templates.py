"""Non-authorizing review document templates bundled from keel-permit.

A review document template names, for one trusted Permit semantic, the facts a
reviewer reads before deciding a held request, how each is labelled, where it
comes from and whether it is essential.  This module loads the bundled
``review_document_templates/v1.json`` (byte-identical to keel-permit) and
returns a template by ``template_id`` together with the registry's RFC 8785
digest, so a caller can pin the exact registry a document was rendered from.

Nothing in this module is imported by adjudication code.  It never feeds
verdicts, claim adjudication, cryptographic checks or process exit codes, and
it cannot create, alter or complete a fact: templates only label and order
facts that are already bound or checked elsewhere.

The verifier does not validate bundled registries against their schemas at
load time; the bundled bytes are pinned by the release manifest and checked
against ``v1.schema.json`` in the test suite and in keel-permit's CI.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import hashlib
from importlib import resources
import json
from typing import Any

import rfc8785

REGISTRY_RESOURCE = "data/permit_to_x/review_document_templates/v1.json"
SCHEMA_RESOURCE = "data/permit_to_x/review_document_templates/v1.schema.json"
REGISTRY_ARTIFACT_ID = "keel.permit.review_document_templates"
REGISTRY_VERSION = "keel.review_document_templates.v1"


@dataclass(frozen=True)
class ReviewDocumentTemplate:
    """One template plus the identity of the registry it was read from."""

    template: dict[str, Any]
    registry_artifact_id: str
    registry_version: str
    # sha256 over the RFC 8785 (JCS) canonical form of the whole registry.
    registry_digest: str
    # sha256 over the bundled file bytes, as listed in the release manifest.
    registry_file_sha256: str


@lru_cache(maxsize=1)
def _load_raw() -> tuple[bytes, str]:
    raw = resources.files("keel_verifier").joinpath(REGISTRY_RESOURCE).read_bytes()
    registry = json.loads(raw.decode("utf-8"))
    if not isinstance(registry, dict):
        raise ValueError("review document template registry is not an object")
    if registry.get("artifact_id") != REGISTRY_ARTIFACT_ID:
        raise ValueError("review document template registry has an unexpected artifact_id")
    if registry.get("version") != REGISTRY_VERSION:
        raise ValueError("review document template registry has an unexpected version")
    templates = registry.get("templates")
    if not isinstance(templates, list) or not all(
        isinstance(item, dict) and isinstance(item.get("template_id"), str)
        for item in templates
    ):
        raise ValueError("review document template registry has malformed templates")
    template_ids = [item["template_id"] for item in templates]
    if len(template_ids) != len(set(template_ids)):
        raise ValueError("review document template ids are not distinct")
    digest = f"sha256:{hashlib.sha256(rfc8785.dumps(registry)).hexdigest()}"
    return raw, digest


def load_review_document_templates() -> dict[str, Any]:
    """Return a defensive copy of the bundled review document template registry."""

    raw, _digest = _load_raw()
    return json.loads(raw.decode("utf-8"))


def load_review_document_templates_schema() -> dict[str, Any]:
    """Return the bundled JSON Schema for the template registry."""

    raw = resources.files("keel_verifier").joinpath(SCHEMA_RESOURCE).read_bytes()
    return json.loads(raw.decode("utf-8"))


def review_document_templates_digest() -> str:
    """Return ``sha256:<hex>`` over the registry's RFC 8785 canonical form."""

    return _load_raw()[1]


def get_review_document_template(template_id: str) -> ReviewDocumentTemplate:
    """Return the template with ``template_id`` and the registry's digest.

    Raises ``KeyError`` for an id the bundled registry does not define; an
    unknown template is never guessed at or substituted.
    """

    raw, digest = _load_raw()
    registry = json.loads(raw.decode("utf-8"))
    for template in registry["templates"]:
        if template["template_id"] == template_id:
            return ReviewDocumentTemplate(
                template=template,
                registry_artifact_id=registry["artifact_id"],
                registry_version=registry["version"],
                registry_digest=digest,
                registry_file_sha256=f"sha256:{hashlib.sha256(raw).hexdigest()}",
            )
    raise KeyError(template_id)
