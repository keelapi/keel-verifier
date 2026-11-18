"""Non-authorizing review document templates bundled from keel-permit.

A review document template names, for one trusted Permit semantic, the facts a
reviewer reads before deciding a held request, how each is labelled, where it
comes from and whether it is essential.  This module loads the bundled
``review_document_templates/v<N>.json`` registries (byte-identical to
keel-permit) and returns a template by ``template_id`` together with the
registry's RFC 8785 digest, so a caller can pin the exact registry a document
was rendered from.

Three registry versions are bundled.  A published version is never edited, so
each stays loadable by its exact version string:

- ``keel.review_document_templates.v1`` (document format
  ``keel.review_document.v1``): the Okta group-grant template.
- ``keel.review_document_templates.v2`` (document format
  ``keel.review_document.v2``): v1's template plus the ``generic`` rule set,
  pinned to semantic registry v23, presentation registry v24 and fact
  profiles v20 (``source_registries``).
- ``keel.review_document_templates.v3`` (document format
  ``keel.review_document.v2``): v2's generic rules plus tailored templates,
  pinned to presentation registry v25.

Every function takes an optional ``version`` and defaults to v1, so callers
written for 3.35.0 get the same registry, digest and template as before.  An
unknown version or template id raises ``KeyError``; nothing is guessed or
substituted.

Nothing in this module is imported by adjudication code.  It never feeds
verdicts, claim adjudication, cryptographic checks or process exit codes, and
it cannot create, alter or complete a fact: templates only label and order
facts that are already bound or checked elsewhere.  The verifier does not
apply the v2/v3 generic rules or render documents.

The verifier does not validate bundled registries against their schemas at
load time; the bundled bytes are pinned by the release manifest and checked
against their schemas in the test suite and in keel-permit's CI.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import hashlib
from importlib import resources
import json
from typing import Any

import rfc8785

REGISTRY_ARTIFACT_ID = "keel.permit.review_document_templates"

REGISTRY_VERSION_V1 = "keel.review_document_templates.v1"
REGISTRY_VERSION_V2 = "keel.review_document_templates.v2"
REGISTRY_VERSION_V3 = "keel.review_document_templates.v3"

# Registry version -> (registry resource, schema resource), oldest first.
REGISTRY_RESOURCES: dict[str, tuple[str, str]] = {
    REGISTRY_VERSION_V1: (
        "data/permit_to_x/review_document_templates/v1.json",
        "data/permit_to_x/review_document_templates/v1.schema.json",
    ),
    REGISTRY_VERSION_V2: (
        "data/permit_to_x/review_document_templates/v2.json",
        "data/permit_to_x/review_document_templates/v2.schema.json",
    ),
    REGISTRY_VERSION_V3: (
        "data/permit_to_x/review_document_templates/v3.json",
        "data/permit_to_x/review_document_templates/v3.schema.json",
    ),
}
REGISTRY_VERSIONS: tuple[str, ...] = tuple(REGISTRY_RESOURCES)
LATEST_REGISTRY_VERSION = REGISTRY_VERSION_V3

# The 3.35.0 single-registry API.  These names keep pointing at v1, and every
# function below defaults to it.
REGISTRY_VERSION = REGISTRY_VERSION_V1
REGISTRY_RESOURCE, SCHEMA_RESOURCE = REGISTRY_RESOURCES[REGISTRY_VERSION_V1]


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


def _resources_for(version: str) -> tuple[str, str]:
    try:
        return REGISTRY_RESOURCES[version]
    except (KeyError, TypeError):
        raise KeyError(version) from None


@lru_cache(maxsize=None)
def _load_raw(version: str) -> tuple[bytes, str]:
    registry_resource, _schema_resource = _resources_for(version)
    raw = resources.files("keel_verifier").joinpath(registry_resource).read_bytes()
    registry = json.loads(raw.decode("utf-8"))
    if not isinstance(registry, dict):
        raise ValueError("review document template registry is not an object")
    if registry.get("artifact_id") != REGISTRY_ARTIFACT_ID:
        raise ValueError("review document template registry has an unexpected artifact_id")
    if registry.get("version") != version:
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


def load_review_document_templates(version: str = REGISTRY_VERSION) -> dict[str, Any]:
    """Return a defensive copy of the bundled registry ``version`` (default v1)."""

    raw, _digest = _load_raw(version)
    return json.loads(raw.decode("utf-8"))


def load_review_document_templates_schema(
    version: str = REGISTRY_VERSION,
) -> dict[str, Any]:
    """Return the bundled JSON Schema for registry ``version`` (default v1)."""

    _registry_resource, schema_resource = _resources_for(version)
    raw = resources.files("keel_verifier").joinpath(schema_resource).read_bytes()
    return json.loads(raw.decode("utf-8"))


def review_document_templates_digest(version: str = REGISTRY_VERSION) -> str:
    """Return ``sha256:<hex>`` over registry ``version``'s RFC 8785 form."""

    return _load_raw(version)[1]


def review_document_templates_file_sha256(version: str = REGISTRY_VERSION) -> str:
    """Return ``sha256:<hex>`` over registry ``version``'s bundled file bytes."""

    return f"sha256:{hashlib.sha256(_load_raw(version)[0]).hexdigest()}"


def get_review_document_template(
    template_id: str,
    *,
    version: str = REGISTRY_VERSION,
) -> ReviewDocumentTemplate:
    """Return the template with ``template_id`` from registry ``version``.

    ``version`` defaults to v1.  Raises ``KeyError`` for a version this build
    does not bundle or an id that registry does not define; an unknown
    template is never guessed at or taken from another version.
    """

    raw, digest = _load_raw(version)
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
