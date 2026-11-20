"""Provider wire-body request canonicalization v6.

keel-api binds every newly issued v5-v8 Permit's provider request body with
request canonicalization v6 (RFC 8785 JCS, volatile and credential keys
stripped from the top level only) and keeps v5 (stripped at every depth) for
Permits first bound before v6 existed. Through 3.37.0 the verifier only knew
v5, so genuine v6 evidence whose body carried such a key below the top level
was disproved.

The request canonical version is not in the signed binding payload. These
tests pin what the verifier accepts from the unsigned
``binding_request_canonical_version`` evidence field and what it reports.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from conftest import (
    keypair as export_keypair,
    write_combined_key_manifest,
    write_signed_export,
)
from step4_permit_helpers import keypair, write_permit_trust_root
from test_permit_decision_v1 import (
    _add_permit_decision_pins,
    _binding_evidence,
    _binding_payload,
    _claim,
    _report_claim,
    _v7_binding_payload,
    _verify_export_args,
)
from keel_verifier.canonical import permit_binding
from keel_verifier.verifier import verify_export_structured

VECTORS_PATH = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "request_canonicalization_v6_issuer_vectors.json"
)
VECTORS = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))["vectors"]
VECTORS_BY_ID = {vector["id"]: vector for vector in VECTORS}

MCP_BODY = VECTORS_BY_ID["mcp_tools_call_nested_volatile_arguments"]["body"]
MCP_NESTED_PATHS = (
    "params.arguments.timestamp",
    "params.arguments.request_id",
    "params.arguments.api_key",
    "params.arguments.labels.[].trace_id",
)
PLAIN_BODY = VECTORS_BY_ID["openai_responses_no_nested_volatile"]["body"]
MCP_IDEMPOTENCY_BODY = VECTORS_BY_ID["mcp_tools_call_idempotency_key_argument"]["body"]


# --- canonicalizer -----------------------------------------------------------


@pytest.mark.parametrize("vector", VECTORS, ids=[v["id"] for v in VECTORS])
def test_wire_body_bytes_match_issuer_vectors(vector: dict[str, Any]) -> None:
    body = vector["body"]
    for version in ("v1", "v5", "v6"):
        assert (
            permit_binding.canonical_provider_wire_body_hash(
                body, binding_request_canonical_version=version
            )
            == vector[f"{version}_sha256"]
        ), version
        assert (
            permit_binding.canonical_provider_wire_body_hash(
                body,
                binding_request_canonical_version=version,
                preserve_mcp_tool_argument_idempotency=True,
            )
            == vector[f"{version}_mcp_sha256" if version != "v6" else "v6_sha256"]
        ), version
    assert permit_binding.canonical_provider_wire_body(
        body, binding_request_canonical_version="v6"
    ) == vector["v6_canonical_utf8"].encode("utf-8")


def test_v6_keeps_nested_credential_like_keys_that_v5_strips() -> None:
    v5 = json.loads(
        permit_binding.canonical_provider_wire_body(
            MCP_BODY, binding_request_canonical_version="v5"
        )
    )
    v6 = json.loads(
        permit_binding.canonical_provider_wire_body(
            MCP_BODY, binding_request_canonical_version="v6"
        )
    )

    for parsed in (v5, v6):
        assert "request_id" not in parsed
        assert "x-keel-timestamp" not in parsed
    assert v6["params"]["arguments"]["timestamp"] == "2026-11-19T09:59:00Z"
    assert v6["params"]["arguments"]["request_id"] == "customer-ticket-4411"
    assert v6["params"]["arguments"]["api_key"] == "placeholder-not-a-secret"
    assert v6["params"]["arguments"]["labels"] == [
        {"name": "security", "trace_id": "label-trace-1"}
    ]
    assert set(v5["params"]["arguments"]) == {"repository", "title", "labels"}
    assert v5["params"]["arguments"]["labels"] == [{"name": "security"}]


def test_nested_request_keys_outside_binding() -> None:
    assert (
        permit_binding.nested_request_keys_outside_binding(
            MCP_BODY, binding_request_canonical_version="v5"
        )
        == MCP_NESTED_PATHS
    )
    assert (
        permit_binding.nested_request_keys_outside_binding(
            MCP_BODY, binding_request_canonical_version="v6"
        )
        == ()
    )
    assert (
        permit_binding.nested_request_keys_outside_binding(
            PLAIN_BODY, binding_request_canonical_version="v5"
        )
        == ()
    )
    # A stripped top-level key takes its subtree with it under every version.
    assert (
        permit_binding.nested_request_keys_outside_binding(
            {"authorization": {"request_id": "x"}, "a": 1},
            binding_request_canonical_version="v5",
        )
        == ()
    )


def test_mcp_idempotency_argument_is_kept_only_for_an_mcp_dispatch() -> None:
    def arguments(version: str, preserve: bool) -> dict[str, Any]:
        return json.loads(
            permit_binding.canonical_provider_wire_body(
                MCP_IDEMPOTENCY_BODY,
                binding_request_canonical_version=version,
                preserve_mcp_tool_argument_idempotency=preserve,
            )
        )["params"]["arguments"]

    for version in ("v1", "v5"):
        assert arguments(version, True)["idempotency_key"] == "refund-ch_123-1"
        assert "idempotency_key" not in arguments(version, False)
        assert permit_binding.nested_request_keys_outside_binding(
            MCP_IDEMPOTENCY_BODY,
            binding_request_canonical_version=version,
            preserve_mcp_tool_argument_idempotency=True,
        ) == ()
        assert permit_binding.nested_request_keys_outside_binding(
            MCP_IDEMPOTENCY_BODY,
            binding_request_canonical_version=version,
        ) == ("params.arguments.idempotency_key",)
    for preserve in (True, False):
        assert arguments("v6", preserve)["idempotency_key"] == "refund-ch_123-1"
    # Only that exact path: other volatile arguments are still dropped.
    assert "timestamp" not in json.loads(
        permit_binding.canonical_provider_wire_body(
            MCP_BODY,
            binding_request_canonical_version="v5",
            preserve_mcp_tool_argument_idempotency=True,
        )
    )["params"]["arguments"]


def test_request_canonical_version_helpers_mirror_issuer() -> None:
    for binding_version in ("v5", "v6", "v7", "v8"):
        assert (
            permit_binding.binding_request_canonical_version_for_binding(binding_version)
            == "v5"
        )
        assert (
            permit_binding.binding_request_canonical_version_for_issuance(
                binding_version
            )
            == "v6"
        )
        assert permit_binding.binding_request_canonical_versions_for_binding(
            binding_version
        ) == frozenset({"v5", "v6"})
    for binding_version in ("v1", "v2", "v3", "v4", None, ""):
        assert (
            permit_binding.binding_request_canonical_version_for_binding(binding_version)
            == "v1"
        )
        assert (
            permit_binding.binding_request_canonical_version_for_issuance(
                binding_version
            )
            == "v1"
        )
        assert permit_binding.binding_request_canonical_versions_for_binding(
            binding_version
        ) == frozenset({"v1"})


# --- permit.decision.v1 ------------------------------------------------------


def _issuer_hash(
    body: dict[str, Any], request_canonical_version: str, *, mcp: bool = False
) -> str:
    """The Issuer's own hash for a vector body, independent of the code under test."""

    (vector,) = [vector for vector in VECTORS if vector["body"] == body]
    if mcp and request_canonical_version != "v6":
        return vector[f"{request_canonical_version}_mcp_sha256"]
    return vector[f"{request_canonical_version}_sha256"]


def _payload(
    public_key: str,
    version: str,
    final_request_hash: str,
    provider: str | None = None,
) -> dict[str, Any]:
    if version == "v7":
        payload = _v7_binding_payload(
            public_key, final_request_hash="sha256:" + final_request_hash
        )
    else:
        payload = _binding_payload(public_key, version=version)
        payload["final_request_hash"] = "sha256:" + final_request_hash
    if provider is not None:
        payload["provider"] = provider
    return payload


def _wire_evidence(
    private_key,
    public_key: str,
    *,
    binding_version: str,
    bound_body: dict[str, Any],
    bound_with: str,
    presented_body: dict[str, Any] | None = None,
    declared: Any = "__bound_with__",
    provider: str | None = None,
) -> dict[str, Any]:
    bound_hash = _issuer_hash(bound_body, bound_with, mcp=provider == "mcp")
    evidence = _binding_evidence(
        private_key,
        public_key,
        version=binding_version,
        payload=_payload(public_key, binding_version, bound_hash, provider),
    )
    evidence["binding_request_hash"] = bound_hash
    if declared == "__bound_with__":
        evidence["binding_request_canonical_version"] = bound_with
    elif declared is not None:
        evidence["binding_request_canonical_version"] = declared
    evidence["binding_request_body"] = copy.deepcopy(
        bound_body if presented_body is None else presented_body
    )
    return evidence


@pytest.mark.parametrize("binding_version", ["v5", "v6", "v7"])
def test_genuine_v6_bound_body_with_nested_keys_is_supported(
    tmp_path: Path, binding_version: str
) -> None:
    private_key, public_key = keypair(b"r6" * 16)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    evidence = _wire_evidence(
        private_key,
        public_key,
        binding_version=binding_version,
        bound_body=MCP_BODY,
        bound_with="v6",
    )

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "supported"
    assert claim.reason_code == "PERMIT_DECISION_SUPPORTED"
    # A v6 match binds everything below the top level: no added boundary.
    assert claim.does_not_establish is None


def test_v6_bound_body_was_disproved_under_v5_only(tmp_path: Path) -> None:
    """What 3.37.0 did: recompute with v5, which drops the nested arguments."""

    assert _issuer_hash(MCP_BODY, "v6") != _issuer_hash(MCP_BODY, "v5")
    private_key, public_key = keypair(b"r7" * 16)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    # Absent version means v5, exactly as keel-api reads a Permit with none.
    evidence = _wire_evidence(
        private_key,
        public_key,
        binding_version="v7",
        bound_body=MCP_BODY,
        bound_with="v6",
        declared=None,
    )

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "permit.binding.v7.wire_body_hash_mismatch"


@pytest.mark.parametrize("binding_version", ["v5", "v7"])
@pytest.mark.parametrize("declared", ["v5", None])
def test_legacy_v5_bound_permit_still_verifies(
    tmp_path: Path, binding_version: str, declared: str | None
) -> None:
    private_key, public_key = keypair(b"l5" * 16)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    evidence = _wire_evidence(
        private_key,
        public_key,
        binding_version=binding_version,
        bound_body=PLAIN_BODY,
        bound_with="v5",
        declared=declared,
    )

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "supported"
    assert claim.reason_code == "PERMIT_DECISION_SUPPORTED"
    assert claim.does_not_establish is None


def test_legacy_v5_bound_body_with_nested_keys_names_unbound_paths(
    tmp_path: Path,
) -> None:
    private_key, public_key = keypair(b"l6" * 16)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    evidence = _wire_evidence(
        private_key,
        public_key,
        binding_version="v7",
        bound_body=MCP_BODY,
        bound_with="v5",
    )

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "supported"
    assert claim.reason_code == "PERMIT_DECISION_SUPPORTED"
    assert claim.does_not_establish is not None
    (boundary,) = [
        entry for entry in claim.does_not_establish if "request-body values" in entry
    ]
    for path in MCP_NESTED_PATHS:
        assert path in boundary
    assert "not signed" in boundary


def test_downgrade_to_v5_cannot_hide_injected_nested_values(tmp_path: Path) -> None:
    """A presenter who declares v5 for a v6-bound Permit gets only v5's guarantee.

    The verifier cannot tell this from a genuine v5-bound Permit (the version is
    unsigned), so the verdict stays supported, as 3.37.0's v5-only recompute
    already returned, but the injected nested values are named as not bound.
    """

    private_key, public_key = keypair(b"d5" * 16)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    injected = copy.deepcopy(PLAIN_BODY)
    injected["input"][0]["content"][0]["request_id"] = "injected-not-dispatched"
    evidence = _wire_evidence(
        private_key,
        public_key,
        binding_version="v7",
        bound_body=PLAIN_BODY,
        bound_with="v6",
        presented_body=injected,
        declared="v5",
    )

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "supported"
    assert claim.does_not_establish is not None
    assert any(
        "input.[].content.[].request_id" in entry
        for entry in claim.does_not_establish
    )

    # Declaring the version the Issuer actually used exposes the injection.
    evidence["binding_request_canonical_version"] = "v6"
    claim = _claim(evidence, trust_root)
    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "permit.binding.v7.wire_body_hash_mismatch"


def test_downgrade_to_v5_cannot_alter_bound_nested_values(tmp_path: Path) -> None:
    private_key, public_key = keypair(b"d6" * 16)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    tampered = copy.deepcopy(MCP_BODY)
    tampered["params"]["arguments"]["timestamp"] = "2030-01-01T00:00:00Z"
    evidence = _wire_evidence(
        private_key,
        public_key,
        binding_version="v7",
        bound_body=MCP_BODY,
        bound_with="v6",
        presented_body=tampered,
        declared="v5",
    )

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "permit.binding.v7.wire_body_hash_mismatch"


@pytest.mark.parametrize("binding_version", ["v5", "v6", "v7"])
def test_tampered_nested_argument_under_v6_is_disproved(
    tmp_path: Path, binding_version: str
) -> None:
    private_key, public_key = keypair(b"t6" * 16)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    tampered = copy.deepcopy(MCP_BODY)
    tampered["params"]["arguments"]["request_id"] = "customer-ticket-9999"
    evidence = _wire_evidence(
        private_key,
        public_key,
        binding_version=binding_version,
        bound_body=MCP_BODY,
        bound_with="v6",
        presented_body=tampered,
    )

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == f"permit.binding.{binding_version}.wire_body_hash_mismatch"


@pytest.mark.parametrize("binding_version", ["v5", "v6", "v7"])
@pytest.mark.parametrize("declared", ["v1", "v7", "V6", " v4 ", 6])
def test_unknown_declared_request_canonical_version_is_disproved(
    tmp_path: Path, binding_version: str, declared: Any
) -> None:
    private_key, public_key = keypair(b"m6" * 16)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    evidence = _wire_evidence(
        private_key,
        public_key,
        binding_version=binding_version,
        bound_body=PLAIN_BODY,
        bound_with="v6",
        declared=declared,
    )

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "disproved"
    assert (
        claim.reason_code
        == f"permit.binding.{binding_version}.request_canonical_version_mismatch"
    )
    assert "canonical" in claim.message.lower()
    assert "version" in claim.message.lower()


def test_legacy_binding_versions_ignore_declared_request_canonical_version(
    tmp_path: Path,
) -> None:
    """v1-v4: the signed binding version alone fixes v1, unchanged from 3.37.0."""

    private_key, public_key = keypair(b"g2" * 16)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    evidence = _wire_evidence(
        private_key,
        public_key,
        binding_version="v2",
        bound_body=MCP_BODY,
        bound_with="v1",
        declared="v6",
    )

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "supported"
    assert claim.does_not_establish is None


@pytest.mark.parametrize(
    ("binding_version", "bound_with"),
    [("v2", "v1"), ("v5", "v5"), ("v7", "v5"), ("v7", "v6")],
)
def test_mcp_permit_keeps_idempotency_key_argument(
    tmp_path: Path, binding_version: str, bound_with: str
) -> None:
    """3.37.0 dropped params.arguments.idempotency_key for every provider."""

    private_key, public_key = keypair(b"i5" * 16)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    evidence = _wire_evidence(
        private_key,
        public_key,
        binding_version=binding_version,
        bound_body=MCP_IDEMPOTENCY_BODY,
        bound_with=bound_with,
        provider="mcp",
    )

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "supported"
    assert claim.reason_code == "PERMIT_DECISION_SUPPORTED"
    assert claim.does_not_establish is None

    tampered = copy.deepcopy(MCP_IDEMPOTENCY_BODY)
    tampered["params"]["arguments"]["idempotency_key"] = "refund-ch_123-2"
    evidence["binding_request_body"] = tampered
    claim = _claim(evidence, trust_root)
    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code.endswith("wire_body_hash_mismatch")


def test_non_mcp_permit_still_strips_idempotency_key_argument(
    tmp_path: Path,
) -> None:
    private_key, public_key = keypair(b"i6" * 16)
    trust_root = write_permit_trust_root(tmp_path, public_key)
    evidence = _wire_evidence(
        private_key,
        public_key,
        binding_version="v7",
        bound_body=MCP_IDEMPOTENCY_BODY,
        bound_with="v5",
    )

    claim = _claim(evidence, trust_root)

    assert claim.aggregate_verdict == "supported"
    assert claim.does_not_establish is not None
    assert any(
        "params.arguments.idempotency_key" in entry
        for entry in claim.does_not_establish
    )

    # The signed provider decides: changing it to flip the exception breaks the
    # canonical hash before any wire-body check runs.
    mcp_bound = _wire_evidence(
        private_key,
        public_key,
        binding_version="v7",
        bound_body=MCP_IDEMPOTENCY_BODY,
        bound_with="v5",
        provider="mcp",
    )
    mcp_bound["canonical_payload"]["provider"] = "openai"
    claim = _claim(mcp_bound, trust_root)
    assert claim.aggregate_verdict == "disproved"
    assert claim.reason_code == "PERMIT_DECISION_CANONICAL_HASH_MISMATCH"


def test_full_export_verifies_v6_bound_evidence(tmp_path: Path) -> None:
    export_private, export_public, export_key_id = export_keypair()
    binding_private, binding_public = keypair(b"e6" * 16)
    key_manifest = write_combined_key_manifest(
        tmp_path,
        export_public_key=export_public,
        export_key_id=export_key_id,
        binding_public_key=binding_public,
    )
    evidence = _wire_evidence(
        binding_private,
        binding_public,
        binding_version="v7",
        bound_body=MCP_BODY,
        bound_with="v6",
    )
    export_file, manifest = write_signed_export(
        tmp_path,
        {"permit_decision": evidence},
        export_private_key=export_private,
        export_public_key=export_public,
        export_key_id=export_key_id,
    )
    _add_permit_decision_pins(manifest)

    report = verify_export_structured(
        _verify_export_args(export_file, manifest, key_manifest)
    )
    claim = _report_claim(report, "permit.decision.v1")

    assert report.exit_code == 0
    assert claim["verdict"] == "supported"
    assert claim["reason_code"] == "PERMIT_DECISION_SUPPORTED"


def test_full_export_reports_unbound_nested_paths_in_json(tmp_path: Path) -> None:
    export_private, export_public, export_key_id = export_keypair()
    binding_private, binding_public = keypair(b"e5" * 16)
    key_manifest = write_combined_key_manifest(
        tmp_path,
        export_public_key=export_public,
        export_key_id=export_key_id,
        binding_public_key=binding_public,
    )
    evidence = _wire_evidence(
        binding_private,
        binding_public,
        binding_version="v7",
        bound_body=MCP_BODY,
        bound_with="v5",
    )
    export_file, manifest = write_signed_export(
        tmp_path,
        {"permit_decision": evidence},
        export_private_key=export_private,
        export_public_key=export_public,
        export_key_id=export_key_id,
    )
    _add_permit_decision_pins(manifest)

    report = verify_export_structured(
        _verify_export_args(export_file, manifest, key_manifest)
    )
    claim = _report_claim(report, "permit.decision.v1")

    assert report.exit_code == 0
    assert claim["verdict"] == "supported"
    assert any(
        "params.arguments.timestamp" in entry for entry in claim["does_not_establish"]
    )
