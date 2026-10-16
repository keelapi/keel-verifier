"""Offline exported chains preserve current issuance policy and verb semantics."""
from __future__ import annotations

import json

import pytest

from conftest import keypair, write_json, write_signed_export
from keel_verifier import semantics, verifier
from test_authority_chain_v1 import (
    _key_manifest_for_authority_export,
    _semantic_ref,
    _signed_authority_edge,
    _supported_authority_export,
    _two_edge_authority_export,
)


def _fixture(*, edge_policy=None, permit_policy="permit-policy.v1", verbs=("execute",)):
    if len(verbs) == 1:
        document, root = _supported_authority_export()
    else:
        document, root = _two_edge_authority_export(parent_resources={}, child_resources={})
    edges = []
    keys = []
    for old, verb in zip(document["authority_edges"], verbs):
        payload = old["payload"]
        private, public, key_id = keypair()
        payload["signing_key"]["key_id"] = key_id
        payload["parent_edge_digest"] = edges[-1]["edge_digest"] if edges else None
        payload["policy_version"] = edge_policy
        payload["scope"]["action_verbs"] = [verb]
        payload["scope"]["action_classes"] = ["llm.invoke"] if verb == "execute" else ["value_transfer"]
        edges.append(_signed_authority_edge(private_key=private, payload=payload))
        keys.append({**root["keys"][len(keys)], "key_id": key_id, "public_key_bytes": public})
    document["authority_edges"] = edges
    root["keys"] = keys
    chain = verifier._authority_chain_payload_for_edges(edges)
    chain["policy_version"] = permit_policy
    document["authority_chain"]["payload"] = chain
    document["permit"]["policy_version"] = permit_policy
    document["permit"]["authority_chain_digest"] = verifier._authority_sha256_hex(verifier._authority_rfc8785_bytes(chain))
    kind = "execute" if verbs[-1] == "execute" else "payment_execute"
    document["requested_action"] = {"kind": kind}
    document["action_class_map"] = {kind: ["llm.invoke"] if kind == "execute" else ["value_transfer"]}
    return document, root


def _public_cli(tmp_path, run_cli, document, root):
    private, public, key_id = keypair()
    export, manifest = write_signed_export(tmp_path, document, export_private_key=private, export_public_key=public, export_key_id=key_id)
    keys = _key_manifest_for_authority_export(tmp_path, export_public_key=public, export_key_id=key_id, trust_root=root)
    m = json.loads(manifest.read_text())
    m["claim_set"] = {"version": semantics.CLAIM_REGISTRY_VERSION, "registry": _semantic_ref(semantics.CLAIM_REGISTRY_ID), "claims": [
        {"name": "export.integrity.v1", "required": True},
        {"name": "permit.authority_chain.v1", "required": True},
    ]}
    m["semantics_pins"] = {"version": semantics.SEMANTICS_PINS_VERSION, "mode": "pinned", "artifacts": [
        _semantic_ref(semantics.EXPORT_MANIFEST_INTEGRITY_ID),
        _semantic_ref(semantics.PERMIT_AUTHORITY_CHAIN_ID),
    ]}
    write_json(manifest, m)
    result = run_cli("export", str(export), str(manifest), "--key-manifest", str(keys), "--json")
    report = json.loads(result.stdout)
    claim = next(c for c in report["claims"] if c["name"] == "permit.authority_chain.v1")
    return result, report, claim


@pytest.mark.parametrize("edge_policy", [None, "edge-policy.v1", "permit-policy.v1"])
def test_public_offline_chain_binds_issuance_policy_independently_of_edge_policy(tmp_path, run_cli, edge_policy):
    document, root = _fixture(edge_policy=edge_policy)
    original_edges = json.dumps(document["authority_edges"], sort_keys=True)
    result, report, claim = _public_cli(tmp_path, run_cli, document, root)
    assert result.returncode == 0, report
    assert claim["verdict"] == "supported"
    assert json.dumps(document["authority_edges"], sort_keys=True) == original_edges


@pytest.mark.parametrize("verbs", [
    ("payment.execute",), ("mpp_payment",), ("payment_execute",),
    ("payment.execute", "payment_execute"), ("payment_execute", "mpp_payment"),
    ("mpp_payment", "payment.execute"), (" PAYMENT.EXECUTE ", "payment_execute"),
])
def test_public_offline_chain_matches_existing_aliases_without_rewriting_signed_edges(tmp_path, run_cli, verbs):
    document, root = _fixture(edge_policy="permit-policy.v1", verbs=verbs)
    original_edges = json.dumps(document["authority_edges"], sort_keys=True)
    result, report, claim = _public_cli(tmp_path, run_cli, document, root)
    assert result.returncode == 0, report
    assert claim["verdict"] == "supported"
    assert json.dumps(document["authority_edges"], sort_keys=True) == original_edges


@pytest.mark.parametrize("mutation", ["chain-policy", "permit-policy", "edge-policy", "malformed-policy", "missing-policy", "missing-payment-class", "unmapped-action", "different-tool-verb"])
def test_public_offline_chain_rejects_tamper_and_authority_broadening(tmp_path, run_cli, mutation):
    document, root = _fixture(edge_policy="permit-policy.v1", verbs=("payment.execute",))
    if mutation == "chain-policy":
        document["authority_chain"]["payload"]["policy_version"] = "tampered-policy"
    elif mutation == "permit-policy":
        document["permit"]["policy_version"] = "tampered-policy"
    elif mutation == "edge-policy":
        document["authority_edges"][0]["payload"]["policy_version"] = "tampered-policy"
    elif mutation in {"malformed-policy", "missing-policy"}:
        if mutation == "malformed-policy":
            document["authority_chain"]["payload"]["policy_version"] = 42
        else:
            del document["authority_chain"]["payload"]["policy_version"]
        document["permit"]["authority_chain_digest"] = verifier._authority_sha256_hex(verifier._authority_rfc8785_bytes(document["authority_chain"]["payload"]))
    elif mutation == "missing-payment-class":
        document, root = _fixture(edge_policy="permit-policy.v1", verbs=("execute",))
        document["requested_action"] = {"kind": "payment_execute"}
        document["action_class_map"] = {"payment_execute": ["value_transfer"]}
    elif mutation == "unmapped-action":
        document["requested_action"] = {"kind": "mcp.tool.call"}
    else:
        document, root = _fixture(edge_policy="permit-policy.v1", verbs=("tool.call", "mcp.tool.call"))
    result, report, claim = _public_cli(tmp_path, run_cli, document, root)
    assert result.returncode == 1, report
    assert claim["verdict"] != "supported"
    assert report["ok"] is False


def test_historical_chain_without_redundant_permit_policy_projection_still_verifies(tmp_path, run_cli):
    document, root = _fixture(edge_policy=None)
    del document["permit"]["policy_version"]
    result, report, claim = _public_cli(tmp_path, run_cli, document, root)
    assert result.returncode == 0, report
    assert claim["verdict"] == "supported"


def test_nullable_issuance_policy_is_distinct_from_edge_policy(tmp_path, run_cli):
    document, root = _fixture(edge_policy="edge-policy.v1", permit_policy=None)
    result, report, claim = _public_cli(tmp_path, run_cli, document, root)
    assert result.returncode == 0, report
    assert claim["verdict"] == "supported"


@pytest.mark.parametrize("kind", [None, {}, [], 42, "payment.execute.lookalike"])
def test_malformed_or_unknown_requested_action_does_not_gain_alias_authority(tmp_path, run_cli, kind):
    document, root = _fixture(edge_policy="permit-policy.v1", verbs=("payment.execute",))
    document["requested_action"] = {"kind": kind}
    result, report, claim = _public_cli(tmp_path, run_cli, document, root)
    assert result.returncode == 1, report
    assert claim["verdict"] != "supported"
