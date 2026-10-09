"""Per-pack authority proof: an R1 refusal after a signed edge revocation.

The fixture was produced by keel-api's real signing paths
(tests/test_authority_chain_denial_proof_postgres.py with
KEEL_DENIAL_PACK_OUT): a server-signed authority edge, its revocation through
the revoke cascade (signed key.status.v1), and the signed deny Permit the R1
gate issued afterwards. Only public test keys are included.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from keel_verifier.authority_proof import (
    COMPOSITE_REFUSAL_CLAIM,
    adjudicate_authority_chain_proof_document,
)
from keel_verifier.cli import _build_parser, main

FIXTURE = Path(__file__).parent / "fixtures" / "authority_refusal"


def _load(name: str):
    return json.loads((FIXTURE / name).read_text(encoding="utf-8"))


def _composite(pack: dict, *, authority_keys: dict | None = None) -> dict:
    result = adjudicate_authority_chain_proof_document(
        {"schema": "keel.authority_inventory_chain_proof_export/v1",
         "authority_chain_proofs": [pack]},
        key_manifest_source=str(FIXTURE / "instance-key-pin.json"),
        authority_trust_root=authority_keys or _load("authority-keys.json"),
    )
    (packed,) = result["packs"]
    (claim,) = packed["claims"]
    assert claim["claim"] == COMPOSITE_REFUSAL_CLAIM
    return claim


def test_refusal_after_signed_edge_revocation_is_supported():
    claim = _composite(_load("denial-pack.json"))
    assert claim["verdict"] == "supported", claim
    revocation = claim["checks"][1]["authority.edge_revocation.v1"]
    assert revocation["verdict"] == "disproved"
    assert revocation["reason_code"] == (
        "authority_edge_revocation.edge_revoked_at_or_before_resolution"
    )


def test_tampered_refusal_subject_breaks_the_signed_permit():
    pack = _load("denial-pack.json")
    pack["permit_decision"]["canonical_payload"]["subject_id"] = (
        "00000000-0000-0000-0000-000000000000"
    )
    assert _composite(pack)["verdict"] != "supported"


def test_missing_revocation_evidence_is_insufficient():
    pack = _load("denial-pack.json")
    for claim in pack["authority_chain_proofs"]:
        claim["edge_revoke_events"] = []
    assert _composite(pack)["verdict"] == "insufficient_evidence"


def test_revocation_moved_after_the_refusal_does_not_verify():
    pack = _load("denial-pack.json")
    event = pack["authority_chain_proofs"][0]["edge_revoke_events"][0]["signed_event"]
    event["revoked_at"] = "2099-01-01T00:00:00.000000Z"
    assert _composite(pack)["verdict"] == "insufficient_evidence"


def test_tampered_edge_payload_is_disproved():
    pack = _load("denial-pack.json")
    pack["authority_edges"][0]["payload"]["scope"]["action_verbs"] = ["anything"]
    assert _composite(pack)["verdict"] == "disproved"


def test_edge_key_from_another_signer_is_disproved():
    keys = copy.deepcopy(_load("authority-keys.json"))
    for key in keys["keys"]:
        key["signer_id"] = "00000000-0000-0000-0000-000000000001"
    assert _composite(_load("denial-pack.json"), authority_keys=keys)["verdict"] == "disproved"


def test_non_r1_refusal_is_not_credited():
    pack = _load("denial-pack.json")
    pack["permit_decision"]["expected_decision"] = "deny"
    pack["permit_decision"]["canonical_payload"]["reason"] = "policy.rule_denied"
    # The signed payload no longer matches its signature: never supported.
    assert _composite(pack)["verdict"] != "supported"


def test_cli_exposes_authority_proof():
    args = _build_parser().parse_args(
        ["authority-proof", "export.json", "--authority-keys", "k.json", "--json"]
    )
    assert args.cmd == "authority-proof"
    assert args.authority_keys == "k.json"


def test_cli_main_routes_authority_proof(capsys):
    """main() must not hand the subcommand to the legacy single-file parser."""
    with pytest.raises(SystemExit) as raised:
        main(["authority-proof", "--help"])
    assert raised.value.code == 0
    assert "--authority-keys" in capsys.readouterr().out
