from __future__ import annotations

import hashlib

from keel_verifier import verifier
from keel_verifier.canonical import permit_binding


RECORD_ONE = {
    "event_id": "evt_001",
    "event_type": "permit.created",
    "resource_type": "permit",
    "resource_id": "permit_001",
    "outcome": "approved",
    "severity": "info",
    "created_at": "2026-05-07T12:34:56.789123Z",
    "prev_hash": "0" * 64,
    "sequence_number": 1,
}

RECORD_TWO = {
    "event_id": "evt_002",
    "event_type": "provider.response.received",
    "resource_type": None,
    "resource_id": None,
    "outcome": None,
    "severity": "warning",
    "created_at": "2026-05-07T12:34:57.000001+00:00",
    "prev_hash": "a" * 64,
    "sequence_number": 2,
}

CLOSURE_V1 = {
    "binding_version": "closure_v1",
    "permit_id": "permit_123",
    "execution_id": "exec_123",
    "correlation_id": "corr_123",
    "provider": "openai",
    "model": "gpt-4o-mini",
    "provider_response_digest_v1": "a" * 64,
    "client_response_digest_v1": "b" * 64,
    "closure_status": "closed",
    "status_code": 200,
    "provider_response_id": "resp_123",
    "provider_response_digest_semantics": "provider_bytes_received_by_keel",
    "client_response_digest_semantics": "response_bytes_handed_to_asgi_not_tcp_receipt",
    "request_created_at": "2026-05-07T12:34:50Z",
    "started_at": "2026-05-07T12:34:51Z",
    "completed_at": "2026-05-07T12:34:55Z",
    "provider_response_received_at": "2026-05-07T12:34:54Z",
    "client_response_delivered_at": "2026-05-07T12:34:55Z",
    "closure_signed_at": "2026-05-07T12:34:56Z",
    "binding_key_id": "abcd1234abcd1234",
}

CLOSURE_V2 = {
    **CLOSURE_V1,
    "binding_version": "closure_v2",
    "dispatch_request_digest_v1": "c" * 64,
    "dispatch_request_digest_semantics": "approved_request_body_bytes_at_dispatch_time",
}

CANONICAL = {"z": [3, 2, 1], "a": {"emoji": "keel", "number": 7}, "none": None, "bool": True}
PERMIT_BINDING_SOURCE = (
    "keel-api/app/services/permit_binding.py at commit "
    "03bcd1d964c6f25f9c985850d1452a19ee771a5a"
)
PERMIT_BINDING_CANONICAL_JSON = {
    "z": ["é", 2, None],
    "a": {"currency": "USD", "amount": 5000},
    "bool": True,
}
PERMIT_BINDING_SPEND_SCOPE = {
    "amount_max": "5000",
    "currency_class": "usd_fiat",
    "cadence": "ONE_TIME",
    "ttl_seconds": "900",
    "purpose_binding": "Purchase.Once",
    "recipient_address_digest": "ABCDEF",
    "merchant_id_digest": "",
    "description_digest": None,
}
PERMIT_BINDING_DELEGATION_POLICY = {
    "delegations": [
        {
            "verb": "Refund.Issue",
            "amount_max": None,
            "currency_class": None,
            "ttl_seconds": 300,
            "allowed_purpose_bindings": ["refund.once", "Refund.Once"],
        },
        {
            "verb": "Purchase.Create",
            "amount_max": "5000",
            "currency_class": "usd_fiat",
            "ttl_seconds": "900",
            "allowed_purpose_bindings": ["Purchase.Once", "purchase.recurring"],
        },
    ]
}
PERMIT_BINDING_BASE_FIELDS = {
    "permit_id": "10000000-0000-4000-8000-000000000222",
    "project_id": "20000000-0000-4000-8000-000000000333",
    "parent_permit_id": "30000000-0000-4000-8000-000000000444",
    "decision": " ALLOW ",
    "reason": " policy.allow ",
    "provider": "OpenAI",
    "model": "gpt-5",
    "operation": "RESPONSES.CREATE",
    "action_name": "mpp.purchase",
    "request_fingerprint": "SHA256:" + "A" * 64,
    "constraints": {"max_amount": "5000", "currency_class": "USD_FIAT"},
    "routing": {
        "requested_provider": "OPENAI",
        "requested_model": "gpt-5",
        "selected_provider": "OPENAI",
        "selected_model": "gpt-5",
        "fallback_chain": [{"provider": "ANTHROPIC", "model": "claude-opus-4"}],
        "reason_code": "primary_selected",
        "fallback_occurred": False,
        "reason_metadata": {"latency_tier": "interactive"},
    },
    "policy_id": "policy_mpp",
    "policy_version": "2026-06-04",
    "policy_snapshot_hash": "SHA256:" + "B" * 64,
    "issued_at": "2026-06-04T12:00:00Z",
    "expires_at": "2026-06-04T12:15:00Z",
    "is_dry_run": False,
    "binding_key_id": "permit-key-1",
    "final_request_hash": "SHA256:" + "C" * 64,
}
PERMIT_BINDING_V2_FIELDS = {
    "binding_session_id": "session_abc",
    "binding_session_event_hash": "SHA256:" + "D" * 64,
    "binding_project_anchor_hash": "SHA256:" + "E" * 64,
    "permit_chain_role": "SESSION_CHILD",
    "inherits_from": "40000000-0000-4000-8000-000000000555",
    "authority_delta": {"actions": ["payments.charge"], "max_amount": 5000},
}


def test_record_hash_v1_matches_keel_api_golden_vectors():
    assert verifier._compute_record_hash_v1(**RECORD_ONE) == "649d339d4da8efbff5ffe9737d0acba8d58623111baeece16195d9b36cd2b7c1"
    assert verifier._compute_record_hash_v1(**RECORD_TWO) == "935ae82c362544389f187e4b6a233046b1f287dc45fe0813a410baeadd45f376"


def test_closure_canonical_hash_matches_keel_api_golden_vectors():
    assert verifier._compute_canonical_binding_hash(CLOSURE_V1) == "fd10f28d706055f95ce5c4cb1fcc227c47420e4b543688ca549c4ac10f72b2e8"
    assert verifier._compute_canonical_binding_hash(CLOSURE_V2) == "f8c5eb7635180e662351af2f7aad47c27d478bdc57ca25e9708660a6273083dc"


def test_canonical_json_matches_keel_api_golden_vector():
    assert verifier._canonical_json(CANONICAL) == '{"a":{"emoji":"keel","number":7},"bool":true,"none":null,"z":[3,2,1]}'
    assert verifier._compute_canonical_binding_hash(CANONICAL) == "0643da58d8d3b61b2e9c1a0d1c2472c7eed4ebaa89ae3e118ab153aa3d9a0f11"


def test_canonical_json_byte_identity_with_keel_api():
    # Produced by keel-api/app/services/permit_binding.py at commit
    # 03bcd1d964c6f25f9c985850d1452a19ee771a5a.
    assert PERMIT_BINDING_SOURCE
    assert permit_binding._canonical_json(PERMIT_BINDING_CANONICAL_JSON).hex() == (
        "7b2261223a7b22616d6f756e74223a353030302c2263757272656e6379223a"
        "22555344227d2c22626f6f6c223a747275652c227a223a5b22c3a9222c32"
        "2c6e756c6c5d7d"
    )


def test_canonical_spend_scope_payload_byte_identity():
    # Produced by keel-api/app/services/permit_binding.py at commit
    # 03bcd1d964c6f25f9c985850d1452a19ee771a5a.
    assert permit_binding.canonical_spend_scope_payload(PERMIT_BINDING_SPEND_SCOPE) == (
        "f744453b37ab4e6cc05a8137abb69e4a430449d0825fb2066d97db61e57915ce"
    )


def test_canonical_binding_payload_v2_byte_identity():
    # Produced by keel-api/app/services/permit_binding.py at commit
    # 03bcd1d964c6f25f9c985850d1452a19ee771a5a.
    payload = permit_binding.canonical_binding_payload_v2(
        **PERMIT_BINDING_BASE_FIELDS,
        **PERMIT_BINDING_V2_FIELDS,
    )
    assert hashlib.sha256(permit_binding._canonical_json(payload)).hexdigest() == (
        "52464d7545a142012d3e0097233e278a68489483971675dbffee569796b3c21b"
    )


def test_canonical_binding_payload_v3_byte_identity():
    # Produced by keel-api/app/services/permit_binding.py at commit
    # 03bcd1d964c6f25f9c985850d1452a19ee771a5a.
    payload = permit_binding.canonical_binding_payload_v3(
        **PERMIT_BINDING_BASE_FIELDS,
        **PERMIT_BINDING_V2_FIELDS,
        spend_scope_hash=permit_binding.canonical_spend_scope_payload(
            PERMIT_BINDING_SPEND_SCOPE
        ),
    )
    assert hashlib.sha256(permit_binding._canonical_json(payload)).hexdigest() == (
        "808261240a2602579b090068115a06826494a48dd3104d3e161345e6e51fcef8"
    )


def test_canonical_binding_payload_v4_byte_identity():
    # Produced by keel-api/app/services/permit_binding.py at commit
    # 03bcd1d964c6f25f9c985850d1452a19ee771a5a.
    payload = permit_binding.canonical_binding_payload_v4(
        **PERMIT_BINDING_BASE_FIELDS,
        **PERMIT_BINDING_V2_FIELDS,
        spend_scope_hash=permit_binding.canonical_spend_scope_payload(
            PERMIT_BINDING_SPEND_SCOPE
        ),
        delegation_policy_hash=permit_binding.canonical_delegation_policy_payload(
            PERMIT_BINDING_DELEGATION_POLICY
        ),
    )
    assert hashlib.sha256(permit_binding._canonical_json(payload)).hexdigest() == (
        "356935ee2a827a72cd5fbe99a6d8fe53bb296aa47b5793dcd0954ec8e6f290e8"
    )


def test_canonical_delegation_policy_payload_byte_identity():
    # Produced by keel-api/app/services/permit_binding.py at commit
    # 03bcd1d964c6f25f9c985850d1452a19ee771a5a.
    assert permit_binding.canonical_delegation_policy_payload(
        PERMIT_BINDING_DELEGATION_POLICY
    ) == "4231454d7dec489042aa687e0d3b1c077d28a1e25f5ca83b10269f0875d70e01"
