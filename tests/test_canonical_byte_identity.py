from __future__ import annotations

from keel_verifier import verifier


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


def test_record_hash_v1_matches_keel_api_golden_vectors():
    assert verifier._compute_record_hash_v1(**RECORD_ONE) == "649d339d4da8efbff5ffe9737d0acba8d58623111baeece16195d9b36cd2b7c1"
    assert verifier._compute_record_hash_v1(**RECORD_TWO) == "935ae82c362544389f187e4b6a233046b1f287dc45fe0813a410baeadd45f376"


def test_closure_canonical_hash_matches_keel_api_golden_vectors():
    assert verifier._compute_canonical_binding_hash(CLOSURE_V1) == "fd10f28d706055f95ce5c4cb1fcc227c47420e4b543688ca549c4ac10f72b2e8"
    assert verifier._compute_canonical_binding_hash(CLOSURE_V2) == "f8c5eb7635180e662351af2f7aad47c27d478bdc57ca25e9708660a6273083dc"


def test_canonical_json_matches_keel_api_golden_vector():
    assert verifier._canonical_json(CANONICAL) == '{"a":{"emoji":"keel","number":7},"bool":true,"none":null,"z":[3,2,1]}'
    assert verifier._compute_canonical_binding_hash(CANONICAL) == "0643da58d8d3b61b2e9c1a0d1c2472c7eed4ebaa89ae3e118ab153aa3d9a0f11"
