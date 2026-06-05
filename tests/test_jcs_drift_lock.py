from __future__ import annotations

from datetime import datetime, timezone

import rfc8785

from keel_verifier.canonical.permit_binding import canonical_binding_bytes


REALISTIC_KEEL_PAYLOADS = [
    {
        "binding_version": "v5",
        "permit_id": "10000000-0000-4000-8000-000000000001",
        "project_id": "20000000-0000-4000-8000-000000000002",
        "decision": "allow",
        "provider": "openai",
        "model": "gpt-5",
        "constraints": {"max_output_tokens": 1024, "currency_class": "USD_FIAT"},
    },
    {
        "binding_version": "v5",
        "spend_scope": {
            "amount_max": 5000,
            "currency_class": "USD_FIAT",
            "cadence": "one_time",
            "ttl_seconds": 900,
        },
    },
    {
        "binding_version": "v5",
        "delegation_policy": {
            "delegations": [
                {"verb": "purchase.create", "amount_max": 5000},
                {"verb": "refund.issue", "amount_max": None},
            ]
        },
    },
    {
        "binding_version": "v5",
        "provider_body": {
            "model": "gpt-5",
            "temperature": 1.0,
            "messages": [{"role": "user", "content": "approve"}],
        },
    },
    {
        "binding_version": "v5",
        "issued_at": datetime(2026, 6, 4, 12, 0, tzinfo=timezone.utc).isoformat(),
        "routing": {
            "selected_provider": "openai",
            "fallback_chain": [{"provider": "anthropic", "model": "claude-opus-4"}],
        },
    },
]

RFC8785_REFERENCE_VECTORS = [
    {"value": 0},
    {"value": 1.0},
    {"value": -0.0},
    {"value": 333333333.3333333},
    {"value": 1e30},
    {"value": 4.5},
    {"value": True},
    {"value": None},
    {"\uffff": 1, "\U00010000": 2},
]


def test_v5_jcs_drift_lock_realistic_keel_payloads() -> None:
    for payload in REALISTIC_KEEL_PAYLOADS:
        assert canonical_binding_bytes("v5", payload) == rfc8785.dumps(payload)


def test_v5_jcs_drift_lock_rfc8785_reference_vectors() -> None:
    for payload in RFC8785_REFERENCE_VECTORS:
        assert canonical_binding_bytes("v5", payload) == rfc8785.dumps(payload)
