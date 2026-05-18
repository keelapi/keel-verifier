from __future__ import annotations

from datetime import datetime, timezone

from keel_verifier import verifier


def test_malformed_valid_to_is_excluded_but_absent_valid_to_is_open_ended():
    signing_time = datetime(2026, 6, 1, tzinfo=timezone.utc)
    entries = [
        {
            "key_id": "malformed-valid-to",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": "",
        },
        {
            "key_id": "absent-valid-to",
            "valid_from": "2026-01-01T00:00:00Z",
        },
    ]

    matches = verifier._filter_by_active_window(entries, signing_time)

    assert [entry["key_id"] for entry in matches] == ["absent-valid-to"]
