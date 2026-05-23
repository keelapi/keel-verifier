from __future__ import annotations

import pytest

from scripts.generate_release_manifest import _canonical_json_bytes


def test_rfc8785_jcs_sorts_keys_and_removes_whitespace() -> None:
    assert _canonical_json_bytes({"b": 2, "a": 1}) == b'{"a":1,"b":2}'


def test_rfc8785_jcs_escapes_strings_and_preserves_arrays() -> None:
    payload = {"z": "line\nquote\"", "a": [True, None, 1.5]}

    assert _canonical_json_bytes(payload) == b'{"a":[true,null,1.5],"z":"line\\nquote\\""}'


def test_rfc8785_jcs_rejects_unsafe_json_integer_domain() -> None:
    with pytest.raises(SystemExit) as exc:
        _canonical_json_bytes({"unsafe": 2**53})

    assert "canonicalize JSON" in str(exc.value)
