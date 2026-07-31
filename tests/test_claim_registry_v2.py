from __future__ import annotations

import json

import pytest

from keel_verifier import verdicts


def test_current_claim_registry_composes_pinned_v1_base() -> None:
    registry = verdicts.load_claim_registry()

    assert registry.version == "verifier-claims.v2"
    assert registry.claim("permit.decision.v1").name == "permit.decision.v1"
    assert registry.claim("permit.type.v1").name == "permit.type.v1"
    assert registry.claim("provider.completed.v1").does_not_establish


def test_v2_claim_registry_rejects_wrong_base_digest(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = verdicts.resources.files("keel_verifier").joinpath(
        "data/claim_registry/v2.json"
    )
    payload = json.loads(source.read_text(encoding="utf-8"))
    payload["extends"]["sha256"] = "0" * 64
    path = tmp_path / "claim-registry-v2.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("KEEL_CLAIM_REGISTRY", str(path))
    verdicts.load_claim_registry.cache_clear()

    with pytest.raises(ValueError, match="pins v1 digest"):
        verdicts.load_claim_registry()

    verdicts.load_claim_registry.cache_clear()


def test_v2_claim_registry_rejects_duplicate_base_claim(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = verdicts.resources.files("keel_verifier").joinpath(
        "data/claim_registry/v2.json"
    )
    payload = json.loads(source.read_text(encoding="utf-8"))
    payload["claims"].append(
        {
            "name": "permit.decision.v1",
            "verdict_enum": payload["verdict_enum"],
        }
    )
    path = tmp_path / "claim-registry-v2.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("KEEL_CLAIM_REGISTRY", str(path))
    verdicts.load_claim_registry.cache_clear()

    with pytest.raises(ValueError, match="duplicates base claims"):
        verdicts.load_claim_registry()

    verdicts.load_claim_registry.cache_clear()
