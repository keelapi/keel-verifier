"""Contract rules for ``keel.work_authority.v2``, checked without keel-api.

A Work is a bounded authority container, so a root may carry a phone call and a
payment side by side. What must not follow is that a non-monetary lane can
quietly acquire monetary meaning, or that an unknown future contract is
optimistically accepted.

These exercise the contract validator directly, so they depend on no export,
no database, and no Keel service.
"""

from __future__ import annotations

import pytest

from keel_verifier.work_chain import (
    WORK_AUTHORITY_V1,
    WORK_AUTHORITY_V2,
    _Failure,
    _validate_work_authority_contract,
    work_authority_is_monetary,
    work_authority_value_binding,
)


def _v1(**overrides) -> dict:
    authority = {
        "version": WORK_AUTHORITY_V1,
        "trusted_action": "payment.execute",
        "comparator_version": "work-payment-authority.v1",
        "value_max_minor": 50_000,
        "currency": "USD",
    }
    authority.update(overrides)
    return authority


def _v2(**overrides) -> dict:
    authority = {
        "version": WORK_AUTHORITY_V2,
        "trusted_action": "call.outbound",
        "comparator_version": "work-action-authority.v2",
        "value_binding": "none",
    }
    authority.update(overrides)
    return authority


def _validate(authority: dict) -> None:
    _validate_work_authority_contract(authority, index=0, authority_id="lane")


def _failure(authority: dict) -> _Failure:
    with pytest.raises(_Failure) as excinfo:
        _validate(authority)
    return excinfo.value


# --------------------------------------------------------------------------
# v1 is unchanged
# --------------------------------------------------------------------------


def test_v1_payment_authority_still_validates() -> None:
    _validate(_v1())
    assert work_authority_value_binding(_v1()) == "declared_bounded"
    assert work_authority_is_monetary(_v1()) is True


def test_v1_still_rejects_a_non_payment_action() -> None:
    """v1 is published as payment-only. That guarantee does not move."""

    failure = _failure(_v1(trusted_action="call.outbound"))
    assert failure.verdict == "disproved"
    assert failure.code == "WORK_AUTHORITY_SCOPE_MISMATCH"


def test_v1_rejects_a_v2_field() -> None:
    failure = _failure(_v1(value_binding="none"))
    assert failure.verdict == "disproved"


def test_v1_rejects_the_v2_comparator() -> None:
    failure = _failure(_v1(comparator_version="work-action-authority.v2"))
    assert failure.verdict == "disproved"


# --------------------------------------------------------------------------
# v2 accepts heterogeneous actions
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "action",
    ["call.outbound", "calendar.event.create", "travel.lodging.book"],
)
def test_v2_accepts_any_bound_action(action: str) -> None:
    _validate(_v2(trusted_action=action))


def test_v2_monetary_lane_validates() -> None:
    authority = _v2(
        trusted_action="travel.lodging.book",
        value_binding="declared_bounded",
        value_max_minor=50_000,
        currency="USD",
    )
    _validate(authority)
    assert work_authority_is_monetary(authority) is True


def test_v2_none_lane_is_not_monetary() -> None:
    assert work_authority_is_monetary(_v2()) is False
    assert work_authority_value_binding(_v2()) == "none"


# --------------------------------------------------------------------------
# Malformed v2 is disproved, never tolerated
# --------------------------------------------------------------------------


def test_none_lane_carrying_a_ceiling_is_disproved() -> None:
    """The combination the contract forbids: no value, but a value limit."""

    failure = _failure(_v2(value_max_minor=50_000))
    assert failure.verdict == "disproved"
    assert failure.code == "WORK_AUTHORITY_MANIFEST_SCHEMA_INVALID"


def test_none_lane_carrying_a_currency_is_disproved() -> None:
    assert _failure(_v2(currency="USD")).verdict == "disproved"


def test_monetary_lane_without_a_ceiling_is_disproved() -> None:
    failure = _failure(_v2(value_binding="declared_bounded", currency="USD"))
    assert failure.verdict == "disproved"


def test_monetary_lane_without_a_currency_is_disproved() -> None:
    failure = _failure(_v2(value_binding="declared_bounded", value_max_minor=10))
    assert failure.verdict == "disproved"


@pytest.mark.parametrize("binding", ["", "free", "NONE", None, 1, True])
def test_unrecognised_value_binding_is_disproved(binding) -> None:
    assert _failure(_v2(value_binding=binding)).verdict == "disproved"


def test_missing_value_binding_is_disproved() -> None:
    authority = _v2()
    authority.pop("value_binding")
    assert _failure(authority).verdict == "disproved"


@pytest.mark.parametrize("cap", [0, -1, "50000", 1.5, True])
def test_malformed_ceiling_is_disproved(cap) -> None:
    failure = _failure(
        _v2(value_binding="declared_bounded", value_max_minor=cap, currency="USD")
    )
    assert failure.verdict == "disproved"


@pytest.mark.parametrize("currency", ["usd", "US", "USDD", "", 1])
def test_malformed_currency_is_disproved(currency) -> None:
    failure = _failure(
        _v2(value_binding="declared_bounded", value_max_minor=10, currency=currency)
    )
    assert failure.verdict == "disproved"


@pytest.mark.parametrize("action", ["", "   ", None, 42])
def test_missing_trusted_action_is_disproved(action) -> None:
    assert _failure(_v2(trusted_action=action)).verdict == "disproved"


def test_v2_rejects_the_v1_comparator() -> None:
    failure = _failure(_v2(comparator_version="work-payment-authority.v1"))
    assert failure.verdict == "disproved"


# --------------------------------------------------------------------------
# Unknown future contracts stay unsupported
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "version",
    ["keel.work_authority.v3", "keel.work_authority.v0", "", None, "v2"],
)
def test_unknown_contract_version_is_unverifiable_not_accepted(version) -> None:
    """An unknown contract means "this build cannot check it", never "fine"."""

    failure = _failure(_v2(version=version))
    assert failure.verdict == "unverifiable_scope"
    assert failure.code == "WORK_VERSION_UNSUPPORTED"
