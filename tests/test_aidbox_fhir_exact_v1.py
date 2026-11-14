"""Synthetic Aidbox exact administration actions (selector v23, fact profiles v20).

keel-permit 8016036f (PR #65) adds three exact actions as additive successors:
selector registry v23 preserves every v22 entry, fact profile registry v20
preserves every v19 profile, and both bind the new
``aidbox-fhir-exact-facts-v1`` schema.  These tests pin the vendored bytes to
that canonical commit, prove the historical registries are untouched, and
adjudicate the three actions through the exact Permit pack path.  The facts are
the canonical synthetic conformance fixtures, not issued Permits or provider
evidence.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

import test_permit_exact_v2 as exact
from keel_verifier import permit_exact_v2, work_chain_v2
from keel_verifier.permit_exact_v2 import (
    REFUND_ORIGINAL_PAYMENT_BOUND_CLAIM,
    adjudicate_permit_exact_v2_body,
)
from keel_verifier.permit_presentation import resolve_permit_presentation


REPO_ROOT = Path(__file__).resolve().parents[1]
PTX = REPO_ROOT / "keel_verifier" / "data" / "permit_to_x"


def _main_checkout() -> Path:
    """The primary checkout, so a linked worktree still finds its siblings."""

    common = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "--path-format=absolute", "--git-common-dir"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    return Path(common).parent if common else REPO_ROOT


CANONICAL_PERMIT_CANDIDATES = (
    REPO_ROOT.parent / "keel-permit",
    _main_checkout().parent / "keel-permit",
)
CANONICAL_COMMIT = "8016036f6d8da968a02de47179e4dbc7975b988b"

# Vendored path under keel_verifier/data/permit_to_x -> (keel-permit path, sha256).
AIDBOX_ARTIFACTS = {
    "semantic_registry/v23.json": (
        "semantic_registry/v23.json",
        "42022f73fbd8e59f79cec80d2857c21922f051cd48f33f559db0cd2435ce09c8",
    ),
    "semantic_registry/v23.schema.json": (
        "semantic_registry/v23.schema.json",
        "70dc85e9c68497f7252a39acb9bd52cfa4529792ec231f8803536ce86bd04897",
    ),
    "fact_profiles/v20.json": (
        "fact_profiles/v20.json",
        "f72e8d8f7f7c57ea9e70bb9bc0b80097c2f23fc901513d95652bb709a77e5b0f",
    ),
    "fact_profiles/v20.schema.json": (
        "fact_profiles/v20.schema.json",
        "253e29dba5f0ad009e4751b9540aa60d689b54f61627fa2ae20583846fff6a62",
    ),
    "schemas/aidbox-fhir-exact-facts-v1.schema.json": (
        "schemas/aidbox-fhir-exact-facts-v1.schema.json",
        "48eb067a4da5352d17edab2140059413dbfbd939d0907e632a8c7f4d89a216d8",
    ),
    # Optional synthetic conformance fixture (not runtime-required).
    "test_vectors/fact_profiles/aidbox-v1.json": (
        "fact_profiles/test-vectors/aidbox-v1.json",
        "48353bc0df78a8629e518fa07429617115cd6265a0087b516fcf58220aa66a74",
    ),
}
# The predecessors stay byte-identical: v22 / v19 as shipped since 3.24.0.
HISTORICAL_PREDECESSORS = {
    "semantic_registry/v22.json": (
        "0f62cd9b39a593b301c71f2171c38ea162745b80172d65a7119a7ddc147cc127"
    ),
    "fact_profiles/v19.json": (
        "680c53cc575697c313128bf798550cbceb482793d0e4fd731ed707d77478ebd6"
    ),
}

ADDRESS = "healthcare.patient.mailing_address.update"
RESCHEDULE = "healthcare.appointment.reschedule"
RELEASE = "healthcare.records.release"
SEMANTICS = {
    ADDRESS: "keel.action.healthcare_patient_mailing_address_update.v1",
    RESCHEDULE: "keel.action.healthcare_appointment_reschedule.v1",
    RELEASE: "keel.action.healthcare_records_release.v1",
}
PROFILES = {
    ADDRESS: "keel.facts.healthcare_patient_mailing_address_update_exact.v1",
    RESCHEDULE: "keel.facts.healthcare_appointment_reschedule_exact.v1",
    RELEASE: "keel.facts.healthcare_records_release_exact.v1",
}
# Inside every fixture's [preflight_observed_at, preflight_expires_at) window.
ISSUED_AT = "2026-11-14T01:58:00Z"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json(relative: str) -> dict:
    return json.loads((PTX / relative).read_text(encoding="utf-8"))


def _vectors() -> dict[str, dict]:
    cases = _json("test_vectors/fact_profiles/aidbox-v1.json")["cases"]
    return {case["action"]: copy.deepcopy(case["facts"]) for case in cases}


def aidbox_body(action: str, facts: dict | None = None) -> dict:
    """Bind one canonical fixture exactly as the issuer stamps an Aidbox Permit.

    The issuer has no presentation profile for these semantics, so the signed
    binding carries no ``non_authorizing_presentation_profile_id``.
    """

    signed_facts = facts if facts is not None else _vectors()[action]
    body = exact._v4_body(
        semantic_id=SEMANTICS[action],
        fact_profile_id=PROFILES[action],
        facts=copy.deepcopy(signed_facts),
        action_name=action,
        operation="call.tools",
        governed_surface="mcp_tool",
        presentation_profile_id="unused",
        selector_registry_file="v23.json",
        fact_registry_file="v20.json",
    )
    binding = body["semantic_binding"]
    binding.pop("non_authorizing_presentation_profile_id")
    binding["chain_role"] = "action_child"
    for projection in (
        body["permit_decision"]["resource_attributes_json"],
        body["permit_receipt"]["action"]["resource_attributes_json"],
    ):
        projection["permit_semantic_binding_v2"] = copy.deepcopy(binding)
    body["permit_decision"]["canonical_payload"]["issued_at"] = ISSUED_AT
    body["permit_decision"]["canonical_payload"]["expires_at"] = "2026-11-14T02:00:00Z"
    exact._replace_authorization_facts(body, signed_facts)
    return body


def _claims(body: dict) -> dict:
    return exact._claim_map(
        adjudicate_permit_exact_v2_body(body, decision_verdict="supported")
    )


# --- canonical parity -------------------------------------------------------


@pytest.mark.parametrize("vendored", sorted(AIDBOX_ARTIFACTS))
def test_vendored_aidbox_artifact_matches_canonical_digest(vendored: str) -> None:
    _canonical, expected = AIDBOX_ARTIFACTS[vendored]
    assert _sha256(PTX / vendored) == expected


def _canonical_bytes(path: str) -> bytes:
    """Read ``path`` at the pinned keel-permit commit, or skip without it."""

    env_root = os.getenv("KEEL_PERMIT_PTX_ROOT")
    if env_root:
        candidate = Path(env_root).expanduser() / path
        head = subprocess.run(
            ["git", "-C", str(Path(env_root).expanduser()), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
        if candidate.is_file() and head in ("", CANONICAL_COMMIT):
            return candidate.read_bytes()
    for root in CANONICAL_PERMIT_CANDIDATES:
        shown = subprocess.run(
            ["git", "-C", str(root), "show", f"{CANONICAL_COMMIT}:{path}"],
            capture_output=True,
            check=False,
        )
        if shown.returncode == 0:
            return shown.stdout
    message = (
        f"keel-permit {CANONICAL_COMMIT} is not available next to keel-verifier "
        f"({', '.join(map(str, CANONICAL_PERMIT_CANDIDATES))}); set KEEL_PERMIT_PTX_ROOT"
    )
    if os.getenv("KEEL_REQUIRE_GOLDEN_CORPUS"):
        raise FileNotFoundError(message)
    pytest.skip(message)


@pytest.mark.parametrize("vendored", sorted(AIDBOX_ARTIFACTS))
def test_vendored_aidbox_artifact_is_byte_identical_to_keel_permit(
    vendored: str,
) -> None:
    canonical, _expected = AIDBOX_ARTIFACTS[vendored]
    assert (PTX / vendored).read_bytes() == _canonical_bytes(canonical)


@pytest.mark.parametrize("relative", sorted(HISTORICAL_PREDECESSORS))
def test_historical_predecessor_registries_are_unchanged(relative: str) -> None:
    assert _sha256(PTX / relative) == HISTORICAL_PREDECESSORS[relative]


def test_selector_v23_and_profiles_v20_are_strictly_additive() -> None:
    for directory, old, new, field, identity in (
        ("semantic_registry", 22, 23, "entries", "semantic_id"),
        ("fact_profiles", 19, 20, "profiles", "fact_profile_id"),
    ):
        before = _json(f"{directory}/v{old}.json")
        after = _json(f"{directory}/v{new}.json")
        previous = {entry[identity]: entry for entry in before[field]}
        current = {entry[identity]: entry for entry in after[field]}
        assert len(current) == len(after[field])
        assert all(current[key] == value for key, value in previous.items())
        added = set(current) - set(previous)
        assert len(added) == 3
        if field == "entries":
            assert added == set(SEMANTICS.values())
        else:
            assert added == set(PROFILES.values())
    assert (
        _json("fact_profiles/v20.json")["disclosure_contract"]
        == _json("fact_profiles/v19.json")["disclosure_contract"]
    )


def test_aidbox_profiles_pin_the_vendored_facts_schema() -> None:
    schema_digest = "sha256:" + AIDBOX_ARTIFACTS[
        "schemas/aidbox-fhir-exact-facts-v1.schema.json"
    ][1]
    profiles = {
        profile["fact_profile_id"]: profile
        for profile in _json("fact_profiles/v20.json")["profiles"]
    }
    for action, profile_id in PROFILES.items():
        profile = profiles[profile_id]
        assert profile["authorized_action"] == action
        assert profile["semantic_ids"] == [SEMANTICS[action]]
        assert profile["facts_schema"] == "schemas/aidbox-fhir-exact-facts-v1.schema.json"
        assert profile["facts_schema_digest"] == schema_digest


# --- version consumers ----------------------------------------------------------


def test_every_version_consumer_names_the_aidbox_registries() -> None:
    from keel_verifier import permit_presentation

    assert (
        permit_presentation._SEMANTIC_REGISTRY_BY_VERSION[
            "keel.semantic_selector_registry.v23"
        ]
        == "semantic_registry/v23.json"
    )
    assert work_chain_v2._SELECTOR_FILES[
        "keel.semantic_selector_registry.v23"
    ].endswith("semantic_registry/v23.json")
    assert work_chain_v2._FACT_PROFILE_FILES[
        "keel.fact_profile_registry.v20"
    ].endswith("fact_profiles/v20.json")
    sync_source = (REPO_ROOT / "scripts" / "sync_permit_to_x_artifacts.py").read_text(
        encoding="utf-8"
    )
    for vendored, (canonical, _digest) in AIDBOX_ARTIFACTS.items():
        assert f'"{canonical}"' in sync_source
        assert f'"permit_to_x/{vendored}"' in sync_source


# --- semantic binding -------------------------------------------------------


@pytest.mark.parametrize("action", sorted(SEMANTICS))
def test_aidbox_exact_permit_verifies_from_canonical_fixture(action: str) -> None:
    result = adjudicate_permit_exact_v2_body(
        aidbox_body(action), decision_verdict="supported"
    )
    claims = exact._claim_map(result)

    assert result.semantic_id == SEMANTICS[action]
    assert result.fact_profile_id == PROFILES[action]
    assert result.authorized_action == action
    for name in ("permit.type.v1", "permit.exact_target.v1", "permit.material_request.v1"):
        assert claims[name].verdict == "supported", (name, claims[name])


@pytest.mark.parametrize("action", sorted(SEMANTICS))
def test_aidbox_compact_pins_resolve_from_bundled_v23_v20(action: str) -> None:
    body = aidbox_body(action)
    body["profile"] = permit_exact_v2.PROFILE_V4
    body["profile_version"] = 4
    for pin in body["contract_pins"].values():
        if isinstance(pin, dict):
            pin.pop("content_base64", None)

    claims = _claims(body)

    assert claims["permit.type.v1"].verdict == "supported", claims["permit.type.v1"]
    assert all(
        claim.reason_code != "PERMIT_CONTRACT_PIN_UNSUPPORTED" for claim in claims.values()
    )


def test_aidbox_contract_pin_bytes_not_bundled_are_unsupported() -> None:
    body = aidbox_body(ADDRESS)
    pin = body["contract_pins"]["fact_profile_registry"]
    raw = base64.b64decode(pin["content_base64"]) + b"\n"
    pin["content_base64"] = base64.b64encode(raw).decode("ascii")
    pin["sha256"] = "sha256:" + hashlib.sha256(raw).hexdigest()

    claims = _claims(body)

    assert claims["permit.type.v1"].verdict == "unverifiable_scope"
    assert claims["permit.type.v1"].reason_code == "PERMIT_CONTRACT_PIN_UNSUPPORTED"


def test_aidbox_semantic_cannot_be_bound_under_selector_v22() -> None:
    body = aidbox_body(ADDRESS)
    selector_path = PTX / "semantic_registry/v22.json"
    body["contract_pins"]["semantic_selector_registry"] = exact._pin(
        selector_path, artifact_id="keel.permit.semantic_selector_registry"
    )
    binding = body["semantic_binding"]
    binding["selector_registry_version"] = "keel.semantic_selector_registry.v22"
    binding["selector_registry_digest"] = exact._digest_bytes(selector_path.read_bytes())
    exact._replace_authorization_facts(body, body["authorization_facts"])

    claims = _claims(body)

    assert claims["permit.type.v1"].verdict != "supported"


def test_aidbox_profile_cannot_ride_inside_another_aidbox_binding() -> None:
    vectors = _vectors()
    body = aidbox_body(ADDRESS)
    exact._replace_authorization_facts(body, vectors[RESCHEDULE])

    claims = _claims(body)

    assert claims["permit.type.v1"].verdict == "disproved"
    assert claims["permit.type.v1"].reason_code == "PERMIT_TYPE_FACT_PROFILE_MISMATCH"


@pytest.mark.parametrize("action", sorted(SEMANTICS))
def test_aidbox_cross_action_fact_profile_substitution_is_disproved(action: str) -> None:
    other = {ADDRESS: RESCHEDULE, RESCHEDULE: RELEASE, RELEASE: ADDRESS}[action]
    facts = _vectors()[action]
    facts["fact_profile_id"] = PROFILES[other]
    body = aidbox_body(action)
    exact._replace_authorization_facts(body, facts)

    claims = _claims(body)

    assert claims["permit.type.v1"].verdict == "disproved"
    assert claims["permit.type.v1"].reason_code == "PERMIT_TYPE_FACT_PROFILE_MISMATCH"


# --- exact-action invariants ---------------------------------------------------


@pytest.mark.parametrize(
    ("action", "field", "value", "reason"),
    (
        (ADDRESS, "provider_environment", "production", "PERMIT_AUTHORIZATION_FACTS_SCHEMA_INVALID"),
        (ADDRESS, "connector_identity", "hapi-fhir", "PERMIT_AUTHORIZATION_FACTS_SCHEMA_INVALID"),
        (ADDRESS, "clinical_field_mutation_requested", True, "PERMIT_AUTHORIZATION_FACTS_SCHEMA_INVALID"),
        (ADDRESS, "address_field_set", ["city", "line"], "PERMIT_AUTHORIZATION_FACTS_SCHEMA_INVALID"),
        (RESCHEDULE, "schedule_conflict_count", 1, "PERMIT_AUTHORIZATION_FACTS_SCHEMA_INVALID"),
        (RELEASE, "max_uses", 2, "PERMIT_AUTHORIZATION_FACTS_SCHEMA_INVALID"),
        (RELEASE, "document_count", 9, "PERMIT_AUTHORIZATION_FACTS_SCHEMA_INVALID"),
        (RELEASE, "patient_name", "Synthetic Patient", "PERMIT_AUTHORIZATION_FACTS_SCHEMA_INVALID"),
        (ADDRESS, "verification_expires_at", "2026-11-14T01:59:00Z", "PERMIT_COMMERCE_REGULATED_INVARIANT_INVALID"),
        (RESCHEDULE, "verification_expires_at", "2026-11-14T01:59:45Z", "PERMIT_COMMERCE_REGULATED_INVARIANT_INVALID"),
        (RELEASE, "disclosure_expires_at", "2026-11-14T01:59:00Z", "PERMIT_COMMERCE_REGULATED_INVARIANT_INVALID"),
    ),
)
def test_aidbox_facts_fail_closed(action: str, field: str, value: object, reason: str) -> None:
    facts = _vectors()[action]
    facts[field] = value
    body = aidbox_body(action, facts)

    claims = _claims(body)

    assert claims["permit.type.v1"].verdict == "disproved"
    assert claims["permit.type.v1"].reason_code == reason


def test_aidbox_reschedule_must_move_to_a_different_slot() -> None:
    facts = _vectors()[RESCHEDULE]
    facts["new_slot_reference_commitment"] = copy.deepcopy(
        facts["old_slot_reference_commitment"]
    )
    claims = _claims(aidbox_body(RESCHEDULE, facts))

    assert claims["permit.type.v1"].verdict == "disproved"
    assert claims["permit.type.v1"].reason_code == (
        "PERMIT_COMMERCE_REGULATED_INVARIANT_INVALID"
    )


def test_aidbox_deadline_equal_to_preflight_expiry_is_accepted() -> None:
    facts = _vectors()[RELEASE]
    facts["verification_expires_at"] = facts["preflight_expires_at"]
    facts["disclosure_expires_at"] = facts["preflight_expires_at"]

    claims = _claims(aidbox_body(RELEASE, facts))

    assert claims["permit.type.v1"].verdict == "supported"


@pytest.mark.parametrize("action", sorted(SEMANTICS))
def test_aidbox_preflight_must_be_fresh_at_authorization(action: str) -> None:
    body = aidbox_body(action)
    body["permit_decision"]["canonical_payload"]["issued_at"] = "2026-11-14T01:59:46Z"
    body["permit_decision"]["canonical_payload"]["resource_attributes_canonical_hash"] = (
        exact.canonical_resource_attributes_payload(
            body["permit_decision"]["resource_attributes_json"]
        )
    )

    claims = _claims(body)

    assert claims["permit.type.v1"].verdict == "disproved"
    assert claims["permit.type.v1"].reason_code == "PERMIT_PREFLIGHT_WINDOW_INVALID"


def test_existing_commerce_regulated_actions_still_reject_aidbox_connector() -> None:
    with pytest.raises(permit_exact_v2._AdjudicationError) as caught:
        permit_exact_v2._verify_commerce_regulated_invariants(
            {
                **_vectors()[ADDRESS],
                "action": "healthcare.patient_administrative_record.update",
            }
        )
    assert caught.value.reason_code == "PERMIT_COMMERCE_REGULATED_INVARIANT_INVALID"


# --- requested claims ------------------------------------------------------------


def test_aidbox_baseline_claims_cannot_be_selected_away() -> None:
    body = aidbox_body(RELEASE)
    body["declared_claims"] = ["permit.decision.v1"]

    claims = _claims(body)

    assert {"permit.type.v1", "permit.exact_target.v1", "permit.material_request.v1"} <= set(claims)
    assert claims["permit.type.v1"].verdict == "supported"


@pytest.mark.parametrize("action", sorted(SEMANTICS))
def test_aidbox_dispatch_and_provider_claims_need_their_own_evidence(action: str) -> None:
    claims = _claims(aidbox_body(action))

    for name in (
        "permit.valid_at_dispatch.v1",
        "permit.enforced_at_certified_boundary.v1",
        "provider.accepted.v1",
        "provider.completed.v1",
    ):
        assert claims[name].verdict != "supported", (name, claims[name])


def test_aidbox_release_cannot_borrow_a_refund_consequence_claim() -> None:
    body = aidbox_body(RELEASE)
    body["declared_claims"].append(REFUND_ORIGINAL_PAYMENT_BOUND_CLAIM)

    claim = _claims(body)[REFUND_ORIGINAL_PAYMENT_BOUND_CLAIM]

    assert claim.verdict == "disproved"
    assert claim.reason_code == "REFUND_ORIGINAL_PAYMENT_BINDING_MISMATCH"


def test_aidbox_unimplemented_requested_claim_is_out_of_scope() -> None:
    body = aidbox_body(RELEASE)
    body["declared_claims"].append("healthcare.records.delivered.v1")

    claim = _claims(body)["healthcare.records.delivered.v1"]

    assert claim.verdict == "unverifiable_scope"
    assert claim.reason_code == "PERMIT_EXACT_DECLARED_CLAIM_UNSUPPORTED"


def test_aidbox_verifier_safe_facts_carry_commitments_not_identifiers() -> None:
    result = adjudicate_permit_exact_v2_body(
        aidbox_body(RELEASE), decision_verdict="supported"
    )
    safe = result.verifier_safe_facts

    assert safe["action"] == RELEASE
    for name in (
        "patient_reference_commitment",
        "recipient_reference_commitment",
        "document_set_commitment",
    ):
        value = safe.get(name)
        assert value is None or set(value) <= {"method", "digest"}


# --- presentation stays generic ---------------------------------------------------


@pytest.mark.parametrize("action", sorted(SEMANTICS))
def test_aidbox_permits_fall_back_to_the_generic_title(action: str) -> None:
    resolved = resolve_permit_presentation(aidbox_body(action)["semantic_binding"])

    assert resolved["customer_title"] == "AI Permit"
    assert resolved["resolution"] == "generic_profile_missing"


def test_preserved_v22_semantic_under_selector_v23_keeps_its_v24_title() -> None:
    registry_path = PTX / "semantic_registry/v23.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    entry = next(
        item
        for item in registry["entries"]
        if item["semantic_id"] == "keel.action.payment_execute.v1"
        and "action_gateway_service" in item["trusted_source_kinds"]
    )
    presentation = _json("presentation_registry/v24.json")
    profile = next(
        item
        for item in presentation["profiles"]
        if item["semantic_id"] == entry["semantic_id"]
    )
    match = entry["match"]
    binding = {
        "version": "keel.permit_semantic_binding.v2",
        "semantic_id": entry["semantic_id"],
        "trusted_source_kind": "action_gateway_service",
        "chain_role": match["allowed_chain_roles"][0],
        "action_name": match["action_names"][0],
        "operation": match["operations"][0],
        "governed_surface": "keel_action_gateway",
        "non_authorizing_presentation_profile_id": profile["presentation_profile_id"],
        "selector_registry_version": registry["version"],
        "selector_registry_digest": exact._digest_bytes(registry_path.read_bytes()),
        "selector_entry_digest": exact._digest_object(entry),
    }

    resolved = resolve_permit_presentation(binding)

    assert resolved["resolution"] == "trusted_signed_semantic"
    assert resolved["customer_title"] == profile["customer_title"]
    assert resolved["presentation_registry_version"] == "keel.presentation_registry.v24"


# --- built and installed wheel ---------------------------------------------------


_INSTALLED_PROBE = r"""
import hashlib, json, sys
from importlib import resources
from pathlib import Path

import keel_verifier
from keel_verifier import permit_exact_v2, permit_presentation, work_chain_v2

repo_root, expected_path, bodies_path = sys.argv[1:4]
package = Path(keel_verifier.__file__).resolve()
assert not str(package).startswith(repo_root), package
data = resources.files("keel_verifier").joinpath("data/permit_to_x")
for relative, digest in json.loads(Path(expected_path).read_text()).items():
    raw = data.joinpath(relative).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest, relative
selector = permit_exact_v2._json("semantic_registry/v23.json")
profiles = permit_exact_v2._json("fact_profiles/v20.json")
assert selector["version"] == "keel.semantic_selector_registry.v23"
assert profiles["version"] == "keel.fact_profile_registry.v20"
assert permit_presentation._load("semantic_registry/v23.json")[0] == selector
assert "keel.fact_profile_registry.v20" in work_chain_v2._FACT_PROFILE_FILES
results = {}
for action, body in json.loads(Path(bodies_path).read_text()).items():
    result = permit_exact_v2.adjudicate_permit_exact_v2_body(
        body, decision_verdict="supported"
    )
    results[action] = {
        "semantic_id": result.semantic_id,
        "fact_profile_id": result.fact_profile_id,
        "claims": {claim.name: claim.verdict for claim in result.claims},
    }
print(json.dumps({"package": str(package), "results": results}))
"""


def test_installed_wheel_ships_and_loads_aidbox_artifacts(tmp_path: Path) -> None:
    import sys
    from zipfile import ZipFile

    import test_installed_wheel_semantics as wheel_tests

    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    wheel_tests._run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--skip-dependency-check",
            "--outdir",
            str(wheelhouse),
        ],
        cwd=REPO_ROOT,
        env=wheel_tests._clean_env(),
    )
    wheels = sorted(wheelhouse.glob("keel_verifier-*.whl"))
    assert len(wheels) == 1, wheels
    with ZipFile(wheels[0]) as wheel_file:
        names = set(wheel_file.namelist())
        for vendored, (_canonical, digest) in AIDBOX_ARTIFACTS.items():
            member = f"keel_verifier/data/permit_to_x/{vendored}"
            assert member in names
            assert hashlib.sha256(wheel_file.read(member)).hexdigest() == digest

    venv = tmp_path / "venv"
    wheel_tests._run(
        [sys.executable, "-m", "venv", str(venv)],
        cwd=tmp_path,
        env=wheel_tests._clean_env(),
    )
    venv_python = wheel_tests._venv_python(venv)
    wheel_tests._run(
        [str(venv_python), "-m", "pip", "install", str(wheels[0])],
        cwd=tmp_path,
        env=wheel_tests._clean_env(),
    )
    expected = tmp_path / "expected.json"
    expected.write_text(
        json.dumps({key: value[1] for key, value in AIDBOX_ARTIFACTS.items()}),
        encoding="utf-8",
    )
    bodies = tmp_path / "bodies.json"
    bodies.write_text(
        json.dumps({action: aidbox_body(action) for action in SEMANTICS}),
        encoding="utf-8",
    )
    probe = tmp_path / "probe.py"
    probe.write_text(_INSTALLED_PROBE, encoding="utf-8")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    result = wheel_tests._run(
        [str(venv_python), "-I", str(probe), str(REPO_ROOT), str(expected), str(bodies)],
        cwd=run_dir,
        env=wheel_tests._clean_env(),
    )
    payload = json.loads(result.stdout)

    assert not payload["package"].startswith(str(REPO_ROOT))
    for action, outcome in payload["results"].items():
        assert outcome["semantic_id"] == SEMANTICS[action]
        assert outcome["fact_profile_id"] == PROFILES[action]
        for name in (
            "permit.type.v1",
            "permit.exact_target.v1",
            "permit.material_request.v1",
        ):
            assert outcome["claims"][name] == "supported", (action, name)
