"""Parity + safety checks for the human-report presentation registry.

The presentation registry (``report_presentation_v0.json``) is a pure
rendering layer over the pinned claim registry (``claim_registry_v0.json``).
It must never drift from the claim registry and must never let a friendlier
label overclaim. These tests make both properties mechanical:

* every claim is accounted for (surfaced or explicitly not surfaced),
* every reference points at a real claim,
* every surfaced claim has a label for each verdict,
* no label uses forbidden ("overclaiming") wording.

It deliberately reads the JSON files directly, mirroring
``test_claim_registry_parity.py`` and avoiding any dependency on verifier
internals -- the presentation layer is not a trust input.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
BUNDLED_DATA = REPO_ROOT / "keel_verifier" / "data"
CLAIM_REGISTRY = BUNDLED_DATA / "claim_registry_v0.json"
PRESENTATION_REGISTRY = BUNDLED_DATA / "report_presentation_v0.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def claim_registry() -> dict:
    return _load(CLAIM_REGISTRY)


@pytest.fixture(scope="module")
def presentation() -> dict:
    return _load(PRESENTATION_REGISTRY)


@pytest.fixture(scope="module")
def claim_names(claim_registry: dict) -> set[str]:
    return {claim["name"] for claim in claim_registry["claims"]}


def test_presentation_is_marked_non_trust_input(presentation: dict) -> None:
    assert presentation.get("not_a_trust_input") is True, (
        "Presentation registry must declare not_a_trust_input: true so it can "
        "never be mistaken for a semantics/trust artifact."
    )


def test_verdict_keys_match_claim_registry(
    presentation: dict, claim_registry: dict
) -> None:
    assert presentation["verdict_keys"] == claim_registry["verdict_enum"], (
        "Presentation verdict_keys must match the claim registry verdict_enum "
        "exactly; otherwise labels and verdicts can silently diverge."
    )


def test_every_claim_accounted_for_exactly_once(
    presentation: dict, claim_names: set[str]
) -> None:
    surfaced = [entry["claim"] for entry in presentation["assertions"]]
    not_surfaced = [entry["claim"] for entry in presentation["not_surfaced"]]
    covered = surfaced + not_surfaced

    # No duplicates within or across the two lists.
    duplicates = sorted({name for name in covered if covered.count(name) > 1})
    assert not duplicates, f"Claims listed more than once: {duplicates}"

    missing = sorted(claim_names - set(covered))
    assert not missing, (
        f"Claims in claim_registry_v0.json with no presentation decision: {missing}. "
        "Add each to `assertions` or `not_surfaced`."
    )

    unknown = sorted(set(covered) - claim_names)
    assert not unknown, (
        f"Presentation references claims absent from claim_registry_v0.json: {unknown}."
    )


def test_assertion_dimensions_and_provenance_are_known(presentation: dict) -> None:
    dimensions = {dim["id"] for dim in presentation["dimensions"]}
    provenance_classes = set(presentation["provenance_classes"])
    for entry in presentation["assertions"]:
        claim = entry["claim"]
        assert entry["dimension"] in dimensions, (
            f"{claim}: unknown dimension {entry['dimension']!r}"
        )
        assert entry["provenance"] in provenance_classes, (
            f"{claim}: unknown provenance {entry['provenance']!r}"
        )


def test_every_surfaced_claim_has_all_verdict_labels(presentation: dict) -> None:
    verdict_keys = set(presentation["verdict_keys"])
    for entry in presentation["assertions"]:
        labels = entry.get("labels", {})
        missing = sorted(verdict_keys - set(labels))
        assert not missing, f"{entry['claim']}: missing labels for verdicts {missing}"
        for verdict, text in labels.items():
            assert text and text.strip(), (
                f"{entry['claim']}: empty label for verdict {verdict!r}"
            )


def test_no_label_uses_forbidden_wording(presentation: dict) -> None:
    """Invariant #8/#10: a friendly label must never claim more than proved.

    No assurance label may assert legitimacy/safety/etc. Forbidden phrases are
    checked case-insensitively against every label (all verdicts), plus any
    entry-specific forbidden wording.
    """
    global_forbidden = [w.lower() for w in presentation["global_forbidden_wording"]]
    violations: list[str] = []
    for entry in presentation["assertions"]:
        entry_forbidden = [w.lower() for w in entry.get("forbidden_wording", [])]
        forbidden = global_forbidden + entry_forbidden
        for verdict, text in entry["labels"].items():
            lowered = text.lower()
            for phrase in forbidden:
                if phrase in lowered:
                    violations.append(
                        f"{entry['claim']} [{verdict}] contains forbidden "
                        f"phrase {phrase!r}: {text!r}"
                    )
    assert not violations, "Overclaiming labels found:\n" + "\n".join(violations)


def test_session_and_artifact_lines_have_known_provenance(presentation: dict) -> None:
    provenance_classes = set(presentation["provenance_classes"])
    for group in ("session_lines", "artifact_lines"):
        for line in presentation[group]:
            assert line["provenance"] in provenance_classes, (
                f"{group} entry {line['id']!r} has unknown provenance "
                f"{line['provenance']!r}"
            )


def test_trust_modes_cover_trusted_and_untrusted(presentation: dict) -> None:
    modes = presentation["trust_modes"]
    assert any(m["trusted"] for m in modes), "Need at least one trusted mode"
    untrusted = [m for m in modes if not m["trusted"]]
    assert untrusted, "Need at least one untrusted mode (e.g. self-attested)"
    for mode in untrusted:
        assert mode.get("warning"), (
            f"Untrusted trust mode {mode['id']!r} must carry a warning string."
        )
