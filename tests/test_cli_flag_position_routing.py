"""CLI routing must not depend on where flags sit relative to the file.

3.31.0 auto-detected a self-attesting bundle, ``.keelpermit`` package, or
work-chain pack only when the file was ``argv[0]``. ``keel-verify --json
BUNDLE.json`` therefore fell through to the legacy checkpoint verifier
(``missing or malformed composite_hash``, exit 1) while ``keel-verify
BUNDLE.json --json`` passed, and ``keel-verify --json export BUNDLE.json``
exited 2 with the legacy usage. Routing now keys on the first positional
argument, and ``export`` accepts every self-attesting input that bare
auto-detect accepts.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import zipfile

import pytest

from keel_verifier.cli import _route_argv, main
import test_work_chain_v1 as work_chain_v1

BUNDLE_FIXTURE = Path(__file__).parent / "fixtures/production_bundles/ai-ptrm-a66f7f81.json"


def _digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _keelpermit(path: Path) -> Path:
    """Package the production bundle as a .keelpermit with a non-JSON view."""

    evidence = BUNDLE_FIXTURE.read_bytes()
    view = b"<html><body>AI Permit</body></html>"
    report = b'{"ok":true}'
    entries = [
        ("permit.html", "human_view", "text/html", view),
        ("verification-report.json", "verification_report", "application/json", report),
        ("evidence/permit-exact.json", "signed_evidence", "application/json", evidence),
    ]
    manifest = {
        "version": "keel.permit_package_manifest.v1",
        "artifact_id": "flag-position-package",
        "created_at": "2026-08-21T20:30:00Z",
        "primary_view": "permit.html",
        "signed_evidence": "evidence/permit-exact.json",
        "trust_rule": "verify_signed_evidence_and_regenerate_human_view",
        "entries": [
            {
                "path": name,
                "role": role,
                "media_type": media_type,
                "sha256": _digest(payload),
                "size_bytes": len(payload),
            }
            for name, role, media_type, payload in entries
        ],
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        for name, _role, _media_type, payload in entries:
            archive.writestr(name, payload)
    return path


def _work_chain(tmp_path: Path) -> tuple[Path, Path]:
    pack, trust_root = work_chain_v1._build_pack(tmp_path)
    path = tmp_path / "work-chain.json"
    path.write_text(json.dumps(pack), encoding="utf-8")
    return path, trust_root


def _run(capsys: pytest.CaptureFixture[str], argv: list[str]) -> tuple[int, dict]:
    code = main(argv)
    captured = capsys.readouterr()
    try:
        payload = json.loads(captured.out)
    except json.JSONDecodeError:
        pytest.fail(f"argv={argv!r} exit={code} did not print JSON\nstderr:\n{captured.err}")
    return code, payload


# Every placement of --json relative to the file and an explicit subcommand.
FLAG_POSITIONS = {
    "trailing_json": lambda f: [f, "--json"],
    "leading_json": lambda f: ["--json", f],
    "export_leading_json": lambda f: ["export", "--json", f],
    "export_trailing_json": lambda f: ["export", f, "--json"],
    "json_before_export": lambda f: ["--json", "export", f],
}


@pytest.mark.parametrize("position", sorted(FLAG_POSITIONS))
def test_self_attesting_bundle_verifies_for_every_flag_position(
    position: str, capsys: pytest.CaptureFixture[str]
) -> None:
    code, payload = _run(capsys, FLAG_POSITIONS[position](str(BUNDLE_FIXTURE)))

    assert code == 0
    assert payload["ok"] is True
    assert payload["artifact"]["kind"] == "permit_exact"


@pytest.mark.parametrize("position", sorted(FLAG_POSITIONS))
def test_keelpermit_package_verifies_for_every_flag_position(
    position: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    package = _keelpermit(tmp_path / "permit.keelpermit")

    code, payload = _run(capsys, FLAG_POSITIONS[position](str(package)))

    assert code == 0
    assert payload["package"]["inventory"] == "verified"
    assert payload["package"]["artifact_id"] == "flag-position-package"
    assert payload["verification_report"]["ok"] is True


WORK_CHAIN_POSITIONS = {
    **{
        name: (lambda build: lambda f, t: [*build(f), "--trust-root", t])(build)
        for name, build in FLAG_POSITIONS.items()
    },
    # A value-taking option before the file: its value must not be routed on.
    "leading_trust_root": lambda f, t: ["--trust-root", t, "--json", f],
    "leading_key_manifest_alias": lambda f, t: ["--key-manifest", t, f, "--json"],
    "abbreviated_leading_option": lambda f, t: ["--trust", t, "--json", f],
    "equals_form_leading_option": lambda f, t: [f"--trust-root={t}", "--json", f],
    "explicit_work_chain_leading_json": lambda f, t: ["--json", "work-chain", f, "--trust-root", t],
}


@pytest.mark.parametrize("position", sorted(WORK_CHAIN_POSITIONS))
def test_work_chain_pack_verifies_for_every_flag_position(
    position: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pack, trust_root = _work_chain(tmp_path)

    code, payload = _run(capsys, WORK_CHAIN_POSITIONS[position](str(pack), str(trust_root)))

    assert code == 0
    assert payload["artifact"]["kind"] == "work_chain_pack"
    assert [claim["verdict"] for claim in payload["claims"][:4]] == ["supported"] * 4


def test_explicit_export_of_work_chain_refuses_flags_it_cannot_honor(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pack, trust_root = _work_chain(tmp_path)

    with pytest.raises(SystemExit) as excinfo:
        main(["export", "--json", str(pack), "--trust-root", str(trust_root), "--walk-events"])

    assert excinfo.value.code == 2
    assert "not supported for a work-chain pack: --walk-events" in capsys.readouterr().err


def test_explicit_export_of_work_chain_refuses_both_trust_aliases(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pack, trust_root = _work_chain(tmp_path)

    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "export",
                str(pack),
                "--trust-root",
                str(trust_root),
                "--key-manifest",
                str(trust_root),
            ]
        )

    assert excinfo.value.code == 2
    assert "pass only one" in capsys.readouterr().err


def test_option_value_named_like_a_subcommand_is_not_routed_on() -> None:
    bundle = str(BUNDLE_FIXTURE)

    assert _route_argv(["--trust-root", "export", "--json", bundle]) == [
        "export",
        "--trust-root",
        "export",
        "--json",
        bundle,
    ]


@pytest.mark.parametrize(
    "argv",
    [
        ["--json", "checkpoint.json"],
        ["checkpoint.json", "--json"],
        ["--no-tsa", "--json", "checkpoint.json"],
        ["--json"],
    ],
)
def test_non_self_attesting_inputs_still_reach_the_legacy_verifier(
    argv: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "checkpoint.json").write_text(json.dumps({"composite_hash": "x"}))

    assert _route_argv(argv) is None


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--help"],
        ["--version"],
        ["export", "--json", "file.json"],
        ["self-check", "--json"],
    ],
)
def test_explicit_subcommands_and_top_level_flags_pass_through(argv: list[str]) -> None:
    assert _route_argv(argv) == argv


def test_leading_flag_before_any_subcommand_is_hoisted() -> None:
    assert _route_argv(["--json", "self-check"]) == ["self-check", "--json"]
