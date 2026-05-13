from __future__ import annotations

from pathlib import Path

import keel_verifier
from keel_verifier import cli
from keel_verifier import verifier


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_import_version_and_public_api():
    assert keel_verifier.__version__ == "1.1.0"
    assert callable(keel_verifier.verify)
    assert callable(keel_verifier.verify_export_walk_events)
    assert callable(keel_verifier.verify_closure_record)


def test_module_help_shows_phase_flags(run_cli):
    result = run_cli("--help")
    assert result.returncode == 0
    assert "--walk-events" in result.stdout
    assert "--verify-closure" in result.stdout
    assert "--offline" not in result.stdout


def test_export_help_shows_phase_flags(run_cli):
    result = run_cli("export", "--help")
    assert result.returncode == 0
    assert "--walk-events" in result.stdout
    assert "--verify-closure" in result.stdout
    assert "--allow-unsigned" in result.stdout
    assert "--offline" in result.stdout
    assert "URL trust-root flags still take precedence" in result.stdout


def test_checkpoint_help_shows_offline_flag(run_cli):
    result = run_cli("checkpoint", "--help")
    assert result.returncode == 0
    assert "--offline" in result.stdout
    assert "URL trust-root flags still take precedence" in result.stdout


def test_v020_sample_still_verifies_self_attested(run_cli):
    result = run_cli("sample/export.json", "--self-attested")
    assert result.returncode == 0, result.stderr
    assert "VERIFIED:" in result.stdout
    assert "self-attested" in result.stdout


def test_legacy_help_shows_offline_flag(run_cli):
    result = run_cli("sample/export.json", "--help")
    assert result.returncode == 0
    assert "--offline" in result.stdout
    assert "--public-key-url still takes precedence" in result.stdout


def test_offline_with_url_trust_root_keeps_url_precedence(monkeypatch, capsys):
    def fail_urlopen(*_args, **_kwargs):
        raise RuntimeError("url precedence sentinel")

    monkeypatch.setattr(verifier.urllib.request, "urlopen", fail_urlopen)

    rc = cli.main(
        [
            "checkpoint",
            "sample/export.json",
            "--offline",
            "--public-key-url",
            "https://example.invalid/key.json",
        ]
    )

    captured = capsys.readouterr()
    assert rc == 1
    assert "url precedence sentinel" in captured.err


def test_v020_offline_alias_still_parses(run_cli):
    result = run_cli("sample/export.json", "--offline", "--self-attested")
    assert result.returncode == 0, result.stderr


def test_changelog_dates_match_release_history():
    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## v1.0.1 (2026-05-07)" in changelog
    assert "## v1.0.2 (2026-05-07)" in changelog
    assert "## v1.0.3 (2026-05-07)" in changelog
