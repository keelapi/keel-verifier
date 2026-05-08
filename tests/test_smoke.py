from __future__ import annotations

import keel_verifier


def test_import_version_and_public_api():
    assert keel_verifier.__version__ == "1.0.2"
    assert callable(keel_verifier.verify)
    assert callable(keel_verifier.verify_export_walk_events)
    assert callable(keel_verifier.verify_closure_record)


def test_module_help_shows_phase_flags(run_cli):
    result = run_cli("--help")
    assert result.returncode == 0
    assert "--walk-events" in result.stdout
    assert "--verify-closure" in result.stdout


def test_export_help_shows_phase_flags(run_cli):
    result = run_cli("export", "--help")
    assert result.returncode == 0
    assert "--walk-events" in result.stdout
    assert "--verify-closure" in result.stdout


def test_v020_sample_still_verifies_self_attested(run_cli):
    result = run_cli("sample/export.json", "--self-attested")
    assert result.returncode == 0, result.stderr
    assert "VERIFIED:" in result.stdout
    assert "self-attested" in result.stdout


def test_v020_offline_alias_still_parses(run_cli):
    result = run_cli("sample/export.json", "--offline", "--self-attested")
    assert result.returncode == 0, result.stderr
