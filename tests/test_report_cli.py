"""CLI wiring for the opt-in `--report` human view on export/checkpoint.

These exercise the real CLI (subprocess) to confirm:
* `--report` renders the permit view and injects session values at the call site,
* `--report` is opt-in: the default output and `--json` are unchanged,
* `--json` still emits valid JSON (not the report).

The sample input has no manifest, so verification does not pass; that is fine --
the wiring renders whatever the model produced (here an INCOMPLETE report),
which is exactly what we need to prove the seam without a fully-verifying fixture.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE = "sample/export.json"


def _run(*argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "keel_verifier", *argv],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


def test_export_report_renders_permit_view_with_session_footer() -> None:
    result = _run("export", SAMPLE, "--report")
    assert result.stdout.startswith("AI PERMIT — Verification Report")
    assert "Evidence:" in result.stdout
    # Session values are computed at the call site and surfaced in the footer.
    assert "Verified at:" in result.stdout
    assert "Input: sha256:" in result.stdout
    # Exit code reflects the verification outcome, not the rendering.
    assert result.returncode in (0, 1)


def test_checkpoint_report_renders_audit_checkpoint() -> None:
    result = _run("checkpoint", SAMPLE, "--report")
    assert result.stdout.startswith("AUDIT CHECKPOINT")
    assert "Finding:" not in result.stdout


def test_default_output_is_unchanged_without_report_flag() -> None:
    result = _run("export", SAMPLE)
    assert "AI PERMIT" not in result.stdout
    # Legacy path reports the missing manifest on stderr.
    assert "FAILED" in (result.stdout + result.stderr)


def test_json_output_is_unchanged_and_not_the_report() -> None:
    result = _run("export", SAMPLE, "--json")
    assert "AI PERMIT" not in result.stdout
    payload = json.loads(result.stdout)  # still valid JSON
    assert payload["schema"].startswith("keel.verifier.verdicts/")


def test_json_takes_precedence_when_both_flags_passed() -> None:
    result = _run("export", SAMPLE, "--json", "--report")
    # --json wins: output is JSON, not the human report.
    assert "AI PERMIT" not in result.stdout
    json.loads(result.stdout)


def test_report_is_permit_shaped_for_a_real_permit_fixture() -> None:
    """End-to-end: a real operator-approved permit export renders permit-first.

    Proves the verified signed fields are lifted into the model and rendered as
    a permit identity + authorized-action block, with the slot family collapsed
    and the export trust mode resolved.
    """
    d = "tests/fixtures/permit_v2_signature_envelope/happy_path_operator_approved"
    result = _run(
        "export", f"{d}/export.json", f"{d}/manifest.json",
        "--key-manifest", f"{d}/key_manifest.json", "--report",
    )
    out = result.stdout
    assert out.startswith("AI PERMIT — Verification Report")
    assert "Authorized action" in out
    assert "Action: generate_report" in out
    assert "Provider: openai" in out
    assert "Model: gpt-5" in out
    assert "✓ Operator approval verified" in out
    assert "Operator approval: insufficient evidence" not in out
    assert "Trust mode: Keel production trust root" in out
