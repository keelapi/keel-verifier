from __future__ import annotations

from conftest import content_hash, write_json


def _write_unsigned_export(tmp_path):
    export_path = tmp_path / "export.json"
    export_path.write_text('{"records":[]}\n', encoding="utf-8")
    manifest_path = write_json(
        tmp_path / "manifest.json",
        {"content_hash": content_hash(export_path.read_bytes())},
    )
    return export_path, manifest_path


def test_verify_export_unsigned_manifest_fails_by_default(tmp_path, run_cli):
    export_path, manifest_path = _write_unsigned_export(tmp_path)

    # --raw exercises the legacy split-file technical output path, where the
    # strict unsigned-manifest rejection surfaces its precise reason code.
    # (The default AI Permit report rejects the same input with exit 1 and an
    # "Evidence: INCOMPLETE / Export integrity: insufficient evidence" finding;
    # see test_unsigned_manifest_report_default below for that surface.)
    result = run_cli("export", str(export_path), str(manifest_path), "--raw")

    assert result.returncode == 1
    assert (
        "FAILED: Export manifest is unsigned (no signature in manifest)."
        in result.stderr
    )


def test_verify_export_unsigned_with_allow_unsigned_passes_with_warning(
    tmp_path,
    run_cli,
):
    export_path, manifest_path = _write_unsigned_export(tmp_path)

    result = run_cli(
        "export",
        str(export_path),
        str(manifest_path),
        "--allow-unsigned",
        "--raw",
    )

    assert result.returncode == 0
    assert (
        "WARNING: Export manifest is unsigned (no signature in manifest)."
        in result.stderr
    )
    assert "Content hash verified:" in result.stdout


def test_unsigned_manifest_report_default_still_rejects(tmp_path, run_cli):
    """The default AI Permit report path must NOT weaken the strict check.

    PR #41 / "Default export to AI permit report" flipped the export default
    from the legacy technical output to the human report. This regression
    guard pins that an unsigned manifest is still REJECTED (exit 1) on the
    default surface, not silently accepted.
    """
    export_path, manifest_path = _write_unsigned_export(tmp_path)

    result = run_cli("export", str(export_path), str(manifest_path))

    assert result.returncode == 1
    # The report wording differs from the raw path, but the verdict is a
    # refusal: integrity cannot be established without a signature.
    assert "VERIFIED (Keel production trust root)" not in result.stdout
    assert (
        "INCOMPLETE" in result.stdout
        or "insufficient evidence" in result.stdout
    )
