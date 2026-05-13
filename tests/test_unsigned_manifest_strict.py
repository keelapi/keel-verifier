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

    result = run_cli("export", str(export_path), str(manifest_path))

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
    )

    assert result.returncode == 0
    assert (
        "WARNING: Export manifest is unsigned (no signature in manifest)."
        in result.stderr
    )
    assert "Content hash verified:" in result.stdout
