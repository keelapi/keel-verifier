"""Tests for CLI auto-detection of self-attesting bundles.

When a bare file path is passed to `python -m keel_verifier <path>` without a
subcommand, the CLI should peek at the file and route self-attesting bundles
to the export subcommand instead of falling through to the legacy verifier.
"""

from __future__ import annotations

import json
from pathlib import Path

from keel_verifier.cli import _looks_like_self_attesting_bundle


def _write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_detects_self_attesting_bundle_shape(tmp_path: Path) -> None:
    path = _write_json(
        tmp_path / "bundle.json",
        {
            "schema_version": "keel.evidence_bundle/v1",
            "body": {"schema": "keel.evidence/v1"},
            "signature_envelope": {"content_hash": "sha256:" + "0" * 64},
        },
    )
    assert _looks_like_self_attesting_bundle(str(path)) is True


def test_rejects_wrong_schema_version(tmp_path: Path) -> None:
    path = _write_json(
        tmp_path / "wrong_version.json",
        {
            "schema_version": "something.else/v2",
            "body": {},
            "signature_envelope": {},
        },
    )
    assert _looks_like_self_attesting_bundle(str(path)) is False


def test_rejects_missing_body(tmp_path: Path) -> None:
    path = _write_json(
        tmp_path / "no_body.json",
        {
            "schema_version": "keel.evidence_bundle/v1",
            "signature_envelope": {},
        },
    )
    assert _looks_like_self_attesting_bundle(str(path)) is False


def test_rejects_missing_signature_envelope(tmp_path: Path) -> None:
    path = _write_json(
        tmp_path / "no_envelope.json",
        {
            "schema_version": "keel.evidence_bundle/v1",
            "body": {},
        },
    )
    assert _looks_like_self_attesting_bundle(str(path)) is False


def test_rejects_legacy_export_manifest(tmp_path: Path) -> None:
    """Legacy compliance manifests have content_hash + signature at top level
    but no schema_version=keel.evidence_bundle/v1. Must fall through to legacy."""
    path = _write_json(
        tmp_path / "legacy_manifest.json",
        {
            "export_id": "abc",
            "content_hash": "sha256:" + "0" * 64,
            "signature": "ed25519:...",
        },
    )
    assert _looks_like_self_attesting_bundle(str(path)) is False


def test_rejects_non_json_file(tmp_path: Path) -> None:
    path = tmp_path / "not_json.txt"
    path.write_text("hello world", encoding="utf-8")
    assert _looks_like_self_attesting_bundle(str(path)) is False


def test_rejects_nonexistent_file(tmp_path: Path) -> None:
    assert _looks_like_self_attesting_bundle(str(tmp_path / "does_not_exist.json")) is False


def test_rejects_json_array_at_root(tmp_path: Path) -> None:
    """Arrays are valid JSON but not bundles. Must not match."""
    path = tmp_path / "array.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    assert _looks_like_self_attesting_bundle(str(path)) is False
