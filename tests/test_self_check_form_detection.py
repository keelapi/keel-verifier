from __future__ import annotations

import importlib.metadata
from pathlib import Path, PurePosixPath

import pytest

import keel_verifier
from keel_verifier import self_check


class FakeDistribution:
    def __init__(
        self,
        *,
        texts: dict[str, str | None] | None = None,
        files: list[PurePosixPath] | None = None,
        root: Path | None = None,
    ) -> None:
        self._texts = texts or {}
        self.files = files
        self._root = root or Path("/site-packages")

    def read_text(self, name: str) -> str | None:
        return self._texts.get(name)

    def locate_file(self, path: PurePosixPath) -> Path:
        return self._root.joinpath(*path.parts)


def test_detect_form_missing_distribution_metadata_has_remediation(monkeypatch) -> None:
    def missing_distribution(name: str):
        del name
        raise importlib.metadata.PackageNotFoundError

    monkeypatch.setattr(self_check.importlib.metadata, "distribution", missing_distribution)

    with pytest.raises(self_check.SelfCheckError) as exc:
        self_check.detect_form()

    assert exc.value.code == "SELF_CHECK_FORM_UNSUPPORTED"
    assert "pip install keel-verifier" in exc.value.remediation


def test_detect_form_editable_install_has_clean_wheel_remediation(monkeypatch) -> None:
    dist = FakeDistribution(
        texts={
            "direct_url.json": '{"dir_info":{"editable":true}}',
            "WHEEL": "Wheel-Version: 1.0\n",
        }
    )
    monkeypatch.setattr(self_check.importlib.metadata, "distribution", lambda name: dist)

    with pytest.raises(self_check.SelfCheckError) as exc:
        self_check.detect_form()

    assert exc.value.code == "SELF_CHECK_FORM_UNSUPPORTED"
    assert "pip uninstall" in exc.value.remediation
    assert "python -m venv" in exc.value.remediation
    assert "--no-cache-dir" in exc.value.remediation


def test_detect_form_sdist_has_binary_wheel_remediation(monkeypatch) -> None:
    dist = FakeDistribution(texts={"direct_url.json": None, "WHEEL": None})
    monkeypatch.setattr(self_check.importlib.metadata, "distribution", lambda name: dist)

    with pytest.raises(self_check.SelfCheckError) as exc:
        self_check.detect_form()

    assert exc.value.code == "SELF_CHECK_FORM_UNSUPPORTED"
    assert "--only-binary" in exc.value.remediation


def test_shadow_import_detection_fires_on_metadata_mismatch(monkeypatch, tmp_path: Path) -> None:
    dist_root = tmp_path / "venv" / "site-packages"
    shadow_root = tmp_path / "shadow" / "keel_verifier"
    dist = FakeDistribution(
        files=[PurePosixPath("keel_verifier/__init__.py")],
        root=dist_root,
    )
    monkeypatch.setattr(self_check.importlib.metadata, "distribution", lambda name: dist)
    monkeypatch.setattr(keel_verifier, "__file__", str(shadow_root / "__init__.py"))

    with pytest.raises(self_check.SelfCheckError) as exc:
        self_check.verify_import_isolation()

    assert exc.value.code == "SELF_CHECK_SHADOW_IMPORT"
    assert str(shadow_root / "__init__.py") in exc.value.message
    assert str(dist_root / "keel_verifier") in exc.value.message
    assert "PYTHONPATH" in exc.value.remediation


def test_shadow_import_detection_passes_when_import_matches_metadata(
    monkeypatch,
    tmp_path: Path,
) -> None:
    dist_root = tmp_path / "venv" / "site-packages"
    imported_file = dist_root / "keel_verifier" / "__init__.py"
    dist = FakeDistribution(
        files=[PurePosixPath("keel_verifier/__init__.py")],
        root=dist_root,
    )
    monkeypatch.setattr(self_check.importlib.metadata, "distribution", lambda name: dist)
    monkeypatch.setattr(keel_verifier, "__file__", str(imported_file))

    result = self_check.verify_import_isolation()
    assert result.imported_path == imported_file.resolve()
    assert result.checked is True


def test_shadow_import_detection_skips_when_distribution_files_missing(
    monkeypatch,
    tmp_path: Path,
) -> None:
    imported_file = tmp_path / "shadow" / "keel_verifier" / "__init__.py"
    dist = FakeDistribution(files=None)
    monkeypatch.setattr(self_check.importlib.metadata, "distribution", lambda name: dist)
    monkeypatch.setattr(keel_verifier, "__file__", str(imported_file))

    result = self_check.verify_import_isolation()
    assert result.imported_path == imported_file.resolve()
    assert result.checked is False


def test_shadow_import_failure_code_registered() -> None:
    assert "SELF_CHECK_SHADOW_IMPORT" in self_check.SELF_CHECK_FAILURE_CODES
