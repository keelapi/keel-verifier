"""Shared local installation diagnostics for self-check and doctor."""

from __future__ import annotations

import importlib
import importlib.metadata
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal


PACKAGE_NAME = "keel_verifier"
DIST_NAME = "keel-verifier"

MISSING_INSTALL_REMEDIATION = "Install the published wheel: pip install keel-verifier"
EDITABLE_INSTALL_REMEDIATION = (
    "Install and check the published wheel in a clean environment:\n"
    "  pip uninstall -y keel-verifier\n"
    "  python -m venv /tmp/demo-venv\n"
    "  source /tmp/demo-venv/bin/activate\n"
    "  pip install --no-cache-dir keel-verifier\n"
    "  keel-verify self-check"
)
SDIST_INSTALL_REMEDIATION = (
    "Force-reinstall the wheel form: pip install --force-reinstall --no-deps "
    "--only-binary :all: keel-verifier"
)
SHADOW_IMPORT_REMEDIATION = (
    "Another keel_verifier on sys.path is shadowing the installed wheel.\n"
    "Diagnose with:\n"
    "  python -c 'import keel_verifier; print(keel_verifier.__file__)'\n"
    "  python -c 'import sys; print(chr(10).join(sys.path))'\n"
    "  printenv PYTHONPATH\n"
    "Then unset PYTHONPATH, remove the shadowing path, or pip uninstall the user-site "
    "editable."
)

InstallForm = Literal["wheel", "editable", "sdist", "missing"]


@dataclass(frozen=True)
class InstallFormDiagnostic:
    form: InstallForm
    distribution: Any | None
    message: str
    remediation: str | None = None


@dataclass(frozen=True)
class ImportIsolationDiagnostic:
    imported_path: Path | None
    checked: bool
    aligned: bool | None
    expected_dirs: tuple[Path, ...]
    message: str
    code: str | None = None
    remediation: str | None = None


def inspect_install_form(
    *,
    distribution_getter: Callable[[str], Any] | None = None,
) -> InstallFormDiagnostic:
    get_distribution = distribution_getter or importlib.metadata.distribution
    try:
        dist = get_distribution(DIST_NAME)
    except importlib.metadata.PackageNotFoundError:
        return InstallFormDiagnostic(
            form="missing",
            distribution=None,
            message="keel-verifier distribution metadata is not installed",
            remediation=MISSING_INSTALL_REMEDIATION,
        )

    direct_url = dist.read_text("direct_url.json")
    if direct_url:
        try:
            direct_url_payload = json.loads(direct_url)
        except json.JSONDecodeError:
            direct_url_payload = {}
        if direct_url_payload.get("dir_info", {}).get("editable") is True:
            return InstallFormDiagnostic(
                form="editable",
                distribution=dist,
                message="editable installs are outside the wheel self-check scope",
                remediation=EDITABLE_INSTALL_REMEDIATION,
            )

    if dist.read_text("WHEEL") is not None:
        return InstallFormDiagnostic(
            form="wheel",
            distribution=dist,
            message="wheel form selected",
        )

    return InstallFormDiagnostic(
        form="sdist",
        distribution=dist,
        message="only installed wheel form is supported by keel-verify self-check",
        remediation=SDIST_INSTALL_REMEDIATION,
    )


def inspect_import_isolation(
    *,
    distribution: Any | None = None,
    distribution_getter: Callable[[str], Any] | None = None,
) -> ImportIsolationDiagnostic:
    package = importlib.import_module(PACKAGE_NAME)
    imported_file = getattr(package, "__file__", None)
    actual_path = Path(imported_file).resolve() if imported_file else None
    if actual_path is None:
        return ImportIsolationDiagnostic(
            imported_path=None,
            checked=False,
            aligned=False,
            expected_dirs=(),
            message="keel_verifier is importable but does not expose __file__",
            code="SELF_CHECK_SHADOW_IMPORT",
            remediation=SHADOW_IMPORT_REMEDIATION,
        )

    dist = distribution
    if dist is None:
        get_distribution = distribution_getter or importlib.metadata.distribution
        try:
            dist = get_distribution(DIST_NAME)
        except importlib.metadata.PackageNotFoundError:
            return ImportIsolationDiagnostic(
                imported_path=actual_path,
                checked=False,
                aligned=False,
                expected_dirs=(),
                message="keel-verifier distribution metadata is not installed",
                code="SELF_CHECK_FORM_UNSUPPORTED",
                remediation=MISSING_INSTALL_REMEDIATION,
            )

    files = dist.files
    if not files:
        return ImportIsolationDiagnostic(
            imported_path=actual_path,
            checked=False,
            aligned=None,
            expected_dirs=(),
            message="distribution file metadata unavailable, shadow-import check skipped",
        )

    expected_dirs: set[Path] = set()
    for dist_file in files:
        metadata_path = PurePosixPath(str(dist_file))
        if len(metadata_path.parts) < 2 or metadata_path.parts[0] != PACKAGE_NAME:
            continue
        expected_dirs.add(Path(dist.locate_file(dist_file)).resolve().parent)

    if not expected_dirs:
        return ImportIsolationDiagnostic(
            imported_path=actual_path,
            checked=False,
            aligned=None,
            expected_dirs=(),
            message="distribution package file metadata unavailable, shadow-import check skipped",
        )

    actual_parent = actual_path.parent
    if actual_parent not in expected_dirs:
        expected = ", ".join(str(path) for path in sorted(expected_dirs))
        return ImportIsolationDiagnostic(
            imported_path=actual_path,
            checked=True,
            aligned=False,
            expected_dirs=tuple(sorted(expected_dirs)),
            message=(
                f"keel_verifier imported from {actual_path} but distribution metadata says "
                f"it lives at {expected}"
            ),
            code="SELF_CHECK_SHADOW_IMPORT",
            remediation=SHADOW_IMPORT_REMEDIATION,
        )

    return ImportIsolationDiagnostic(
        imported_path=actual_path,
        checked=True,
        aligned=True,
        expected_dirs=tuple(sorted(expected_dirs)),
        message="import location matches distribution metadata",
    )
