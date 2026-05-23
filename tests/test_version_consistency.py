from __future__ import annotations

import json
import re
from importlib.metadata import PackageNotFoundError
from importlib.metadata import distribution
from pathlib import Path

import keel_verifier


REPO_ROOT = Path(__file__).resolve().parents[1]
EMBEDDED_MANIFEST = REPO_ROOT / "keel_verifier" / "_release_manifest.json"
URL_VERSION_RE = re.compile(r"(?:refs/tags/|releases/download/)(v\d+\.\d+\.\d+)")
URL_FIELDS = (
    "expected_signing_identity",
    "release_manifest_url",
    "release_manifest_signature_url",
    "release_manifest_tsa_witness_url",
)


def _project_version() -> str:
    current_section: str | None = None
    for raw_line in (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line.strip("[]")
            continue
        if current_section == "project" and line.startswith("version "):
            _, value = line.split("=", 1)
            return value.strip().strip('"')
    raise AssertionError("missing project.version in pyproject.toml")


def _embedded_manifest() -> dict:
    return json.loads(EMBEDDED_MANIFEST.read_text(encoding="utf-8"))


def _installed_or_source_version() -> str:
    try:
        dist = distribution("keel-verifier")
    except PackageNotFoundError:
        return _project_version()
    if Path(dist.locate_file("")).resolve() == REPO_ROOT:
        return dist.version
    return _project_version()


def test_init_version_matches_pyproject_toml() -> None:
    pyproject_version = _project_version()

    assert _installed_or_source_version() == pyproject_version
    assert keel_verifier.__version__ == pyproject_version


def test_release_manifest_version_matches_pyproject_toml() -> None:
    manifest = _embedded_manifest()

    assert manifest["version_tag"] == f"v{_project_version()}"


def test_release_manifest_urls_match_version_tag() -> None:
    manifest = _embedded_manifest()
    version_tag = manifest["version_tag"]

    for field in URL_FIELDS:
        match = URL_VERSION_RE.search(manifest[field])
        assert match is not None, f"{field} does not contain a release version"
        assert match.group(1) == version_tag
