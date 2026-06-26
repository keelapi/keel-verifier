from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Callable, Literal

import pytest

import keel_verifier
from keel_verifier.semantics import CLAIM_SEMANTICS, RELEASED_ARTIFACT_HASHES


REPO_ROOT = Path(__file__).resolve().parents[1]
EMBEDDED_MANIFEST = REPO_ROOT / "keel_verifier" / "_release_manifest.json"
CLAIM_REGISTRY = REPO_ROOT / "keel_verifier" / "data" / "claim_registry" / "v0.json"
URL_VERSION_RE = re.compile(r"(?:refs/tags/|releases/download/)(v\d+\.\d+\.\d+)")
VERSION_PATTERN = re.compile(r"\b2\.\d+\.\d+\b")
URL_FIELDS = (
    "expected_signing_identity",
    "release_manifest_url",
    "release_manifest_signature_url",
    "release_manifest_tsa_witness_url",
)
SCAN_SUFFIXES = {".py", ".json", ".toml"}
VersionFormat = Literal["bare", "v-prefixed"]


@dataclass(frozen=True)
class VersionParityEntry:
    file: Path
    locator: str
    extractor: Callable[[Path], str]
    expected_format: VersionFormat


@dataclass(frozen=True)
class HistoricalReference:
    file: Path
    line_number_or_pattern: int | re.Pattern[str]
    justification: str

    def matches(self, line_number: int, line: str) -> bool:
        if isinstance(self.line_number_or_pattern, int):
            return self.line_number_or_pattern == line_number
        return bool(self.line_number_or_pattern.search(line))


REGISTERED_LOCATOR_PATTERNS: dict[str, re.Pattern[str]] = {
    "project.version source of truth": re.compile(r'^\s*version\s*='),
    "_SOURCE_TREE_VERSION constant assignment": re.compile(
        r"^\s*_SOURCE_TREE_VERSION\s*="
    ),
    "verifier.version": re.compile(r'^\s*"version"\s*:'),
    "version_tag": re.compile(r'^\s*"version_tag"\s*:'),
}


def _project_version() -> str:
    current_section: str | None = None
    for raw_line in (REPO_ROOT / "pyproject.toml").read_text(
        encoding="utf-8"
    ).splitlines():
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


def _extract_project_version(path: Path) -> str:
    assert path == REPO_ROOT / "pyproject.toml"
    return _project_version()


def _extract_source_tree_version(path: Path) -> str:
    module = ast.parse(path.read_text(encoding="utf-8"))
    for node in module.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == "_SOURCE_TREE_VERSION"
            for target in node.targets
        ):
            continue
        if not isinstance(node.value, ast.Constant) or not isinstance(
            node.value.value, str
        ):
            raise AssertionError("_SOURCE_TREE_VERSION must be assigned a string")
        return node.value.value
    raise AssertionError("missing _SOURCE_TREE_VERSION assignment")


def _extract_capability_verifier_version(path: Path) -> str:
    return json.loads(path.read_text(encoding="utf-8"))["verifier"]["version"]


def _extract_release_manifest_version_tag(path: Path) -> str:
    return json.loads(path.read_text(encoding="utf-8"))["version_tag"]


VERSION_PARITY_REGISTRY: list[VersionParityEntry] = [
    VersionParityEntry(
        file=REPO_ROOT / "pyproject.toml",
        locator="project.version source of truth",
        extractor=_extract_project_version,
        expected_format="bare",
    ),
    VersionParityEntry(
        file=REPO_ROOT / "keel_verifier" / "__init__.py",
        locator="_SOURCE_TREE_VERSION constant assignment",
        extractor=_extract_source_tree_version,
        expected_format="bare",
    ),
    VersionParityEntry(
        file=REPO_ROOT / "keel_verifier" / "capability" / "v1.json",
        locator="verifier.version",
        extractor=_extract_capability_verifier_version,
        expected_format="bare",
    ),
    VersionParityEntry(
        file=EMBEDDED_MANIFEST,
        locator="version_tag",
        extractor=_extract_release_manifest_version_tag,
        expected_format="v-prefixed",
    ),
    # Future entries go here. When a new version-bearing file is added, the
    # discovery scanner below fails until the location is registered here.
]

HISTORICAL_REFERENCE_ALLOWLIST: list[HistoricalReference] = [
    HistoricalReference(
        file=REPO_ROOT / "keel_verifier" / "self_check.py",
        line_number_or_pattern=re.compile(r"v2\.4\.2 release bundle"),
        justification=(
            "historical context for the sigstore warning filter added after v2.4.2"
        ),
    ),
    HistoricalReference(
        file=REPO_ROOT / "keel_verifier" / "verifier.py",
        line_number_or_pattern=re.compile(r"RFC 3161 \u00a72\.4\.2"),
        justification="RFC section reference, not a keel-verifier version",
    ),
]

STEP4_FAILURE_CODES = {
    "PERMIT_DECISION_EVIDENCE_MISSING",
    "PERMIT_DECISION_SCHEMA_INVALID",
    "PERMIT_DECISION_CANONICAL_HASH_MISMATCH",
    "PERMIT_DECISION_CANONICAL_PAYLOAD_MISMATCH",
    "PERMIT_DECISION_SIGNATURE_INVALID",
    "PERMIT_DECISION_TRUST_ROOT_UNRESOLVABLE",
    "PERMIT_DECISION_KEY_ID_MISMATCH",
    "PERMIT_DECISION_UNTRUSTED_KEY",
    "PERMIT_DECISION_UNSUPPORTED_BINDING_VERSION",
    "PERMIT_REVOKED_EVIDENCE_MISSING",
    "PERMIT_REVOKED_SCHEMA_INVALID",
    "PERMIT_REVOKED_SIGNATURE_INVALID",
    "PERMIT_REVOKED_TRUST_ROOT_UNRESOLVABLE",
    "PERMIT_REVOKED_PROJECT_ID_MISMATCH",
    "PERMIT_REVOKED_PERMIT_ID_MISMATCH",
    "PERMIT_REVOKED_EFFECTIVE_AT_MISMATCH",
    "PERMIT_REVOKED_ACTOR_PII_DETECTED",
    "PERMIT_REVOKED_ACTOR_KIND_UNSUPPORTED",
    "EXPORT_SCOPE_PREDICATE_OUT_OF_GRAMMAR",
    "EXPORT_SCOPE_POST_REVOCATION_DISPATCH_PRESENT",
    "EXPORT_SCOPE_BRIDGE_RECORD_MATCHES_PREDICATE",
}


def _relative(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def _expected_version(expected_format: VersionFormat) -> str:
    version = _project_version()
    if expected_format == "bare":
        return version
    if expected_format == "v-prefixed":
        return f"v{version}"
    raise AssertionError(f"unknown version format: {expected_format}")


def _load_embedded_manifest() -> dict:
    return json.loads(EMBEDDED_MANIFEST.read_text(encoding="utf-8"))


def _load_inventory() -> dict:
    text = resources.files("keel_verifier.capability").joinpath("v1.json").read_text()
    return json.loads(text)


def _claim_names_with_status(inventory: dict, status: str) -> set[str]:
    return {c["name"] for c in inventory["claims"] if c.get("status") == status}


def _is_excluded_from_scan(path: Path) -> bool:
    relative = path.relative_to(REPO_ROOT)
    parts = relative.parts
    if not parts:
        return True
    if parts[0] in {".git", "dist", "build", "sample", "_internal-local"}:
        return True
    if parts[0].startswith(".venv"):
        return True
    if len(parts) >= 2 and parts[0] == "tests" and parts[1] == "fixtures":
        return True
    if parts[0] == "tests" and path.name.startswith("test_") and path.suffix == ".py":
        return True
    if len(parts) >= 2 and parts[0] == "keel_verifier" and parts[1] == "data":
        return True
    return False


def _is_registered_version_site(path: Path, line: str) -> bool:
    for entry in VERSION_PARITY_REGISTRY:
        if path != entry.file:
            continue
        locator_pattern = REGISTERED_LOCATOR_PATTERNS[entry.locator]
        if locator_pattern.search(line):
            return True
    return False


def _is_historical_reference(path: Path, line_number: int, line: str) -> bool:
    return any(
        reference.file == path and reference.matches(line_number, line)
        for reference in HISTORICAL_REFERENCE_ALLOWLIST
    )


def _scan_version_strings() -> list[str]:
    unregistered: list[str] = []
    for path in sorted(REPO_ROOT.rglob("*")):
        if not path.is_file() or path.suffix not in SCAN_SUFFIXES:
            continue
        if _is_excluded_from_scan(path):
            continue
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            for match in VERSION_PATTERN.finditer(line):
                if _is_registered_version_site(path, line):
                    continue
                if _is_historical_reference(path, line_number, line):
                    continue
                unregistered.append(
                    f"{_relative(path)}:{line_number}: {match.group(0)} in "
                    f"{line.strip()!r}"
                )
    return unregistered


@pytest.mark.parametrize(
    "entry",
    VERSION_PARITY_REGISTRY,
    ids=lambda entry: f"{_relative(entry.file)}::{entry.locator}",
)
def test_registered_version_matches_pyproject_toml(entry: VersionParityEntry) -> None:
    actual = entry.extractor(entry.file)
    expected = _expected_version(entry.expected_format)

    assert actual == expected, (
        "registered version-bearing location mismatched pyproject.toml: "
        f"{_relative(entry.file)} ({entry.locator}) expected {expected!r}, "
        f"got {actual!r}"
    )


def test_imported_package_version_matches_pyproject_toml() -> None:
    assert keel_verifier.__version__ == _project_version()


def test_release_manifest_urls_match_pyproject_version() -> None:
    manifest = _load_embedded_manifest()
    expected_version_tag = f"v{_project_version()}"

    for field in URL_FIELDS:
        match = URL_VERSION_RE.search(manifest[field])
        assert match is not None, f"{field} does not contain a release version"
        assert match.group(1) == expected_version_tag, (
            f"{field} contains {match.group(1)!r}, expected {expected_version_tag!r}"
        )


def test_no_unregistered_version_strings_in_source() -> None:
    unregistered = _scan_version_strings()

    assert not unregistered, (
        "unregistered version string(s) found. Register real version-bearing "
        "locations in VERSION_PARITY_REGISTRY or add legitimate historical "
        "references to HISTORICAL_REFERENCE_ALLOWLIST:\n- "
        + "\n- ".join(unregistered)
    )


def test_capability_schema_version_present() -> None:
    inv = _load_inventory()
    assert inv.get("capability_schema_version") == "1.0"


def test_verifier_version_matches_package() -> None:
    inv = _load_inventory()
    assert inv["verifier"]["version"] == keel_verifier.__version__


def test_capability_versions() -> None:
    inv = _load_inventory()
    assert inv["verifier"]["version"] == _project_version()
    assert inv["spec_compatibility"]["permit_spec_version"] == "1.4.1"


def test_step4_claims_and_failure_codes_advertised() -> None:
    inv = _load_inventory()
    implemented = _claim_names_with_status(inv, "implemented")
    assert {
        "permit.decision.v1",
        "permit.revoked.v1",
        "permit.dispatch_absence_after_revocation.v1",
    } <= implemented
    codes = set(inv["failure_codes"]["implemented_subset"])
    assert STEP4_FAILURE_CODES <= codes


def test_inventory_claims_match_claim_registry() -> None:
    inv = _load_inventory()
    registry = json.loads(CLAIM_REGISTRY.read_text(encoding="utf-8"))
    inventory_claims = {claim["name"] for claim in inv["claims"]}
    registry_claims = {claim["name"] for claim in registry["claims"]}
    assert inventory_claims == registry_claims


def test_inventory_pinned_semantics_match_allowlist_hashes() -> None:
    inv = _load_inventory()
    inventory_pins = {pin["id"]: pin["hash"] for pin in inv["pinned_semantics"]}
    referenced = {
        semantic_id
        for claim in inv["claims"]
        for semantic_id in claim["depends_on_semantics"]
        if semantic_id.startswith("keel.permit.")
        or semantic_id.startswith("keel.authority.")
        or semantic_id.startswith("keel.rail.")
        or semantic_id.startswith("keel.scope_state.")
        or semantic_id.startswith("keel.quota.")
        or semantic_id.startswith("keel.budget.")
        or semantic_id == "keel.export.scope_faithfulness.v1"
    }
    assert set(inventory_pins) == referenced
    assert inventory_pins == {
        semantic_id: RELEASED_ARTIFACT_HASHES[semantic_id]
        for semantic_id in sorted(referenced)
    }


def test_every_code_claim_is_implemented_in_inventory() -> None:
    inv = _load_inventory()
    implemented = _claim_names_with_status(inv, "implemented")
    code_claims = set(CLAIM_SEMANTICS.keys())
    missing = code_claims - implemented
    assert not missing, (
        "CLAIM_SEMANTICS contains claims that the inventory does not mark "
        f"'implemented': {sorted(missing)}"
    )


def test_every_implemented_claim_has_code_implementation() -> None:
    inv = _load_inventory()
    implemented = _claim_names_with_status(inv, "implemented")
    code_claims = set(CLAIM_SEMANTICS.keys())
    extra = implemented - code_claims
    assert not extra, (
        "Inventory marks these claims 'implemented' but they have no "
        f"CLAIM_SEMANTICS entry: {sorted(extra)}"
    )


def test_planned_claims_have_no_code_implementation() -> None:
    inv = _load_inventory()
    planned = _claim_names_with_status(inv, "planned")
    code_claims = set(CLAIM_SEMANTICS.keys())
    leaks = planned & code_claims
    assert not leaks, (
        "Inventory marks these claims 'planned' but they have a CLAIM_SEMANTICS "
        "entry (must be 'implemented' or removed from the inventory): "
        f"{sorted(leaks)}"
    )


def test_inventory_claims_have_required_fields() -> None:
    inv = _load_inventory()
    required = {"name", "status", "description", "verdicts"}
    for claim in inv["claims"]:
        missing = required - claim.keys()
        assert not missing, (
            f"Inventory claim {claim.get('name', '<unnamed>')!r} missing: "
            f"{sorted(missing)}"
        )
