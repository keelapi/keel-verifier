#!/usr/bin/env python3
"""Fail-loud gate for the release-pinned historical compatibility corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = (
    ROOT
    / "tests"
    / "fixtures"
    / "historical_compatibility"
    / "v1"
    / "manifest.json"
)
REQUIRED_CATEGORIES = {
    "issued_permits",
    "evidence_bundles",
    "registry_versions",
    "fact_profiles",
    "trust_roots",
    "exact_action_divergence",
    "co_signature_false_target",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"historical compatibility manifest is missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"historical compatibility manifest is invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("historical compatibility manifest must be an object")
    return value


def validate_manifest(path: Path = DEFAULT_MANIFEST) -> list[str]:
    manifest = _load_manifest(path)
    if (
        manifest.get("schema_version")
        != "keel.verifier.historical_compatibility.v1"
    ):
        raise ValueError("unsupported historical compatibility manifest version")
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("historical compatibility corpus must contain cases")

    categories: set[str] = set()
    case_ids: set[str] = set()
    nodeids: list[str] = []
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise ValueError(f"historical compatibility case {index} must be an object")
        case_id = case.get("id")
        category = case.get("category")
        if not isinstance(case_id, str) or not case_id:
            raise ValueError(f"historical compatibility case {index} has no id")
        if case_id in case_ids:
            raise ValueError(f"duplicate historical compatibility case id: {case_id}")
        case_ids.add(case_id)
        if not isinstance(category, str) or category not in REQUIRED_CATEGORIES:
            raise ValueError(f"{case_id}: unsupported or missing category")
        categories.add(category)

        artifacts = case.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            raise ValueError(f"{case_id}: at least one pinned artifact is required")
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                raise ValueError(f"{case_id}: artifact entry must be an object")
            relative = artifact.get("path")
            expected = artifact.get("sha256")
            if not isinstance(relative, str) or not relative:
                raise ValueError(f"{case_id}: artifact path is missing")
            if (
                not isinstance(expected, str)
                or len(expected) != 64
                or any(character not in "0123456789abcdef" for character in expected)
            ):
                raise ValueError(f"{case_id}: artifact SHA-256 is malformed")
            artifact_path = ROOT / relative
            if not artifact_path.is_file():
                raise ValueError(f"{case_id}: required artifact is missing: {relative}")
            actual = _sha256(artifact_path)
            if actual != expected:
                raise ValueError(
                    f"{case_id}: artifact digest drift for {relative}: "
                    f"expected={expected} actual={actual}"
                )

        case_nodeids = case.get("pytest_nodeids")
        if not isinstance(case_nodeids, list) or not case_nodeids:
            raise ValueError(f"{case_id}: executable pytest coverage is required")
        for nodeid in case_nodeids:
            if not isinstance(nodeid, str) or not nodeid:
                raise ValueError(f"{case_id}: pytest node id is malformed")
            test_path = ROOT / nodeid.split("::", 1)[0]
            if not test_path.is_file():
                raise ValueError(f"{case_id}: pytest source is missing: {nodeid}")
            nodeids.append(nodeid)

    missing = REQUIRED_CATEGORIES - categories
    if missing:
        raise ValueError(
            "historical compatibility corpus is missing categories: "
            + ", ".join(sorted(missing))
        )
    return list(dict.fromkeys(nodeids))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--run",
        action="store_true",
        help="Run the manifest's executable pytest cases after validating pins.",
    )
    args = parser.parse_args()
    try:
        nodeids = validate_manifest(args.manifest.resolve())
    except ValueError as exc:
        print(f"FAILED: historical compatibility corpus: {exc}", file=sys.stderr)
        return 1
    if args.run:
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", *nodeids],
            cwd=ROOT,
            check=False,
        )
        if completed.returncode != 0:
            return completed.returncode
    print(
        "PASS: historical compatibility corpus: "
        f"{len(nodeids)} executable case(s), "
        f"{len(REQUIRED_CATEGORIES)} required categories"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
