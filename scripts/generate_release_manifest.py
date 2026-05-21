#!/usr/bin/env python3
"""Generate keel-verifier release provenance manifests."""

from __future__ import annotations

import argparse
import json
import platform
import re
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any


RELEASE_NAME = "keel-verifier"
PACKAGE_ROOT = "keel_verifier"
GITHUB_REPOSITORY = "keelapi/keel-verifier"
RELEASE_MANIFEST_VERSION = "1.0"
TAG_RE = re.compile(r"^v(?P<version>\d+\.\d+\.\d+)$")


def _error(message: str) -> SystemExit:
    return SystemExit(f"error: {message}")


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise _error(f"missing required file: {path}") from exc


def _load_json(path: Path) -> Any:
    raw = _read_text(path)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        first_line = next((line for line in raw.splitlines() if line.strip()), "")
        try:
            return json.loads(first_line)
        except json.JSONDecodeError as exc:
            raise _error(f"{path} is not valid JSON or JSONL bundle data") from exc


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )


def _sha256(path: Path) -> str:
    digest = sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except FileNotFoundError as exc:
        raise _error(f"missing required file: {path}") from exc
    return digest.hexdigest()


def _tag_version(tag: str) -> str:
    match = TAG_RE.match(tag)
    if not match:
        raise _error(f"tag must match vX.Y.Z, got {tag!r}")
    return match.group("version")


def _parse_pyproject_value(pyproject: Path, section: str, key: str) -> str:
    current_section: str | None = None
    for raw_line in _read_text(pyproject).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line.strip("[]")
            continue
        if current_section == section and line.startswith(f"{key} "):
            _, value = line.split("=", 1)
            return value.strip().strip('"')
    raise _error(f"missing {section}.{key} in {pyproject}")


def _project_version(repo_root: Path) -> str:
    return _parse_pyproject_value(repo_root / "pyproject.toml", "project", "version")


def _build_backend(repo_root: Path) -> str:
    return _parse_pyproject_value(
        repo_root / "pyproject.toml",
        "build-system",
        "build-backend",
    )


def _assert_version_matches(repo_root: Path, tag: str) -> str:
    tag_version = _tag_version(tag)
    project_version = _project_version(repo_root)
    if project_version != tag_version:
        raise _error(
            f"tag {tag} resolves to version {tag_version}, "
            f"but pyproject.toml declares {project_version}"
        )
    return tag_version


def _signing_identity(tag: str) -> str:
    return (
        f"https://github.com/{GITHUB_REPOSITORY}/.github/workflows/"
        f"release.yml@refs/tags/{tag}"
    )


def _release_url(tag: str, filename: str) -> str:
    return f"https://github.com/{GITHUB_REPOSITORY}/releases/download/{tag}/{filename}"


def _is_package_payload(path: Path, package_root: Path) -> bool:
    if path.name == "_release_manifest.json":
        return False
    if "__pycache__" in path.parts or path.name == ".DS_Store":
        return False
    if path.suffix == ".py":
        return True
    try:
        relative = path.relative_to(package_root)
    except ValueError:
        return False
    if relative.parts[:1] == ("data",) and path.suffix == ".json":
        return True
    if relative.parts[:1] == ("keys",) and path.suffix == ".json":
        return True
    if relative.parts[:1] == ("capability",) and path.suffix in {".json", ".md"}:
        return True
    return False


def _package_file_digests(repo_root: Path) -> dict[str, str]:
    package_root = repo_root / PACKAGE_ROOT
    if not package_root.is_dir():
        raise _error(f"missing package directory: {package_root}")

    digests: dict[str, str] = {}
    for path in sorted(package_root.rglob("*")):
        if not path.is_file() or not _is_package_payload(path, package_root):
            continue
        rel_path = path.relative_to(repo_root).as_posix()
        digests[rel_path] = _sha256(path)

    if not digests:
        raise _error(f"no package payload files found below {package_root}")
    return digests


def _find_rekor_log_index(value: Any) -> int | None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = key.replace("_", "").lower()
            if normalized == "logindex":
                try:
                    index = int(item)
                except (TypeError, ValueError):
                    continue
                if index >= 0:
                    return index
        for item in value.values():
            found = _find_rekor_log_index(item)
            if found is not None:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _find_rekor_log_index(item)
            if found is not None:
                return found
    return None


def _rekor_log_index(bundle_path: Path) -> int:
    index = _find_rekor_log_index(_load_json(bundle_path))
    if index is None:
        raise _error(f"could not find Rekor logIndex in {bundle_path}")
    return index


def _artifact_entry(dist_dir: Path, filename: str, content_type: str) -> dict[str, Any]:
    artifact_path = dist_dir / filename
    bundle_name = f"{filename}.sigstore"
    bundle_path = dist_dir / bundle_name
    index = _rekor_log_index(bundle_path)
    return {
        "filename": filename,
        "sha256": _sha256(artifact_path),
        "content_type": content_type,
        "sigstore_bundle": bundle_name,
        "rekor_log_index": index,
        "rekor_log_url": f"https://rekor.sigstore.dev/api/v1/log/entries/{index}",
    }


def write_embedded_manifest(args: argparse.Namespace) -> None:
    repo_root = args.repo_root.resolve()
    version = _assert_version_matches(repo_root, args.tag)
    manifest = {
        "version": RELEASE_MANIFEST_VERSION,
        "release_name": RELEASE_NAME,
        "version_tag": args.tag,
        "expected_signing_identity": _signing_identity(args.tag),
        "release_manifest_url": _release_url(args.tag, "manifest.json"),
        "release_manifest_signature_url": _release_url(args.tag, "manifest.json.sigstore"),
        "per_file_digests": _package_file_digests(repo_root),
    }
    output_path = repo_root / PACKAGE_ROOT / "_release_manifest.json"
    _write_json(output_path, manifest)
    print(f"wrote {output_path.relative_to(repo_root)} for {version}")


def write_release_manifest(args: argparse.Namespace) -> None:
    repo_root = args.repo_root.resolve()
    version = _assert_version_matches(repo_root, args.tag)
    dist_dir = repo_root / args.dist_dir
    sbom_path = repo_root / args.sbom
    wheel_name = f"keel_verifier-{version}-py3-none-any.whl"
    sdist_name = f"keel_verifier-{version}.tar.gz"
    sbom_bundle_name = f"keel_verifier-{version}-sbom.intoto.jsonl"
    sbom_bundle_path = dist_dir / sbom_bundle_name
    if not sbom_bundle_path.is_file():
        raise _error(f"missing required file: {sbom_bundle_path}")

    manifest = {
        "version": RELEASE_MANIFEST_VERSION,
        "release_name": RELEASE_NAME,
        "version_tag": args.tag,
        "released_at": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "signing_identity": _signing_identity(args.tag),
        "artifacts": [
            _artifact_entry(dist_dir, wheel_name, "application/x-wheel+zip"),
            _artifact_entry(dist_dir, sdist_name, "application/gzip"),
        ],
        "sbom": {
            "format": "cyclonedx",
            "filename": sbom_path.name,
            "attestation_bundle": sbom_bundle_name,
            "sha256": _sha256(sbom_path),
        },
        "build_environment": {
            "runner": args.runner,
            "python_version": args.python_version or platform.python_version(),
            "cosign_version": args.cosign_version,
            "build_backend": _build_backend(repo_root),
        },
    }
    output_path = repo_root / args.output
    _write_json(output_path, manifest)
    print(f"wrote {output_path.relative_to(repo_root)} for {version}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate embedded and release-level keel-verifier manifests."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="Repository root. Defaults to the current working directory.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    embedded = subparsers.add_parser("embedded", help="write package embedded manifest")
    embedded.add_argument("--tag", required=True, help="Release tag, for example v2.2.0")
    embedded.set_defaults(func=write_embedded_manifest)

    release = subparsers.add_parser("release", help="write signed release manifest")
    release.add_argument("--tag", required=True, help="Release tag, for example v2.2.0")
    release.add_argument("--dist-dir", default="dist", help="Distribution directory")
    release.add_argument(
        "--sbom",
        default="sbom.cyclonedx.json",
        help="CycloneDX SBOM path relative to the repo root",
    )
    release.add_argument("--output", default="manifest.json", help="Release manifest path")
    release.add_argument("--runner", default="ubuntu-latest", help="GitHub runner label")
    release.add_argument(
        "--python-version",
        default=None,
        help="Python version to record in build_environment",
    )
    release.add_argument(
        "--cosign-version",
        required=True,
        help="Cosign version to record in build_environment",
    )
    release.set_defaults(func=write_release_manifest)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
