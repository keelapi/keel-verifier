from __future__ import annotations

import json
import hashlib
import subprocess
import sys
from pathlib import Path

import rfc8785


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "generate_release_manifest.py"


def _write_pyproject(root: Path, version: str) -> None:
    root.joinpath("pyproject.toml").write_text(
        "\n".join(
            [
                "[build-system]",
                'requires = ["setuptools>=68", "wheel"]',
                'build-backend = "setuptools.build_meta"',
                "",
                "[project]",
                'name = "keel-verifier"',
                f'version = "{version}"',
                "",
            ]
        ),
        encoding="utf-8",
    )


def _run_generator(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--repo-root", str(root), *args],
        text=True,
        capture_output=True,
        check=False,
    )


def test_generate_embedded_manifest_records_package_payload_digests(tmp_path: Path) -> None:
    _write_pyproject(tmp_path, "2.2.0")
    package = tmp_path / "keel_verifier"
    package.joinpath("data").mkdir(parents=True)
    package.joinpath("__init__.py").write_text('__version__ = "2.2.0"\n', encoding="utf-8")
    package.joinpath("data", "trust_root.json").write_text("{}\n", encoding="utf-8")

    result = _run_generator(tmp_path, "embedded", "--tag", "v2.2.0")

    assert result.returncode == 0, result.stderr
    manifest = json.loads(package.joinpath("_release_manifest.json").read_text())
    assert manifest["version"] == "1.0"
    assert manifest["release_name"] == "keel-verifier"
    assert manifest["version_tag"] == "v2.2.0"
    assert manifest["expected_signing_identity"].endswith(
        "/.github/workflows/release.yml@refs/tags/v2.2.0"
    )
    assert manifest["release_manifest_tsa_witness_url"].endswith(
        "/releases/download/v2.2.0/manifest.json.tsa.json"
    )
    assert set(manifest["per_file_digests"]) == {
        "keel_verifier/__init__.py",
        "keel_verifier/data/trust_root.json",
    }


def test_generate_release_manifest_reads_rekor_indices_from_bundles(
    tmp_path: Path,
) -> None:
    _write_pyproject(tmp_path, "2.2.0")
    package = tmp_path / "keel_verifier"
    package.joinpath("data").mkdir(parents=True)
    package.joinpath("__init__.py").write_text('__version__ = "2.2.0"\n', encoding="utf-8")
    package.joinpath("data", "trust_root.json").write_text("{}\n", encoding="utf-8")
    embedded_result = _run_generator(tmp_path, "embedded", "--tag", "v2.2.0")
    assert embedded_result.returncode == 0, embedded_result.stderr

    dist = tmp_path / "dist"
    dist.mkdir()
    for filename in [
        "keel_verifier-2.2.0-py3-none-any.whl",
        "keel_verifier-2.2.0.tar.gz",
    ]:
        dist.joinpath(filename).write_bytes(filename.encode("utf-8"))
        dist.joinpath(f"{filename}.sigstore").write_text(
            json.dumps({"verificationMaterial": {"tlogEntries": [{"logIndex": "42"}]}}),
            encoding="utf-8",
        )
    dist.joinpath("keel_verifier-2.2.0-sbom.intoto.jsonl").write_text(
        json.dumps({"verificationMaterial": {"tlogEntries": [{"logIndex": 99}]}}),
        encoding="utf-8",
    )
    tmp_path.joinpath("sbom.cyclonedx.json").write_text(
        '{"bomFormat":"CycloneDX"}\n',
        encoding="utf-8",
    )

    result = _run_generator(
        tmp_path,
        "release",
        "--tag",
        "v2.2.0",
        "--python-version",
        "3.12.0",
        "--cosign-version",
        "v2.5.0",
    )

    assert result.returncode == 0, result.stderr
    manifest = json.loads(tmp_path.joinpath("manifest.json").read_text())
    assert manifest["signing_identity"].endswith(
        "/.github/workflows/release.yml@refs/tags/v2.2.0"
    )
    assert [artifact["rekor_log_index"] for artifact in manifest["artifacts"]] == [42, 42]
    embedded_manifest = json.loads(package.joinpath("_release_manifest.json").read_text())
    expected_embedded_hash = hashlib.sha256(rfc8785.dumps(embedded_manifest)).hexdigest()
    assert manifest["embedded_manifests"] == [
        {
            "artifact": "wheel",
            "path": "keel_verifier/_release_manifest.json",
            "media_type": "application/json",
            "canonicalization": "rfc8785-jcs",
            "sha256": f"sha256:{expected_embedded_hash}",
        }
    ]
    assert manifest["sbom"]["attestation_bundle"] == "keel_verifier-2.2.0-sbom.intoto.jsonl"
    assert manifest["build_environment"] == {
        "runner": "ubuntu-latest",
        "python_version": "3.12.0",
        "cosign_version": "v2.5.0",
        "build_backend": "setuptools.build_meta",
    }
