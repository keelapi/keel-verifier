from __future__ import annotations

import hashlib
import json
import zipfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import rfc8785

from keel_verifier import self_check


WHEEL_URL = (
    "https://files.pythonhosted.org/packages/source/k/keel-verifier/"
    "keel_verifier-2.4.4-py3-none-any.whl"
)


@dataclass(frozen=True)
class PublishedWheelFixture:
    wheel_bytes: bytes
    pypi_payload: dict[str, Any]
    embedded_manifest: dict[str, Any]
    signed_manifest_bytes: bytes


def _embedded_manifest(version: str = "2.4.4") -> dict[str, Any]:
    init_payload = f'__version__ = "{version}"\n'.encode("utf-8")
    return {
        "version": "1.0",
        "release_name": "keel-verifier",
        "version_tag": f"v{version}",
        "expected_signing_identity": (
            "https://github.com/keelapi/keel-verifier/.github/workflows/"
            f"release.yml@refs/tags/v{version}"
        ),
        "release_manifest_url": "https://example.invalid/releases/v2.4.4/manifest.json",
        "release_manifest_signature_url": (
            "https://example.invalid/releases/v2.4.4/manifest.json.sigstore"
        ),
        "release_manifest_tsa_witness_url": (
            "https://example.invalid/releases/v2.4.4/manifest.json.tsa.json"
        ),
        "per_file_digests": {
            "keel_verifier/__init__.py": hashlib.sha256(init_payload).hexdigest(),
        },
    }


def _signed_manifest(embedded_manifest: dict[str, Any]) -> dict[str, Any]:
    embedded_hash = hashlib.sha256(rfc8785.dumps(embedded_manifest)).hexdigest()
    return {
        "version": "1.0",
        "release_name": "keel-verifier",
        "version_tag": embedded_manifest["version_tag"],
        "signing_identity": embedded_manifest["expected_signing_identity"],
        "artifacts": [
            {
                "filename": "keel_verifier-2.4.4-py3-none-any.whl",
                "sha256": "f" * 64,
            }
        ],
        "embedded_manifests": [
            {
                "artifact": "wheel",
                "path": "keel_verifier/_release_manifest.json",
                "media_type": "application/json",
                "canonicalization": "rfc8785-jcs",
                "sha256": f"sha256:{embedded_hash}",
            }
        ],
    }


def _fixture_wheel(version: str = "2.4.4") -> PublishedWheelFixture:
    embedded_manifest = _embedded_manifest(version)
    signed_manifest_bytes = json.dumps(_signed_manifest(embedded_manifest)).encode("utf-8")
    init_payload = f'__version__ = "{version}"\n'.encode("utf-8")
    wheel_buffer = BytesIO()
    with zipfile.ZipFile(wheel_buffer, mode="w") as wheel:
        wheel.writestr("keel_verifier/__init__.py", init_payload)
        wheel.writestr(
            "keel_verifier/_release_manifest.json",
            json.dumps(embedded_manifest, sort_keys=True),
        )
        wheel.writestr(
            f"keel_verifier-{version}.dist-info/WHEEL",
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )

    wheel_bytes = wheel_buffer.getvalue()
    pypi_payload = {
        "info": {"version": version},
        "releases": {
            version: [
                {
                    "packagetype": "bdist_wheel",
                    "url": WHEEL_URL,
                    "digests": {"sha256": hashlib.sha256(wheel_bytes).hexdigest()},
                }
            ]
        },
        "urls": [
            {
                "packagetype": "bdist_wheel",
                "url": WHEEL_URL,
                "digests": {"sha256": hashlib.sha256(wheel_bytes).hexdigest()},
            }
        ],
    }
    return PublishedWheelFixture(
        wheel_bytes=wheel_bytes,
        pypi_payload=pypi_payload,
        embedded_manifest=embedded_manifest,
        signed_manifest_bytes=signed_manifest_bytes,
    )


def _install_fixture_fetches(
    monkeypatch: pytest.MonkeyPatch,
    fixture: PublishedWheelFixture,
) -> None:
    def fake_fetch(url: str, **kwargs: Any) -> bytes:
        del kwargs
        if url == self_check.PYPI_METADATA_URL:
            return json.dumps(fixture.pypi_payload).encode("utf-8")
        if url == WHEEL_URL:
            return fixture.wheel_bytes
        if url == fixture.embedded_manifest["release_manifest_url"]:
            return fixture.signed_manifest_bytes
        if url == fixture.embedded_manifest["release_manifest_signature_url"]:
            return b'{"mock":"sigstore"}'
        if url == fixture.embedded_manifest["release_manifest_tsa_witness_url"]:
            return b'{"mock":"tsa"}'
        raise AssertionError(url)

    monkeypatch.setattr(self_check, "_fetch_url", fake_fetch)


def _run_fixture_self_check(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    installed_info: self_check.InstalledDistributionInfo | None = None,
) -> self_check.SelfCheckResult:
    fixture = _fixture_wheel()
    _install_fixture_fetches(monkeypatch, fixture)
    monkeypatch.setattr(
        self_check,
        "inspect_installed_distribution",
        lambda: installed_info
        or self_check.InstalledDistributionInfo(
            version="2.4.4",
            form="wheel",
        ),
    )
    monkeypatch.setattr(
        self_check,
        "verify_sigstore",
        lambda *args, **kwargs: self_check.SigstoreVerification(log_index=42),
    )
    monkeypatch.setattr(
        self_check,
        "verify_rekor",
        lambda *args, **kwargs: self_check.RekorVerification(
            log_index=42,
            checkpoint_present=True,
        ),
    )
    monkeypatch.setattr(
        self_check,
        "verify_tsa",
        lambda manifest, sidecar: self_check.TSAVerification(
            providers=["digicert", "globalsign"],
            message_imprint=self_check._sha256_prefixed(manifest),
        ),
    )

    return self_check.run_self_check(
        SimpleNamespace(
            form="auto",
            offline=False,
            no_cache=False,
            cache_dir=str(tmp_path),
            published_wheel="",
        )
    )


def test_published_wheel_resolves_latest_from_pypi(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    fixture = _fixture_wheel()

    def fake_fetch(url: str, **kwargs: Any) -> bytes:
        assert url == self_check.PYPI_METADATA_URL
        assert kwargs["cache_dir"] == tmp_path / "pypi"
        return json.dumps(fixture.pypi_payload).encode("utf-8")

    monkeypatch.setattr(self_check, "_fetch_url", fake_fetch)

    resolution = self_check.resolve_published_wheel(
        "",
        offline=False,
        cache_dir=tmp_path,
        no_cache=False,
    )

    assert resolution.version == "2.4.4"
    assert resolution.source_url == WHEEL_URL
    assert resolution.sha256 == hashlib.sha256(fixture.wheel_bytes).hexdigest()


def test_published_wheel_pinned_version_validates_pep440(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        self_check,
        "_fetch_url",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("network used")),
    )

    with pytest.raises(self_check.SelfCheckError) as exc:
        self_check.resolve_published_wheel(
            "not a version",
            offline=False,
            cache_dir=tmp_path,
            no_cache=False,
        )

    assert exc.value.code == "SELF_CHECK_FETCH_FAILED"
    assert "PEP 440" in exc.value.message


def test_published_wheel_digest_mismatch_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(self_check, "_fetch_url", lambda *args, **kwargs: b"wrong")
    resolution = self_check.PublishedWheelResolution(
        version="2.4.4",
        source_url=WHEEL_URL,
        sha256="0" * 64,
    )

    with pytest.raises(self_check.SelfCheckError) as exc:
        self_check.download_published_wheel(
            resolution,
            offline=False,
            cache_dir=tmp_path,
            no_cache=False,
        )

    assert exc.value.code == "SELF_CHECK_PUBLISHED_WHEEL_DIGEST_MISMATCH"
    assert "https://status.python.org/" in (exc.value.remediation or "")
    assert "--no-cache" in (exc.value.remediation or "")
    assert "SELF_CHECK_PUBLISHED_WHEEL_DIGEST_MISMATCH" in self_check.SELF_CHECK_FAILURE_CODES


def test_published_wheel_offline_uses_cache_only(tmp_path: Path) -> None:
    wheel_bytes = b"cached wheel bytes"
    pypi_payload = {
        "info": {"version": "2.4.4"},
        "releases": {
            "2.4.4": [
                {
                    "packagetype": "bdist_wheel",
                    "url": WHEEL_URL,
                    "digests": {"sha256": hashlib.sha256(wheel_bytes).hexdigest()},
                }
            ]
        },
    }
    pypi_cache, pypi_metadata = self_check._cache_paths(
        tmp_path / "pypi",
        self_check.PYPI_METADATA_URL,
    )
    wheel_cache, wheel_metadata = self_check._cache_paths(
        tmp_path / "published-wheels",
        WHEEL_URL,
    )
    self_check._write_cache(
        pypi_cache,
        pypi_metadata,
        self_check.PYPI_METADATA_URL,
        json.dumps(pypi_payload).encode("utf-8"),
    )
    self_check._write_cache(wheel_cache, wheel_metadata, WHEEL_URL, wheel_bytes)

    resolution = self_check.resolve_published_wheel(
        "",
        offline=True,
        cache_dir=tmp_path,
        no_cache=False,
    )
    download = self_check.download_published_wheel(
        resolution,
        offline=True,
        cache_dir=tmp_path,
        no_cache=False,
    )

    assert resolution.version == "2.4.4"
    assert download.wheel_bytes == wheel_bytes

    with pytest.raises(self_check.SelfCheckError) as exc:
        self_check.resolve_published_wheel(
            "",
            offline=True,
            cache_dir=tmp_path / "empty",
            no_cache=False,
        )
    assert exc.value.code == "SELF_CHECK_FETCH_FAILED"
    assert "offline mode requested" in exc.value.message


def test_published_wheel_labeling_explicit() -> None:
    result = self_check.SelfCheckResult(
        form="published_wheel",
        stages=[
            self_check.SelfCheckStage(
                name="published_wheel_resolve",
                ok=True,
                message="PyPI metadata resolved to keel-verifier 2.4.4",
            )
        ],
        published_wheel_info=self_check.PublishedWheelInfo(
            version="2.4.4",
            source_url=WHEEL_URL,
            installed_version="2.4.4",
            installed_form="editable",
            installed_location="/Users/foo/dev/keel-verifier",
        ),
    )

    human = result.format_human()
    payload = result.to_dict()

    assert "PASS: keel-verifier published wheel v2.4.4 verified" in human
    assert "This verifies the PUBLISHED wheel" in human
    assert "Your locally installed copy" in human
    assert "version 2.4.4 (editable install at /Users/foo/dev/keel-verifier)" in human
    assert payload["published_wheel_info"]["source_url"] == WHEEL_URL
    assert payload["published_wheel_info"]["installed_form"] == "editable"


def test_published_wheel_chain_against_tempdir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    result = _run_fixture_self_check(monkeypatch, tmp_path)

    assert result.ok is True
    assert result.form == "published_wheel"
    assert [stage.name for stage in result.stages] == [
        "published_wheel_resolve",
        "published_wheel_download",
        "embedded_manifest",
        "fetch",
        "sigstore_signature",
        "rekor_inclusion",
        "tsa_witnesses",
        "embedded_binding",
        "per_file_digests",
    ]
    assert result.stages[-1].message == "published wheel files match embedded per-file digests"


def test_published_wheel_skips_form_and_import_isolation_stages(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        self_check,
        "detect_form",
        lambda: (_ for _ in ()).throw(AssertionError("detect_form called")),
    )
    monkeypatch.setattr(
        self_check,
        "verify_import_isolation",
        lambda: (_ for _ in ()).throw(AssertionError("verify_import_isolation called")),
    )

    result = _run_fixture_self_check(monkeypatch, tmp_path)

    stage_names = [stage.name for stage in result.stages]
    assert "form" not in stage_names
    assert "import_isolation" not in stage_names
    assert result.ok is True


def test_published_wheel_with_installed_editable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    result = _run_fixture_self_check(
        monkeypatch,
        tmp_path,
        installed_info=self_check.InstalledDistributionInfo(
            version="2.4.4",
            form="editable",
            location="/Users/foo/dev/keel-verifier",
        ),
    )

    human = result.format_human()

    assert result.ok is True
    assert result.published_wheel_info is not None
    assert result.published_wheel_info.installed_form == "editable"
    assert "This verifies the PUBLISHED wheel" in human
    assert "editable install at /Users/foo/dev/keel-verifier" in human
