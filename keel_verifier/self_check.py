"""Installed-wheel self-check for keel-verifier release provenance."""

from __future__ import annotations

import base64
import hashlib
import io
import importlib.metadata
import importlib.resources
import json
import logging
import re
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlparse

from keel_verifier.install_diagnostics import (
    DIST_NAME,
    PACKAGE_NAME,
    SHADOW_IMPORT_REMEDIATION,
    inspect_import_isolation,
    inspect_install_form,
)

CACHE_SECONDS = 24 * 60 * 60
DEFAULT_CACHE_DIR = Path.home() / ".keel-verifier" / "cache"
PYPI_METADATA_URL = "https://pypi.org/pypi/keel-verifier/json"
GITHUB_ACTIONS_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
REQUIRED_TSA_PROVIDERS = {"digicert", "globalsign"}
EMBEDDED_MANIFEST_PATH = "keel_verifier/_release_manifest.json"
EMBEDDED_CANONICALIZATION = "rfc8785-jcs"
PEP440_VERSION_RE = re.compile(
    r"""
    \Av?
    (?:
        (?:(?:[0-9]+)!)?
        [0-9]+(?:\.[0-9]+)*
        (?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?[0-9]*)?
        (?:
            -[0-9]+
            |
            [-_.]?(?:post|rev|r)[-_.]?[0-9]*
        )?
        (?:[-_.]?dev[-_.]?[0-9]*)?
    )
    (?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?
    \Z
    """,
    re.IGNORECASE | re.VERBOSE,
)
FORBIDDEN_EMBEDDED_FIELDS = {
    "artifacts",
    "build_environment",
    "embedded_manifests",
    "rekor",
    "rekor_log_index",
    "rekor_log_url",
    "released_at",
    "release_manifest_signature",
    "release_manifest_tsa_receipt",
    "release_manifest_tsa_receipts",
    "sbom",
    "signature",
    "signing_identity",
    "tsa",
    "tsa_receipts",
}
SELF_CHECK_FAILURE_CODES = frozenset(
    {
        "SELF_CHECK_EMBEDDED_BINDING_MISMATCH",
        "SELF_CHECK_EMBEDDED_BINDING_MISSING",
        "SELF_CHECK_EMBEDDED_MANIFEST_INVALID",
        "SELF_CHECK_EMBEDDED_MANIFEST_NOT_FOUND",
        "SELF_CHECK_FETCH_FAILED",
        "SELF_CHECK_FILE_DIGEST_MISMATCH",
        "SELF_CHECK_FILE_MISSING",
        "SELF_CHECK_FORBIDDEN_EMBEDDED_FIELD",
        "SELF_CHECK_FORM_UNSUPPORTED",
        "SELF_CHECK_REKOR_INVALID",
        "SELF_CHECK_PUBLISHED_WHEEL_DIGEST_MISMATCH",
        "SELF_CHECK_RUNTIME_DEPENDENCY_MISSING",
        "SELF_CHECK_SHADOW_IMPORT",
        "SELF_CHECK_SIGNED_MANIFEST_INVALID",
        "SELF_CHECK_SIGSTORE_INVALID",
        "SELF_CHECK_SIGNING_IDENTITY_MISMATCH",
        "SELF_CHECK_TSA_INVALID",
        "SELF_CHECK_TSA_MISSING",
        "SELF_CHECK_WHEEL_SUBJECT_MISSING",
    }
)
_SIGSTORE_TRUST_LOGGER = "sigstore._internal.trust"
_SIGSTORE_UNSUPPORTED_KEY_TYPE_7_WARNING = (
    "Failed to load a trusted root key: unsupported key type: 7"
)


class _SigstoreUnsupportedKeyType7Filter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return not (
            record.name == _SIGSTORE_TRUST_LOGGER
            and record.getMessage() == _SIGSTORE_UNSUPPORTED_KEY_TYPE_7_WARNING
        )


@contextmanager
def _suppress_sigstore_unsupported_key_type_7_warning():
    logger = logging.getLogger(_SIGSTORE_TRUST_LOGGER)
    warning_filter = _SigstoreUnsupportedKeyType7Filter()
    logger.addFilter(warning_filter)
    try:
        yield
    finally:
        logger.removeFilter(warning_filter)


@dataclass(frozen=True)
class SelfCheckError(Exception):
    code: str
    message: str
    remediation: str | None = None

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass
class SelfCheckStage:
    name: str
    ok: bool
    code: str | None = None
    message: str | None = None
    remediation: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self.name,
            "ok": self.ok,
            "code": self.code,
            "message": self.message,
        }
        if self.remediation is not None:
            payload["remediation"] = self.remediation
        if self.details:
            payload["details"] = self.details
        return payload


@dataclass
class SigstoreVerification:
    log_index: int | None = None
    log_id: str | None = None
    integrated_time: int | None = None


@dataclass
class RekorVerification:
    log_index: int
    checkpoint_present: bool


@dataclass
class TSAVerification:
    providers: list[str]
    message_imprint: str


@dataclass
class EmbeddedBindingVerification:
    artifact: str
    sha256: str


@dataclass
class PerFileDigestVerification:
    checked: int


@dataclass(frozen=True)
class ImportIsolationVerification:
    imported_path: Path
    checked: bool


@dataclass(frozen=True)
class InstalledDistributionInfo:
    version: str | None
    form: str | None
    location: str | None = None


@dataclass(frozen=True)
class PublishedWheelInfo:
    version: str
    source_url: str
    installed_version: str | None
    installed_form: str | None
    installed_location: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "version": self.version,
            "source_url": self.source_url,
            "installed_version": self.installed_version,
            "installed_form": self.installed_form,
        }
        if self.installed_location is not None:
            payload["installed_location"] = self.installed_location
        return payload


@dataclass(frozen=True)
class PublishedWheelResolution:
    version: str
    source_url: str
    sha256: str


@dataclass(frozen=True)
class PublishedWheelDownload:
    wheel_bytes: bytes
    sha256: str


@dataclass
class SelfCheckResult:
    form: str
    stages: list[SelfCheckStage]
    published_wheel_info: PublishedWheelInfo | None = None

    @property
    def ok(self) -> bool:
        return all(stage.ok for stage in self.stages)

    @property
    def summary(self) -> str:
        if self.published_wheel_info is not None:
            scope = f"published wheel v{self.published_wheel_info.version}"
            return (
                f"keel-verifier {scope} verified"
                if self.ok
                else f"keel-verifier {scope} verification failed"
            )
        if self.form == "published_wheel":
            return (
                "keel-verifier published wheel verification passed"
                if self.ok
                else "keel-verifier published wheel verification failed"
            )
        scope = f"installed {self.form} form"
        return (
            f"keel-verifier self-check passed for {scope}"
            if self.ok
            else f"keel-verifier self-check failed for {scope}"
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ok": self.ok,
            "form": self.form,
            "summary": self.summary,
            "stages": [stage.to_dict() for stage in self.stages],
        }
        if self.published_wheel_info is not None:
            payload["published_wheel_info"] = self.published_wheel_info.to_dict()
        return payload

    def format_human(self) -> str:
        status = "PASS" if self.ok else "FAILED"
        lines = [f"{status}: {self.summary}"]
        if self.published_wheel_info is not None:
            info = self.published_wheel_info
            lines.append(f"  Source: {info.source_url}")
            lines.append(
                "  Note: This verifies the PUBLISHED wheel. "
                "Your locally installed copy:"
            )
            if info.installed_version is None:
                lines.append("    not installed")
            else:
                form = info.installed_form or "unknown form"
                local = f"version {info.installed_version} ({form} install"
                if info.installed_location is not None:
                    local += f" at {info.installed_location}"
                local += ")"
                lines.append(f"    {local}")
        for stage in self.stages:
            marker = "OK" if stage.ok else "FAIL"
            if stage.ok:
                lines.append(f"  [{marker}] {stage.name}: {stage.message or 'verified'}")
            else:
                lines.append(
                    f"  [{marker}] {stage.name}: {stage.code}: {stage.message or 'failed'}"
                )
                if stage.remediation is not None:
                    lines.append("  To fix this:")
                    lines.extend(
                        f"    {line}" if line else "    "
                        for line in stage.remediation.splitlines()
                    )
        return "\n".join(lines)


def _json_object(raw: bytes | str, *, code: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SelfCheckError(code, f"{label} is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise SelfCheckError(code, f"{label} must be a JSON object")
    return value


def _canonical_json_bytes(payload: Any) -> bytes:
    try:
        import rfc8785
    except ImportError as exc:
        raise SelfCheckError(
            "SELF_CHECK_RUNTIME_DEPENDENCY_MISSING",
            "rfc8785 is required for embedded-manifest binding verification",
        ) from exc
    try:
        return rfc8785.dumps(payload)
    except Exception as exc:
        raise SelfCheckError(
            "SELF_CHECK_EMBEDDED_MANIFEST_INVALID",
            f"embedded manifest is not RFC 8785 JCS canonicalizable: {exc}",
        ) from exc


def _sha256_prefixed(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _url_basename(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return Path(urlparse(value).path).name


def validate_embedded_manifest(embedded_manifest: dict[str, Any]) -> None:
    forbidden = sorted(FORBIDDEN_EMBEDDED_FIELDS.intersection(embedded_manifest))
    if forbidden:
        raise SelfCheckError(
            "SELF_CHECK_FORBIDDEN_EMBEDDED_FIELD",
            "embedded manifest contains forbidden outer-manifest field(s): "
            + ", ".join(forbidden),
        )

    expected_url_basenames = {
        "release_manifest_url": "manifest.json",
        "release_manifest_signature_url": "manifest.json.sigstore",
        "release_manifest_tsa_witness_url": "manifest.json.tsa.json",
    }
    for field_name, expected_basename in expected_url_basenames.items():
        value = embedded_manifest.get(field_name)
        parsed = urlparse(value) if isinstance(value, str) else None
        if (
            parsed is None
            or parsed.scheme not in {"https", "http"}
            or _url_basename(value) != expected_basename
        ):
            raise SelfCheckError(
                "SELF_CHECK_EMBEDDED_MANIFEST_INVALID",
                f"{field_name} must point to {expected_basename}",
            )

    per_file_digests = embedded_manifest.get("per_file_digests")
    if not isinstance(per_file_digests, dict) or not per_file_digests:
        raise SelfCheckError(
            "SELF_CHECK_EMBEDDED_MANIFEST_INVALID",
            "embedded manifest must contain non-empty per_file_digests",
        )
    normalized_paths = {_normalize_manifest_path(path) for path in per_file_digests}
    if EMBEDDED_MANIFEST_PATH in normalized_paths:
        raise SelfCheckError(
            "SELF_CHECK_FORBIDDEN_EMBEDDED_FIELD",
            "embedded manifest per_file_digests must not contain _release_manifest.json",
        )


def _validate_published_wheel_version(version: str) -> str:
    normalized = version.strip()
    if not normalized or not PEP440_VERSION_RE.fullmatch(normalized):
        raise SelfCheckError(
            "SELF_CHECK_FETCH_FAILED",
            f"--published-wheel version is not a valid PEP 440 version: {version}",
        )
    if normalized[0].lower() == "v":
        normalized = normalized[1:]
    return normalized.lower()


def _direct_url_location(direct_url_payload: dict[str, Any]) -> str | None:
    url = direct_url_payload.get("url")
    if not isinstance(url, str) or not url:
        return None
    parsed = urlparse(url)
    if parsed.scheme == "file":
        return unquote(parsed.path)
    return url


def inspect_installed_distribution() -> InstalledDistributionInfo:
    try:
        dist = importlib.metadata.distribution(DIST_NAME)
    except importlib.metadata.PackageNotFoundError:
        return InstalledDistributionInfo(version=None, form=None)

    form: str | None = None
    location: str | None = None
    direct_url = dist.read_text("direct_url.json")
    if direct_url:
        try:
            direct_url_payload = json.loads(direct_url)
        except json.JSONDecodeError:
            direct_url_payload = {}
        if (
            isinstance(direct_url_payload, dict)
            and direct_url_payload.get("dir_info", {}).get("editable") is True
        ):
            form = "editable"
            location = _direct_url_location(direct_url_payload)

    if form is None:
        form = "wheel" if dist.read_text("WHEEL") is not None else "sdist"

    return InstalledDistributionInfo(
        version=dist.version,
        form=form,
        location=location if form == "editable" else None,
    )


def detect_form() -> str:
    diagnostic = inspect_install_form(
        distribution_getter=importlib.metadata.distribution,
    )
    if diagnostic.form == "wheel":
        return "wheel"
    if diagnostic.form == "missing":
        raise SelfCheckError(
            "SELF_CHECK_FORM_UNSUPPORTED",
            diagnostic.message,
            diagnostic.remediation,
        )
    if diagnostic.form == "editable":
        raise SelfCheckError(
            "SELF_CHECK_FORM_UNSUPPORTED",
            diagnostic.message,
            diagnostic.remediation,
        )

    raise SelfCheckError(
        "SELF_CHECK_FORM_UNSUPPORTED",
        diagnostic.message,
        diagnostic.remediation,
    )


def verify_import_isolation() -> ImportIsolationVerification:
    diagnostic = inspect_import_isolation(
        distribution_getter=importlib.metadata.distribution,
    )
    if diagnostic.aligned is False:
        raise SelfCheckError(
            str(diagnostic.code),
            diagnostic.message,
            diagnostic.remediation,
        )
    if diagnostic.imported_path is None:
        raise SelfCheckError(
            "SELF_CHECK_SHADOW_IMPORT",
            "keel_verifier is importable but does not expose __file__",
            SHADOW_IMPORT_REMEDIATION,
        )
    return ImportIsolationVerification(
        imported_path=diagnostic.imported_path,
        checked=diagnostic.checked,
    )


def load_embedded_manifest(
    form: str,
    base_path: Path | None = None,
) -> dict[str, Any]:
    if form != "wheel":
        raise SelfCheckError(
            "SELF_CHECK_FORM_UNSUPPORTED",
            f"unsupported self-check form: {form}",
        )
    if base_path is None:
        try:
            manifest_ref = importlib.resources.files(PACKAGE_NAME).joinpath(
                "_release_manifest.json"
            )
            raw = manifest_ref.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise SelfCheckError(
                "SELF_CHECK_EMBEDDED_MANIFEST_NOT_FOUND",
                "wheel does not contain keel_verifier/_release_manifest.json",
            ) from exc
        except ModuleNotFoundError as exc:
            raise SelfCheckError(
                "SELF_CHECK_FORM_UNSUPPORTED",
                "keel_verifier package is not importable",
            ) from exc
    else:
        manifest_path = base_path / PACKAGE_NAME / "_release_manifest.json"
        try:
            raw = manifest_path.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise SelfCheckError(
                "SELF_CHECK_EMBEDDED_MANIFEST_NOT_FOUND",
                "published wheel does not contain keel_verifier/_release_manifest.json",
            ) from exc

    manifest = _json_object(
        raw,
        code="SELF_CHECK_EMBEDDED_MANIFEST_INVALID",
        label="embedded release manifest",
    )
    validate_embedded_manifest(manifest)
    return manifest


def _release_entries_for_version(
    pypi_payload: dict[str, Any],
    version: str,
) -> list[dict[str, Any]]:
    releases = pypi_payload.get("releases")
    if isinstance(releases, dict):
        release_entries = releases.get(version)
        if isinstance(release_entries, list):
            return [entry for entry in release_entries if isinstance(entry, dict)]

        for release_version, entries in releases.items():
            if not isinstance(release_version, str) or not isinstance(entries, list):
                continue
            try:
                normalized_release_version = _validate_published_wheel_version(
                    release_version
                )
            except SelfCheckError:
                continue
            if normalized_release_version == version:
                return [entry for entry in entries if isinstance(entry, dict)]

    info = pypi_payload.get("info")
    latest_version = info.get("version") if isinstance(info, dict) else None
    urls = pypi_payload.get("urls")
    if latest_version == version and isinstance(urls, list):
        return [entry for entry in urls if isinstance(entry, dict)]
    return []


def resolve_published_wheel(
    requested_version: str,
    *,
    offline: bool,
    cache_dir: Path,
    no_cache: bool,
) -> PublishedWheelResolution:
    pinned_version = (
        _validate_published_wheel_version(requested_version)
        if requested_version
        else None
    )
    metadata_bytes = _fetch_url(
        PYPI_METADATA_URL,
        offline=offline,
        cache_dir=cache_dir / "pypi",
        no_cache=no_cache,
        label="PyPI metadata for keel-verifier",
    )
    pypi_payload = _json_object(
        metadata_bytes,
        code="SELF_CHECK_FETCH_FAILED",
        label="PyPI metadata for keel-verifier",
    )

    if pinned_version is not None:
        version = pinned_version
    else:
        info = pypi_payload.get("info")
        latest_version = info.get("version") if isinstance(info, dict) else None
        if not isinstance(latest_version, str) or not latest_version:
            raise SelfCheckError(
                "SELF_CHECK_FETCH_FAILED",
                "PyPI metadata does not contain info.version",
            )
        version = _validate_published_wheel_version(latest_version)

    wheel_entries = [
        entry
        for entry in _release_entries_for_version(pypi_payload, version)
        if entry.get("packagetype") == "bdist_wheel"
    ]
    if not wheel_entries:
        raise SelfCheckError(
            "SELF_CHECK_FETCH_FAILED",
            f"PyPI metadata has no wheel file for keel-verifier {version}",
        )

    wheel_entry = wheel_entries[0]
    source_url = wheel_entry.get("url")
    digests = wheel_entry.get("digests")
    digest = digests.get("sha256") if isinstance(digests, dict) else None
    if not isinstance(source_url, str) or not source_url:
        raise SelfCheckError(
            "SELF_CHECK_FETCH_FAILED",
            f"PyPI wheel metadata for keel-verifier {version} has no URL",
        )
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(char not in "0123456789abcdefABCDEF" for char in digest)
    ):
        raise SelfCheckError(
            "SELF_CHECK_FETCH_FAILED",
            f"PyPI wheel metadata for keel-verifier {version} has no SHA-256 digest",
        )
    return PublishedWheelResolution(
        version=version,
        source_url=source_url,
        sha256=digest.lower(),
    )


def download_published_wheel(
    resolution: PublishedWheelResolution,
    *,
    offline: bool,
    cache_dir: Path,
    no_cache: bool,
) -> PublishedWheelDownload:
    wheel_bytes = _fetch_url(
        resolution.source_url,
        offline=offline,
        cache_dir=cache_dir / "published-wheels",
        no_cache=no_cache,
        label=f"published keel-verifier wheel {resolution.version}",
    )
    actual = hashlib.sha256(wheel_bytes).hexdigest()
    if actual != resolution.sha256:
        raise SelfCheckError(
            "SELF_CHECK_PUBLISHED_WHEEL_DIGEST_MISMATCH",
            (
                "downloaded wheel SHA-256 does not match PyPI metadata: "
                f"expected {resolution.sha256}, got {actual}"
            ),
            (
                "Check PyPI status: https://status.python.org/\n"
                "Then retry without cached bytes: "
                "keel-verify self-check --published-wheel"
                f"={resolution.version} --no-cache"
            ),
        )
    return PublishedWheelDownload(wheel_bytes=wheel_bytes, sha256=actual)


def extract_wheel_to_base_path(wheel_bytes: bytes, base_path: Path) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as wheel:
            resolved_base = base_path.resolve()
            for member in wheel.infolist():
                target = (base_path / member.filename).resolve()
                if target != resolved_base and resolved_base not in target.parents:
                    raise SelfCheckError(
                        "SELF_CHECK_FETCH_FAILED",
                        f"wheel contains unsafe archive path: {member.filename}",
                    )
            wheel.extractall(base_path)
    except zipfile.BadZipFile as exc:
        raise SelfCheckError(
            "SELF_CHECK_FETCH_FAILED",
            "downloaded wheel is not a valid ZIP archive",
        ) from exc


def _cache_paths(cache_dir: Path, url: str) -> tuple[Path, Path]:
    key = hashlib.sha256(url.encode("utf-8")).hexdigest()
    return cache_dir / f"{key}.bin", cache_dir / f"{key}.json"


def _cache_is_fresh(path: Path) -> bool:
    try:
        age = time.time() - path.stat().st_mtime
    except FileNotFoundError:
        return False
    return age <= CACHE_SECONDS


def _read_cache(cache_path: Path) -> bytes | None:
    try:
        return cache_path.read_bytes()
    except FileNotFoundError:
        return None


def _write_cache(cache_path: Path, metadata_path: Path, url: str, payload: bytes) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_bytes(payload)
    metadata_path.write_text(
        json.dumps({"url": url, "cached_at": int(time.time())}, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _fetch_url(
    url: str,
    *,
    offline: bool,
    cache_dir: Path,
    no_cache: bool,
    label: str,
) -> bytes:
    if no_cache:
        if offline:
            raise SelfCheckError(
                "SELF_CHECK_FETCH_FAILED",
                f"cannot fetch {label}: --offline and --no-cache were both supplied",
            )
        cache_path = metadata_path = None
    else:
        cache_path, metadata_path = _cache_paths(cache_dir, url)
        if _cache_is_fresh(cache_path):
            cached = _read_cache(cache_path)
            if cached is not None:
                return cached
        if offline:
            cached = _read_cache(cache_path)
            if cached is not None:
                return cached
            raise SelfCheckError(
                "SELF_CHECK_FETCH_FAILED",
                f"offline mode requested but no cached {label} is available",
            )

    try:
        with urllib.request.urlopen(url, timeout=20) as response:
            payload = response.read()
    except (OSError, urllib.error.URLError) as exc:
        if not no_cache and cache_path is not None:
            cached = _read_cache(cache_path)
            if cached is not None:
                return cached
        raise SelfCheckError(
            "SELF_CHECK_FETCH_FAILED",
            f"failed to fetch {label} and no cache is available: {exc}",
        ) from exc

    if not no_cache and cache_path is not None and metadata_path is not None:
        _write_cache(cache_path, metadata_path, url, payload)
    return payload


def fetch_signed_manifest(
    url: str,
    *,
    offline: bool,
    cache_dir: Path,
    no_cache: bool = False,
) -> bytes:
    return _fetch_url(
        url,
        offline=offline,
        cache_dir=cache_dir,
        no_cache=no_cache,
        label="signed release manifest",
    )


def verify_sigstore(
    signed_manifest_bytes: bytes,
    signature: bytes,
    expected_identity: str,
    *,
    offline: bool = False,
) -> SigstoreVerification:
    """Verify the signed release manifest with sigstore-python.

    sigstore-python 3.6.7 can warn while skipping Sigstore's Rekor 2025
    Ed25519 trusted-root key. The v2.4.2 release bundle verifies against the
    existing Rekor v1 key, so the skipped key is not load-bearing for this
    check. Keep the suppression scoped to that exact library warning.
    """
    try:
        from sigstore.errors import VerificationError
        from sigstore.models import Bundle
        from sigstore.verify import Verifier
        from sigstore.verify.policy import Identity
    except ImportError as exc:
        raise SelfCheckError(
            "SELF_CHECK_RUNTIME_DEPENDENCY_MISSING",
            "sigstore-python is required for self-check",
        ) from exc

    try:
        bundle = Bundle.from_json(signature)
        with _suppress_sigstore_unsupported_key_type_7_warning():
            verifier = Verifier.production(offline=offline)
            verifier.verify_artifact(
                signed_manifest_bytes,
                bundle,
                Identity(
                    identity=expected_identity,
                    issuer=GITHUB_ACTIONS_OIDC_ISSUER,
                ),
            )
    except VerificationError as exc:
        message = str(exc)
        code = (
            "SELF_CHECK_SIGNING_IDENTITY_MISMATCH"
            if "SANs do not match" in message or "OIDCIssuer" in message
            else "SELF_CHECK_SIGSTORE_INVALID"
        )
        raise SelfCheckError(code, message) from exc
    except Exception as exc:
        raise SelfCheckError("SELF_CHECK_SIGSTORE_INVALID", str(exc)) from exc

    return SigstoreVerification(
        log_index=getattr(bundle.log_entry, "log_index", None),
        log_id=getattr(bundle.log_entry, "log_id", None),
        integrated_time=getattr(bundle.log_entry, "integrated_time", None),
    )


def verify_rekor(signed_manifest_bytes: bytes, signature: bytes) -> RekorVerification:
    del signed_manifest_bytes
    try:
        from sigstore.models import Bundle
    except ImportError as exc:
        raise SelfCheckError(
            "SELF_CHECK_RUNTIME_DEPENDENCY_MISSING",
            "sigstore-python is required for Rekor verification",
        ) from exc

    try:
        bundle = Bundle.from_json(signature)
        proof = bundle.log_entry.inclusion_proof
        checkpoint = getattr(proof, "checkpoint", None)
        log_index = int(bundle.log_entry.log_index)
    except Exception as exc:
        raise SelfCheckError("SELF_CHECK_REKOR_INVALID", str(exc)) from exc
    if not checkpoint:
        raise SelfCheckError(
            "SELF_CHECK_REKOR_INVALID",
            "Sigstore bundle does not contain a Rekor inclusion checkpoint",
        )
    return RekorVerification(log_index=log_index, checkpoint_present=True)


TSA_GRANTED_STATUSES = {"granted", "granted_with_mods"}


def _decode_tsa_response(receipt_der: bytes) -> Any:
    """BER-tolerant decode of an RFC 3161 TimeStampResp.

    Uses asn1crypto rather than a strict-DER parser. Real-world commercial TSAs
    (DigiCert, GlobalSign) frequently return BER-encoded responses; a strict
    parser rejects them on canonical SET ordering even though the receipts are
    RFC 3161-compliant.
    """
    try:
        from asn1crypto import tsp
    except ImportError as exc:
        raise SelfCheckError(
            "SELF_CHECK_RUNTIME_DEPENDENCY_MISSING",
            "asn1crypto is required for TSA receipt parsing",
        ) from exc
    try:
        # strict=True rejects trailing bytes after the TimeStampResp structure;
        # without it, an attacker who controls the sidecar storage could append
        # arbitrary data, update receipt_hash, and pass verification.
        parsed = tsp.TimeStampResp.load(receipt_der, strict=True)
        # asn1crypto parses children lazily; force eager validation so a
        # missing required field (e.g. time_stamp_token) is surfaced here
        # rather than at a later field access in verify_tsa.
        parsed._parse_children(recurse=True)
        return parsed
    except Exception as exc:
        raise SelfCheckError(
            "SELF_CHECK_TSA_INVALID",
            f"TSA receipt is not a valid TimeStampResp: {exc}",
        ) from exc


def _extract_tst_info(ts_resp: Any) -> Any:
    """Pull TSTInfo out of the SignedData inside the TimeStampToken."""
    from asn1crypto import core

    token = ts_resp["time_stamp_token"]
    if isinstance(token, core.Void) or token.native is None:
        raise SelfCheckError(
            "SELF_CHECK_TSA_INVALID",
            "TimeStampResp does not contain a TimeStampToken",
        )
    encap = token["content"]["encap_content_info"]
    content_type = encap["content_type"].native
    if content_type != "tst_info":
        raise SelfCheckError(
            "SELF_CHECK_TSA_INVALID",
            f"unexpected encap content type: {content_type}",
        )
    return encap["content"].parsed


def verify_tsa(signed_manifest_bytes: bytes, sidecar: dict[str, Any]) -> TSAVerification:
    """Bind-level TSA verification: parse + GRANTED + message_imprint match.

    Intentionally does NOT perform CMS signature verification or
    certificate-chain validation. The honest claim at this layer is bounded: a
    provider-labeled RFC 3161 response structure binds to the signed manifest
    hash and reports `granted` status. Deeper assertions about signer
    authenticity, timestamping EKU, chain validity, and release-pinned CRL
    status are reported by checkpoint TSA chain validation, not this self-check.
    """
    message_imprint = _sha256_prefixed(signed_manifest_bytes)
    if sidecar.get("message_imprint") != message_imprint:
        raise SelfCheckError(
            "SELF_CHECK_TSA_INVALID",
            "TSA sidecar message_imprint does not match manifest bytes",
        )
    if sidecar.get("receipt_format") != "rfc3161-timestamp-response-der":
        raise SelfCheckError(
            "SELF_CHECK_TSA_INVALID",
            "TSA sidecar receipt_format must be rfc3161-timestamp-response-der",
        )

    receipts = sidecar.get("receipts")
    if not isinstance(receipts, list):
        raise SelfCheckError("SELF_CHECK_TSA_MISSING", "TSA sidecar receipts must be a list")
    providers = {
        receipt.get("provider")
        for receipt in receipts
        if isinstance(receipt, dict) and isinstance(receipt.get("provider"), str)
    }
    missing = sorted(REQUIRED_TSA_PROVIDERS.difference(providers))
    if missing:
        raise SelfCheckError(
            "SELF_CHECK_TSA_MISSING",
            "TSA sidecar is missing required provider receipt(s): " + ", ".join(missing),
        )

    expected_imprint_bytes = hashlib.sha256(signed_manifest_bytes).digest()
    verified_providers: list[str] = []
    for receipt in receipts:
        if not isinstance(receipt, dict):
            raise SelfCheckError("SELF_CHECK_TSA_INVALID", "TSA receipt must be an object")
        provider = receipt.get("provider")
        if provider not in REQUIRED_TSA_PROVIDERS:
            continue
        receipt_b64 = receipt.get("receipt_b64")
        receipt_hash = receipt.get("receipt_hash")
        if not isinstance(receipt_b64, str) or not isinstance(receipt_hash, str):
            raise SelfCheckError(
                "SELF_CHECK_TSA_INVALID",
                f"TSA receipt for {provider} is missing receipt_b64 or receipt_hash",
            )
        try:
            receipt_der = base64.b64decode(receipt_b64, validate=True)
        except Exception as exc:
            raise SelfCheckError(
                "SELF_CHECK_TSA_INVALID",
                f"TSA receipt for {provider} is not valid base64: {exc}",
            ) from exc
        actual_hash = _sha256_prefixed(receipt_der)
        if actual_hash != receipt_hash:
            raise SelfCheckError(
                "SELF_CHECK_TSA_INVALID",
                f"TSA receipt_hash mismatch for {provider}",
            )

        ts_resp = _decode_tsa_response(receipt_der)
        status = ts_resp["status"]["status"].native
        if status not in TSA_GRANTED_STATUSES:
            raise SelfCheckError(
                "SELF_CHECK_TSA_INVALID",
                f"TSA receipt for {provider} has non-granted status: {status}",
            )

        tst_info = _extract_tst_info(ts_resp)
        algo = tst_info["message_imprint"]["hash_algorithm"]["algorithm"].native
        if algo != "sha256":
            raise SelfCheckError(
                "SELF_CHECK_TSA_INVALID",
                f"TSA receipt for {provider} used unexpected hash algorithm: {algo}",
            )
        receipt_imprint = tst_info["message_imprint"]["hashed_message"].native
        if receipt_imprint != expected_imprint_bytes:
            raise SelfCheckError(
                "SELF_CHECK_TSA_INVALID",
                f"TSA receipt for {provider} does not witness the signed manifest hash",
            )

        verified_providers.append(provider)

    if set(verified_providers) != REQUIRED_TSA_PROVIDERS:
        missing_verified = sorted(REQUIRED_TSA_PROVIDERS.difference(verified_providers))
        raise SelfCheckError(
            "SELF_CHECK_TSA_INVALID",
            "required TSA provider receipt(s) did not verify: "
            + ", ".join(missing_verified),
        )
    return TSAVerification(providers=sorted(verified_providers), message_imprint=message_imprint)


def verify_embedded_manifest_binding(
    signed_manifest: dict[str, Any],
    embedded_manifest: dict[str, Any],
) -> EmbeddedBindingVerification:
    artifacts = signed_manifest.get("artifacts")
    if not isinstance(artifacts, list) or not any(
        isinstance(artifact, dict)
        and isinstance(artifact.get("filename"), str)
        and artifact["filename"].endswith(".whl")
        and isinstance(artifact.get("sha256"), str)
        for artifact in artifacts
    ):
        raise SelfCheckError(
            "SELF_CHECK_WHEEL_SUBJECT_MISSING",
            "signed release manifest does not keep the wheel artifact as a primary subject",
        )

    entries = signed_manifest.get("embedded_manifests")
    if not isinstance(entries, list):
        raise SelfCheckError(
            "SELF_CHECK_EMBEDDED_BINDING_MISSING",
            "signed release manifest has no embedded_manifests array",
        )
    wheel_entries = [
        entry
        for entry in entries
        if isinstance(entry, dict)
        and entry.get("artifact") == "wheel"
        and entry.get("path") == EMBEDDED_MANIFEST_PATH
    ]
    if len(wheel_entries) != 1:
        raise SelfCheckError(
            "SELF_CHECK_EMBEDDED_BINDING_MISSING",
            "signed release manifest must contain exactly one wheel embedded manifest binding",
        )
    entry = wheel_entries[0]
    if entry.get("media_type") != "application/json":
        raise SelfCheckError(
            "SELF_CHECK_EMBEDDED_BINDING_MISMATCH",
            "embedded manifest binding media_type must be application/json",
        )
    if entry.get("canonicalization") != EMBEDDED_CANONICALIZATION:
        raise SelfCheckError(
            "SELF_CHECK_EMBEDDED_BINDING_MISMATCH",
            "embedded manifest binding canonicalization must be rfc8785-jcs",
        )
    expected_hash = _sha256_prefixed(_canonical_json_bytes(embedded_manifest))
    if entry.get("sha256") != expected_hash:
        raise SelfCheckError(
            "SELF_CHECK_EMBEDDED_BINDING_MISMATCH",
            "embedded manifest JCS hash does not match signed release manifest binding",
        )
    return EmbeddedBindingVerification(artifact="wheel", sha256=expected_hash)


def _normalize_manifest_path(raw_path: Any) -> str:
    if not isinstance(raw_path, str) or not raw_path:
        raise SelfCheckError(
            "SELF_CHECK_EMBEDDED_MANIFEST_INVALID",
            "per_file_digests paths must be non-empty strings",
        )
    normalized = raw_path.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise SelfCheckError(
            "SELF_CHECK_EMBEDDED_MANIFEST_INVALID",
            f"unsafe per_file_digests path: {raw_path}",
        )
    return path.as_posix()


def _installed_file_path(manifest_path: str, base_path: Path | None = None) -> Path:
    normalized = _normalize_manifest_path(manifest_path)
    posix_path = PurePosixPath(normalized)
    if not posix_path.parts or posix_path.parts[0] != PACKAGE_NAME:
        raise SelfCheckError(
            "SELF_CHECK_EMBEDDED_MANIFEST_INVALID",
            f"per_file_digests path is outside {PACKAGE_NAME}: {manifest_path}",
        )
    if base_path is not None:
        return base_path.joinpath(*posix_path.parts)
    package_root = Path(str(importlib.resources.files(PACKAGE_NAME)))
    return package_root.parent.joinpath(*posix_path.parts)


def verify_per_file_digests(
    embedded_manifest: dict[str, Any],
    base_path: Path | None = None,
) -> PerFileDigestVerification:
    per_file_digests = embedded_manifest.get("per_file_digests")
    if not isinstance(per_file_digests, dict) or not per_file_digests:
        raise SelfCheckError(
            "SELF_CHECK_EMBEDDED_MANIFEST_INVALID",
            "embedded manifest must contain per_file_digests",
        )

    checked = 0
    for manifest_path, expected in per_file_digests.items():
        normalized_path = _normalize_manifest_path(manifest_path)
        if normalized_path == EMBEDDED_MANIFEST_PATH:
            raise SelfCheckError(
                "SELF_CHECK_FORBIDDEN_EMBEDDED_FIELD",
                "per_file_digests must not include _release_manifest.json",
            )
        if not isinstance(expected, str):
            raise SelfCheckError(
                "SELF_CHECK_EMBEDDED_MANIFEST_INVALID",
                f"digest for {manifest_path} must be a string",
            )
        expected_hex = expected.removeprefix("sha256:")
        installed_path = _installed_file_path(normalized_path, base_path=base_path)
        try:
            payload = installed_path.read_bytes()
        except FileNotFoundError as exc:
            scope = "published wheel" if base_path is not None else "installed"
            raise SelfCheckError(
                "SELF_CHECK_FILE_MISSING",
                f"{scope} file listed in embedded manifest is missing: {normalized_path}",
            ) from exc
        actual_hex = hashlib.sha256(payload).hexdigest()
        if actual_hex != expected_hex:
            scope = "published wheel" if base_path is not None else "installed"
            raise SelfCheckError(
                "SELF_CHECK_FILE_DIGEST_MISMATCH",
                f"{scope} file digest mismatch: {normalized_path}",
            )
        checked += 1
    return PerFileDigestVerification(checked=checked)


def _stage_ok(name: str, message: str, **details: Any) -> SelfCheckStage:
    return SelfCheckStage(name=name, ok=True, message=message, details=details)


def _stage_fail(name: str, exc: SelfCheckError) -> SelfCheckStage:
    return SelfCheckStage(
        name=name,
        ok=False,
        code=exc.code,
        message=exc.message,
        remediation=exc.remediation,
    )


def _result_form(
    form: str,
    published_wheel_info: PublishedWheelInfo | None,
) -> str:
    return "published_wheel" if published_wheel_info is not None else form


def _self_check_result(
    *,
    form: str,
    stages: list[SelfCheckStage],
    published_wheel_info: PublishedWheelInfo | None = None,
) -> SelfCheckResult:
    return SelfCheckResult(
        form=_result_form(form, published_wheel_info),
        stages=stages,
        published_wheel_info=published_wheel_info,
    )


def _load_embedded_manifest_for_base(
    form: str,
    base_path: Path | None,
) -> dict[str, Any]:
    if base_path is None:
        return load_embedded_manifest(form)
    return load_embedded_manifest(form, base_path=base_path)


def _verify_per_file_digests_for_base(
    embedded_manifest: dict[str, Any],
    base_path: Path | None,
) -> PerFileDigestVerification:
    if base_path is None:
        return verify_per_file_digests(embedded_manifest)
    return verify_per_file_digests(embedded_manifest, base_path=base_path)


def _run_self_check_chain(
    *,
    form: str,
    stages: list[SelfCheckStage],
    cache_dir: Path,
    offline: bool,
    no_cache: bool,
    base_path: Path | None = None,
    published_wheel_info: PublishedWheelInfo | None = None,
) -> SelfCheckResult:
    try:
        embedded_manifest = _load_embedded_manifest_for_base(form, base_path)
        stages.append(
            _stage_ok(
                "embedded_manifest",
                "embedded release manifest is present and cycle-safe",
            )
        )
    except SelfCheckError as exc:
        stages.append(_stage_fail("embedded_manifest", exc))
        return _self_check_result(
            form=form,
            stages=stages,
            published_wheel_info=published_wheel_info,
        )

    try:
        signed_manifest_bytes = fetch_signed_manifest(
            embedded_manifest["release_manifest_url"],
            offline=offline,
            cache_dir=cache_dir,
            no_cache=no_cache,
        )
        signature = _fetch_url(
            embedded_manifest["release_manifest_signature_url"],
            offline=offline,
            cache_dir=cache_dir,
            no_cache=no_cache,
            label="release manifest Sigstore bundle",
        )
        tsa_sidecar_bytes = _fetch_url(
            embedded_manifest["release_manifest_tsa_witness_url"],
            offline=offline,
            cache_dir=cache_dir,
            no_cache=no_cache,
            label="release manifest TSA witness sidecar",
        )
        stages.append(_stage_ok("fetch", "release manifest, signature, and TSA sidecar loaded"))
    except SelfCheckError as exc:
        stages.append(_stage_fail("fetch", exc))
        return _self_check_result(
            form=form,
            stages=stages,
            published_wheel_info=published_wheel_info,
        )

    try:
        sigstore_result = verify_sigstore(
            signed_manifest_bytes,
            signature,
            str(embedded_manifest["expected_signing_identity"]),
            offline=offline,
        )
        stages.append(
            _stage_ok(
                "sigstore_signature",
                "signed release manifest verifies against expected GitHub Actions identity",
                log_index=sigstore_result.log_index,
            )
        )
    except SelfCheckError as exc:
        stages.append(_stage_fail("sigstore_signature", exc))
        return _self_check_result(
            form=form,
            stages=stages,
            published_wheel_info=published_wheel_info,
        )

    try:
        rekor_result = verify_rekor(signed_manifest_bytes, signature)
        stages.append(
            _stage_ok(
                "rekor_inclusion",
                "Rekor inclusion proof is present and verified by sigstore-python",
                log_index=rekor_result.log_index,
            )
        )
    except SelfCheckError as exc:
        stages.append(_stage_fail("rekor_inclusion", exc))
        return _self_check_result(
            form=form,
            stages=stages,
            published_wheel_info=published_wheel_info,
        )

    try:
        tsa_sidecar = _json_object(
            tsa_sidecar_bytes,
            code="SELF_CHECK_TSA_INVALID",
            label="TSA sidecar",
        )
        tsa_result = verify_tsa(signed_manifest_bytes, tsa_sidecar)
        stages.append(
            _stage_ok(
                "tsa_witnesses",
                "DigiCert and GlobalSign RFC 3161 receipts witness the manifest hash "
                "(bind-level; cert-chain validation is opt-in)",
                providers=tsa_result.providers,
                message_imprint=tsa_result.message_imprint,
            )
        )
    except SelfCheckError as exc:
        stages.append(_stage_fail("tsa_witnesses", exc))
        return _self_check_result(
            form=form,
            stages=stages,
            published_wheel_info=published_wheel_info,
        )

    try:
        signed_manifest = _json_object(
            signed_manifest_bytes,
            code="SELF_CHECK_SIGNED_MANIFEST_INVALID",
            label="signed release manifest",
        )
        binding_result = verify_embedded_manifest_binding(
            signed_manifest,
            embedded_manifest,
        )
        stages.append(
            _stage_ok(
                "embedded_binding",
                "embedded manifest JCS hash matches signed release manifest binding",
                sha256=binding_result.sha256,
            )
        )
    except SelfCheckError as exc:
        stages.append(_stage_fail("embedded_binding", exc))
        return _self_check_result(
            form=form,
            stages=stages,
            published_wheel_info=published_wheel_info,
        )

    try:
        per_file_result = _verify_per_file_digests_for_base(embedded_manifest, base_path)
        per_file_message = (
            "published wheel files match embedded per-file digests"
            if base_path is not None
            else "installed wheel files match embedded per-file digests"
        )
        stages.append(
            _stage_ok(
                "per_file_digests",
                per_file_message,
                checked=per_file_result.checked,
            )
        )
    except SelfCheckError as exc:
        stages.append(_stage_fail("per_file_digests", exc))

    return _self_check_result(
        form=form,
        stages=stages,
        published_wheel_info=published_wheel_info,
    )


def _run_published_wheel_self_check(
    *,
    requested_version: str,
    stages: list[SelfCheckStage],
    cache_dir: Path,
    offline: bool,
    no_cache: bool,
) -> SelfCheckResult:
    installed_info = inspect_installed_distribution()
    published_wheel_info: PublishedWheelInfo | None = None
    try:
        resolution = resolve_published_wheel(
            requested_version,
            offline=offline,
            cache_dir=cache_dir,
            no_cache=no_cache,
        )
        published_wheel_info = PublishedWheelInfo(
            version=resolution.version,
            source_url=resolution.source_url,
            installed_version=installed_info.version,
            installed_form=installed_info.form,
            installed_location=installed_info.location,
        )
        stages.append(
            _stage_ok(
                "published_wheel_resolve",
                f"PyPI metadata resolved to keel-verifier {resolution.version}",
                version=resolution.version,
                source_url=resolution.source_url,
                sha256=resolution.sha256,
            )
        )
    except SelfCheckError as exc:
        stages.append(_stage_fail("published_wheel_resolve", exc))
        return _self_check_result(
            form="published_wheel",
            stages=stages,
            published_wheel_info=published_wheel_info,
        )

    with tempfile.TemporaryDirectory(prefix="keel-verify-pubwheel-") as tempdir:
        base_path = Path(tempdir)
        try:
            download = download_published_wheel(
                resolution,
                offline=offline,
                cache_dir=cache_dir,
                no_cache=no_cache,
            )
            extract_wheel_to_base_path(download.wheel_bytes, base_path)
            stages.append(
                _stage_ok(
                    "published_wheel_download",
                    f"wheel downloaded + SHA-256 verified ({download.sha256})",
                    sha256=download.sha256,
                )
            )
        except SelfCheckError as exc:
            stages.append(_stage_fail("published_wheel_download", exc))
            return _self_check_result(
                form="published_wheel",
                stages=stages,
                published_wheel_info=published_wheel_info,
            )

        return _run_self_check_chain(
            form="wheel",
            stages=stages,
            cache_dir=cache_dir,
            offline=offline,
            no_cache=no_cache,
            base_path=base_path,
            published_wheel_info=published_wheel_info,
        )


def run_self_check(args: Any) -> SelfCheckResult:
    stages: list[SelfCheckStage] = []
    requested_form = getattr(args, "form", "auto")
    cache_dir = Path(getattr(args, "cache_dir", None) or DEFAULT_CACHE_DIR).expanduser()
    offline = bool(getattr(args, "offline", False))
    no_cache = bool(getattr(args, "no_cache", False))
    published_wheel = getattr(args, "published_wheel", None)

    if published_wheel is not None:
        return _run_published_wheel_self_check(
            requested_version=str(published_wheel),
            stages=stages,
            cache_dir=cache_dir,
            offline=offline,
            no_cache=no_cache,
        )

    try:
        form = detect_form() if requested_form == "auto" else requested_form
        if form != "wheel":
            raise SelfCheckError(
                "SELF_CHECK_FORM_UNSUPPORTED",
                f"unsupported self-check form: {form}",
            )
        stages.append(_stage_ok("form", "wheel form selected", form=form))
    except SelfCheckError as exc:
        stages.append(_stage_fail("form", exc))
        return SelfCheckResult(form=str(requested_form), stages=stages)

    try:
        import_isolation = verify_import_isolation()
        if import_isolation.checked:
            import_isolation_message = (
                f"keel_verifier imported from {import_isolation.imported_path} "
                "matches distribution metadata"
            )
        else:
            import_isolation_message = (
                f"keel_verifier imported from {import_isolation.imported_path}; "
                "distribution file metadata unavailable, shadow-import check skipped"
            )
        stages.append(
            _stage_ok(
                "import_isolation",
                import_isolation_message,
            )
        )
    except SelfCheckError as exc:
        stages.append(_stage_fail("import_isolation", exc))
        return SelfCheckResult(form=form, stages=stages)

    return _run_self_check_chain(
        form=form,
        stages=stages,
        cache_dir=cache_dir,
        offline=offline,
        no_cache=no_cache,
    )
