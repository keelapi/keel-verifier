"""Safe inventory verification for downloadable ``.keelpermit`` packages.

The package manifest is never a trust root.  This module proves only that the
ZIP inventory matches the manifest and returns the signed evidence bytes for
normal verifier adjudication.  The caller must verify those bytes and
regenerate the human view from the resulting report.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from importlib import resources
import json
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any
import zipfile

import jsonschema


MANIFEST_PATH = "manifest.json"
MAX_FILES = 128
MAX_ENTRY_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_COMPRESSION_RATIO = 200
_SAFE_PATH = re.compile(r"[A-Za-z0-9._/-]+")


@dataclass(frozen=True)
class VerifiedPermitPackage:
    manifest: dict[str, Any]
    signed_evidence: bytes
    primary_view: bytes
    primary_view_media_type: str


def _schema() -> dict[str, Any]:
    resource = resources.files("keel_verifier").joinpath(
        "data/permit_to_x/schemas/permit-package-manifest-v1.schema.json"
    )
    value = json.loads(resource.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Permit package manifest schema must be an object")
    return value


def _safe_path(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(
        value
        and not value.startswith("/")
        and "\\" not in value
        and _SAFE_PATH.fullmatch(value) is not None
        and not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def _digest(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _entry_by_path(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        raise ValueError("Permit package entries are missing")
    by_path: dict[str, dict[str, Any]] = {}
    for raw_entry in entries:
        if not isinstance(raw_entry, dict):
            raise ValueError("Permit package entry must be an object")
        path = str(raw_entry.get("path") or "")
        if path in by_path:
            raise ValueError(f"Permit package repeats inventory path: {path}")
        by_path[path] = raw_entry
    return by_path


def verify_package_inventory(path: str | Path) -> VerifiedPermitPackage:
    """Validate a package without extracting any member to the filesystem."""

    package_path = Path(path)
    try:
        archive = zipfile.ZipFile(package_path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError(f"Permit package is not a valid ZIP: {exc}") from exc
    with archive:
        all_infos = archive.infolist()
        if len(all_infos) > MAX_FILES:
            raise ValueError("Permit package contains too many files")
        infos: list[zipfile.ZipInfo] = []
        zip_names: set[str] = set()
        for info in all_infos:
            candidate_name = info.filename.rstrip("/") if info.is_dir() else info.filename
            if not _safe_path(candidate_name):
                raise ValueError(
                    f"Permit package contains an unsafe path: {info.filename}"
                )
            if info.filename in zip_names:
                raise ValueError(
                    f"Permit package repeats ZIP member: {info.filename}"
                )
            zip_names.add(info.filename)
            file_type = (info.external_attr >> 16) & 0o170000
            if file_type == stat.S_IFLNK:
                raise ValueError(
                    f"Permit package contains a symbolic link: {info.filename}"
                )
            if info.is_dir():
                continue
            infos.append(info)
        names: set[str] = set()
        total_size = 0
        for info in infos:
            names.add(info.filename)
            if info.flag_bits & 0x1:
                raise ValueError(
                    f"Permit package contains an encrypted member: {info.filename}"
                )
            if info.file_size > MAX_ENTRY_BYTES:
                raise ValueError(
                    f"Permit package member is too large: {info.filename}"
                )
            if (
                info.compress_size > 0
                and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO
            ):
                raise ValueError(
                    f"Permit package member compression ratio is unsafe: {info.filename}"
                )
            total_size += info.file_size
            if total_size > MAX_TOTAL_BYTES:
                raise ValueError("Permit package uncompressed size is too large")

        if MANIFEST_PATH not in names:
            raise ValueError("Permit package is missing manifest.json")
        manifest_info = archive.getinfo(MANIFEST_PATH)
        if manifest_info.file_size > MAX_MANIFEST_BYTES:
            raise ValueError("Permit package manifest is too large")
        try:
            manifest = json.loads(archive.read(MANIFEST_PATH).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Permit package manifest is invalid JSON: {exc}") from exc
        if not isinstance(manifest, dict):
            raise ValueError("Permit package manifest must be an object")
        jsonschema.Draft202012Validator(
            _schema(), format_checker=jsonschema.FormatChecker()
        ).validate(manifest)
        if manifest.get("trust_rule") != (
            "verify_signed_evidence_and_regenerate_human_view"
        ):
            raise ValueError("Permit package trust rule is not supported")

        inventory = _entry_by_path(manifest)
        expected_files = {MANIFEST_PATH, *inventory}
        if names != expected_files:
            missing = sorted(expected_files - names)
            unexpected = sorted(names - expected_files)
            raise ValueError(
                "Permit package ZIP inventory diverges from manifest "
                f"(missing={missing}, unexpected={unexpected})"
            )
        roles: dict[str, list[str]] = {}
        payloads: dict[str, bytes] = {}
        for member_path, entry in inventory.items():
            payload = archive.read(member_path)
            payloads[member_path] = payload
            if len(payload) != entry.get("size_bytes"):
                raise ValueError(
                    f"Permit package size mismatch for {member_path}"
                )
            if _digest(payload) != entry.get("sha256"):
                raise ValueError(
                    f"Permit package digest mismatch for {member_path}"
                )
            roles.setdefault(str(entry.get("role")), []).append(member_path)
        for required_role in (
            "human_view",
            "signed_evidence",
            "verification_report",
        ):
            if len(roles.get(required_role, [])) != 1:
                raise ValueError(
                    f"Permit package requires exactly one {required_role} entry"
                )

        primary_view = str(manifest["primary_view"])
        signed_evidence = str(manifest["signed_evidence"])
        if inventory.get(primary_view, {}).get("role") != "human_view":
            raise ValueError("Permit package primary_view is not the human view")
        if inventory.get(signed_evidence, {}).get("role") != "signed_evidence":
            raise ValueError(
                "Permit package signed_evidence is not the signed evidence entry"
            )
        return VerifiedPermitPackage(
            manifest=manifest,
            signed_evidence=payloads[signed_evidence],
            primary_view=payloads[primary_view],
            primary_view_media_type=str(inventory[primary_view]["media_type"]),
        )


__all__ = ["VerifiedPermitPackage", "verify_package_inventory"]
