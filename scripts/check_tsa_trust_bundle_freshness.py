#!/usr/bin/env python3
"""CI guard for release-pinned TSA CRL snapshot freshness."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUNDLE = REPO_ROOT / "keel_verifier" / "data" / "tsa_trust" / "tsa_trust_bundle_v1.json"


def _parse_z(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} is not a valid RFC3339 timestamp: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _to_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def check_bundle(path: Path, *, min_valid_days: int, now: datetime | None = None) -> None:
    body = json.loads(path.read_text(encoding="utf-8"))
    files = body.get("files")
    if not isinstance(files, list):
        raise ValueError("TSA trust bundle files must be a list")

    crl_next_updates = [
        _parse_z(entry.get("next_update"), field=f"{entry.get('path')}.next_update")
        for entry in files
        if isinstance(entry, dict) and entry.get("kind") == "crl"
    ]
    if not crl_next_updates:
        raise ValueError("TSA trust bundle does not declare any CRL next_update values")

    earliest = min(crl_next_updates)
    validation = body.get("validation")
    if not isinstance(validation, dict):
        raise ValueError("TSA trust bundle validation block is missing")
    declared_refresh = _parse_z(
        validation.get("crl_refresh_required_before"),
        field="validation.crl_refresh_required_before",
    )
    if declared_refresh != earliest:
        raise ValueError(
            "validation.crl_refresh_required_before must equal earliest CRL next_update: "
            f"declared {_to_z(declared_refresh)}, expected {_to_z(earliest)}"
        )

    current = now or datetime.now(timezone.utc)
    guard_boundary = current + timedelta(days=min_valid_days)
    if earliest <= guard_boundary:
        raise ValueError(
            "release-pinned TSA CRL snapshots need refresh before release: "
            f"earliest next_update {_to_z(earliest)} is within {min_valid_days} days "
            f"of {_to_z(current)}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail when bundled TSA CRL snapshots are inside the refresh guard window."
    )
    parser.add_argument("--bundle", type=Path, default=DEFAULT_BUNDLE)
    parser.add_argument("--min-valid-days", type=int, default=7)
    args = parser.parse_args()

    try:
        check_bundle(args.bundle, min_valid_days=args.min_valid_days)
    except Exception as exc:
        print(f"FAILED: TSA trust bundle freshness: {exc}", file=sys.stderr)
        return 1

    print(
        "PASS: TSA trust bundle CRL freshness guard "
        f"(min_valid_days={args.min_valid_days})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
