#!/usr/bin/env python3
"""Release gate for the GitHub-served trust root.

This script is intentionally stricter than normal verifier loading. Release
publication must see a remote ``keel.public_key_manifest.v1`` signed by one of
the real production export-signing key ids allowlisted here. Unsigned manifests,
source-tree scaffold signatures, or signatures by non-production test keys fail
closed.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any, Mapping

from keel_verifier import verifier


REAL_EXPORT_SIGNING_KEY_IDS = frozenset(
    {
        "sha256:341fe2190d167abc491db6d041da0677",
    }
)


def _load_json_source(source: str) -> dict[str, Any]:
    if source == "github":
        source = verifier.GITHUB_TRUST_ROOT_URL
    if source.startswith(("http://", "https://")):
        with urllib.request.urlopen(source, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
    else:
        payload = json.loads(Path(source).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("trust root must be a JSON object")
    return payload


def validate_release_trust_root(
    body: Mapping[str, Any],
    *,
    source: str,
    allowed_key_ids: frozenset[str] = REAL_EXPORT_SIGNING_KEY_IDS,
) -> None:
    if body.get("manifest_version") != "keel.public_key_manifest.v1":
        raise ValueError("release trust root must be keel.public_key_manifest.v1")
    if body.get("publication_scaffold") is not None:
        raise ValueError("release trust root must not carry publication_scaffold")

    signature = body.get("manifest_signature")
    if not isinstance(signature, Mapping):
        raise ValueError("release trust root is missing manifest_signature")
    if signature.get("purpose") != "export_signing":
        raise ValueError("release trust root must be signed by export_signing")

    signer_key_id = signature.get("key_id")
    if signer_key_id not in allowed_key_ids:
        raise ValueError(
            "release trust root signer is not an allowlisted real export_signing key"
        )

    verifier._verify_public_key_manifest_signature(body, source=source)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail release unless the served trust root is real-signed."
    )
    parser.add_argument(
        "--source",
        default="github",
        help=(
            "Trust-root source URL or local path. Use 'github' for "
            "keel_verifier.verifier.GITHUB_TRUST_ROOT_URL."
        ),
    )
    args = parser.parse_args()
    source = verifier.GITHUB_TRUST_ROOT_URL if args.source == "github" else args.source

    try:
        body = _load_json_source(args.source)
        validate_release_trust_root(body, source=source)
    except Exception as exc:
        print(f"FAILED: release trust-root gate: {exc}", file=sys.stderr)
        return 1

    signature = body["manifest_signature"]
    print(
        "PASS: release trust-root gate: "
        f"{body['manifest_version']} signed by {signature['key_id']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
