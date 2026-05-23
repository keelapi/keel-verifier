#!/usr/bin/env python3
"""Generate the detached RFC 3161 TSA witness sidecar for manifest.json."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rfc3161_client import HashAlgorithm, PKIStatus, TimestampRequestBuilder
from rfc3161_client import decode_timestamp_response


PROVIDERS: tuple[tuple[str, str, str], ...] = (
    (
        "digicert",
        "http://timestamp.digicert.com",
        "public CA-operated timestamp authority",
    ),
    (
        "globalsign",
        "http://timestamp.globalsign.com/tsa/r6advanced1",
        "public CA-operated timestamp authority",
    ),
)


def _error(message: str) -> SystemExit:
    return SystemExit(f"error: {message}")


def _read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except FileNotFoundError as exc:
        raise _error(f"missing required file: {path}") from exc


def _request_der(manifest_bytes: bytes) -> bytes:
    request = (
        TimestampRequestBuilder()
        .data(manifest_bytes)
        .hash_algorithm(HashAlgorithm.SHA256)
        .cert_request(cert_request=True)
        .build()
    )
    return request.as_bytes()


def _post_timestamp_request(tsa_url: str, request_der: bytes) -> bytes:
    request = urllib.request.Request(
        tsa_url,
        data=request_der,
        headers={
            "Content-Type": "application/timestamp-query",
            "Accept": "application/timestamp-reply",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return response.read()


def _receipt(
    *,
    provider: str,
    tsa_url: str,
    witness_type: str,
    manifest_sha256: bytes,
    response_der: bytes,
    requested_at: str,
) -> dict[str, str]:
    response = decode_timestamp_response(response_der)
    if PKIStatus(response.status) not in {PKIStatus.GRANTED, PKIStatus.GRANTED_WITH_MODS}:
        raise ValueError(f"TSA returned non-granted status: {response.status_string}")
    if response.tst_info.message_imprint.message != manifest_sha256:
        raise ValueError("TSA response message imprint does not match manifest SHA-256")

    return {
        "provider": provider,
        "witness_type": witness_type,
        "tsa_url": tsa_url,
        "requested_at": requested_at,
        "receipt_b64": base64.b64encode(response_der).decode("ascii"),
        "receipt_hash": f"sha256:{hashlib.sha256(response_der).hexdigest()}",
    }


def generate_sidecar(manifest_path: Path) -> dict[str, Any]:
    manifest_bytes = _read_bytes(manifest_path)
    manifest_sha256 = hashlib.sha256(manifest_bytes).digest()
    request_der = _request_der(manifest_bytes)

    receipts: list[dict[str, str]] = []
    attempts: list[dict[str, str]] = []
    for provider, tsa_url, witness_type in PROVIDERS:
        requested_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        requested_at = requested_at.replace("+00:00", "Z")
        try:
            response_der = _post_timestamp_request(tsa_url, request_der)
            receipts.append(
                _receipt(
                    provider=provider,
                    tsa_url=tsa_url,
                    witness_type=witness_type,
                    manifest_sha256=manifest_sha256,
                    response_der=response_der,
                    requested_at=requested_at,
                )
            )
            status = "succeeded"
        except Exception as exc:
            status = "failed"
            print(f"TSA witness failed for {provider}: {exc}")
        attempts.append(
            {
                "provider": provider,
                "tsa_url": tsa_url,
                "witness_type": witness_type,
                "status": status,
            }
        )

    return {
        "version": "1.0",
        "artifact": manifest_path.name,
        "message_imprint": f"sha256:{manifest_sha256.hex()}",
        "receipt_format": "rfc3161-timestamp-response-der",
        "receipts": receipts,
        "attempts": attempts,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate manifest.json.tsa.json with DigiCert and GlobalSign receipts."
    )
    parser.add_argument("--manifest", type=Path, default=Path("manifest.json"))
    parser.add_argument("--output", type=Path, default=Path("manifest.json.tsa.json"))
    return parser


def main() -> int:
    args = build_parser().parse_args()
    sidecar = generate_sidecar(args.manifest)
    args.output.write_text(json.dumps(sidecar, indent=2) + "\n", encoding="utf-8")

    expected = {provider for provider, _url, _witness_type in PROVIDERS}
    actual = {receipt.get("provider") for receipt in sidecar["receipts"]}
    if actual != expected:
        missing = ", ".join(sorted(expected.difference(actual)))
        raise _error(f"missing required TSA receipt(s): {missing}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
