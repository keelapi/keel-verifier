#!/usr/bin/env python3
"""Generate the detached RFC 3161 TSA witness sidecar for manifest.json.

Uses asn1crypto for BER-tolerant ASN.1 parsing of TSA responses. Real-world
commercial TSAs (DigiCert, GlobalSign) frequently return BER-encoded responses
that strict-DER parsers reject; asn1crypto handles both DER and BER.

Build-time verification scope is intentionally narrow:
  1. Response decodes as TimeStampResp
  2. status == GRANTED or GRANTED_WITH_MODS
  3. messageImprint.hashedMessage matches sha256(manifest_bytes)

Full CMS signature + certificate-chain validation is deferred to opt-in trust
extension (matches the existing keel-verifier checkpoint TSA pattern in
verifier.py:_verify_tsa_receipt). The receipt's raw DER bytes are stored
verbatim in the sidecar so any downstream consumer can perform deeper
validation independently.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from asn1crypto import algos, cms, core, tsp


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


GRANTED_STATUSES = {"granted", "granted_with_mods"}


def _error(message: str) -> SystemExit:
    return SystemExit(f"error: {message}")


def _read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except FileNotFoundError as exc:
        raise _error(f"missing required file: {path}") from exc


def _build_request(manifest_sha256: bytes) -> bytes:
    """Build an RFC 3161 TimeStampReq with cert_req=True."""
    request = tsp.TimeStampReq(
        {
            "version": "v1",
            "message_imprint": {
                "hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
                "hashed_message": manifest_sha256,
            },
            "cert_req": True,
        }
    )
    return request.dump()


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


def _extract_tst_info(ts_resp: tsp.TimeStampResp) -> tsp.TSTInfo:
    """Pull the inner TSTInfo from the TimeStampToken's SignedData."""
    token = ts_resp["time_stamp_token"]
    if isinstance(token, core.Void) or token.native is None:
        raise ValueError("TimeStampResp does not contain a TimeStampToken")
    signed_data: cms.SignedData = token["content"]
    encap = signed_data["encap_content_info"]
    content_type = encap["content_type"].native
    if content_type != "tst_info":
        raise ValueError(f"unexpected encap content type: {content_type}")
    return encap["content"].parsed


def _receipt(
    *,
    provider: str,
    tsa_url: str,
    witness_type: str,
    manifest_sha256: bytes,
    response_der: bytes,
    requested_at: str,
) -> dict[str, str]:
    ts_resp = tsp.TimeStampResp.load(response_der)
    status = ts_resp["status"]["status"].native
    if status not in GRANTED_STATUSES:
        fail_info = ts_resp["status"].native.get("fail_info")
        raise ValueError(
            f"TSA returned non-granted status: {status}"
            + (f" (fail_info={fail_info})" if fail_info else "")
        )

    tst_info = _extract_tst_info(ts_resp)
    imprint = tst_info["message_imprint"]["hashed_message"].native
    algo = tst_info["message_imprint"]["hash_algorithm"]["algorithm"].native
    if algo != "sha256":
        raise ValueError(f"TSA used unexpected hash algorithm: {algo}")
    if imprint != manifest_sha256:
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
    request_der = _build_request(manifest_sha256)

    receipts: list[dict[str, str]] = []
    attempts: list[dict[str, str]] = []
    for provider, tsa_url, witness_type in PROVIDERS:
        requested_at = (
            datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        )
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
