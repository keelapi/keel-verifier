"""Dependency-free WebAuthn verification for ``permit.co_signature.v1``.

The check order and reason codes mirror keel-permit's Phase-0 reference
verifier. Pack integrity and trusted key-manifest resolution are deliberately
handled by the caller before this protocol-unit verifier runs.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519


CO_SIGNATURE_VERIFIED = "CO_SIGNATURE_VERIFIED"
CO_SIGNATURE_EVIDENCE_MISSING = "CO_SIGNATURE_EVIDENCE_MISSING"
CO_SIGNATURE_VERSION_UNSUPPORTED = "CO_SIGNATURE_VERSION_UNSUPPORTED"
CO_SIGNATURE_ALGORITHM_UNSUPPORTED = "CO_SIGNATURE_ALGORITHM_UNSUPPORTED"
CO_SIGNATURE_PERMIT_BINDING_MISMATCH = "CO_SIGNATURE_PERMIT_BINDING_MISMATCH"
CO_SIGNATURE_CREDENTIAL_MISMATCH = "CO_SIGNATURE_CREDENTIAL_MISMATCH"
CO_SIGNATURE_ALGORITHM_MISMATCH = "CO_SIGNATURE_ALGORITHM_MISMATCH"
CO_SIGNATURE_CLIENT_DATA_INVALID = "CO_SIGNATURE_CLIENT_DATA_INVALID"
CO_SIGNATURE_TYPE_INVALID = "CO_SIGNATURE_TYPE_INVALID"
CO_SIGNATURE_CHALLENGE_MISMATCH = "CO_SIGNATURE_CHALLENGE_MISMATCH"
CO_SIGNATURE_ORIGIN_NOT_ALLOWED = "CO_SIGNATURE_ORIGIN_NOT_ALLOWED"
CO_SIGNATURE_AUTHENTICATOR_DATA_INVALID = "CO_SIGNATURE_AUTHENTICATOR_DATA_INVALID"
CO_SIGNATURE_RP_ID_HASH_MISMATCH = "CO_SIGNATURE_RP_ID_HASH_MISMATCH"
CO_SIGNATURE_USER_PRESENCE_REQUIRED = "CO_SIGNATURE_USER_PRESENCE_REQUIRED"
CO_SIGNATURE_USER_VERIFICATION_REQUIRED = "CO_SIGNATURE_USER_VERIFICATION_REQUIRED"
CO_SIGNATURE_SIGNATURE_MALFORMED = "CO_SIGNATURE_SIGNATURE_MALFORMED"
CO_SIGNATURE_INVALID_SIGNATURE = "CO_SIGNATURE_INVALID_SIGNATURE"

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_SHA256_HEX_RE = re.compile(r"^[a-f0-9]{64}$")
_CLAIM_FIELDS = {
    "payload_type",
    "permit_id",
    "permit_canonical_hash",
    "action",
    "resource",
    "modality",
    "co_signer_id",
    "role",
    "key_id",
    "custody_tier",
    "signed_at",
    "assertion",
}
_ASSERTION_FIELDS = {
    "credential_id",
    "authenticator_data",
    "client_data_json",
    "signature",
    "cose_alg",
}


@dataclass(frozen=True, slots=True)
class CoSignatureResult:
    verdict: str
    reason: str
    flags: int | None = None
    backup_eligible: bool | None = None
    backup_state: bool | None = None
    sign_count: int | None = None


def _result(verdict: str, reason: str, **detail: Any) -> CoSignatureResult:
    return CoSignatureResult(verdict=verdict, reason=reason, **detail)


def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_base64url(value: Any) -> bytes:
    if not isinstance(value, str) or not _B64URL_RE.fullmatch(value) or "=" in value:
        raise ValueError("non-canonical base64url")
    padding = "=" * ((4 - len(value) % 4) % 4)
    decoded = base64.b64decode(
        value.replace("-", "+").replace("_", "/") + padding,
        validate=True,
    )
    if not decoded or _encode_base64url(decoded) != value:
        raise ValueError("non-canonical base64url")
    return decoded


def _read_cbor_unsigned(data: bytes, cursor: int, additional: int) -> tuple[int, int]:
    if additional < 24:
        return additional, cursor
    widths = {24: 1, 25: 2, 26: 4, 27: 8}
    width = widths.get(additional)
    if width is None or cursor + width > len(data):
        raise ValueError("unsupported or truncated CBOR length")
    value = int.from_bytes(data[cursor : cursor + width], "big")
    if (
        (width == 1 and value < 24)
        or (width == 2 and value <= 0xFF)
        or (width == 4 and value <= 0xFFFF)
        or (width == 8 and value <= 0xFFFFFFFF)
    ):
        raise ValueError("non-minimal CBOR length")
    return value, cursor + width


def _read_cbor(data: bytes, cursor: int = 0) -> tuple[Any, int]:
    if cursor >= len(data):
        raise ValueError("truncated CBOR")
    initial = data[cursor]
    cursor += 1
    major = initial >> 5
    additional = initial & 0x1F
    argument, cursor = _read_cbor_unsigned(data, cursor, additional)
    if major == 0:
        return argument, cursor
    if major == 1:
        return -1 - argument, cursor
    if major == 2:
        end = cursor + argument
        if end > len(data):
            raise ValueError("truncated CBOR bytes")
        return data[cursor:end], end
    if major == 5:
        result: dict[Any, Any] = {}
        for _ in range(argument):
            key, cursor = _read_cbor(data, cursor)
            if key in result:
                raise ValueError("duplicate CBOR map key")
            value, cursor = _read_cbor(data, cursor)
            result[key] = value
        return result, cursor
    raise ValueError("unsupported CBOR type")


def _decode_cose_public_key(encoded: Any, expected_algorithm: int) -> Any:
    data = _decode_base64url(encoded)
    cose, cursor = _read_cbor(data)
    if not isinstance(cose, dict) or cursor != len(data) or cose.get(3) != expected_algorithm:
        raise ValueError("COSE algorithm mismatch")
    if expected_algorithm == -7:
        x = cose.get(-2)
        y = cose.get(-3)
        if (
            cose.get(1) != 2
            or cose.get(-1) != 1
            or not isinstance(x, bytes)
            or len(x) != 32
            or not isinstance(y, bytes)
            or len(y) != 32
        ):
            raise ValueError("ES256 requires EC2 P-256 COSE key")
        return ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"),
            int.from_bytes(y, "big"),
            ec.SECP256R1(),
        ).public_key()
    if expected_algorithm == -8:
        x = cose.get(-2)
        if cose.get(1) != 1 or cose.get(-1) != 6 or not isinstance(x, bytes) or len(x) != 32:
            raise ValueError("EdDSA requires OKP Ed25519 COSE key")
        return ed25519.Ed25519PublicKey.from_public_bytes(x)
    raise ValueError("unsupported algorithm")


def _read_der_length(data: bytes, cursor: int) -> tuple[int, int]:
    if cursor >= len(data):
        raise ValueError("truncated DER length")
    first = data[cursor]
    cursor += 1
    if first < 0x80:
        return first, cursor
    count = first & 0x7F
    if count == 0 or count > 2 or cursor + count > len(data) or data[cursor] == 0:
        raise ValueError("non-minimal DER length")
    length = int.from_bytes(data[cursor : cursor + count], "big")
    if length < 0x80:
        raise ValueError("non-minimal DER length")
    return length, cursor + count


def _read_der_integer(data: bytes, cursor: int) -> int:
    if cursor >= len(data) or data[cursor] != 0x02:
        raise ValueError("DER integer expected")
    length, body_start = _read_der_length(data, cursor + 1)
    body_end = body_start + length
    if length == 0 or body_end > len(data) or data[body_start] & 0x80:
        raise ValueError("invalid DER integer")
    if length > 1 and data[body_start] == 0 and not data[body_start + 1] & 0x80:
        raise ValueError("non-minimal DER integer")
    return body_end


def _valid_es256_der(signature: bytes) -> bool:
    try:
        if not signature or signature[0] != 0x30:
            return False
        sequence_length, body_start = _read_der_length(signature, 1)
        if body_start + sequence_length != len(signature):
            return False
        after_r = _read_der_integer(signature, body_start)
        return _read_der_integer(signature, after_r) == len(signature)
    except ValueError:
        return False


def verify_protocol(
    *,
    claim: Mapping[str, Any] | None,
    target_permit: Mapping[str, Any] | None,
    registered_key: Mapping[str, Any] | None,
    allowed_origins: list[str] | tuple[str, ...] | None,
    require_user_verification: bool = True,
) -> CoSignatureResult:
    if claim is None or target_permit is None or registered_key is None:
        return _result("insufficient_evidence", CO_SIGNATURE_EVIDENCE_MISSING)
    payload_type = claim.get("payload_type")
    if payload_type != "permit.co_signature.v1":
        return _result("unverifiable_scope", CO_SIGNATURE_VERSION_UNSUPPORTED)
    assertion = claim.get("assertion")
    if (
        set(claim) != _CLAIM_FIELDS
        or not isinstance(assertion, Mapping)
        or set(assertion) != _ASSERTION_FIELDS
    ):
        return _result("disproved", CO_SIGNATURE_PERMIT_BINDING_MISMATCH)
    permit_hash = claim.get("permit_canonical_hash")
    if not isinstance(permit_hash, str) or _SHA256_HEX_RE.fullmatch(permit_hash) is None:
        return _result("disproved", CO_SIGNATURE_PERMIT_BINDING_MISMATCH)

    for field in ("permit_id", "permit_canonical_hash", "action", "resource", "modality"):
        if claim.get(field) != target_permit.get(field):
            return _result("disproved", CO_SIGNATURE_PERMIT_BINDING_MISMATCH)
    principal = registered_key.get("principal")
    registered_co_signer_id = (
        principal.get("id")
        if isinstance(principal, Mapping)
        else registered_key.get("co_signer_id")
    )
    if (
        claim.get("key_id") != registered_key.get("key_id")
        or claim.get("co_signer_id") != registered_co_signer_id
        or claim.get("custody_tier") != "human_passkey"
    ):
        return _result("disproved", CO_SIGNATURE_PERMIT_BINDING_MISMATCH)
    if assertion.get("credential_id") != registered_key.get("credential_id"):
        return _result("disproved", CO_SIGNATURE_CREDENTIAL_MISMATCH)
    cose_alg = assertion.get("cose_alg")
    if isinstance(cose_alg, bool) or not isinstance(cose_alg, int):
        return _result("disproved", CO_SIGNATURE_ALGORITHM_MISMATCH)
    if cose_alg != registered_key.get("cose_alg"):
        return _result("disproved", CO_SIGNATURE_ALGORITHM_MISMATCH)
    if cose_alg not in {-7, -8}:
        return _result("unverifiable_scope", CO_SIGNATURE_ALGORITHM_UNSUPPORTED)

    try:
        client_data_bytes = _decode_base64url(assertion.get("client_data_json"))
        client_data = json.loads(client_data_bytes.decode("utf-8", errors="strict"))
        if (
            not isinstance(client_data, dict)
            or not isinstance(client_data.get("type"), str)
            or not isinstance(client_data.get("challenge"), str)
            or not isinstance(client_data.get("origin"), str)
        ):
            raise ValueError("invalid client data fields")
    except Exception:
        return _result("disproved", CO_SIGNATURE_CLIENT_DATA_INVALID)
    if client_data["type"] != "webauthn.get":
        return _result("disproved", CO_SIGNATURE_TYPE_INVALID)
    try:
        challenge = _decode_base64url(client_data["challenge"])
        expected_challenge = bytes.fromhex(permit_hash)
    except ValueError:
        return _result("disproved", CO_SIGNATURE_CHALLENGE_MISMATCH)
    if len(expected_challenge) != 32 or challenge != expected_challenge:
        return _result("disproved", CO_SIGNATURE_CHALLENGE_MISMATCH)
    if (
        not isinstance(allowed_origins, (list, tuple))
        or client_data["origin"] not in allowed_origins
    ):
        return _result("disproved", CO_SIGNATURE_ORIGIN_NOT_ALLOWED)

    try:
        auth_data = _decode_base64url(assertion.get("authenticator_data"))
    except ValueError:
        return _result("disproved", CO_SIGNATURE_AUTHENTICATOR_DATA_INVALID)
    if len(auth_data) < 37:
        return _result("disproved", CO_SIGNATURE_AUTHENTICATOR_DATA_INVALID)
    flags = auth_data[32]
    backup_eligible = bool(flags & 0x08)
    backup_state = bool(flags & 0x10)
    if backup_state and not backup_eligible:
        return _result("disproved", CO_SIGNATURE_AUTHENTICATOR_DATA_INVALID)
    rp_id = registered_key.get("rp_id")
    if (
        not isinstance(rp_id, str)
        or auth_data[:32] != hashlib.sha256(rp_id.encode("utf-8")).digest()
    ):
        return _result("disproved", CO_SIGNATURE_RP_ID_HASH_MISMATCH)
    if not flags & 0x01:
        return _result("disproved", CO_SIGNATURE_USER_PRESENCE_REQUIRED)
    if require_user_verification and not flags & 0x04:
        return _result("disproved", CO_SIGNATURE_USER_VERIFICATION_REQUIRED)

    try:
        public_key = _decode_cose_public_key(registered_key.get("public_key_cose"), cose_alg)
    except Exception:
        return _result("disproved", CO_SIGNATURE_ALGORITHM_MISMATCH)
    try:
        signature = _decode_base64url(assertion.get("signature"))
    except ValueError:
        return _result("disproved", CO_SIGNATURE_SIGNATURE_MALFORMED)
    if (cose_alg == -7 and not _valid_es256_der(signature)) or (
        cose_alg == -8 and len(signature) != 64
    ):
        return _result("disproved", CO_SIGNATURE_SIGNATURE_MALFORMED)
    signed_data = auth_data + hashlib.sha256(client_data_bytes).digest()
    try:
        if cose_alg == -7:
            public_key.verify(signature, signed_data, ec.ECDSA(hashes.SHA256()))
        else:
            public_key.verify(signature, signed_data)
    except (InvalidSignature, ValueError):
        return _result("disproved", CO_SIGNATURE_INVALID_SIGNATURE)
    return _result(
        "supported",
        CO_SIGNATURE_VERIFIED,
        flags=flags,
        backup_eligible=backup_eligible,
        backup_state=backup_state,
        sign_count=int.from_bytes(auth_data[33:37], "big"),
    )


__all__ = [
    "CO_SIGNATURE_ALGORITHM_UNSUPPORTED",
    "CO_SIGNATURE_EVIDENCE_MISSING",
    "CO_SIGNATURE_VERIFIED",
    "CO_SIGNATURE_VERSION_UNSUPPORTED",
    "CoSignatureResult",
    "verify_protocol",
]
