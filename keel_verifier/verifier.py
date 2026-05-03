"""Core verification logic for Keel signed exports.

A Keel signed export ("integrity checkpoint") is a single JSON document
containing the chain heads of every scope at a point in time, a SHA-256
composite hash over those heads, an Ed25519 signature over that
composite, and an optional RFC 3161 timestamp receipt.

This module verifies, in order:

    1. The composite_hash recomputes from chain_heads exactly.
    2. The Ed25519 signature is valid against the resolved trust root.
    3. The optional TSA receipt's MessageImprint equals composite_hash.

The verifier is intentionally pure-Python and has no dependency on the
Keel API codebase. It runs offline against a sealed export. Trust-root
resolution may optionally fetch the public key over HTTPS; this is the
only outbound call the verifier ever makes (alongside the optional TSA
fetch, which the verifier does not perform — TSA receipts are only
verified, never requested).
"""

from __future__ import annotations

import base64
import hashlib
import json
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


@dataclass
class VerifyResult:
    ok: bool
    error: str | None = None

    checkpoint_id: str | None = None
    computed_at: str | None = None
    composite_hash: str | None = None
    chain_heads_count: int = 0

    public_key: str | None = None
    key_id: str | None = None
    trust_source: str | None = None
    self_attested: bool = False

    tsa_present: bool = False
    tsa_checked: bool = False
    tsa_verified: bool | None = None
    tsa_reason: str | None = None
    tsa_url: str | None = None
    tsa_requested_at: str | None = None

    diagnostics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "error": self.error,
            "checkpoint_id": self.checkpoint_id,
            "computed_at": self.computed_at,
            "composite_hash": self.composite_hash,
            "chain_heads_count": self.chain_heads_count,
            "public_key": self.public_key,
            "key_id": self.key_id,
            "trust_source": self.trust_source,
            "self_attested": self.self_attested,
            "tsa": {
                "present": self.tsa_present,
                "checked": self.tsa_checked,
                "verified": self.tsa_verified,
                "reason": self.tsa_reason,
                "url": self.tsa_url,
                "requested_at": self.tsa_requested_at,
            },
            "diagnostics": list(self.diagnostics),
        }


def _composite_hash(chain_heads: dict[str, dict[str, Any]]) -> str:
    parts: list[str] = []
    for scope_key in sorted(chain_heads.keys()):
        head = chain_heads[scope_key]
        parts.append(
            f"{scope_key}:{head['sequence_number']}:{head['last_record_hash']}"
        )
    combined = "\n".join(parts)
    return f"sha256:{hashlib.sha256(combined.encode('utf-8')).hexdigest()}"


def _verify_ed25519(pub: str, signed_message: bytes, sig: str) -> bool:
    try:
        pub_bytes = base64.b64decode(pub.removeprefix("ed25519:"))
        sig_bytes = base64.b64decode(sig.removeprefix("ed25519:"))
        Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig_bytes, signed_message)
        return True
    except Exception:
        return False


def _public_key_fingerprint(pub: str) -> str:
    raw = base64.b64decode(pub.removeprefix("ed25519:"))
    return f"sha256:{hashlib.sha256(raw).hexdigest()[:32]}"


def _fetch_trust_root(url: str) -> tuple[str | None, str | None]:
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        return None, f"could not fetch trust root from {url}: {exc}"
    pub = body.get("public_key") if isinstance(body, dict) else None
    if not isinstance(pub, str) or not pub.startswith("ed25519:"):
        return None, f"unexpected response shape from {url} (missing ed25519 public_key)"
    return pub, None


def _load_bundled_offline_key() -> tuple[str | None, str | None]:
    bundled = Path(__file__).parent / "keys" / "keel_checkpoint.pub.json"
    if not bundled.exists():
        return None, f"bundled offline key not found at {bundled}"
    try:
        body = json.loads(bundled.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, f"could not parse bundled offline key: {exc}"
    pub = body.get("public_key") if isinstance(body, dict) else None
    if not isinstance(pub, str) or not pub.startswith("ed25519:"):
        return None, "bundled offline key file is missing an ed25519 public_key field"
    return pub, None


def _resolve_trust_root(
    embedded_pub: str | None,
    *,
    public_key: str | None,
    public_key_url: str | None,
    offline: bool,
) -> tuple[str | None, str | None, str | None]:
    """Returns (trusted_public_key, trust_source, error)."""
    if public_key is not None:
        if not public_key.startswith("ed25519:"):
            return None, None, "--public-key must start with 'ed25519:'"
        return public_key, "user-supplied (--public-key)", None

    if public_key_url is not None:
        pub, err = _fetch_trust_root(public_key_url)
        if err:
            return None, None, err
        return pub, f"fetched from {public_key_url}", None

    if offline:
        pub, err = _load_bundled_offline_key()
        if err:
            return None, None, err
        return pub, "bundled offline trust root", None

    if embedded_pub is not None:
        return embedded_pub, "self-attested (embedded public_key)", None

    return None, None, "no trust root available (artifact has no public_key)"


def _verify_tsa_receipt(receipt_b64: str, content_hash_hex: str) -> tuple[bool, str]:
    """Verify the TSA receipt's MessageImprint equals the composite hash.

    Note: this confirms the timestamp authority signed *this* hash, but
    does not validate the TSA's own certificate chain. For full RFC 3161
    trust-chain verification, use ``openssl ts -verify`` against a CA
    bundle.
    """
    try:
        from asn1crypto import cms, tsp  # type: ignore[import-untyped]
    except ImportError:
        return False, "asn1crypto not installed (pip install asn1crypto)"

    try:
        raw_der = base64.b64decode(receipt_b64)
        content_info = cms.ContentInfo.load(raw_der)
        signed_data = content_info["content"]
        encap = signed_data["encap_content_info"]
        tst_info = tsp.TSTInfo.load(encap["content"].parsed.dump())
        imprint = tst_info["message_imprint"]["hashed_message"].native
        expected = bytes.fromhex(content_hash_hex)
        if imprint != expected:
            return False, "TSA message imprint does not match composite_hash"
        return True, "TSA message imprint matches composite_hash"
    except Exception as exc:
        return False, f"TSA parse/verify failed: {exc}"


def verify(
    export_path: str | Path,
    *,
    public_key: str | None = None,
    public_key_url: str | None = None,
    offline: bool = False,
    check_tsa: bool = True,
) -> VerifyResult:
    """Verify a single sealed Keel export at ``export_path``.

    Returns a ``VerifyResult`` with ``ok=True`` if every check passed.
    On failure, ``ok=False`` and ``error`` carries the first failure
    reason; ``diagnostics`` may carry additional notes.
    """
    path = Path(export_path)

    try:
        body = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return VerifyResult(ok=False, error=f"file not found: {path}")
    except json.JSONDecodeError as exc:
        return VerifyResult(ok=False, error=f"invalid JSON: {exc}")
    except Exception as exc:
        return VerifyResult(ok=False, error=f"could not read {path}: {exc}")

    if not isinstance(body, dict):
        return VerifyResult(ok=False, error="top-level JSON must be an object")

    composite = body.get("composite_hash")
    signature = body.get("signature")
    embedded_pub = body.get("public_key")
    chain_heads_raw = body.get("chain_heads") or {}
    tsa = body.get("tsa")
    artifact_key_id = body.get("key_id") if isinstance(body.get("key_id"), str) else None

    if not isinstance(composite, str) or not composite.startswith("sha256:"):
        return VerifyResult(
            ok=False, error="missing or malformed composite_hash"
        )
    if not isinstance(chain_heads_raw, dict):
        return VerifyResult(ok=False, error="chain_heads must be an object")

    # Validate chain_heads shape before recomputing
    for scope_key, head in chain_heads_raw.items():
        if not isinstance(head, dict):
            return VerifyResult(
                ok=False, error=f"chain_heads[{scope_key}] must be an object"
            )
        if not isinstance(head.get("sequence_number"), int):
            return VerifyResult(
                ok=False,
                error=f"chain_heads[{scope_key}].sequence_number must be an int",
            )
        if not isinstance(head.get("last_record_hash"), str):
            return VerifyResult(
                ok=False,
                error=f"chain_heads[{scope_key}].last_record_hash must be a string",
            )

    try:
        recomputed = _composite_hash(chain_heads_raw)
    except Exception as exc:
        return VerifyResult(
            ok=False, error=f"could not recompute composite_hash: {exc}"
        )
    if recomputed != composite:
        return VerifyResult(
            ok=False,
            error=(
                "composite_hash mismatch — chain_heads have been altered\n"
                f"  stored:     {composite}\n"
                f"  recomputed: {recomputed}"
            ),
            checkpoint_id=str(body.get("checkpoint_id") or "") or None,
            composite_hash=composite,
            chain_heads_count=len(chain_heads_raw),
        )

    if not isinstance(signature, str):
        return VerifyResult(
            ok=False,
            error="export is unsigned (no signature field)",
            checkpoint_id=str(body.get("checkpoint_id") or "") or None,
            composite_hash=composite,
            chain_heads_count=len(chain_heads_raw),
        )

    trusted_pub, trust_source, err = _resolve_trust_root(
        embedded_pub if isinstance(embedded_pub, str) else None,
        public_key=public_key,
        public_key_url=public_key_url,
        offline=offline,
    )
    if err is not None or trusted_pub is None:
        return VerifyResult(
            ok=False,
            error=err or "could not resolve trust root",
            checkpoint_id=str(body.get("checkpoint_id") or "") or None,
            composite_hash=composite,
            chain_heads_count=len(chain_heads_raw),
        )

    if isinstance(embedded_pub, str) and embedded_pub != trusted_pub:
        return VerifyResult(
            ok=False,
            error=(
                "embedded public_key does not match resolved trust root\n"
                f"  trust root: {trusted_pub}\n"
                f"  embedded:   {embedded_pub}"
            ),
            checkpoint_id=str(body.get("checkpoint_id") or "") or None,
            composite_hash=composite,
            chain_heads_count=len(chain_heads_raw),
        )

    if not _verify_ed25519(trusted_pub, composite.encode("utf-8"), signature):
        return VerifyResult(
            ok=False,
            error="signature verification failed",
            checkpoint_id=str(body.get("checkpoint_id") or "") or None,
            composite_hash=composite,
            chain_heads_count=len(chain_heads_raw),
            public_key=trusted_pub,
            key_id=artifact_key_id or _public_key_fingerprint(trusted_pub),
            trust_source=trust_source,
        )

    tsa_present = isinstance(tsa, dict) and isinstance(tsa.get("receipt_b64"), str)
    tsa_checked = False
    tsa_verified: bool | None = None
    tsa_reason: str | None = None
    tsa_url: str | None = None
    tsa_requested_at: str | None = None

    if tsa_present:
        tsa_url = tsa.get("url") if isinstance(tsa.get("url"), str) else None
        tsa_requested_at = (
            tsa.get("requested_at")
            if isinstance(tsa.get("requested_at"), str)
            else None
        )
        if check_tsa:
            tsa_checked = True
            hex_hash = composite.removeprefix("sha256:")
            tsa_verified, tsa_reason = _verify_tsa_receipt(
                tsa["receipt_b64"], hex_hash
            )
            if not tsa_verified:
                return VerifyResult(
                    ok=False,
                    error=f"TSA: {tsa_reason}",
                    checkpoint_id=str(body.get("checkpoint_id") or "") or None,
                    computed_at=str(body.get("computed_at") or "") or None,
                    composite_hash=composite,
                    chain_heads_count=len(chain_heads_raw),
                    public_key=trusted_pub,
                    key_id=artifact_key_id or _public_key_fingerprint(trusted_pub),
                    trust_source=trust_source,
                    self_attested=trust_source.startswith("self-attested"),
                    tsa_present=True,
                    tsa_checked=True,
                    tsa_verified=False,
                    tsa_reason=tsa_reason,
                    tsa_url=tsa_url,
                    tsa_requested_at=tsa_requested_at,
                )

    return VerifyResult(
        ok=True,
        checkpoint_id=str(body.get("checkpoint_id") or "") or None,
        computed_at=str(body.get("computed_at") or "") or None,
        composite_hash=composite,
        chain_heads_count=len(chain_heads_raw),
        public_key=trusted_pub,
        key_id=artifact_key_id or _public_key_fingerprint(trusted_pub),
        trust_source=trust_source,
        self_attested=trust_source.startswith("self-attested"),
        tsa_present=tsa_present,
        tsa_checked=tsa_checked,
        tsa_verified=tsa_verified,
        tsa_reason=tsa_reason,
        tsa_url=tsa_url,
        tsa_requested_at=tsa_requested_at,
    )
