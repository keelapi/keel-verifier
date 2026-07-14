"""Refresh the release-pinned TSA CRL snapshots in the trust bundle.

The bundled CRLs expire on the CAs' own schedule (GlobalSign ~13 days, DigiCert
~21 days), while CI guards a 7-day freshness window. Without this script the
bundle rots silently and blocks every keel-verifier release until someone
notices, so refreshing is a routine chore rather than an incident.

Safety: a downloaded CRL is only accepted when its issuer matches the vendored
issuer certificate's subject AND its signature verifies against that
certificate's public key. The vendored CA certificate is the trust anchor, so a
wrong URL, a stale mirror, or a poisoned response cannot enter the bundle -- it
fails verification and the refresh aborts.

Usage:
    python scripts/refresh_tsa_trust_bundle.py            # refresh in place
    python scripts/refresh_tsa_trust_bundle.py --dry-run  # verify only
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

REPO_ROOT = Path(__file__).resolve().parents[1]
TSA_TRUST = REPO_ROOT / "keel_verifier" / "data" / "tsa_trust"
BUNDLE = TSA_TRUST / "tsa_trust_bundle_v1.json"
VERIFIER = REPO_ROOT / "keel_verifier" / "verifier.py"

# A CA publishes the CRL covering the certificates it ISSUES. The URL lives in
# the CRLDistributionPoints of those issued certificates, so a root's CRL URL is
# discoverable from the intermediate, but an intermediate's own CRL URL is only
# found in leaf TSA certificates. Candidates are therefore listed per CRL and
# every candidate is signature-verified before acceptance.
CANDIDATE_URLS: dict[str, list[str]] = {
    "digicert/trusted_root_g4.crl.pem": [
        "http://crl3.digicert.com/DigiCertTrustedRootG4.crl",
    ],
    "digicert/assured_id_root_ca.crl.pem": [
        "http://crl3.digicert.com/DigiCertAssuredIDRootCA.crl",
    ],
    "digicert/trusted_g4_timestamping_rsa4096_sha256_2025_ca1.crl.pem": [
        "http://crl3.digicert.com/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.crl",
    ],
    "globalsign/timestamping_root_r45.crl.pem": [
        "http://crl.globalsign.com/timestamprootr45.crl",
    ],
    "globalsign/root_r6.crl.pem": [
        "http://crl.globalsign.com/root-r6.crl",
    ],
    # Read from the CRLDistributionPoints of a live leaf certificate returned by
    # GlobalSign's public TSA (rfc3161timestamp.globalsign.com/advanced); an
    # intermediate's own CRL URL appears nowhere else.
    "globalsign/offline_r45_timestamping_ca_2025.crl.pem": [
        "http://crl.globalsign.com/gsoffliner45timestampca2025.crl",
    ],
}


def _z(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _issuer_certificate(bundle: dict[str, Any], issuer_dn: str) -> x509.Certificate:
    for entry in bundle["files"]:
        if entry.get("kind") == "crl":
            continue
        if entry.get("subject") == issuer_dn:
            return x509.load_pem_x509_certificate((TSA_TRUST / entry["path"]).read_bytes())
    raise SystemExit(f"no vendored issuer certificate for {issuer_dn!r}")


def _fetch(url: str) -> bytes | None:
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "keel-verifier-crl-refresh"})
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read()
    except Exception as exc:  # network/HTTP failures are expected while probing
        print(f"      {url} -> {type(exc).__name__}: {exc}")
        return None


def _load_crl(raw: bytes) -> x509.CertificateRevocationList | None:
    for loader in (x509.load_der_x509_crl, x509.load_pem_x509_crl):
        try:
            return loader(raw)
        except Exception:
            continue
    return None


def refresh(*, dry_run: bool, min_valid_days: int) -> int:
    bundle = json.loads(BUNDLE.read_text(encoding="utf-8"))
    now = dt.datetime.now(dt.timezone.utc)
    failures: list[str] = []
    next_updates: list[dt.datetime] = []

    for entry in bundle["files"]:
        if entry.get("kind") != "crl":
            continue
        path = entry["path"]
        issuer_cert = _issuer_certificate(bundle, entry["issuer"])
        print(f"   {path}")
        accepted = None
        for url in CANDIDATE_URLS.get(path, []):
            raw = _fetch(url)
            if raw is None:
                continue
            crl = _load_crl(raw)
            if crl is None:
                print(f"      {url} -> not a parseable CRL")
                continue
            if crl.issuer != issuer_cert.subject:
                print(f"      {url} -> issuer mismatch (rejected)")
                continue
            if not crl.is_signature_valid(issuer_cert.public_key()):
                print(f"      {url} -> SIGNATURE INVALID (rejected)")
                continue
            accepted = (url, crl)
            break

        if accepted is None:
            failures.append(path)
            print("      NO VERIFIED CRL OBTAINED")
            continue

        url, crl = accepted
        headroom = (crl.next_update_utc - now).days
        print(f"      verified via {url}")
        print(f"      next_update {_z(crl.next_update_utc)} ({headroom}d headroom)")
        if headroom < min_valid_days:
            failures.append(f"{path} (only {headroom}d headroom)")
            continue
        next_updates.append(crl.next_update_utc)

        if not dry_run:
            pem = crl.public_bytes(Encoding.PEM)
            (TSA_TRUST / path).write_bytes(pem)
            entry["last_update"] = _z(crl.last_update_utc)
            entry["next_update"] = _z(crl.next_update_utc)
            entry["sha256"] = _sha256(pem)
            entry["source_url"] = url  # record it so the next refresh needs no guessing

    if failures:
        print("\n   FAILED to refresh: " + ", ".join(failures))
        return 1
    if dry_run:
        print("\n   dry run: all CRLs verified, nothing written")
        return 0

    bundle["generated_at"] = _z(now)
    bundle["validation"]["crl_refresh_required_before"] = _z(min(next_updates))
    serialized = json.dumps(bundle, indent=2, sort_keys=True) + "\n"
    BUNDLE.write_text(serialized, encoding="utf-8")

    digest = _sha256(BUNDLE.read_bytes())
    source = VERIFIER.read_text(encoding="utf-8")
    start = source.index("TSA_TRUST_BUNDLE_V1_HASH = (")
    end = source.index(")", start)
    updated = f'TSA_TRUST_BUNDLE_V1_HASH = (\n    "{digest}"\n'
    VERIFIER.write_text(source[:start] + updated + source[end:], encoding="utf-8")

    print(f"\n   bundle rewritten; earliest next_update {_z(min(next_updates))}")
    print(f"   TSA_TRUST_BUNDLE_V1_HASH -> {digest}")
    print("   remember to regenerate the release manifest")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--min-valid-days", type=int, default=7)
    args = parser.parse_args()
    return refresh(dry_run=args.dry_run, min_valid_days=args.min_valid_days)


if __name__ == "__main__":
    sys.exit(main())
