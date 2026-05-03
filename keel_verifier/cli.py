"""Command-line interface for keel_verifier."""

from __future__ import annotations

import argparse
import json
import sys

from keel_verifier import __version__
from keel_verifier.verifier import VerifyResult, verify

KEELAPI_TRUST_ROOT_URL = "https://keelapi.com/v1/integrity/checkpoint-public-key"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m keel_verifier",
        description=(
            "Standalone verifier for Keel's signed compliance exports. "
            "Verifies the chain-heads composite hash, the Ed25519 signature, "
            "and the optional RFC 3161 timestamp receipt."
        ),
    )
    parser.add_argument(
        "export_file",
        help="Path to a sealed Keel export JSON file.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit the result as a single JSON object on stdout.",
    )
    parser.add_argument(
        "--no-tsa",
        action="store_true",
        help="Skip RFC 3161 timestamp receipt verification even if present.",
    )
    parser.add_argument(
        "--public-key",
        metavar="ed25519:BASE64",
        help=(
            "Pin verification to this public key. The export's signature "
            "must verify against it; if the export embeds a public_key, the "
            "two must match."
        ),
    )
    parser.add_argument(
        "--public-key-url",
        metavar="URL",
        help=(
            "Fetch the trust-root public key from this URL "
            f"(canonical: {KEELAPI_TRUST_ROOT_URL})."
        ),
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help=(
            "Use the public key bundled with this verifier as the trust "
            "root. Use this when you cannot reach the network and have "
            "out-of-band confidence in the bundled key."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"keel_verifier {__version__}",
    )
    return parser


def _print_human(result: VerifyResult, export_path: str, stream) -> None:
    p = lambda s="": print(s, file=stream)

    if result.ok:
        p(f"VERIFIED: {export_path}")
    else:
        p(f"FAILED: {export_path}")
        if result.error:
            for line in result.error.splitlines():
                p(f"  {line}")

    if result.checkpoint_id:
        p(f"  Checkpoint:    {result.checkpoint_id}")
    if result.computed_at:
        p(f"  Computed at:   {result.computed_at}")
    if result.composite_hash:
        p(f"  Composite:     {result.composite_hash}")
    if result.chain_heads_count:
        p(f"  Chain heads:   {result.chain_heads_count} scope(s)")
    if result.public_key:
        p(f"  Public key:    {result.public_key}")
    if result.key_id:
        p(f"  Key id:        {result.key_id}")
    if result.trust_source:
        p(f"  Trust source:  {result.trust_source}")

    if result.tsa_present:
        if not result.tsa_checked:
            p("  TSA:           present (skipped — --no-tsa)")
        elif result.tsa_verified:
            p(f"  TSA:           verified ({result.tsa_reason})")
            if result.tsa_url:
                p(f"    url:         {result.tsa_url}")
            if result.tsa_requested_at:
                p(f"    stamped at:  {result.tsa_requested_at}")
        else:
            p(f"  TSA:           FAILED ({result.tsa_reason})")
    else:
        p("  TSA:           not present")

    if result.ok and result.self_attested:
        p()
        p(
            "NOTE: trust source is the export's own embedded public key. "
            "To anchor against"
        )
        p("Keel's published trust root, re-run with:")
        p(f"  --public-key-url {KEELAPI_TRUST_ROOT_URL}")
        p("or with --offline to use the bundled trust root.")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    flag_count = sum(
        bool(x) for x in (args.public_key, args.public_key_url, args.offline)
    )
    if flag_count > 1:
        print(
            "ERROR: --public-key, --public-key-url, and --offline are mutually exclusive.",
            file=sys.stderr,
        )
        return 2

    result = verify(
        args.export_file,
        public_key=args.public_key,
        public_key_url=args.public_key_url,
        offline=args.offline,
        check_tsa=not args.no_tsa,
    )

    if args.as_json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        if not result.ok and result.error:
            print(result.error, file=sys.stderr)
    else:
        stream = sys.stdout if result.ok else sys.stderr
        _print_human(result, args.export_file, stream)

    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
