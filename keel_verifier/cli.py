"""Command-line interface for keel_verifier."""

from __future__ import annotations

import argparse
import json
import sys

from keel_verifier import __version__
from keel_verifier.verifier import (
    KEELAPI_CHECKPOINT_PUBLIC_KEY_URL,
    KEELAPI_COMPLIANCE_KEYS_URL,
    VerifyResult,
    cmd_checkpoint,
    cmd_export,
    verify,
)

LEGACY_COMMANDS = {"export", "checkpoint"}


def _public_key_alias(args: argparse.Namespace) -> None:
    if getattr(args, "public_key", None) and getattr(args, "expected_public_key", None):
        raise argparse.ArgumentTypeError(
            "--public-key and --expected-public-key are aliases; pass only one"
        )
    if getattr(args, "expected_public_key", None) is None:
        args.expected_public_key = getattr(args, "public_key", None)


def _trust_flag_count(args: argparse.Namespace, *, include_public_key_url: bool) -> int:
    values = [
        getattr(args, "expected_public_key", None),
        getattr(args, "key_manifest", None),
        getattr(args, "key_manifest_url", None),
        getattr(args, "self_attested", False),
    ]
    if include_public_key_url:
        values.append(getattr(args, "public_key_url", None))
    return sum(bool(value) for value in values)


def _add_key_manifest_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--key-manifest",
        help=(
            "Local path to a Keel public key manifest JSON file. Defaults to "
            "the bundled production trust root when no trust override is passed."
        ),
    )
    p.add_argument(
        "--key-manifest-url",
        help=f"URL to fetch the key manifest from (canonical: {KEELAPI_COMPLIANCE_KEYS_URL}).",
    )


def _add_common_trust_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--expected-public-key",
        help="ed25519:<base64> public key the artifact must be signed with.",
    )
    p.add_argument(
        "--public-key",
        help="Alias for --expected-public-key, preserved for v0.2.0 users.",
    )
    p.add_argument(
        "--self-attested",
        action="store_true",
        help=(
            "Verify against the artifact's embedded public_key. This only proves "
            "internal consistency; it does not prove Keel signed the artifact."
        ),
    )
    p.add_argument(
        "--offline",
        action="store_true",
        help=argparse.SUPPRESS,
    )


def _cmd_export_cli(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    try:
        _public_key_alias(args)
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))
    args.export_file = args.export_file_flag or args.export_file_pos
    args.manifest = args.manifest_flag or args.manifest_pos
    if not args.export_file:
        parser.error("export requires EXPORT_FILE or --export-file")
    if not args.manifest:
        parser.error("export requires MANIFEST or --manifest")
    if _trust_flag_count(args, include_public_key_url=False) > 1:
        parser.error(
            "--expected-public-key/--public-key, --key-manifest, "
            "--key-manifest-url, and --self-attested are mutually exclusive"
        )
    return cmd_export(args)


def _cmd_checkpoint_cli(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    try:
        _public_key_alias(args)
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))
    args.checkpoint_file = args.checkpoint_file_flag or args.checkpoint_file_pos
    if not args.checkpoint_file:
        parser.error("checkpoint requires CHECKPOINT_FILE or --checkpoint-file")
    if _trust_flag_count(args, include_public_key_url=True) > 1:
        parser.error(
            "--expected-public-key/--public-key, --public-key-url, --key-manifest, "
            "--key-manifest-url, and --self-attested are mutually exclusive"
        )
    return cmd_checkpoint(args)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keel-verify",
        description="Standalone verifier for Keel trust artifacts.",
        epilog=(
            "New export verification supports --walk-events and --verify-closure. "
            "Backward compatible usage remains: python -m keel_verifier <checkpoint.json>."
        ),
    )
    parser.add_argument("--version", action="version", version=f"keel_verifier {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    p_export = sub.add_parser("export", help="Verify a signed compliance export.")
    p_export.add_argument("export_file_pos", nargs="?", metavar="EXPORT_FILE")
    p_export.add_argument("manifest_pos", nargs="?", metavar="MANIFEST")
    p_export.add_argument("--export-file", dest="export_file_flag")
    p_export.add_argument("--manifest", dest="manifest_flag")
    p_export.add_argument(
        "--walk-events",
        action="store_true",
        help=(
            "After export content hash and signature verification, parse an "
            "audit export bundle and walk bundled chain_entries."
        ),
    )
    p_export.add_argument(
        "--verify-closure",
        action="store_true",
        help=(
            "After export content hash and signature verification, verify "
            "permit.closed closure signatures and dispatch/provider/client digest "
            "consistency from bundled chain_entries."
        ),
    )
    _add_common_trust_args(p_export)
    _add_key_manifest_args(p_export)
    p_export.set_defaults(func=lambda args: _cmd_export_cli(p_export, args))

    p_cp = sub.add_parser("checkpoint", help="Verify an integrity checkpoint JSON file.")
    p_cp.add_argument("checkpoint_file_pos", nargs="?", metavar="CHECKPOINT_FILE")
    p_cp.add_argument("--checkpoint-file", dest="checkpoint_file_flag")
    _add_common_trust_args(p_cp)
    p_cp.add_argument(
        "--public-key-url",
        help=(
            "URL to fetch the single checkpoint public key "
            f"(canonical: {KEELAPI_CHECKPOINT_PUBLIC_KEY_URL})."
        ),
    )
    _add_key_manifest_args(p_cp)
    p_cp.add_argument(
        "--tsa-ca-bundle",
        help="Optional CA bundle for TSA trust-chain validation (note only).",
    )
    p_cp.set_defaults(func=lambda args: _cmd_checkpoint_cli(p_cp, args))
    return parser


def _build_legacy_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m keel_verifier",
        description=(
            "Backward-compatible v0.2.0 checkpoint verifier. For signed "
            "compliance exports, use: keel-verify export --help."
        ),
    )
    parser.add_argument("export_file", help="Path to a sealed Keel checkpoint/export JSON file.")
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--no-tsa", action="store_true", help="Skip RFC 3161 TSA receipt verification.")
    parser.add_argument("--public-key", metavar="ed25519:BASE64")
    parser.add_argument(
        "--public-key-url",
        metavar="URL",
        help=f"Fetch the trust-root public key from this URL (canonical: {KEELAPI_CHECKPOINT_PUBLIC_KEY_URL}).",
    )
    parser.add_argument(
        "--self-attested",
        action="store_true",
        dest="self_attested",
        help=(
            "Verify against the artifact's own embedded public_key. This only "
            "proves internal consistency; it does not prove Keel signed it."
        ),
    )
    parser.add_argument("--offline", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--version", action="version", version=f"keel_verifier {__version__}")
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
        p("WARNING: --self-attested verification only proves internal consistency.")
        p("It does not prove that Keel signed this artifact. Drop --self-attested to")
        p("verify against the bundled trust root, or pin explicitly with:")
        p(f"  --public-key-url {KEELAPI_CHECKPOINT_PUBLIC_KEY_URL}")


def _main_legacy(argv: list[str]) -> int:
    parser = _build_legacy_parser()
    args = parser.parse_args(argv)
    flags = (args.public_key, args.public_key_url, args.self_attested)
    if sum(bool(x) for x in flags) > 1:
        print(
            "ERROR: --public-key, --public-key-url, and --self-attested are mutually exclusive.",
            file=sys.stderr,
        )
        return 2

    result = verify(
        args.export_file,
        public_key=args.public_key,
        public_key_url=args.public_key_url,
        self_attested=args.self_attested,
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


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] not in LEGACY_COMMANDS and raw[0] not in {"-h", "--help", "--version"}:
        return _main_legacy(raw)

    parser = _build_parser()
    args = parser.parse_args(raw)
    if not hasattr(args, "func"):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
