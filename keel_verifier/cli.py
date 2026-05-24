"""Command-line interface for keel_verifier."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from keel_verifier import __version__
from keel_verifier.self_check import run_self_check
from keel_verifier.verifier import (
    KEELAPI_CHECKPOINT_PUBLIC_KEY_URL,
    KEELAPI_COMPLIANCE_KEYS_URL,
    REFRESH_KEYS_SOURCES,
    VerifyResult,
    _load_json_evidence,
    cmd_checkpoint,
    cmd_export,
    cmd_refresh_keys,
    verify,
    verify_delegation_denied_correctly,
    verify_permit_v2_signature_claim,
    verify_scope_faithfulness_claim,
)

LEGACY_COMMANDS = {"export", "checkpoint", "refresh-keys", "claim", "self-check"}


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
        help=(
            "Compatibility flag for the default bundled trust-root mode. "
            "URL trust-root flags still take precedence when supplied."
        ),
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


def _cmd_claim_delegation_denied_correctly(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
) -> int:
    if not args.evidence_file:
        parser.error("delegation_denied_correctly requires --evidence-file")
    evidence_path = Path(args.evidence_file)
    result = verify_delegation_denied_correctly(
        _load_json_evidence(str(evidence_path)),
        event_id=args.event_id,
        pack_root=evidence_path.parent,
        include_semantics=True,
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "supported" else 1


def _cmd_claim_scope_faithfulness(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
) -> int:
    if not args.export_file:
        parser.error("scope_faithfulness requires --export-file")
    if not args.manifest:
        parser.error("scope_faithfulness requires --manifest")
    result = verify_scope_faithfulness_claim(
        export_file=args.export_file,
        manifest=args.manifest,
        sidecar=args.sidecar,
        checkpoint=args.checkpoint,
        key_manifest=args.key_manifest,
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "supported" else 1


def _cmd_claim_permit_v2_signature(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
) -> int:
    if not args.export_file:
        parser.error(f"{args.claim_cmd} requires --export-file")
    result = verify_permit_v2_signature_claim(
        claim_type=args.claim_cmd,
        export_file=args.export_file,
        manifest=args.manifest,
        key_manifest=args.key_manifest,
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "supported" else 1


def _cmd_self_check(args: argparse.Namespace) -> int:
    result = run_self_check(args)
    if args.as_json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        stream = sys.stdout if result.ok else sys.stderr
        print(result.format_human(), file=stream)
    return 0 if result.ok else 1


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
    p_export.add_argument("--json", action="store_true", dest="as_json")
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
    p_export.add_argument(
        "--allow-unsigned",
        action="store_true",
        help=(
            "Allow legacy unsigned manifests after content-hash verification. "
            "Prints a warning and exits 0."
        ),
    )
    _add_common_trust_args(p_export)
    _add_key_manifest_args(p_export)
    p_export.set_defaults(func=lambda args: _cmd_export_cli(p_export, args))

    p_cp = sub.add_parser("checkpoint", help="Verify an integrity checkpoint JSON file.")
    p_cp.add_argument("checkpoint_file_pos", nargs="?", metavar="CHECKPOINT_FILE")
    p_cp.add_argument("--checkpoint-file", dest="checkpoint_file_flag")
    p_cp.add_argument("--json", action="store_true", dest="as_json")
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
        help=(
            "Optional CA bundle for opt-in RFC 3161 TSA trust validation. "
            "Verifies chain, signature, and timestamping purpose against this "
            "bundle only; historical revocation is not checked."
        ),
    )
    p_cp.set_defaults(func=lambda args: _cmd_checkpoint_cli(p_cp, args))

    refresh_choices = ["auto"] + [slug for slug, _, _ in REFRESH_KEYS_SOURCES]
    p_refresh = sub.add_parser(
        "refresh-keys",
        help=(
            "Refresh the cached public-key manifest from a live channel "
            "(Keel API or GitHub) into ~/.keel-verifier/trust-root.json. "
            "Subsequent verifications prefer the cached manifest over the "
            "wheel-bundled trust root."
        ),
    )
    p_refresh.add_argument(
        "--source",
        choices=refresh_choices,
        default="auto",
        help=(
            "Which channel to fetch from. 'auto' tries each in order: "
            f"{', '.join(name for _slug, name, _url in REFRESH_KEYS_SOURCES)}."
        ),
    )
    p_refresh.set_defaults(func=cmd_refresh_keys)

    p_self = sub.add_parser(
        "self-check",
        help="Verify this installed keel-verifier wheel against its signed release manifest.",
    )
    p_self.add_argument(
        "--form",
        choices=["auto", "wheel"],
        default="auto",
        help="Installed artifact form to verify. auto currently resolves to wheel only.",
    )
    p_self.add_argument(
        "--offline",
        action="store_true",
        help="Use cached release provenance only; fail closed when required cache entries are absent.",
    )
    p_self.add_argument(
        "--no-cache",
        action="store_true",
        help="Fetch release provenance without reading or writing the 24h cache.",
    )
    p_self.add_argument(
        "--cache-dir",
        help="Directory for the 24h release provenance cache. Defaults to ~/.cache/keel-verifier/.",
    )
    p_self.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit machine-readable self-check results.",
    )
    p_self.set_defaults(func=_cmd_self_check)

    p_claim = sub.add_parser("claim", help="Verify a registered verifier claim.")
    claim_sub = p_claim.add_subparsers(dest="claim_cmd", required=True)
    p_delegation = claim_sub.add_parser(
        "delegation_denied_correctly",
        help="Verify a permit-chain delegation denial.",
    )
    p_delegation.add_argument("--evidence-file", required=True)
    p_delegation.add_argument("--event-id")
    p_delegation.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Accepted for consistency; claim output is JSON by default.",
    )
    p_delegation.set_defaults(
        func=lambda args: _cmd_claim_delegation_denied_correctly(
            p_delegation,
            args,
        )
    )

    p_scope = claim_sub.add_parser(
        "scope_faithfulness",
        help="Verify a scope-faithfulness export segment against its scope-state sidecar.",
    )
    p_scope.add_argument("--export-file", required=True)
    p_scope.add_argument("--manifest", required=True)
    p_scope.add_argument("--sidecar")
    p_scope.add_argument("--checkpoint")
    p_scope.add_argument("--key-manifest")
    p_scope.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Accepted for consistency; claim output is JSON by default.",
    )
    p_scope.set_defaults(
        func=lambda args: _cmd_claim_scope_faithfulness(
            p_scope,
            args,
        )
    )

    for claim_name, help_text in (
        (
            "operator_approved",
            "Verify a Permit v2 operator_approval signature slot.",
        ),
        (
            "counter_signed",
            "Verify a Permit v2 counter_signature pre-dispatch signature slot.",
        ),
        (
            "audit_attested",
            "Verify a Permit v2 audit_attestation signature slot.",
        ),
    ):
        p_permit_v2 = claim_sub.add_parser(claim_name, help=help_text)
        p_permit_v2.add_argument("--export-file", required=True)
        p_permit_v2.add_argument("--manifest")
        p_permit_v2.add_argument("--key-manifest")
        p_permit_v2.add_argument(
            "--json",
            action="store_true",
            dest="as_json",
            help="Accepted for consistency; claim output is JSON by default.",
        )
        p_permit_v2.set_defaults(
            func=lambda args, parser=p_permit_v2: _cmd_claim_permit_v2_signature(
                parser,
                args,
            )
        )

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
    parser.add_argument(
        "--offline",
        action="store_true",
        help=(
            "Compatibility flag for the default bundled trust-root mode. "
            "--public-key-url still takes precedence when supplied."
        ),
    )
    parser.add_argument("--version", action="version", version=f"keel_verifier {__version__}")
    return parser


def _print_human(result: VerifyResult, export_path: str, stream) -> None:
    def p(s: str = "") -> None:
        print(s, file=stream)

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
