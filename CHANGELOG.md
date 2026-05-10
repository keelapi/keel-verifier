# Changelog

## v1.0.4 (2026-05-10)

- Add `refresh-keys` subcommand: pulls a fresh public-key manifest from any of the trust-root channels (Keel API, GitHub) into `~/.keel-verifier/trust-root.json`. Subsequent verifications prefer the cached manifest over the wheel-bundled trust root, so the bundled snapshot does not need to be regenerated when Keel rotates a signing key.
- Trust-root resolution order is now: explicit `--key-manifest[-url]` → cached `~/.keel-verifier/trust-root.json` → wheel-bundled `data/trust_root.json`.
- New `--source` flag on `refresh-keys` (`auto` | `api` | `github`); default `auto` tries channels in order.
- Bump package metadata and module version to v1.0.4

## v1.0.3 (2026-05-07)

- README clarity pass for verifier trust-boundary language
- Add scheduled CI check for bundled trust-root drift against live endpoints
- Bump package metadata to v1.0.3

## v1.0.2 (2026-05-07)

- Bundle permit-binding trust-root keys in `keel_verifier/data/trust_root.json`
- Add test/tool coverage for bundled trust-root key material
- Bump package metadata and module version to v1.0.2

## v1.0.1 (2026-05-07)

- Detect array-order and duplicate-sequence tampering as `WALK_SEQUENCE_INVERSION`
- Update CLI help/documentation URLs to `api.keelapi.com`
- Precision-harden README trust-boundary language
- Bump package metadata and module version to v1.0.1

## v1.0.0 (2026-05-07)

- Add `--walk-events` flag (Phase C verifier walking)
- Add `--verify-closure` flag (Phase C closure record verification)
- Add support for `closure_v2` with `dispatch_request_digest_v1` cross-reference (Phase D)
- Add `WALK_RECORD_HASH_MISMATCH`, `WALK_PREV_HASH_DISCONTINUITY`, `WALK_SEQUENCE_INVERSION`, `WALK_UNKNOWN_CHAIN_FORMAT`, `WALK_CLOSURE_SIGNATURE_INVALID`, `WALK_CLOSURE_DIGEST_MISMATCH`, `WALK_CLOSURE_DIGEST_MISSING`, `WALK_CLOSURE_DISPATCH_DIGEST_MISMATCH`, and `WALK_UNKNOWN_CLOSURE_FORMAT`
- Add `pyproject.toml` for pip-installable distribution
- PyPI package name: `keel-verifier`; console script: `keel-verify`
- Backward compat: `python -m keel_verifier` still works for existing v0.2.0 users
- Bundle production trust root with active-window metadata for currently public export/checkpoint signing keys
- Preserve the no-`app.*` import trust boundary

## v0.2.0

- Added bundled production trust-root verification by default
- Preserved `--self-attested` for development and sample artifacts
- Preserved `python -m keel_verifier <artifact>` invocation
