# Changelog

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
