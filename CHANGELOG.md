# Changelog

## v2.0.0 (2026-05-19)

- Add pack-pinned semantics: the verifier pins `(semantic_id, sha256)` and dispatches verification logic from a permanent, append-only allowlist. A version-pinned pack receives reproducible adjudication: future verifier releases reach the same claim verdicts or explicitly decline, and never silently reinterpret a prior pinned claim.
- Emit structured per-claim verdicts using the four-value enum `supported`, `disproved`, `insufficient_evidence`, and `unverifiable_scope`. `--json` output gains an additive `claims` array carrying these verdicts; existing top-level fields (`ok`, `self_attested`) are unchanged.
- Enforce required claims: for a pinned pack, every claim its `claim_set` marks `required` is adjudicated; a required claim with no evidence is `insufficient_evidence`; `ok` is true only when every required claim is `supported`.
- Add opt-in TSA-authenticity validation: `--tsa-ca-bundle` runs OpenSSL-backed RFC 3161 TSA trust-chain validation as a separate, opt-in trust extension. It does not check historical revocation.
- Register and adjudicate the new `permit_chain.delegation_denied_correctly.v1` claim for `permit.delegated_denied` events correctly denied under `authority-envelope.v0` semantics.
- Make the packaged verifier the single verification core. The wheel bundles the released verifier artifact set.
- Bump package metadata and module version to v2.0.0.

### Breaking changes

- For pinned packs (those carrying a `claim_set`), required-claim enforcement can fail a pack that previously passed. Legacy and unpinned exports are unaffected.

### Compatibility

- The CLI invocation surface is unchanged. Existing `export` and `checkpoint` invocations, including `python -m keel_verifier <artifact>`, work as before.
- Evidence produced by v1.x — exports and checkpoints without pinned semantics — continues to verify, evaluated under the permanent pre-pinning profile.

## v1.1.0 (2026-05-13)

- Verifies `keel.vanta.workflow_evidence/v1` sibling schema: declaration signatures, amendment ordering and signatures.
- Recognizes incident bundle `manifest_version: 2` with new `workflow_declarations.jsonl` and `workflow_amendments.jsonl` files.
- Re-derives `effective_intent_hash` (`SHA-256(declaration.intent_json ‖ ordered amendments at decision time)`) and verifies it matches the value carried in `permit.workflow_state_json`.
- Workflow declaration and amendment signatures are validated against the existing `permit_binding_signing` public-key purpose from the bundled trust root — no new key sources required.
- Backward compatibility: v1 bundles (no workflow files) verify unchanged.
- Bump package metadata and module version to v1.1.0

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
