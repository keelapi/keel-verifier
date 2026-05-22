# Changelog

## Unreleased

- Add public security reporting policy, README badges, compact common commands, TSA trust-validation docs, and clearer network-behavior wording.
- Accept `--json` on `keel-verify claim delegation_denied_correctly` for documented CLI compatibility; claim output remains JSON by default.
- Add Ruff configuration and CI linting.
- Add an explicit source-distribution manifest so tests, fixtures, samples, tools, and public metadata are included consistently.
- Add Python version classifiers to PyPI metadata so the Python versions badge resolves correctly.
- Ignore local `.claude/` workspace settings at the repository level.

## v2.3.0 — Step 4 permit adjudication (2026-05-22)

- Add verifier-side adjudicators for `permit.decision.v1`, `permit.revoked.v1`, and `permit.dispatch_absence_after_revocation.v1`.
- Add scope-faithful absence adjudication for post-revocation `dispatch.egress_bound` evidence, including the strict lower-bound timestamp rule and the `EXPORT_SCOPE_POST_REVOCATION_DISPATCH_PRESENT` failure code.
- Add `EXPORT_SCOPE_BRIDGE_RECORD_MATCHES_PREDICATE` for bridge/proof records that satisfy the absence predicate while preserving `EXPORT_PROOF_BRIDGE_MISCLASSIFIED` for generic scope-faithfulness bridge validation.
- Bundle Permit v1.4.0 pinned semantics, the permit-revoked event schema, and all historical claim-registry bytes needed to resolve pinned registry references.
- Update the capability inventory and test coverage for the new permit claim family.

## v2.2.0 — release provenance spine (2026-05-21)

- Release artifacts are now Sigstore-signed through GitHub Actions OIDC and logged to the public Rekor transparency log.
- Add a signed `manifest.json` release manifest covering the wheel, source distribution, SBOM, Sigstore bundles, Rekor log indices, and build-environment metadata.
- Add a release-time CycloneDX SBOM attestation for the wheel.
- Every wheel now carries `keel_verifier/_release_manifest.json` with per-file digests and release-manifest URLs for future installed-package self-verification.
- No new verifier adjudication functionality is included in v2.2.0; the friendly `keel-verify --self-check` wrapper follows in v2.3.0.

## v2.1.0 — scope-faithful export adjudication (2026-05-20)

### Added

- Add `checkpoint.scope_state.v1` and `export.scope_faithfulness.v1` adjudication for checkpoint-bound scope-state sidecars and signed scope-faithful export packs.
- Add capability inventory entries for the new claims, the `checkpoint_scope_state_v1` artifact format, the Step 2 failure-code subset, and the newly pinned scope-state/export semantics.
- Add the scope-faithfulness CLI verification surface for export segments backed by scope-state sidecars.
- Add vendored pinned semantics for `keel.scope_state.merkle.v1`, `keel.scope_state.sidecar_format.v1`, and `keel.export.scope_faithfulness.v1`.

### Changed

- Clarify the `export.scope_identity.v1` capability description wording only; pinned semantics and verifier behavior are unchanged.

### Compatibility

- Existing v1.x packs continue to verify under the permanent pre-pinning profile.
- Existing v2.0.x packs are unchanged.
- Scope-faithfulness corpus discovery now consumes the public `keel-permit/test-vectors/verifier_claims/v0` path.

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
