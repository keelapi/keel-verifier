# Changelog

## v2.4.3 — suppress benign sigstore-python warning (2026-05-23)

- Scoped logging filter for the `Failed to load a trusted root key: unsupported
  key type: 7` warning emitted by sigstore-python 3.x's TUF root loader during
  `keel-verify self-check`. Key type 7 in the installed `sigstore-protobuf-specs`
  enum is `PKIX_ED25519`, and the skipped key is the Rekor v2 transparency log
  (`log2025-1.rekor.sigstore.dev`) that sigstore 3.x does not yet validate
  against. Current bundles are logged in Rekor v1, so skipping the v2 key is
  non-blocking for verification.
- Filter is scoped to the exact warning string only — NOT blanket suppression of
  sigstore-python warnings. To be removed when migrating to sigstore 4.x (after
  Rekor v1 sunset). See upstream pypa/sigstore-python#1423 and #1424.
- Floor pin `sigstore>=3.6.7,<4` (was `>=3.0,<4`).
- Regression test in `tests/test_self_check_happy.py` asserts stderr is clean
  during `verify_sigstore` against a v2.4.2 fixture bundle.
- No runtime verification logic changes from v2.4.2.

## v2.4.2 — source drift fix + trusted publishing (2026-05-23)

- Stop hardcoding `keel_verifier.__version__`; runtime version now comes from
  installed package metadata, with a source-tree fallback matching
  `pyproject.toml`.
- Regenerate the embedded release manifest for v2.4.2 so local-built wheels
  reference the v2.4.2 GitHub Release instead of stale v2.4.0 assets.
- Add version-consistency regression tests covering `pyproject.toml`,
  `keel_verifier.__version__`, the embedded manifest tag, and embedded
  manifest URLs.
- Add a Trusted Publishing PyPI job that publishes the GitHub Actions-built
  wheel and source distribution after the GitHub Release upload. Until
  Trusted Publishing is activated on PyPI, fallback publication must download
  release artifacts from GitHub and upload those files with Twine.
- v2.4.1 is yanked on PyPI because the PyPI upload used a stale local build
  whose embedded manifest still pointed at v2.4.0 release assets.

## v2.4.1 — bundle format fix (2026-05-23, YANKED)

- Switch the release workflow's `cosign sign-blob` calls to
  `--new-bundle-format`, producing Sigstore Bundle Format v0.3 (`mediaType:
  application/vnd.dev.sigstore.bundle+json;version=0.3`). The legacy cosign
  bundle format (`base64Signature` + `cert` + `rekorBundle`) is not readable
  by `sigstore-python`'s `Bundle.from_json()`, which caused `keel-verify
  self-check` to fail at the `sigstore_signature` stage on v2.4.0.
- Update the `RELEASING.md` verification recipe to add `--new-bundle-format`
  to the three `cosign verify-blob` commands. (The SBOM attestation
  `cosign verify-blob-attestation` command is unchanged — DSSE in-toto
  attestations use a different format and were not affected by the bug.)
- v2.4.0 is yanked on PyPI. Releases from v2.4.1 onward use the new bundle
  format throughout.
- **Yank note**: v2.4.1 is yanked on PyPI because the locally built PyPI wheel
  carried stale v2.4.0 runtime metadata and embedded release-manifest URLs.
  The GitHub Release artifacts for v2.4.1 were built by Actions and had the
  corrected v2.4.1 embedded manifest.

## v2.4.0 — A.2: TSA witness + self-check (2026-05-23, YANKED)

- Add `keel-verify self-check` for installed-wheel verification against the signed release manifest (full Sigstore signature + cert chain), the Rekor inclusion proof, the DigiCert and GlobalSign TSA witnesses, the RFC 8785 JCS embedded-manifest binding, and per-file wheel digests.

- Add `keel-verify self-check` for installed-wheel verification against the signed release manifest (full Sigstore signature + cert chain), the Rekor inclusion proof, the DigiCert and GlobalSign TSA witnesses, the RFC 8785 JCS embedded-manifest binding, and per-file wheel digests.
- TSA witness verification is **bind-level by default** — the receipt is parsed, its status is confirmed as `granted`/`granted_with_mods`, and its `messageImprint` is checked to match the signed manifest hash. This mirrors the existing keel-verifier checkpoint-TSA doctrine (`verifier.py:_verify_tsa_receipt`). Full CMS signature and certificate-chain validation against TSA trust roots remains opt-in via the existing `--tsa-ca-bundle` extension pattern.
- **Note**: v2.4.0 is yanked because the release workflow used cosign's
  legacy bundle format for `.sigstore` files, which `sigstore-python`
  cannot parse. v2.4.1 fixes this. See the v2.4.1 entry above.
- Use `asn1crypto` for BER-tolerant ASN.1 parsing of RFC 3161 receipts (replaces `rfc3161-client`, which enforced strict-DER set ordering that real-world DigiCert and GlobalSign receipts do not satisfy).
- Add `embedded_manifests` bindings to the signed release manifest and enforce cycle-prevention rules for the embedded `_release_manifest.json`.
- Add the detached `manifest.json.tsa.json` release sidecar carrying DigiCert and GlobalSign RFC 3161 timestamp receipts for `manifest.json`.
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
- Consume the promoted `keel-permit` v1.4.1 public corpus for the Step 4 permit-claim negative and edge fixtures; local generated unit fixtures remain implementation tests only.
- Finalize the 2.3.0 capability inventory against the claim registry, permit semantics pins, and complete Step 4 failure-code subset.
- Verify wheel package data includes the permit semantics, permit-revoked event schema, and historical claim-registry byte bundle needed by clean installs.

## v2.2.0 — release provenance spine (2026-05-21)

- Release artifacts are now Sigstore-signed through GitHub Actions OIDC and logged to the public Rekor transparency log.
- Add a signed `manifest.json` release manifest covering the wheel, source distribution, SBOM, Sigstore bundles, Rekor log indices, and build-environment metadata.
- Add a release-time CycloneDX SBOM attestation for the wheel.
- Every wheel now carries `keel_verifier/_release_manifest.json` with per-file digests and release-manifest URLs for future installed-package self-verification.
- No new verifier adjudication functionality is included in v2.2.0; installed-wheel self-check follows in v2.4.0.

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
