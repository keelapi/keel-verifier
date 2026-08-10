# Changelog

## 3.18.0

- Vendor the exact Payment & Ledger contracts, fact-profile registry v5,
  semantic selector registry v7, presentation registry v6, and conformance
  vectors from `keel-permit v1.17.0`.
- Resolve and verify signed AI Permit-to-Pay-Invoice,
  AI Permit-to-Record-Ledger-Entry, and AI Permit-to-Reconcile-Payment
  artifacts while retaining byte-identical support for every earlier registry.
- Reject cross-action fact/profile substitution and fail closed when invoice,
  double-entry, or reconciliation preconditions do not validate against the
  signed exact-facts schema.

## 3.17.0

- Vendor the immutable database exact-facts contract, fact-profile registry v4,
  semantic selector registry v6, presentation registry v5, and conformance
  vectors from `keel-permit v1.16.0`.
- Admit exact database contract pins during offline verification while retaining
  byte-identical support for every previously released registry version.
- Validate action-specific database facts and reject cross-action fact-profile
  substitution, including a coherent facts object riding inside a different
  signed semantic binding, before a database Permit can receive a specific title.

## 3.16.0

- Vendor the additive consequence registry, semantic selector registry v5,
  presentation registry v4, and database-action conformance vectors from
  `keel-permit v1.15.0`.
- Resolve exact, signed database action semantics as
  AI Permit-to-Insert-Database-Rows, AI Permit-to-Update-Database-Rows,
  AI Permit-to-Delete-Database-Rows, AI Permit-to-Apply-Database-Migration,
  and AI Permit-to-Export-Dataset while preserving every historical title.
- Keep unknown registry versions, mismatched profile identifiers, and
  unverified caller labels on the generic AI Permit fallback.

## 3.15.0

- Vendor the human-first Permit-to-X v3 presentation registry from
  `keel-permit v1.14.0`, deterministic
  summary semantics, human artifact schema, package manifest schema, and
  conformance vectors from `keel-permit`.
- Derive exact Permit report titles from the already-verified signed semantic
  and presentation profile instead of hardcoding Permit-to-Pay. Preserve the
  historical Refund title while resolving newly issued refund evidence as
  AI Permit-to-Refund-Payment; unknown or mismatched profiles fail generic.
- Add a schema-valid human Permit projection with issued/expires/status fields,
  verifier-derived summary, evidence boundaries, trust mode, and no caller
  authority over title or summary. Verifier JSON includes only fields marked
  safe by the pinned fact profile.
- Verify `.keelpermit` package inventory without extraction, reject traversal,
  links, encryption, duplicate/unlisted files, digest or size drift, ambiguous
  roles, and pointer substitution, then verify signed evidence and regenerate
  the human view. Default output remains human-first; `--json` and `--raw`
  expose advanced views.

## 3.14.0

- Adjudicate `keel.permit_co_signature/v1` bodies in single-file evidence
  bundles, so a downloaded Permit co-signature artifact verifies with
  `keel-verify export <file>` and no manifest sidecar. Previously such a body
  produced an envelope-only `VERIFIED` result with no co-signature claim.
- Accept `keel.evidence_bundle/v2`, which carries the same shape as v1 but
  obliges a reader to adjudicate the declared body profile or fail closed.
  Co-signature evidence ships as v2 so a verifier lacking this support refuses
  the artifact rather than reporting the envelope alone as verified.
- Fail closed when an evidence-bundle body carries co-signature evidence under
  no adjudicable profile, and when a co-signature profile is unknown.
- Reject body-supplied WebAuthn user-verification downgrades in self-attesting
  co-signature bundles; the envelope key is not pinned to the Keel trust root
  and must not be able to weaken the ceremony.
- Adjudicate co-signature quorum only when the requirement is bound into a
  v6-or-later decision binding, where resource attributes are hashed into the
  signed canonical payload.

## 3.13.1

- Verify current `permit_semantic_binding_v2` material in `work-chain.v1`
  roots and action children while preserving historical v1 compatibility.
- Fail closed when a Work Permit carries ambiguous or field/version-mismatched
  semantic-binding material.

## 3.13.0

- Adjudicate `keel.permit_exact/v3` packs and reject unknown future exact-pack
  profiles instead of silently omitting exact consequence claims.
- Verify Work issuance-time and dispatch-time enforcement regimes against the
  keel-permit v1.13.0 claim contract, while preserving an honest
  `not recorded` result for historical v1 runtime proofs.
- Compose digest-pinned universal verification semantics through v4 so newer
  recipes retain every inherited verification rule.
- Verify Work enforcement state independently for the root and every child,
  and fail closed when a partially stamped chain claims enforcement evidence.
- Vendor keel-permit v1.13.0 schemas, claim registry v5, universal semantics
  v4, and their golden corpora under the cross-repository parity gate.
- Refresh the TSA trust bundle and schedule reviewed refresh pull requests
  before its freshness guard can block verifier releases.

## 3.12.0

- Adjudicate the exact Generate Text and Refund consequence claims
  (`permit.generate_text_exact_request.v1`,
  `permit.refund_original_payment_bound.v1`) against the Permit-to-X contract
  released in keel-permit v1.11.0.
- Verify Delegate child continuity (`permit.delegate_child_linkage.v1`):
  intended, created, grant-delegate, and acting-child commitment equality, plus
  action-Permit binding and authority-chain digests when acting-child linkage
  is claimed.
- Bind the Delegate semantic to the signed authority grant and honor transport
  rejection evidence distinctly from provider acceptance or completion.
- Add SHA-256-keyed historical claim-registry snapshots so artifacts issued
  against earlier registries keep resolving their claim definitions after v4.
- Vendor the Permit-to-X v1.11.0 exact-action schemas, fact profiles, semantic
  and claim registries, and golden corpora byte-for-byte under the cross-repo
  parity gate.

## 3.11.2

- Preserve every universal exact claim's pinned `does_not_establish` ceiling
  in structured verifier output, including missing, incomplete, disproved, and
  provider-asserted evidence states.
- Merge result-specific provider limitations with the registry ceiling rather
  than replacing broader settlement, deletion, deployment-health, or external
  outcome limits.

## 3.11.1

- Resolve `keel.permit_bounded_use.v1` child evidence against the existing
  pinned `permit_binding_signing` authority, matching the API runtime signer
  while preserving the artifact's domain-separated version and signature
  profile.
- Keep the trust-purpose mapping deliberately narrow: adapter certification,
  deployment assurance, and runtime enforcement proofs still require their
  own independently pinned signing purposes.

## 3.11.0

- Add the fact-profile-driven `keel.permit_exact/v2` adjudicator and released
  `verifier-claims.v2` extension without changing historical v0/v1 claim
  interpretation.
- Emit structured, consequence-neutral claims for exact Permit type, target,
  material request, dispatch-time validity and revocation, certified
  enforcement, bounded and single use, replay, idempotency, and provider
  receipt states.
- Verify the signed Permit decision as the authority source, embedded
  release-pinned contracts by exact bytes and digests, selector uniqueness,
  profile-specific facts, and privacy-safe low-entropy commitments.
- Verify active adapter certification, customer deployment assurance, runtime
  enforcement proof, and signed monotonic bounded-use transitions as
  digest-bound chains; missing scope-faithful evidence remains explicitly
  unverifiable rather than inferred.
- Add the reusable provider receipt state machine while preserving the
  transport-observation ceiling and claim-level `does_not_establish` for
  provider assertions and external outcomes.
- Vendor the Permit-to-X v1.10.0 universal schemas and cross-repository
  conformance corpus, and add negative coverage for semantic ambiguity,
  expiry, revocation, certificate substitution and expiry, limit overflow,
  replay, idempotency rebinding, provider state ceilings, and low-entropy
  plain hashes.

## 3.10.1

- Make the historical compatibility release gate non-vacuous in tag builds by
  checking out the exact released `keel-permit` v1.9.1 contract and golden
  corpus before packaging. The failed v3.10.0 tag produced no release
  artifacts and is superseded by this patch release.

## 3.10.0

- Cross-bind exact Permit semantics, authorization facts, and payment
  classification to the resource-attribute commitment of a separately
  supported signed Permit decision. Receipt projections are comparison
  evidence only and can no longer supply authority.
- Emit `permit.exact_action.v1` for both success and failure, including a
  signed-bundle negative proving that a divergent receipt cannot be masked by
  otherwise-valid outer-pack and Permit-decision signatures.
- Correct `permit.co_signature.v1` to establish only the WebAuthn ceremony
  when its target is an unsigned export projection; expose the limitation as
  claim-level `does_not_establish`.
- Add target-bound `permit.co_signature.v2` and signed-requirement
  `permit.co_signature.quorum.v1` adjudication, including a self-consistent
  false-target replay negative.
- Adopt released `verifier-claims.v1` while preserving the historical v0
  registry and pinned semantic recipes, and add claim-level
  `does_not_establish` output.
- Resolve semantic registry v3 in Permit presentation so current
  AI Permit-to-Pay evidence retains its specific title.
- Confirm the bundled production-signed trust root, remove its stale
  pre-production note, refresh issuer-verified TSA CRL snapshots, and add a
  scheduled fail-loud refresh workflow.
- Add a release-gated historical compatibility corpus covering issued
  Permits, evidence bundles, registry versions, fact profiles, trust roots,
  exact-action divergence, and co-signature false-target evidence.

## 3.9.0

- Verify canonical `keel.permit_exact/v1` evidence packs for
  AI Permit-to-Pay, including signed exact amount, currency, payment rail,
  request digest, privacy-preserving recipient commitments, and optional
  recipient openings.
- Re-derive `payment.execute` from the signed payment classification in the
  production report pipeline and reject mismatched fact, selector, schema, or
  registry digests.
- Adjudicate the original signed review decision and the separately signed
  human-review transition without treating mutable Permit row state as
  issuance-time evidence.
- Render actionable incomplete-check reasons and exact Permit-to-Pay facts in
  the human report while preserving explicit non-claims for dispatch, provider
  success, and settlement.
- When the selected cached trust root lacks the Permit-binding signing key,
  identify the cache path and recommend the explicit signed-manifest refresh
  command without enabling automatic network access during verification.

## 3.8.0

- Add the reference verifier for MCP payment classification derivation
  (keel.permit.action_classification_derivation.v1). Given a permit's signed
  classification facts and an explicit immutable trust configuration, it
  re-derives the authorized_action offline from signed facts plus the vendored,
  hash-pinned keel-permit artifacts alone, trusting nothing the issuer asserts
  about the classification. Display-only and strictly non-authorizing.
- Vendor the value-movement classification registry, the derivation ruleset, and
  the conformance corpus byte-for-byte from keel-permit, under the cross-repo
  parity guard. All 14 corpus vectors pass against the production module.

## 3.7.0

- Resolve each permit against the semantic registry it was issued under.
  Bindings embed `selector_registry_version` and digests of the registry and
  matched entry; loading a single hardcoded registry meant publishing a new one
  would retitle every historical record to "specific title unavailable". v1
  stays vendored for the life of any record issued under it, and an unrecognised
  version resolves to the historical fallback rather than borrowing a title.
- Vendor semantic registry v2, in which surface is no longer part of authority
  identity. The surface check is applied only where a registry declares one, so
  v1 records keep their constraint and v2 records are not rejected by a missing
  key read as an empty allow-list.

## 3.6.0

- Add independent `work-chain.v1` verification for Work authority, child
  containment, dispatch-boundary liveness, and payment value conservation.
- Add self-contained Work evidence artifact validation, exact Permit binding
  verification, signed export-scope checkpoints, and explicit negative-space
  diagnostics for facts the evidence does not establish.
- Add the generic Permit-to-X human renderer with signed semantic provenance,
  historical presentation resolution, generic fallback, and a presentation
  isolation test proving titles cannot affect claim verdicts or exit status.

## 3.5.1

- Add offline adjudication for `permit.co_signature.v1`, including strict
  Phase-0 WebAuthn verification, independently derived Permit binding,
  signed-pack integrity gating, and Keel-pinned signed co-signer key-status
  resolution with `custody_tier=human_passkey`.
- Extend the pinned claim registry and key-status manifest vocabulary for
  project-scoped co-signer passkeys while retaining legacy key-status manifest
  compatibility.

## 3.5.0

- Add release-pinned TSA chain validation for checkpoint RFC 3161 receipts,
  including offline DigiCert/GlobalSign trust material, timestamping EKU
  enforcement, certificate validity at `genTime`, and CRL revocation checks at
  `genTime`.
- Harden TSA trust regression coverage with real OpenSSL 3 certificate-chain
  negatives and real CRL boundary fixtures, plus a CI OpenSSL 3 gate for the
  load-bearing TSA tests.
- Default checkpoint verification now reports
  `tsa_chain_validation: "not_validated"` for receipts outside the
  release-pinned trust bundle instead of the legacy `tsa_trust_status:
  "skipped"` envelope.

## 3.4.6

- Add the `authority.root_status_temporal.v2` adjudicator: offline-verifiable
  proof that a dispatch did not rely on a root authority after its terminal
  disable time. The adjudicator consumes v1 root-status events for pre-disable
  liveness and v2 events for terminal disable evidence, supports dispatches
  before `disabled_at`, disproves dispatches at or after `disabled_at`, and
  remains masking-resistant by checking terminal disable before
  latest-event-wins status selection. Additive only: the v1 adjudicator,
  schema, and registry entry are unchanged, and the new claim fires only when
  explicitly pinned.

## 3.4.5

- Add the `rail.settlement_reconciled.v1` adjudicator: offline-verifiable proof
  that a rail spend's settled amount reconciles within the permit's spend
  authority (`amount_max`) against an attested settlement record bound into the
  Keel receipt for the bound settlement reference (transaction id + network).
  The settlement record is sourced from a non-Keel authority (the x402
  facilitator's attested settlement for `source_class=facilitator_attested`, or
  an on-chain transaction receipt for `source_class=chain_read`), and the
  adjudicator verifies the reconciliation digest binding the settlement into the
  execution-record hash under the pinned rail settlement-reconciliation
  semantics. This mirrors the `authority.edge_revocation.v1` release shape.
  Additive only: the new adjudicator fires only when the claim is explicitly
  pinned, no existing claim's behavior or semantics hash changes, and the
  claim-registry hash is re-pinned in lockstep with the prior registry
  snapshotted to history.

## 3.4.4

- Add the `authority.edge_revocation.v1` adjudicator: offline-verifiable proof
  that R3's dispatch-time authority-edge revocation was honored before dispatch
  resolution. It adjudicates signed `key.status.v1` governance-chain evidence
  (`key_scope=authority_edge`) for the edge digests in the authority chain,
  recomputing the canonical `event_hash` and verifying the Ed25519 signature
  under an active permit-binding key, and disproves when a verified revocation
  for an in-chain edge digest is effective at or before the resolution time.
  This is the offline mirror of the shipped `authority.root_status_temporal.v1`
  claim and the runtime authority-edge liveness check. Additive only: the new
  adjudicator fires only when the claim is explicitly pinned, no existing
  claim's behavior or semantics hash changes, and the claim-registry hash is
  re-pinned in lockstep with the prior registry snapshotted to history.

## 3.4.3

- Make `keel-verify export` default to the human-readable AI Permit
  verification report, while preserving the legacy technical verifier output
  behind `--raw`.
- Keep `--report` as an explicit compatibility flag for scripts and leave
  `--json` precedence unchanged.

## 3.4.2

- Harden permit v2 signer-slot key resolution by binding each resolved
  signer `key_id` to the SHA-256 digest of the Ed25519 public key bytes.
- Add checkpoint consistency monitoring and keep the release trust-root gate
  closed over signed public-key manifests with Rekor-aware validation.

## 3.4.1

- Add witnessed key-status revocation governance over signed key-status
  manifests, including status-transition coverage for production trust roots.
- Add v7 permit-binding verification support with selector-audit guarding,
  negative corpus coverage, golden vectors, and byte-equivalence floors.
- Add R2c authority-chain and revocation-temporal adjudicators for delegated
  authority evidence.
- Enforce the trust-root publication gate and bundle the now-signed production
  trust root.

## 3.4.0 — self-attesting evidence bundle support

- Add `keel.evidence_bundle/v1` parsing before legacy split-file export
  verification. Single-file bundles verify `artifact_ref.v1`,
  `signature_envelope.content_hash`, Ed25519 signature, and bundled RFC 3161
  TSA receipt imprints without network access.
- Preserve backward compatibility for legacy `export + manifest` verification
  while emitting a deprecation warning for split-file input.
- Accept self-attesting checkpoint bundles in `keel-verify checkpoint` by
  validating the wrapper first, then running the existing checkpoint
  composite-hash, signature, and TSA checks against `bundle.body`.
- CLI auto-detects self-attesting bundles when invoked with a bare file path
  (`python -m keel_verifier <bundle.json>`) and routes to the `export`
  subcommand. Previously the bare form fell through to legacy verification
  and produced a confusing `missing or malformed composite_hash` error.
- Parse `artifact_ref` (artifact_ref.v1 schema) from new-format bundles
- Surface URN as stable artifact identity in verbose output
- Verification is offline-first: URL reachability is diagnostic, never a verification gate
- Forgiving for legacy bundles without artifact_ref (deprecation warning, still verifies)
- Accept `keel.evidence/v1` and `keel.workflow_evidence/v1` while keeping
  legacy Vanta-prefixed schema names verifiable with a deprecation warning

## v3.3.1 — Permit-decision v1-v6 golden vectors (2026-06-13)

- Adds shared golden vectors for `permit.decision.v1` bindings across v1-v6,
  including the v5 RFC 8785 selector shape and v6
  `resource_attributes_canonical_hash`.
- Confirms the existing v5/v6 permit-decision adjudication path accepts signed
  evidence offline and preserves `PERMIT_DECISION_SUPPORTED` verdicts for all
  supported binding versions.
- No runtime verifier changes are required beyond the v3.3.0 v6 implementation.

## v3.3.0 — Binding v6 resource-attributes canonical hash (2026-06-06)

- Adds binding v6 canonical payload support with
  `resource_attributes_canonical_hash` over RFC 8785 canonical
  `resource_attributes_json` bytes, including the locked empty-object digest.
- Verifies v6 permit-decision replay with the four-part invariant: stored v6
  version, present resource-attributes hash, matching recomputed
  resource-attributes hash, and matching signed canonical payload hash.
- Sweeps verifier-side v5 RFC 8785 selectors to v5/v6 while keeping the v6
  recompute-entry predicate exact on `binding_version == "v6"`.

## v3.2.0 — Binding v5 RFC 8785 canonical support (2026-06-05)

- Adds binding v5 (RFC 8785 JCS canonical) as the new default for newly-issued
  permits.
- Verifies v5 permit-decision bindings, including spend-scope and
  delegation-policy sub-hash tamper detection with v5-specific reason codes.
- Adds v5 canonical byte-identity coverage and drift locks while preserving
  v1-v4 golden vectors.

## v3.1.0 — Permit binding-version coverage (2026-06-04)

- Expand `permit.decision.v1` adjudication from v1-only bindings to v1, v2, v3,
  and v4 canonical permit bindings without changing the claim ID.
- Add independent v3 spend-scope and v4 delegation-policy sub-hash recompute
  checks from exported `resource_attributes_json`.
- Port keel-api permit-binding canonical builders into the verifier package for
  byte-identity regression coverage without importing keel-api.

## v3.0.0 — Verifier UX rendering (2026-06-02)

- Add `keel-verify render` for `verifier_output.v3.0` documents with `json`,
  `tree`, `graph`, and `html` output modes.
- Embed the locked 20-outcome render table in the renderer and render
  command help for downstream dashboard and auditor tooling.
- Preserve verification semantics: the render command consumes already
  evaluated `verifier.*` and `execution.*` namespaces and does not re-adjudicate
  provider-attestation outcomes.

## v2.7.0 — Voice-session attestation schema v3 compatibility (2026-05-25)

- Accept voice-session attestation schema v3 artifacts from Keel API's
  hash-only materialization format (`artifact_version=1.2.0`) alongside legacy
  schema v1 artifacts (`artifact_version=1.0.0`).
- Preserve the existing schema v1 verification path while adding schema v3
  chain validation for `payload_materialization=hash_only` and
  `canonicalized_payload_hash` entries.
- Add a synthetic public v3 sample at `sample/voice_session_export_v3.json` and
  regression coverage for v1, v3, and v3 hash tamper detection.

## v2.6.0 — Voice-session attestation support (2026-05-25)

- Add auto-detection for voice-session attestation artifacts via the
  top-level `verifier_compatibility` block while preserving the legacy
  single-file checkpoint verification path.
- Verify session-chain hash linkage, Ed25519 signatures over canonical
  artifact bytes, RFC 3161 timestamp receipts, and embedded policy snapshot
  hashes.
- Add a synthetic public sample at `sample/voice_session_export.json` and
  regression tests for the voice-session happy path, tamper detection, legacy
  backward compatibility, and format auto-detection.

## Unreleased — Permit slot-signature adjudication

- Add verifier adjudication for `permit.operator_approval.v1`,
  `permit.counter_signature.v1`, and `permit.audit_attestation.v1` while
  preserving the earlier `*_approved/*_signed/*_attested` compatibility names.
- Pin the latest slot semantics, including the updated
  `permit.counter_signature.v1` hash
  `sha256:04537c19524dca4098442becbeca7b0377759e323b035dadd7f0cd0c79bc2143`.
- Verify counter-signature `execution_intent_hash` against canonical
  `permit.counter_signature.execution_intent.v1` dispatch facts and use runtime
  failure code `counter_signature.execution_intent_mismatch` on mismatch.
- Add dotted claim CLI subcommands and a 45-record permit v2 slot-signature
  corpus covering positive, negative, and edge fixtures for all three slots.

## v2.5.1 — keel-verify doctor diagnostic command (2026-05-24)

- New: `keel-verify doctor` — environment diagnostic command. Reports install
  form, Python interpreter, import location, sys.path, PYTHONPATH, .pth
  shadows, cache state, and what self-check would do given current state.
- Pure-local by default. Opt-in `--check-network` checks PyPI, Sigstore/Rekor,
  and TSA endpoint reachability with HEAD requests.
- Add `--fail-on-problem` for CI gate usage.

## v2.5.0 — explicit --published-wheel self-check mode (2026-05-24)

- New: `keel-verify self-check --published-wheel[=VERSION]` verifies the
  published wheel from PyPI (downloads + verifies SHA-256 + runs full chain
  against unpacked wheel) instead of the installed copy. Useful for developers
  with editable installs who want to verify published artifacts without leaving
  their dev environment. Output explicitly distinguishes published-wheel
  verification from installed-copy verification.

## v2.4.4 — self-check remediation + shadow-import detection (2026-05-24)

- Self-check emits structured remediation hints for environment-related failures.
- New stage `import_isolation` detects when another `keel_verifier` on `sys.path`
  shadows the installed wheel, with new failure code `SELF_CHECK_SHADOW_IMPORT`.

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
