# keel-verifier

[![PyPI](https://img.shields.io/pypi/v/keel-verifier.svg)](https://pypi.org/project/keel-verifier/)
[![Python](https://img.shields.io/pypi/pyversions/keel-verifier.svg)](https://pypi.org/project/keel-verifier/)
[![CI](https://github.com/keelapi/keel-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/keelapi/keel-verifier/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Independent verifier for Permit-spec governance evidence and Keel audit exports.

## Why this exists

Most AI platforms can tell you what they logged.

This verifier detects post-signing tampering of exported governance evidence. An auditor, customer, regulator, or security team can independently verify decisions, dispatched requests, returned responses, and lifecycle evidence integrity.

Verification runs locally and does not require access to Keel's systems.

## What this verifier can and cannot prove

The verifier proves exported evidence has not been altered after signing. Like any signing system, the trust boundary includes the signer at signing-time. Defending against privileged signing-time manipulation requires a higher-assurance signing architecture beyond the scope of this verifier.

In practical terms:
- Post-signing tampering of any element in the permit lifecycle
  (input, dispatch, provider response, client response, closure
  record) is detected — see the Tampering Detection Matrix in the
  online documentation.
- Pre-signing manipulation by a privileged Keel operator at the
  moment evidence is created is NOT detected by this verifier.
  Defending against that threat model requires hardware-backed
  signing (TEE/HSM), a separate capability tier above what this
  verifier covers.

## Quick Start

```bash
python -m pip install keel-verifier
keel-verify export --help
```

From a checkout:

```bash
python -m pip install -e .
python -m keel_verifier --help
```

The v0.2.0 invocation pattern still works:

```bash
python -m keel_verifier sample/export.json --self-attested
```

## Common Commands

| Task | Command |
| --- | --- |
| Verify a signed export | `keel-verify export export.json manifest.json` |
| Walk lifecycle chain entries | `keel-verify export export.json manifest.json --walk-events` |
| Verify closure records | `keel-verify export export.json manifest.json --walk-events --verify-closure` |
| Verify a checkpoint | `keel-verify checkpoint checkpoint.json` |
| Verify a Phase A voice-session artifact | `python -m keel_verifier voice_session_export.json` |
| Verify a registered claim | `keel-verify claim delegation_denied_correctly --evidence-file evidence.json` |
| Refresh cached trust roots | `keel-verify refresh-keys` |
| Verify the installed wheel | `keel-verify self-check` |

## What It Verifies

`keel-verify export` verifies a signed compliance export in four layers:

1. The export bytes match the signed manifest `content_hash`.
2. The manifest Ed25519 signature verifies against a trusted key.
3. Workflow evidence siblings and incident bundle workflow files are verified when present.
4. Optional Phase C/D checks walk bundled chain entries and verify closure records.

`keel-verify checkpoint` verifies integrity checkpoint JSON artifacts: the `chain_heads` composite hash, the Ed25519 checkpoint signature, and an embedded RFC 3161 timestamp MessageImprint when present.

`keel-verify claim` adjudicates pack-pinned evidence packs against the verifier's claim registry — see [Claim Verification](#claim-verification-pack-pinned-semantics) below.

Phase A voice-session attestation artifacts are auto-detected by a top-level
`verifier_compatibility` block when passed to the legacy single-file verifier
entry point. The verifier accepts both the original schema v1 artifact format
(`artifact_version=1.0.0`, embedded canonical payload material) and main's
current schema v3 hash-only format (`artifact_version=1.2.0`,
`payload_materialization=hash_only`):

```bash
python -m keel_verifier sample/voice_session_export.json
python -m keel_verifier sample/voice_session_export_v3.json
```

For these artifacts, the verifier checks the session chain's per-event hash
linkage, the Ed25519 signature over canonical artifact bytes, the embedded
RFC 3161 timestamp receipt's MessageImprint against the project chain head,
and the locked policy snapshot hash. Legacy checkpoint artifacts continue to
use the existing checkpoint verification path.

`keel-verify self-check` verifies the installed wheel form of `keel-verifier`
against the signed release artifact. It verifies the Sigstore-signed release
manifest (full keyless signature and certificate-chain), the Rekor inclusion
proof, the DigiCert and GlobalSign RFC 3161 TSA witnesses (bind-level: the
receipts bind to the signed manifest hash and report `granted` status; full
CMS signature and cert-chain validation against TSA trust roots is opt-in via
the `--tsa-ca-bundle` extension and is not part of the default self-check),
the embedded manifest's RFC 8785 JCS binding, and the wheel package files
listed in the embedded manifest. It does not claim binary or OCI verification.

## Installed Wheel Self-Check

Run self-check after installing from PyPI:

```bash
python -m pip install keel-verifier
keel-verify self-check
```

Successful output is wheel-scoped:

```text
PASS: keel-verifier self-check passed for installed wheel form
  [OK] form: wheel form selected
  [OK] import_isolation: keel_verifier imported from /path/to/site-packages/keel_verifier/__init__.py matches distribution metadata
  [OK] embedded_manifest: embedded release manifest is present and cycle-safe
  [OK] fetch: release manifest, signature, and TSA sidecar loaded
  [OK] sigstore_signature: signed release manifest verifies against expected GitHub Actions identity
  [OK] rekor_inclusion: Rekor inclusion proof is present and verified by sigstore-python
  [OK] tsa_witnesses: DigiCert and GlobalSign RFC 3161 receipts witness the manifest hash (bind-level; cert-chain validation is opt-in)
  [OK] embedded_binding: embedded manifest JCS hash matches signed release manifest binding
  [OK] per_file_digests: installed wheel files match embedded per-file digests
```

Failure output includes a stable error code:

```text
FAILED: keel-verifier self-check failed for installed wheel form
  [FAIL] per_file_digests: SELF_CHECK_FILE_DIGEST_MISMATCH: installed file digest mismatch: keel_verifier/__init__.py
```

Self-check fetches release provenance online by default and uses a 24 hour cache
under `~/.keel-verifier/cache/`. Use `--offline` to require cached provenance,
`--no-cache` to fetch without reading or writing cache entries, and `--json` for
machine-readable stage results.

Developers with an editable checkout can verify the published PyPI artifact
without leaving that environment:

```bash
keel-verify self-check --published-wheel
keel-verify self-check --published-wheel=VERSION
```

This mode is explicit only: the default self-check never pivots to network
wheel downloads. Published-wheel output labels the PyPI wheel source and the
local installed copy separately.

## Obtaining a Signed Export

Request an audit export from the Keel compliance export API and include chain entries when you want full lifecycle walking:

```bash
curl -sS -X POST "https://api.keelapi.com/v1/compliance/exports?include_chain_entries=true" \
  -H "Authorization: Bearer $KEEL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"project_id":"<project_uuid>","format":"json"}'
```

Download both artifacts returned by the export workflow:

- the export payload, for example `export.json`
- the signed manifest, for example `manifest.json`

Then run:

```bash
keel-verify export export.json manifest.json --walk-events --verify-closure
```

The explicit flag form is also supported:

```bash
keel-verify export --export-file export.json --manifest manifest.json --walk-events --verify-closure
```

Export manifests must be signed by default. Legacy unsigned manifests fail closed
after the content-hash check. Use `--allow-unsigned` only for archaeology or
local fixtures where content-hash consistency is useful but issuer authenticity
is intentionally out of scope:

```bash
keel-verify export export.json manifest.json --allow-unsigned
```

## Chain Walking

`--walk-events` parses `audit_export_bundle` files with `schema_version=2` and `include_chain_entries=true`.

It groups entries by `chain_scope`, sorts by `sequence_number`, recomputes every `record_hash`, verifies `prev_hash` continuity inside the export window, and fails closed on unknown `chain_format_version` values.

Schema version 1 exports remain backward compatible. They can still be verified at the export-signature layer, but they do not contain chain entries to walk.

## Closure Verification

`--verify-closure` verifies `permit.closed` entries.

For `closure_v1`, it verifies the closure Ed25519 signature and cross-references provider/client response digests against the bundled lifecycle events.

For `closure_v2`, it also verifies `dispatch_request_digest_v1` against the permit's `binding_request_hash`, verifying that the dispatch-time request body is the one covered by the closure record.

Closure verification uses public keys with purpose `permit_binding_signing`. Pass a manifest explicitly when needed:

```bash
keel-verify export export.json manifest.json \
  --key-manifest permit-binding-keys.json \
  --walk-events \
  --verify-closure
```

The bundled trust root lives at `keel_verifier/data/trust_root.json`. It includes the production export and checkpoint signing keys currently served by `https://api.keelapi.com/v1/compliance/keys`, plus the production permit-binding key served by `https://api.keelapi.com/v1/integrity/permit-binding-public-keys`.

## Workflow Intent Verification

`keel-verify export` understands `keel.vanta.workflow_evidence/v1` artifacts emitted alongside Vanta evidence exports. When the signed export manifest includes a `sibling_artifacts.workflow_evidence` entry, the verifier checks the sibling file hash, export signature, workflow declaration signatures, workflow amendment signatures, amendment version ordering, declaration `effective_intent_hash`, and any permit `workflow_state_json` snapshots in the main evidence.

Incident evidence zip bundles remain backward compatible. Manifest version 1 bundles without workflow files verify as before. Manifest version 2 bundles must include `workflow_declarations.jsonl` and `workflow_amendments.jsonl`; the verifier validates those files and fails gracefully on unknown manifest versions.

## Claim Verification (Pack-Pinned Semantics)

v2.0.0 adds **pack-pinned semantic verification**: an evidence pack can declare which semantic artifacts it was emitted under (by `(id, sha256)`), and the verifier reproduces those exact semantics from a permanent, append-only allowlist. A version-pinned pack receives reproducible adjudication — any future verifier release must resolve those exact pinned semantics and reach the same claim verdicts, or explicitly decline. It never silently reinterprets a prior pinned claim.

For `closure.dispatch_binding.v1`, streaming dispatch paths emit separate `provider.response.received` and `client.response.delivered` events as digest carriers; non-streaming dispatch paths emit `execution.completed` as the accepted digest carrier. Both shapes carry `provider_response_digest_v1` and `client_response_digest_v1` and are equivalently adjudicated by the verifier.

```bash
keel-verify claim delegation_denied_correctly --evidence-file evidence.json
keel-verify claim permit.operator_approval.v1 path/to/pack/
keel-verify claim permit.counter_signature.v1 path/to/pack/
keel-verify claim permit.audit_attestation.v1 path/to/pack/
```

Claim output is JSON by default. `--json` is accepted for consistency with the
export and checkpoint commands. Permit v2 slot-claim packs may be passed as a
directory containing `export.json`, `manifest.json`, and `key_manifest.json`, or
with explicit `--export-file`, `--manifest`, and `--key-manifest` flags.

A pack carries two manifest blocks:

- `claim_set` — which claims the pack asserts, each marked `required: true|false`.
- `semantics_pins` — which semantic artifacts (by `(id, sha256)`) the verifier should resolve.

The verifier resolves and validates each pin against the permanent allowlist, then adjudicates each declared claim.

### Structured per-claim verdicts

`--json` output gains a `claims` array with per-claim verdicts using a four-value enum:

| verdict | meaning |
| --- | --- |
| `supported` | The claim is positively established by the evidence. |
| `disproved` | The evidence contradicts the claim. |
| `insufficient_evidence` | The pack doesn't carry enough to decide. |
| `unverifiable_scope` | The claim falls outside what the verifier is in scope to decide. |

For a pinned pack, every claim the `claim_set` marks `required` must receive `supported` for the pack's overall `ok` to be true. Legacy un-pinned evidence (no `claim_set` / `semantics_pins`) is evaluated under the permanent `keel.pre_pinning_default.v0` profile and is not subject to required-claim enforcement — v1.x exports continue to verify unchanged.

### Specs

- [`spec/verifier-pack-pinning-v0.md`](https://github.com/keelapi/keel-permit/blob/main/spec/verifier-pack-pinning-v0.md) — pack-pinning mechanism.
- [`spec/verifier-claims-v0.md`](https://github.com/keelapi/keel-permit/blob/main/spec/verifier-claims-v0.md) — claim registry and verdict semantics.
- [`spec/permit-chain-v1.md`](https://github.com/keelapi/keel-permit/blob/main/spec/permit-chain-v1.md) — the `permit_chain.delegation_denied_correctly.v1` claim.

## TSA Trust Validation

Checkpoint verification checks embedded RFC 3161 timestamp receipts by confirming
the TSA MessageImprint matches the checkpoint `composite_hash`.

For opt-in TSA authenticity validation, pass a CA bundle:

```bash
keel-verify checkpoint checkpoint.json --tsa-ca-bundle tsa-ca-bundle.pem
```

This uses OpenSSL 3.x to verify the CMS signature, certificate chain, and
timestamping purpose against the supplied CA bundle. It does not check
historical revocation status at the timestamp issuance time.

## Tampering Matrix

The verifier emits stable `WALK_*` failure codes, including:

- `WALK_RECORD_HASH_MISMATCH`
- `WALK_PREV_HASH_DISCONTINUITY`
- `WALK_SEQUENCE_INVERSION`
- `WALK_UNKNOWN_CHAIN_FORMAT`
- `WALK_CLOSURE_SIGNATURE_INVALID`
- `WALK_CLOSURE_DIGEST_MISMATCH`
- `WALK_CLOSURE_DIGEST_MISSING`
- `WALK_CLOSURE_DISPATCH_DIGEST_MISMATCH`
- `WALK_UNKNOWN_CLOSURE_FORMAT`

Example: if a provider response is modified after signing, verification fails with `WALK_CLOSURE_DIGEST_MISMATCH`.

The authoritative matrix is maintained in the online documentation: https://docs.keelapi.com/12-tampering-detection-matrix

## Trust Model

There are two useful kinds of verification:

- Self-attested: the file agrees with itself. This verifies internal consistency only.
- Trust-root verified: the artifact verifies against a key you trust, such as the bundled production trust root, a pinned public key, or a manifest fetched and saved out-of-band.

Trust sources, strongest first:

| Mode | Flags | Notes |
| --- | --- | --- |
| Pinned key | `--expected-public-key ed25519:...` or `--public-key ed25519:...` | Strongest when obtained out-of-band. |
| Key manifest | `--key-manifest keys.json` | Supports key rotation and active windows. |
| Key manifest URL | `--key-manifest-url URL` | Explicit network fetch. |
| Cached manifest | none (set up via `keel-verify refresh-keys`) | Default once cache exists. Lives at `~/.keel-verifier/trust-root.json`. |
| Bundled trust root | none | Always-present floor. No phone-home. |
| Self-attested | `--self-attested` | Development/sample mode only. |

`--public-key-url` is also supported for checkpoint verification against the single live checkpoint public-key endpoint.

When no flag is passed, the verifier resolves the trust root in this order: explicit `--key-manifest[-url]` → cached `~/.keel-verifier/trust-root.json` (if present) → wheel-bundled `data/trust_root.json`.

### Refreshing trust roots after key rotation

The wheel ships a snapshot of the trust root from build time. After a key rotation, a wheel published before the rotation will not verify post-rotation artifacts out of the box. Three resolutions:

1. `pip install --upgrade keel-verifier` — pulls the latest bundled snapshot.
2. `keel-verify refresh-keys` — fetches a fresh manifest from any trust-root channel and caches it at `~/.keel-verifier/trust-root.json`. The verifier prefers the cache over the bundled snapshot on subsequent runs.
3. Pin a manifest at audit time: download the manifest alongside the artifact, pass it explicitly with `--key-manifest <archived-file>`.

`refresh-keys` flags:

```bash
keel-verify refresh-keys                  # auto: try Keel API, then GitHub
keel-verify refresh-keys --source api     # only try the Keel API
keel-verify refresh-keys --source github  # only try the GitHub mirror
```

## CLI Examples

```bash
keel-verify export export.json manifest.json
keel-verify export export.json manifest.json --walk-events
keel-verify export export.json manifest.json --walk-events --verify-closure
keel-verify export export.json manifest.json --allow-unsigned
keel-verify checkpoint checkpoint.json
keel-verify claim delegation_denied_correctly --evidence-file evidence.json
keel-verify claim delegation_denied_correctly --evidence-file evidence.json --json
keel-verify refresh-keys
keel-verify refresh-keys --source github
python -m keel_verifier sample/export.json --self-attested
python -m keel_verifier sample/export.json --json --self-attested
```

Exit code `0` means verified. Exit code `1` means verification failed. Exit code `2` means bad usage.

## Network Behavior

Normal verification does not phone home. Network fetches happen only when you
run `keel-verify refresh-keys` or pass an explicit URL trust-root flag such as
`--public-key-url` or `--key-manifest-url`.

The repository CI workflows also contact live Keel endpoints to detect bundled
trust-root drift.

There is no telemetry.

## Library Use

```python
import json
from pathlib import Path

from keel_verifier import (
    verify,
    verify_delegation_denied_correctly,
)

result = verify("sample/export.json", self_attested=True)
if not result.ok:
    raise SystemExit(result.error)

evidence = json.loads(Path("evidence.json").read_text())
claim = verify_delegation_denied_correctly(evidence, include_semantics=True)
if claim["status"] != "supported":
    raise SystemExit(claim)
```

## Versioning

v2.0.0 introduces pack-pinned semantics and structured claim verdicts.
The documented CLI invocation patterns still work, including `python -m keel_verifier <artifact>`.

## Related Projects

- Permit Specification: https://github.com/keelapi/keel-permit
- Reference API: https://github.com/keelapi/keel-api
- Documentation: https://docs.keelapi.com

## Maintainer

Maintained by Keel API, Inc.

## License

MIT. See `LICENSE`.
