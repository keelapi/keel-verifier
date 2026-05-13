# keel-verifier

Independent verifier for Permit-spec governance evidence and Keel audit exports.

## Why this exists

Most AI platforms can tell you what they logged.

This verifier detects post-signing tampering of exported governance evidence. An auditor, customer, regulator, or security team can independently verify decisions, dispatched requests, returned responses, and lifecycle evidence integrity.

Verification runs locally and does not require access to Keel systems.

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

## What It Verifies

`keel-verify export` verifies a signed compliance export in three layers:

1. The export bytes match the signed manifest `content_hash`.
2. The manifest Ed25519 signature verifies against a trusted key.
3. Optional Phase C/D checks walk bundled chain entries and verify closure records.

`keel-verify checkpoint` verifies integrity checkpoint JSON artifacts: the `chain_heads` composite hash, the Ed25519 checkpoint signature, and an embedded RFC 3161 timestamp MessageImprint when present.

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
keel-verify refresh-keys
keel-verify refresh-keys --source github
python -m keel_verifier sample/export.json --self-attested
python -m keel_verifier sample/export.json --json --self-attested
```

Exit code `0` means verified. Exit code `1` means verification failed. Exit code `2` means bad usage.

## Network Behavior

The verifier does not phone home. It reaches the network only when you pass `--public-key-url` or `--key-manifest-url`.

There is no telemetry.

## Library Use

```python
from keel_verifier import verify, verify_export_walk_events, verify_closure_record

result = verify("sample/export.json", self_attested=True)
if not result.ok:
    raise SystemExit(result.error)
```

## Versioning

v1.0.0 expands the public verifier across Phase A/B/C/D verification surfaces. v0.2.0 users can keep using `python -m keel_verifier <artifact>`.

## Related Projects

- Permit Specification: https://github.com/keelapi/keel-permit
- Reference API: https://github.com/keelapi/keel-api
- Documentation: https://docs.keelapi.com

## Maintainer

Maintained by Keel API, Inc.

## License

MIT. See `LICENSE`.
