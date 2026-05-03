# keel-verifier

Verify that AI decisions are real, unchanged, and signed by a trusted source.

Most systems give you logs.

Logs can be edited.

Keel gives you evidence you can verify independently.

## Why this exists

Dashboards can be wrong. Screenshots prove nothing.

Keel signs every AI decision record and binds it to a timestamp so that
anyone — a customer, auditor, or partner — can verify that it has not
been altered since it was created.

This tool performs that verification.

It runs locally, requires no access to Keel, and never phones home.

## Quick start

```
git clone https://github.com/keelapi/keel-verifier.git
cd keel-verifier && pip install -r requirements.txt
python -m keel_verifier sample/export.json --self-attested
```

You should see `VERIFIED:`.

Now try without the flag:

```
python -m keel_verifier sample/export.json
```

This fails — because the sample is not signed by Keel's production key.

That distinction is the entire point.

## What you just saw

There are two kinds of verification:

- **Self-attested**  
  → "This file agrees with itself"  
  → proves it wasn't changed  

- **Trust-root verified (default)**  
  → "This file was signed by Keel"  
  → proves it came from the right source  

Most systems stop at the first.

Keel requires the second.

## Why this matters

When something goes wrong with AI, people ask:

- Who approved this?
- What exactly ran?
- Can we prove it?

Logs can't answer that reliably.

A signed, verifiable record can.

## Where this comes from

Every AI request in Keel creates a signed decision record.

That record can be exported and verified like you just did.

## What it verifies

A sealed Keel export is a single JSON document. The verifier checks, in order:

1. **Composite hash recomputes.** The exported `chain_heads` (one entry per scope: `sequence_number` + `last_record_hash`) are deterministically hashed and compared to the export's `composite_hash`. Any byte flipped in any chain head fails this step.
2. **Ed25519 signature is valid against the resolved trust root.** The signature must verify over the composite hash. The trust root is the bundled production key by default (see [Trust model](#trust-model)).
3. **RFC 3161 timestamp is authentic** (when present). The verifier parses the embedded TimeStampToken and checks that its `MessageImprint` equals the composite hash. This proves the timestamp authority signed *this exact export* at the time on the receipt. Pass `--no-tsa` to skip. Full TSA certificate-chain validation is out of scope; use `openssl ts -verify` for that.

Exit `0` on pass, non-zero on fail. The failure reason is written to stderr.

## Trust model

The verifier supports four trust-root sources, in order of strongest to weakest:

| Mode | Flag | Trust chain |
|---|---|---|
| Pinned | `--public-key ed25519:<base64>` | The user obtained the key out-of-band — SOC 2 auditor's report, third-party transparency log, key-transparency feed, or a TLS-verified one-time fetch the user personally performed. Strongest. |
| Live fetch | `--public-key-url <URL>` | Trust root fetched from the URL (canonical: `https://api.keelapi.com/v1/integrity/checkpoint-public-key`). Trust chain: TLS cert + Keel honestly serving the right key. |
| Bundled (default) | *(none)* | Trust root is `keel_verifier/keys/keel_checkpoint.pub.json`, a snapshot of the production key committed to this repository. Trust chain: GitHub authentication of the repo owner + the repo owner committed the right key. CI on every push asserts that the bundled key still matches the live endpoint, so a silent swap or stale rotation fails loudly. |
| Self-attested | `--self-attested` | Trust root is the artifact's own embedded `public_key`. **Only proves internal consistency** — that the artifact was signed by whoever signed it. Does NOT prove Keel signed it. Use only for development, sample testing, or when the embedded key has been authenticated out-of-band. |

`--public-key`, `--public-key-url`, and `--self-attested` are mutually exclusive. With none set, the bundled trust root is used.

## CLI

```
python -m keel_verifier <export.json>                            # default: bundled trust root
python -m keel_verifier <export.json> --self-attested            # weak; embedded public_key
python -m keel_verifier <export.json> --public-key ed25519:...   # pinned
python -m keel_verifier <export.json> --public-key-url URL       # fetched
python -m keel_verifier <export.json> --json                     # structured JSON output
python -m keel_verifier <export.json> --no-tsa                   # skip RFC 3161 check
```

## Public-key endpoint

Keel publishes the checkpoint signing public key at:

```
https://api.keelapi.com/v1/integrity/checkpoint-public-key
```

Response:

```json
{
  "algorithm": "ed25519",
  "public_key": "ed25519:<base64>",
  "key_id": "sha256:<hex-prefix>",
  "scope": "integrity_checkpoints"
}
```

To refresh the bundled trust root after a key rotation:

```
curl -fsS https://api.keelapi.com/v1/integrity/checkpoint-public-key \
    > keel_verifier/keys/keel_checkpoint.pub.json
python tools/check_bundled_key.py
```

CI runs `tools/check_bundled_key.py` on every push and fails the build if the bundled key drifts from the live endpoint.

## Output examples

### Pass — `--self-attested` against the development sample

```
$ python -m keel_verifier sample/export.json --self-attested
VERIFIED: sample/export.json
  Checkpoint:    11111111-2222-3333-4444-555555555555
  Computed at:   2026-04-15T12:00:00Z
  Composite:     sha256:bf13a31ec6d0357288e60f1cbe6ff4ab6369f84797fc598fc834f2ea82d591d7
  Chain heads:   3 scope(s)
  Public key:    ed25519:CvfKyK/t8oZZogxSp61fYXNuGj/Hyz6gwfw5axcR2/Y=
  Key id:        sha256:1a6eb20e308c021dea0c6ee28ad78bfb
  Trust source:  self-attested (embedded public_key)
  TSA:           verified (TSA message imprint matches composite_hash)
    url:         https://example-tsa.invalid/tsr
    stamped at:  2026-04-15T12:00:01Z

WARNING: --self-attested verification only proves internal consistency.
It does not prove that Keel signed this artifact. Drop --self-attested to
verify against the bundled trust root, or pin explicitly with:
  --public-key-url https://api.keelapi.com/v1/integrity/checkpoint-public-key
```

### Trust-root mismatch — default mode against the development sample

The sample is signed by the development key, the bundled trust root is Keel's production key — so the default-mode verification correctly refuses to certify the sample as Keel-signed:

```
$ python -m keel_verifier sample/export.json
FAILED: sample/export.json
  embedded public_key does not match resolved trust root
    trust root: ed25519:3Q1q4PSVcceZe76dsjxcqTHOpvpP/KN/zhSH4QdtE7o=
    embedded:   ed25519:CvfKyK/t8oZZogxSp61fYXNuGj/Hyz6gwfw5axcR2/Y=
  Checkpoint:    11111111-2222-3333-4444-555555555555
  Composite:     sha256:bf13a31ec6d0357288e60f1cbe6ff4ab6369f84797fc598fc834f2ea82d591d7
  Chain heads:   3 scope(s)
  TSA:           not present
$ echo $?
1
```

### Tampered chain

One byte flipped in a chain head's `last_record_hash`. The composite-hash recomputation fails before any trust-root check is reached:

```
$ python -m keel_verifier sample/tampered.json
FAILED: sample/tampered.json
  composite_hash mismatch — chain_heads have been altered
    stored:     sha256:bf13a31ec6d0357288e60f1cbe6ff4ab6369f84797fc598fc834f2ea82d591d7
    recomputed: sha256:05545a901233939246500f53eaafdf0670125b1424a4cd1842e5297e1eb6f0d2
  Checkpoint:    11111111-2222-3333-4444-555555555555
  Composite:     sha256:bf13a31ec6d0357288e60f1cbe6ff4ab6369f84797fc598fc834f2ea82d591d7
  Chain heads:   3 scope(s)
  TSA:           not present
$ echo $?
1
```

### Timestamp mismatch

Signature and chain are intact; the TSA receipt's `MessageImprint` was synthesized for a different hash:

```
$ python -m keel_verifier sample/tsa_tampered.json --self-attested
FAILED: sample/tsa_tampered.json
  TSA: TSA message imprint does not match composite_hash
  Checkpoint:    11111111-2222-3333-4444-555555555555
  Computed at:   2026-04-15T12:00:00Z
  Composite:     sha256:bf13a31ec6d0357288e60f1cbe6ff4ab6369f84797fc598fc834f2ea82d591d7
  Chain heads:   3 scope(s)
  Public key:    ed25519:CvfKyK/t8oZZogxSp61fYXNuGj/Hyz6gwfw5axcR2/Y=
  Key id:        sha256:1a6eb20e308c021dea0c6ee28ad78bfb
  Trust source:  self-attested (embedded public_key)
  TSA:           FAILED (TSA message imprint does not match composite_hash)
$ echo $?
1
```

## Network behavior

The verifier makes no outbound calls by default. It will reach the network only when:

- `--public-key-url URL` is passed (one HTTPS GET to that URL).

There is no telemetry. The verifier never phones home.

## Library use

```python
from keel_verifier import verify

# Default mode: verify against the bundled trust root.
result = verify("path/to/export.json")
if not result.ok:
    raise SystemExit(result.error)
print(result.composite_hash, result.key_id)

# Pin to a specific key:
result = verify("path/to/export.json", public_key="ed25519:...")

# Self-attested (development only):
result = verify("path/to/export.json", self_attested=True)
```

`result.to_dict()` returns the same shape that `--json` writes.

## Versioning

Semantic versioning. v0.2.0 changed the default trust-root from self-attested to the bundled production key; the `--self-attested` flag is required to opt into the v0.1 behavior. The `--offline` flag from v0.1 is preserved as a silent no-op alias for the default.

## License

MIT. See `LICENSE`.

## Links

Keel — <https://keelapi.com>
