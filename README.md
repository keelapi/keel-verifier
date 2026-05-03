# keel-verifier

Standalone verifier for Keel's signed compliance exports. Verifies tamper-evident chains and RFC 3161 timestamps without requiring access to Keel.

## Why this exists

A compliance export is only as trustworthy as the party that issues it. Keel signs every export with an Ed25519 key and binds it to an externally-anchored RFC 3161 timestamp so that customers, auditors, and partners can confirm the artifact has not been altered since issuance — without trusting Keel's word, our infrastructure, or our continued availability. This repository is the reference implementation of that check. It is small, dependency-light, and runs offline against a sealed export.

## Quick start

```
git clone https://github.com/keelapi/keel-verifier.git
cd keel-verifier && pip install -r requirements.txt
python -m keel_verifier sample/export.json
```

The third command should print `VERIFIED:` and exit `0`.

## What it verifies

A sealed Keel export is a single JSON document. The verifier checks, in order:

1. **Composite hash recomputes.** The exported `chain_heads` (one entry per scope: `sequence_number` + `last_record_hash`) are deterministically hashed and compared to the export's `composite_hash`. Any byte flipped in any chain head fails this step.
2. **Ed25519 signature is valid.** The signature must verify against the resolved trust root over the composite hash. By default, the trust root is the export's embedded `public_key` (self-attested). Use `--public-key`, `--public-key-url`, or `--offline` to anchor against an external trust root instead.
3. **RFC 3161 timestamp is authentic** (when present). The verifier parses the embedded TimeStampToken and checks that its `MessageImprint` equals the composite hash. This proves that the timestamp authority signed *this exact export* at the time on the receipt. Pass `--no-tsa` to skip this step. Full TSA certificate-chain validation is out of scope; use `openssl ts -verify` for that.

Exit `0` on pass, non-zero on fail. The failure reason is written to stderr.

## CLI

```
python -m keel_verifier <export.json>                      # human-readable
python -m keel_verifier <export.json> --json               # structured JSON
python -m keel_verifier <export.json> --no-tsa             # skip RFC 3161 check
python -m keel_verifier <export.json> --public-key ed25519:...
python -m keel_verifier <export.json> --public-key-url URL
python -m keel_verifier <export.json> --offline
```

`--public-key`, `--public-key-url`, and `--offline` are mutually exclusive. With none of them set, the verifier runs in self-attested mode and prints a notice with the canonical URL to anchor against.

## Public-key endpoint

Keel publishes the checkpoint signing public key at:

```
https://api.keelapi.com/v1/integrity/checkpoint-public-key
```

The endpoint returns JSON of the form:

```json
{
  "algorithm": "ed25519",
  "public_key": "ed25519:<base64>",
  "key_id": "sha256:<hex-prefix>",
  "scope": "integrity_checkpoints"
}
```

Pass the URL to `--public-key-url` to fetch and pin verification against it. For air-gapped or sandboxed environments, use `--offline`, which reads the bundled copy at `keel_verifier/keys/keel_checkpoint.pub.json`. The bundled copy is committed to this repository as a snapshot of the production trust root; verify it against the live endpoint when you next have network access. The samples in `sample/` are signed by a separate test key, so `--offline` deliberately fails on them — that mismatch is the trust-root check working as intended.

## Output examples

### Pass

```
$ python -m keel_verifier sample/export.json
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

NOTE: trust source is the export's own embedded public key. To anchor against
Keel's published trust root, re-run with:
  --public-key-url https://api.keelapi.com/v1/integrity/checkpoint-public-key
or with --offline to use the bundled trust root.
```

### Tampered chain

One byte flipped in a chain head's `last_record_hash`:

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
$ python -m keel_verifier sample/tsa_tampered.json
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

result = verify("path/to/export.json", offline=True)
if not result.ok:
    raise SystemExit(result.error)
print(result.composite_hash, result.key_id)
```

`result.to_dict()` returns the same shape that `--json` writes.

## License

MIT. See `LICENSE`.

## Links

Keel — <https://keelapi.com>
