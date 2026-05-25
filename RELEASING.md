# Releasing keel-verifier

## How to cut a release

Pre-flight:

- Confirm `CHANGELOG.md` has the intended release entry.
- Confirm `pyproject.toml`, `keel_verifier/__init__.py`,
  `keel_verifier/capability/v1.json`, and
  `keel_verifier/_release_manifest.json` carry the same version.
- Confirm the bundled trust root, pinned semantics, capability inventory, and tests match
  the intended release.
- Confirm every historical `claim_registry` artifact remains bundled, and no pinned
  semantics or trust-root artifacts were pruned from the distribution package.
- For PERMIT_V2 slot-signature releases, confirm the vendored
  `permit.operator_approval.v1`, `permit.counter_signature.v1`, and
  `permit.audit_attestation.v1` semantics hashes still match keel-api main,
  and run the permit v2 slot-signature corpus before tagging.
- Confirm CI is green on `main`.

Create and push the release tag:

```bash
git tag -s v<X.Y.Z> -m "keel-verifier v<X.Y.Z>"
git push origin v<X.Y.Z>
```

Signed tags are the maintainer best practice, but the release workflow does not enforce
GPG tag signatures. The release-authenticity control for published artifacts is Sigstore
keyless signing via GitHub Actions OIDC, with Rekor transparency-log inclusion.

The tag push triggers `.github/workflows/release.yml` automatically for tags matching
`v*.*.*`. The workflow:

1. Generates `keel_verifier/_release_manifest.json`.
2. Builds the wheel and source distribution.
3. Generates `sbom.cyclonedx.json` from the release Python environment.
4. Signs the wheel, source distribution, and `manifest.json` with Sigstore keyless
   signing.
5. Attests the CycloneDX SBOM against the wheel.
6. Uploads all release artifacts to the GitHub Release.
7. Downloads the GitHub Release wheel and source distribution and publishes those exact
   files to PyPI through Trusted Publishing.

PyPI Trusted Publishing must be configured for this repository and workflow on
`pypi.org` before step 7 can succeed. Until that PyPI-side setup is active, the
`publish-to-pypi` job is expected to fail at the OIDC publication step while the GitHub
Release artifacts still complete normally.

Fallback PyPI publication, only until Trusted Publishing is active, must upload the
artifacts already built by GitHub Actions:

```bash
gh release download v<VERSION> --pattern '*.whl' --pattern '*.tar.gz' -D dist/
python -m twine upload dist/*
```

Do not run `python -m build` for fallback publication. Rebuilding locally can publish
bytes that differ from the signed GitHub Release artifacts.

## Build environment pinning

The release workflow pins the build lane rather than claiming byte-for-byte reproducible
builds:

- GitHub runner: `ubuntu-latest`
- Checkout action: `actions/checkout@v6` with full history
- Python action: `actions/setup-python@v6`
- Release Python: `3.12`
- Build backend: `setuptools.build_meta` from `pyproject.toml`
- Build backend requirement: `setuptools>=68`
- Release tools installed in CI: `build`, `twine`, `cyclonedx-bom`
- Cosign installer: `sigstore/cosign-installer@v3`

The signed `manifest.json` records the observed Python version, cosign version, runner,
and build backend for the release.

## Verifying a Keel verifier release

Download the wheel, source distribution, Sigstore bundles, SBOM, SBOM attestation bundle,
`manifest.json`, and `manifest.json.sigstore` from the GitHub Release.

Verify the wheel signature:

```bash
cosign verify-blob \
  --new-bundle-format \
  --certificate-identity-regexp 'https://github.com/keelapi/keel-verifier/\.github/workflows/release\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle keel_verifier-<VERSION>-py3-none-any.whl.sigstore \
  keel_verifier-<VERSION>-py3-none-any.whl
```

Verify the source distribution signature:

```bash
cosign verify-blob \
  --new-bundle-format \
  --certificate-identity-regexp 'https://github.com/keelapi/keel-verifier/\.github/workflows/release\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle keel_verifier-<VERSION>.tar.gz.sigstore \
  keel_verifier-<VERSION>.tar.gz
```

Verify the release manifest signature:

```bash
cosign verify-blob \
  --new-bundle-format \
  --certificate-identity-regexp 'https://github.com/keelapi/keel-verifier/\.github/workflows/release\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle manifest.json.sigstore \
  manifest.json
```

Note: `--new-bundle-format` is required for releases ≥ v2.4.1. These bundles
use Sigstore Bundle Format v0.3 (the format `sigstore-python` reads
natively, which `keel-verify self-check` depends on). v2.4.0 and earlier
used the legacy cosign bundle format and require omitting this flag.

Verify the CycloneDX SBOM attestation against the wheel:

```bash
cosign verify-blob-attestation \
  --certificate-identity-regexp 'https://github.com/keelapi/keel-verifier/\.github/workflows/release\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --type cyclonedx \
  --bundle keel_verifier-<VERSION>-sbom.intoto.jsonl \
  keel_verifier-<VERSION>-py3-none-any.whl
```

Installed wheels can be checked with:

```bash
keel-verify self-check --published-wheel=<VERSION> --json
```

Use this against the GitHub Actions-built artifact after publishing, not a local
rebuild, so the PyPI bytes are verified against the signed release manifest.
