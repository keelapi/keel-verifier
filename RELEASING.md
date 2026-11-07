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
- Confirm `GITHUB_TRUST_ROOT_URL` serves a signed
  `keel.public_key_manifest.v1` trust root before publishing. `refresh-keys`
  requires signed manifests for every HTTP(S) channel, so an unsigned GitHub
  mirror will fail for `refresh-keys --source github` and auto fallback.
- Confirm the existing bundled and GitHub trust-root files with
  `scripts/check_release_trust_root.py`. Do not rotate or re-sign an already
  valid production root merely to cut a release. Key operations should invoke
  `scripts/sign_public_key_manifest.py` only for an explicitly authorized key
  rotation or trust-root publication change.

  The release workflow runs `scripts/check_release_trust_root.py --source github`
  before building artifacts. It fails closed unless the served trust root is a
  signed `keel.public_key_manifest.v1` whose signer is an allowlisted real
  production export-signing key.
- For PERMIT_V2 slot-signature releases, confirm the vendored
  `permit.operator_approval.v1`, `permit.counter_signature.v1`, and
  `permit.audit_attestation.v1` semantics hashes still match keel-api main,
  and run the permit v2 slot-signature corpus before tagging.
- Confirm CI is green on `main`.
- Run
  `python scripts/check_historical_compatibility_corpus.py --run`; the release
  workflow repeats this gate and fails if a required artifact or executable
  historical case is absent.

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
- Checkout action: `actions/checkout` v6, pinned to commit
  `d23441a48e516b6c34aea4fa41551a30e30af803`, with full history
- Python action: `actions/setup-python` v6, pinned to commit
  `ece7cb06caefa5fff74198d8649806c4678c61a1`
- Release Python: `3.12`
- Build backend: `setuptools.build_meta` from `pyproject.toml`
- Build backend requirement: `setuptools>=68`
- Release tools installed in CI: `build`, `twine`, `cyclonedx-bom`
- Cosign installer: `sigstore/cosign-installer` v3, pinned to commit
  `398d4b0eeef1380460a10c8013a76f728fb906ac`
- Release upload: `softprops/action-gh-release` v2, pinned to commit
  `3bb12739c298aeb8a4eeaf626c5b8d85266b0e65`
- PyPI publish: `pypa/gh-action-pypi-publish` `release/v1`, pinned to commit
  `7245906fb61fa33a13554f9d5fb856fe61758086` (the branch head when pinned, tagged v1.14.3)

The signed `manifest.json` records the observed Python version, cosign version, runner,
and build backend for the release.

Every `uses:` in `.github/workflows/` names a full 40-character commit SHA with the
ref it was resolved from in a trailing comment. A tag or branch can be moved after
review; a commit cannot. To update an action pinned from a tag, resolve the tag with
`gh api repos/<owner>/<repo>/git/ref/tags/<tag>` (dereference annotated tags through
`git/tags/<sha>`). For one pinned from a branch, such as
`pypa/gh-action-pypi-publish@release/v1`, use
`gh api repos/<owner>/<repo>/git/ref/heads/<branch>` and take `object.sha`. Then
replace both the SHA and the comment.

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
