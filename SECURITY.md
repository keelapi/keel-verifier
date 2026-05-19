# Security Policy

## Supported Versions

Security fixes are prioritized for the latest published `keel-verifier` release and the
current `main` branch.

## Reporting a Vulnerability

Please do not open a public issue for a suspected vulnerability.

Use GitHub private vulnerability reporting for this repository, or email
`security@keelapi.com` with:

- the affected version or commit
- a minimal reproduction or artifact, if available
- the expected and actual verifier behavior
- any known impact on audit, signature, trust-root, semantic-pin, or packaging integrity

We aim to acknowledge reports within three business days. Coordinated fixes may include a
patched release, a trust-root update, a documentation correction, or a public advisory,
depending on impact.

## Scope

Security-relevant reports include issues in:

- export, checkpoint, closure, workflow, TSA, and claim verification behavior
- bundled trust roots, semantic artifacts, and release artifact packaging
- CLI defaults or documentation that could cause unsafe verification results
- dependency or build issues that affect the integrity of published wheels or source
  distributions

The verifier detects post-signing tampering. It does not claim to detect privileged
signing-time manipulation by an authorized signer; that boundary is documented in the
README trust model.
