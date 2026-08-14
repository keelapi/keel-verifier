# Contributing

## Proposing and Submitting Changes

Use [GitHub Issues](https://github.com/keelapi/keel-verifier/issues) to report a
reproducible defect or propose a change. Search existing issues first, then include the
affected verifier version, the command or API used, expected behavior, actual behavior,
and a minimal non-sensitive artifact when possible. Suspected vulnerabilities must be
reported privately as described in [SECURITY.md](SECURITY.md), not in a public issue.

To contribute code:

1. Fork the repository and create a topic branch from the current `main` branch.
2. Make one focused change and add or update tests for behavior that changes.
3. Run the development checks below.
4. Open a pull request against `main` that explains the behavior change, its security or
   compatibility impact, and the tests run.

Maintainers review pull requests and merge accepted changes. Opening an issue or pull
request does not grant repository or release permissions.

## Development

```bash
python -m pip install -e ".[dev]"
ruff check .
pytest -q
```

The full CI suite also checks the verifier against the golden fixture corpus from a
neighboring `keel-permit` checkout.

## Release Build

Publishing to PyPI is a maintainer-only step and is not part of the contribution process.
Official releases are built, signed, and published by `.github/workflows/release.yml`;
contributors should not upload release artifacts.

```bash
python -m pip install -e ".[dev]"
python -m build
python -m twine check dist/*
```

The local build is for packaging validation only. Maintainers follow [RELEASING.md](RELEASING.md)
for the official release process.
