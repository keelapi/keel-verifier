# Contributing

## Release Build

Publishing to PyPI is a maintainer step and is not performed by CI or pull requests.

```bash
python -m pip install build twine
python -m build
python -m twine upload dist/keel-verifier-1.0.0*
```

Before publishing, confirm the PyPI project name `keel-verifier` is available or owned by Keel API, Inc.
