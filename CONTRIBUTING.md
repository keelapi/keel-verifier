# Contributing

## Development

```bash
python -m pip install -e ".[dev]"
ruff check .
pytest -q
```

The full CI suite also checks the verifier against the golden fixture corpus from a
neighboring `keel-permit` checkout.

## Release Build

Publishing to PyPI is a maintainer step and is not performed by CI or pull requests.

```bash
python -m pip install -e ".[dev]"
python -m build
python -m twine check dist/*
python -m twine upload dist/*
```

Before publishing, confirm the package metadata in `pyproject.toml`, bundled trust root,
semantic artifacts, and changelog all match the intended release.
