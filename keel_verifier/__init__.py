"""Standalone verifier for Keel's signed compliance exports.

Public API:

    from keel_verifier import verify, VerifyResult

    result = verify("path/to/export.json")
    if not result.ok:
        ...

The package is also runnable as a CLI:

    python -m keel_verifier path/to/export.json
"""

from keel_verifier.verifier import VerifyResult, verify

__all__ = ["VerifyResult", "verify", "__version__"]
__version__ = "0.2.0"
