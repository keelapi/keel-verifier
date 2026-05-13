"""Standalone verifier for Keel governance evidence."""

from keel_verifier.verifier import (
    CHAIN_FORMAT_HASHERS,
    CLOSURE_FORMAT_VERIFIERS,
    VerifyResult,
    verify,
    verify_closure_record,
    verify_export_walk_events,
)

__all__ = [
    "CHAIN_FORMAT_HASHERS",
    "CLOSURE_FORMAT_VERIFIERS",
    "VerifyResult",
    "verify",
    "verify_closure_record",
    "verify_export_walk_events",
    "__version__",
]
__version__ = "1.1.0"
