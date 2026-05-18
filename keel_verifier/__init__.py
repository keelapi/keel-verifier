"""Standalone verifier for Keel governance evidence."""

from keel_verifier.verifier import (
    CHAIN_FORMAT_HASHERS,
    CLOSURE_FORMAT_VERIFIERS,
    VerifyResult,
    verify,
    verify_checkpoint,
    verify_closure_record,
    verify_export_walk_events,
)
from keel_verifier.verdicts import (
    ClaimVerdict,
    VerificationReport,
    VerdictSubject,
    aggregate_subject_verdicts,
)

__all__ = [
    "CHAIN_FORMAT_HASHERS",
    "CLOSURE_FORMAT_VERIFIERS",
    "VerifyResult",
    "ClaimVerdict",
    "VerificationReport",
    "VerdictSubject",
    "aggregate_subject_verdicts",
    "verify",
    "verify_checkpoint",
    "verify_closure_record",
    "verify_export_walk_events",
    "__version__",
]
__version__ = "1.1.0"
