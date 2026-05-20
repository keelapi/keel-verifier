"""Standalone verifier for Keel governance evidence."""

from keel_verifier.verifier import (
    VerifyResult,
    verify,
    verify_checkpoint,
    verify_closure_record,
    verify_delegation_denied_correctly,
    verify_export_walk_events,
)
from keel_verifier.verdicts import (
    ClaimVerdict,
    VerificationReport,
    VerdictSubject,
    aggregate_subject_verdicts,
)

__all__ = [
    "VerifyResult",
    "ClaimVerdict",
    "VerificationReport",
    "VerdictSubject",
    "aggregate_subject_verdicts",
    "verify",
    "verify_checkpoint",
    "verify_closure_record",
    "verify_delegation_denied_correctly",
    "verify_export_walk_events",
    "__version__",
]
__version__ = "2.1.0"
