"""Standalone verifier for Keel governance evidence."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _metadata_version
from pathlib import Path

from keel_verifier.verifier import (
    VerifyResult,
    verify,
    verify_attestation_artifact,
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
    "verify_attestation_artifact",
    "verify_checkpoint",
    "verify_closure_record",
    "verify_delegation_denied_correctly",
    "verify_export_walk_events",
    "__version__",
]

_SOURCE_TREE_VERSION = "3.4.2"

try:
    __version__ = _metadata_version("keel-verifier")
except PackageNotFoundError:
    __version__ = _SOURCE_TREE_VERSION

# Source checkouts can otherwise read an unrelated globally installed version.
if (Path(__file__).resolve().parents[1] / "pyproject.toml").is_file():
    __version__ = _SOURCE_TREE_VERSION
