from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PUBLIC_CORPUS_ROOT = (
    REPO_ROOT.parent
    / "keel-permit"
    / "test-vectors"
    / "verifier_claims"
    / "v0"
)
PUBLIC_CORPUS_AVAILABLE = (PUBLIC_CORPUS_ROOT / "corpus.json").exists()
PUBLIC_CORPUS_SKIP_REASON = (
    "keel-permit verifier-claim golden corpus is not checked out next "
    f"to keel-verifier: {PUBLIC_CORPUS_ROOT}"
)

PROMOTED_SCOPE_FAITHFULNESS_IDS = {
    "scope-faithfulness-neg-head-truncate",
    "scope-faithfulness-neg-tail-truncate",
    "scope-faithfulness-neg-scope-relabel",
    "scope-faithfulness-neg-stale-checkpoint-latest-policy",
    "scope-faithfulness-neg-reordered-bounds",
    "scope-faithfulness-neg-forged-predicate",
    "scope-faithfulness-neg-sidecar-missing",
    "scope-faithfulness-neg-sidecar-tampered",
    "scope-faithfulness-neg-cardinality-mismatch",
    "scope-faithfulness-neg-membership-root-mismatch",
    "scope-faithfulness-neg-sidecar-duplicate-predicate-commitment",
    "scope-faithfulness-edge-empty-scope-cardinality-zero",
    "scope-faithfulness-edge-single-entry-scope",
    "scope-faithfulness-edge-multiple-chain-scope-segments",
    "scope-faithfulness-edge-key-rotation-sidecar-export",
    "scope-faithfulness-edge-predicate-grammar-version-mismatch",
    "scope-faithfulness-edge-unknown-commitment-profile",
    "scope-faithfulness-edge-bridge-records-not-members",
    "scope-faithfulness-edge-single-segment-with-two-chain-scopes",
}
