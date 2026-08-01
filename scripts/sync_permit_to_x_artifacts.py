#!/usr/bin/env python3
"""Vendor the released Permit-to-X contracts used by keel-verifier.

The verifier intentionally consumes byte-identical contract artifacts from
``keel-permit``.  It does not import or execute code from that repository.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "keel_verifier" / "data"

COPIES = {
    "claim_registry/v1.json": "claim_registry/v1.json",
    "claim_registry/v2.json": "claim_registry/v2.json",
    "claim_registry/v3.json": "claim_registry/v3.json",
    "claim_registry/v4.json": "claim_registry/v4.json",
    "schemas/permit-co-signature-v2.schema.json": (
        "permit_to_x/schemas/permit-co-signature-v2.schema.json"
    ),
    "schemas/permit-co-signature-quorum-v1.schema.json": (
        "permit_to_x/schemas/permit-co-signature-quorum-v1.schema.json"
    ),
    "test-vectors/permit_co_signature/v2/corpus.json": (
        "permit_to_x/test_vectors/permit_co_signature/v2/corpus.json"
    ),
    "semantics/permit/co_signature_v2.json": (
        "semantics/permit/co_signature_v2.json"
    ),
    "semantics/permit/co_signature_quorum_v1.json": (
        "semantics/permit/co_signature_quorum_v1.json"
    ),
    "semantics/permit/exact_action_v1.json": (
        "semantics/permit/exact_action_v1.json"
    ),
    "semantics/permit/universal_verification_v1.json": (
        "semantics/permit/universal_verification_v1.json"
    ),
    "semantics/permit/universal_verification_v2.json": (
        "semantics/permit/universal_verification_v2.json"
    ),
    "semantics/permit/universal_verification_v3.json": (
        "semantics/permit/universal_verification_v3.json"
    ),
    "semantics/permit/provider_receipt_state_v1.json": (
        "semantics/permit/provider_receipt_state_v1.json"
    ),
    "semantics/permit/authority_edge_revocation_v1.json": (
        "semantics/permit/authority_edge_revocation_v1.json"
    ),
    "semantics/permit/authority_root_status_temporal_v1.json": (
        "semantics/permit/authority_root_status_temporal_v1.json"
    ),
    "semantics/permit/authority_root_status_temporal_v2.json": (
        "semantics/permit/authority_root_status_temporal_v2.json"
    ),
    "semantics/checkpoint/tsa_chain_v1.json": (
        "semantics/checkpoint/tsa_chain_v1.json"
    ),
    "semantics/rail/settlement_reconciled_v1.json": (
        "semantics/rail/settlement_reconciled_v1.json"
    ),
    "semantic_registry/v1.json": "permit_to_x/semantic_registry/v1.json",
    "semantic_registry/v1.schema.json": ("permit_to_x/semantic_registry/v1.schema.json"),
    "semantic_registry/v2.json": "permit_to_x/semantic_registry/v2.json",
    "semantic_registry/v2.schema.json": ("permit_to_x/semantic_registry/v2.schema.json"),
    "semantic_registry/v3.json": "permit_to_x/semantic_registry/v3.json",
    "semantic_registry/v3.schema.json": ("permit_to_x/semantic_registry/v3.schema.json"),
    "semantic_registry/v4.json": "permit_to_x/semantic_registry/v4.json",
    "semantic_registry/v4.schema.json": ("permit_to_x/semantic_registry/v4.schema.json"),
    "presentation_registry/v1.json": "permit_to_x/presentation_registry/v1.json",
    "presentation_registry/v1.schema.json": ("permit_to_x/presentation_registry/v1.schema.json"),
    "presentation_registry/v2.json": "permit_to_x/presentation_registry/v2.json",
    "presentation_registry/v2.schema.json": ("permit_to_x/presentation_registry/v2.schema.json"),
    "schemas/permit-semantic-binding-v1.schema.json": (
        "permit_to_x/schemas/permit-semantic-binding-v1.schema.json"
    ),
    "schemas/permit-semantic-binding-v2.schema.json": (
        "permit_to_x/schemas/permit-semantic-binding-v2.schema.json"
    ),
    "fact_profiles/v1.json": "permit_to_x/fact_profiles/v1.json",
    "fact_profiles/v1.schema.json": "permit_to_x/fact_profiles/v1.schema.json",
    "fact_profiles/v2.json": "permit_to_x/fact_profiles/v2.json",
    "fact_profiles/v2.schema.json": "permit_to_x/fact_profiles/v2.schema.json",
    "fact_profiles/v3.json": "permit_to_x/fact_profiles/v3.json",
    "fact_profiles/v3.schema.json": "permit_to_x/fact_profiles/v3.schema.json",
    "schemas/payment-exact-facts-v1.schema.json": (
        "permit_to_x/schemas/payment-exact-facts-v1.schema.json"
    ),
    "schemas/generate-text-exact-facts-v1.schema.json": (
        "permit_to_x/schemas/generate-text-exact-facts-v1.schema.json"
    ),
    "schemas/refund-exact-facts-v1.schema.json": (
        "permit_to_x/schemas/refund-exact-facts-v1.schema.json"
    ),
    "schemas/delegate-exact-facts-v1.schema.json": (
        "permit_to_x/schemas/delegate-exact-facts-v1.schema.json"
    ),
    "schemas/delegate-child-linkage-v1.schema.json": (
        "permit_to_x/schemas/delegate-child-linkage-v1.schema.json"
    ),
    "schemas/permit-exact-pack-v2.schema.json": (
        "permit_to_x/schemas/permit-exact-pack-v2.schema.json"
    ),
    "schemas/adapter-certification-v1.schema.json": (
        "permit_to_x/schemas/adapter-certification-v1.schema.json"
    ),
    "schemas/deployment-assurance-v1.schema.json": (
        "permit_to_x/schemas/deployment-assurance-v1.schema.json"
    ),
    "schemas/runtime-enforcement-proof-v1.schema.json": (
        "permit_to_x/schemas/runtime-enforcement-proof-v1.schema.json"
    ),
    "schemas/permit-bounded-use-v1.schema.json": (
        "permit_to_x/schemas/permit-bounded-use-v1.schema.json"
    ),
    "schemas/permit-selective-disclosure-v1.schema.json": (
        "permit_to_x/schemas/permit-selective-disclosure-v1.schema.json"
    ),
    "schemas/provider-receipt-v1.schema.json": (
        "permit_to_x/schemas/provider-receipt-v1.schema.json"
    ),
    "test-vectors/universal_verification/v1/corpus.json": (
        "permit_to_x/test_vectors/universal_verification/v1/corpus.json"
    ),
    "test-vectors/delegate_child_linkage/v1/corpus.json": (
        "permit_to_x/test_vectors/delegate_child_linkage/v1/corpus.json"
    ),
    "test-vectors/consequence_claims/v1/corpus.json": (
        "permit_to_x/test_vectors/consequence_claims/v1/corpus.json"
    ),
    "schemas/work-request-v1.schema.json": ("permit_to_x/schemas/work-request-v1.schema.json"),
    "schemas/work-package-v1.schema.json": ("permit_to_x/schemas/work-package-v1.schema.json"),
    "schemas/work-authority-v1.schema.json": ("permit_to_x/schemas/work-authority-v1.schema.json"),
    "schemas/work-value-event-v1.schema.json": (
        "permit_to_x/schemas/work-value-event-v1.schema.json"
    ),
    "schemas/work-chain-pack-v1.schema.json": (
        "permit_to_x/schemas/work-chain-pack-v1.schema.json"
    ),
    "comparator_registry/work-payment-authority-v1.json": (
        "comparator_registry/work-payment-authority-v1.json"
    ),
    "semantics/work/authority_manifest_v1.json": ("semantics/work/authority_manifest_v1.json"),
    "semantics/work/child_containment_v1.json": ("semantics/work/child_containment_v1.json"),
    "semantics/work/execution_authorized_at_boundary_v1.json": (
        "semantics/work/execution_authorized_at_boundary_v1.json"
    ),
    "semantics/work/value_conservation_v1.json": ("semantics/work/value_conservation_v1.json"),
    "test-vectors/permit_to_work/v1/corpus.json": (
        "permit_to_x/test_vectors/permit_to_work/v1/corpus.json"
    ),
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source",
        type=Path,
        required=True,
        help="Path to the keel-permit checkout containing Permit-to-X contracts.",
    )
    args = parser.parse_args()
    source = args.source.resolve()
    for source_name, destination_name in COPIES.items():
        source_path = source / source_name
        destination_path = DATA / destination_name
        if not source_path.is_file():
            raise FileNotFoundError(source_path)
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path, destination_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
