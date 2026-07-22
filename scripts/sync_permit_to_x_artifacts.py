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
    "semantic_registry/v1.json": "permit_to_x/semantic_registry/v1.json",
    "semantic_registry/v1.schema.json": ("permit_to_x/semantic_registry/v1.schema.json"),
    "presentation_registry/v1.json": "permit_to_x/presentation_registry/v1.json",
    "presentation_registry/v1.schema.json": ("permit_to_x/presentation_registry/v1.schema.json"),
    "schemas/permit-semantic-binding-v1.schema.json": (
        "permit_to_x/schemas/permit-semantic-binding-v1.schema.json"
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
