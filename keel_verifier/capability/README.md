# Verifier Capability Inventory

`v1.json` is a machine-readable description of what this verifier — `keel-verifier` — adjudicates, the formats it covers, the trust boundary it operates within, and what it explicitly does *not* prove.

## Purpose

- **Audit / due-diligence**: a single structured document showing exactly what claims this verifier adjudicates and what it doesn't.
- **Drift detection**: paired with `tests/test_capability_inventory_parity.py`, the file is contract-checked against the verifier's code (`CLAIM_SEMANTICS` in `keel_verifier/semantics.py`).
- **Spec alignment**: each implemented claim cross-references keel-permit's `claim_registry/v0.json`.

## Versioning

Three independent versions live in the document:

- `capability_schema_version` — the inventory document schema (currently `"1.0"`). Bumps when the inventory **structure** itself changes.
- `verifier.version` — the keel-verifier package version.
- `spec_compatibility.permit_spec_version` — the keel-permit spec version this inventory is aligned with.

## What's machine-checked

`tests/test_capability_inventory_parity.py` enforces a bidirectional contract:

- Every claim in `CLAIM_SEMANTICS` must appear in `v1.json` with `status: "implemented"`.
- Every entry in `v1.json` with `status: "implemented"` must correspond to a key in `CLAIM_SEMANTICS`.
- Entries with `status: "planned"` must NOT be in `CLAIM_SEMANTICS` (declared-but-not-executable).
- `verifier.version` must match `keel_verifier.__version__`.

## What's prose-curated (not machine-checked)

The `trust_boundary`, `out_of_scope`, and `verdict_durability` sections are reviewed text. Changes there should be human-reviewed and aligned with the keel-verifier README and project doctrine.

## Consuming the inventory

The inventory ships with the wheel:

```python
from importlib import resources
import json

data = json.loads(
    resources.files("keel_verifier.capability").joinpath("v1.json").read_text()
)
```

Or directly: <https://github.com/keelapi/keel-verifier/blob/main/keel_verifier/capability/v1.json>
