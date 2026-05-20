#!/usr/bin/env python3
"""Build verifier-local Step 2 scope-faithfulness negative and edge fixtures."""

from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
PRODUCT_ROOT = ROOT.parent
PERMIT_SCRIPT = PRODUCT_ROOT / "keel-permit" / "scripts" / "build_scope_faithfulness_fixtures.py"
OUT_ROOT = ROOT / "tests" / "fixtures" / "scope_faithfulness_corpus"
FIXTURE_ROOT = OUT_ROOT / "fixtures"
TRUST_ROOT = OUT_ROOT / "trust_roots" / "step2-scope-faithfulness-trust-root.json"


def _load_permit_builder():
    spec = importlib.util.spec_from_file_location("scope_fixture_builder", PERMIT_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {PERMIT_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


P = _load_permit_builder()


@dataclass(frozen=True)
class Case:
    fixture_id: str
    expected_verdict: str
    expected_code: str | None
    title: str
    mutate: Callable[[dict[str, Any]], None]
    predicate: dict[str, Any] | None = None
    raw_filters: dict[str, Any] | None = None
    scope_kind: str = "declared_sample"
    population_label: str = "Verifier-local Step 2 fixture"
    trust_root: str = "trust_roots/step2-scope-faithfulness-trust-root.json"


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(P.pretty_json_bytes(value))


def _sign_sidecar(sidecar: dict[str, Any]) -> None:
    key = P.private_key(P.SCOPE_CHECKPOINT_SEED)
    sidecar["signature"]["key_id"] = P.key_id(key)
    sidecar["trust_root_reference"]["key_id"] = P.key_id(key)
    payload = copy.deepcopy(sidecar)
    payload["signature"]["signature"] = "ed25519:placeholder"
    del payload["signature"]["signature"]
    sidecar["signature"]["signature"] = P.sign_b64(key, P.canonical_json_bytes(payload))


def _sign_checkpoint(checkpoint: dict[str, Any], *, seed: bytes = P.SCOPE_CHECKPOINT_SEED) -> None:
    key = P.private_key(seed)
    checkpoint["key_id"] = P.key_id(key)
    checkpoint["public_key"] = P.public_key_b64(key)
    checkpoint["composite_hash"] = P.composite_hash(checkpoint["chain_heads"])
    checkpoint["signature"] = P.sign_b64(key, checkpoint["composite_hash"].encode("utf-8"))


def _sign_manifest(manifest: dict[str, Any], export_payload: dict[str, Any]) -> bytes:
    export_bytes = P.pretty_json_bytes(export_payload)
    export_hash = P.sha256_prefixed(export_bytes)
    key = P.private_key(P.EXPORT_SEED)
    manifest["content_hash"] = export_hash
    manifest["key_id"] = P.key_id(key)
    manifest["public_key"] = P.public_key_b64(key)
    manifest["signature"] = P.sign_b64(key, export_hash.encode("utf-8"))
    return export_bytes


def _build_trust_root(path: Path = TRUST_ROOT, *, rotated: bool = False) -> None:
    export_key = P.private_key(P.EXPORT_SEED)
    scope_key = P.private_key(P.SCOPE_CHECKPOINT_SEED)
    keys = [
        {
            "algorithm": "ed25519",
            "key_id": P.key_id(export_key),
            "public_key": P.public_key_b64(export_key),
            "purpose": "export_signing",
            "status": "active",
            "valid_from": "2026-05-19T11:00:00Z" if rotated else "2026-01-01T00:00:00Z",
            "valid_to": None,
        },
        {
            "algorithm": "ed25519",
            "key_id": P.key_id(scope_key),
            "public_key": P.public_key_b64(scope_key),
            "purpose": "integrity_checkpoint",
            "status": "active",
            "valid_from": "2026-05-19T11:30:00Z" if rotated else "2026-01-01T00:00:00Z",
            "valid_to": None,
        },
        {
            "algorithm": "ed25519",
            "key_id": P.key_id(scope_key),
            "public_key": P.public_key_b64(scope_key),
            "purpose": "scope_state",
            "status": "active",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": "2026-05-19T12:30:00Z" if rotated else None,
        },
    ]
    _write_json(path, {"schema_version": 1, "generated_at": P.SIGNED_AT, "keys": keys})


def _spec(
    fixture_id: str,
    predicate: dict[str, Any],
    raw_filters: dict[str, Any],
    *,
    scope_kind: str = "declared_sample",
    population_label: str = "Verifier-local Step 2 fixture",
) -> Any:
    return P.FixtureSpec(
        fixture_id=fixture_id,
        title=fixture_id,
        purpose=fixture_id,
        predicate=copy.deepcopy(predicate),
        raw_filters=copy.deepcopy(raw_filters),
        scope_kind=scope_kind,
        population_label=population_label,
        presentation_policy={
            "version": "keel.presentation_policy.v1",
            "policy_kind": "none",
            "policy_parameters": {},
        },
    )


def _base_context(case: Case) -> dict[str, Any]:
    entries = P.make_source_chain()
    checkpoint = P.build_checkpoint(entries)
    predicate = copy.deepcopy(
        case.predicate
        or {
            "version": "keel.scope_predicate.v1",
            "operator": "and",
            "equals": {"permit_id": "permit-alpha"},
            "ranges": {},
        }
    )
    raw_filters = copy.deepcopy(case.raw_filters or predicate.get("equals") or {})
    spec = _spec(
        case.fixture_id,
        predicate,
        raw_filters,
        scope_kind=case.scope_kind,
        population_label=case.population_label,
    )
    refs = [P.entry_ref(entry, redact_details=False) for entry in entries]
    disclosures = [record for record in refs if P.predicate_matches(record, predicate)]
    disclosure_ids = {record["event_id"] for record in disclosures}
    bridges = [record for record in refs if record["event_id"] not in disclosure_ids]
    sidecar = P.build_sidecar(spec=spec, entries=entries, disclosure_records=disclosures)
    storage_uri = f"sidecars/{case.fixture_id}-checkpoint-scope-state-v1.json"
    export_payload = {
        "scope_faithfulness": {
            "version": "keel.export_scope_faithfulness.v1",
            "segments": [
                {
                    "segment_id": case.fixture_id,
                    "declared_scope": {
                        "version": "keel.scope_declaration.v1",
                        "scope_kind": case.scope_kind,
                        "chain_scope": P.CHAIN_SCOPE,
                        "population_label": case.population_label,
                        "predicate": predicate,
                        "presentation_policy": spec.presentation_policy,
                    },
                    "declared_start": {
                        "kind": "genesis",
                        "chain_scope": P.CHAIN_SCOPE,
                        "sequence_number": 1,
                        "genesis_prev_hash": P.GENESIS_PREV_HASH,
                    },
                    "declared_end": {
                        "checkpoint_id": P.CHECKPOINT_ID,
                        "chain_scope": P.CHAIN_SCOPE,
                        "sequence_number": entries[-1]["sequence_number"],
                        "last_record_hash": entries[-1]["record_hash"],
                        "boundary_policy": "explicit_checkpoint",
                    },
                    "scope_state_reference": {
                        "artifact_type": "checkpoint_scope_state",
                        "scope_state_id": sidecar["scope_state_id"],
                        "checkpoint_id": P.CHECKPOINT_ID,
                        "chain_scope": P.CHAIN_SCOPE,
                        "artifact_hash": "sha256:pending",
                        "storage_uri": storage_uri,
                    },
                    "canonical_filters": {
                        "canonicalization_profile": "keel.canonical_json.payload.v1",
                        "raw_filters": raw_filters,
                        "filters_hash": P.sha256_prefixed(P.canonical_json_bytes(raw_filters)),
                    },
                    "chain_evidence": {
                        "disclosure_records": disclosures,
                        "proof_bridge_records": bridges,
                    },
                }
            ],
        }
    }
    manifest = {
        "export_id": case.fixture_id,
        "project_id": P.PROJECT_ID,
        "export_type": "audit_export",
        "format": "json",
        "compressed": False,
        "record_count": len(disclosures),
        "content_hash": "sha256:pending",
        "key_id": "",
        "public_key": "",
        "signed_at": P.SIGNED_AT,
        "claim_set": {
            "version": "verifier-claims.v0",
            "registry": P.registry_ref(),
            "claims": [
                {"name": "export.integrity.v1", "required": True},
                {"name": "checkpoint.scope_state.v1", "required": True},
                {"name": "export.scope_faithfulness.v1", "required": True},
            ],
        },
        "semantics_pins": P.export_semantics_pins(),
        "signature": "",
    }
    return {
        "entries": entries,
        "checkpoint": checkpoint,
        "sidecar": sidecar,
        "extra_sidecars": [],
        "export": export_payload,
        "manifest": manifest,
        "write_sidecar": True,
        "trust_root": case.trust_root,
    }


def _refresh_references(ctx: dict[str, Any]) -> None:
    segment = ctx["export"]["scope_faithfulness"]["segments"][0]
    sidecar = ctx["sidecar"]
    sidecar_bytes = P.pretty_json_bytes(sidecar)
    segment["scope_state_reference"].update(
        {
            "scope_state_id": sidecar["scope_state_id"],
            "checkpoint_id": sidecar["checkpoint_id"],
            "chain_scope": sidecar["chain_scope"],
            "artifact_hash": P.sha256_prefixed(sidecar_bytes),
        }
    )


def _write_case(case: Case) -> dict[str, Any]:
    ctx = _base_context(case)
    case.mutate(ctx)
    _refresh_references(ctx)
    export_bytes = _sign_manifest(ctx["manifest"], ctx["export"])
    fixture_dir = FIXTURE_ROOT / case.fixture_id
    if fixture_dir.exists():
        shutil.rmtree(fixture_dir)
    sidecar_rel = ctx["export"]["scope_faithfulness"]["segments"][0]["scope_state_reference"]["storage_uri"]
    _write_json(fixture_dir / "pack" / "export.json", ctx["export"])
    _write_json(fixture_dir / "pack" / "manifest.json", ctx["manifest"])
    _write_json(fixture_dir / "pack" / "checkpoint.json", ctx["checkpoint"])
    if ctx.get("write_sidecar", True):
        _write_json(fixture_dir / sidecar_rel, ctx["sidecar"])
    for extra_rel, extra_sidecar in ctx.get("extra_sidecars", []):
        _write_json(fixture_dir / extra_rel, extra_sidecar)
    (fixture_dir / "README.md").write_text(f"# {case.fixture_id}\n\nExpected: `{case.expected_verdict}` / `{case.expected_code}`.\n", encoding="utf-8")
    return {
        "id": case.fixture_id,
        "kind": "export",
        "title": case.title,
        "expected_verdict": case.expected_verdict,
        "expected_code": case.expected_code,
        "pack": {
            "export_file": f"fixtures/{case.fixture_id}/pack/export.json",
            "manifest": f"fixtures/{case.fixture_id}/pack/manifest.json",
            "checkpoint_file": f"fixtures/{case.fixture_id}/pack/checkpoint.json",
            "sidecar_file": f"fixtures/{case.fixture_id}/{sidecar_rel}",
            "key_manifest": ctx["trust_root"],
        },
        "expected_current": {
            "outcome": "PASS" if case.expected_verdict == "supported" else "FAIL",
            "reason_classes": [] if case.expected_code is None else [case.expected_code],
        },
        "claims": [
            {"name": "export.scope_faithfulness.v1", "expected_verdict": case.expected_verdict}
        ],
        "payload_hash": P.sha256_prefixed(export_bytes),
    }


def _segment(ctx: dict[str, Any]) -> dict[str, Any]:
    return ctx["export"]["scope_faithfulness"]["segments"][0]


def _set_filter_hash(ctx: dict[str, Any]) -> None:
    filters = _segment(ctx)["canonical_filters"]
    filters["filters_hash"] = P.sha256_prefixed(P.canonical_json_bytes(filters["raw_filters"]))


def _set_sidecar_commitment_for_predicate(ctx: dict[str, Any], predicate: dict[str, Any], disclosures: list[dict[str, Any]]) -> None:
    commitment = ctx["sidecar"]["scope_commitments"][0]
    pred_hash = P.predicate_hash(predicate)
    sequences = [record["sequence_number"] for record in disclosures]
    commitment.update(
        {
            "predicate_value": copy.deepcopy(predicate),
            "predicate_value_hash": pred_hash,
            "first_matching_sequence": min(sequences) if sequences else None,
            "last_matching_sequence": max(sequences) if sequences else None,
            "matching_count": len(disclosures),
            "membership_root_hash": P.merkle_root(disclosures, pred_hash),
        }
    )
    _sign_sidecar(ctx["sidecar"])


def main() -> int:
    if OUT_ROOT.exists():
        shutil.rmtree(OUT_ROOT)
    _build_trust_root()

    def head_truncate(ctx: dict[str, Any]) -> None:
        ev = _segment(ctx)["chain_evidence"]
        ev["disclosure_records"] = [r for r in ev["disclosure_records"] if r["sequence_number"] > 2]
        ev["proof_bridge_records"] = [r for r in ev["proof_bridge_records"] if r["sequence_number"] > 2]

    def tail_truncate(ctx: dict[str, Any]) -> None:
        end = _segment(ctx)["declared_end"]
        end["sequence_number"] = 7
        end["last_record_hash"] = ctx["entries"][6]["record_hash"]

    def scope_relabel(ctx: dict[str, Any]) -> None:
        seg = _segment(ctx)
        new_pred = {"version": "keel.scope_predicate.v1", "operator": "and", "equals": {"permit_id": "permit-alpha"}, "ranges": {}}
        seg["declared_scope"]["predicate"] = new_pred
        seg["canonical_filters"]["raw_filters"] = {"permit_id": "permit-alpha"}
        _set_filter_hash(ctx)
        project_pred = {"version": "keel.scope_predicate.v1", "operator": "and", "equals": {"project_id": P.PROJECT_ID}, "ranges": {}}
        _set_sidecar_commitment_for_predicate(ctx, project_pred, seg["chain_evidence"]["disclosure_records"])

    def stale_checkpoint(ctx: dict[str, Any]) -> None:
        seg = _segment(ctx)
        seg["declared_end"]["boundary_policy"] = "latest_checkpoint_at_export"
        ctx["export"]["scope_faithfulness_freshness"] = {
            seg["segment_id"]: {
                "later_checkpoints": [
                    {
                        "checkpoint_id": "99999999-3333-4444-5555-666666666666",
                        "chain_scope": P.CHAIN_SCOPE,
                        "sequence_number": 9,
                    }
                ]
            }
        }

    def reordered_bounds(ctx: dict[str, Any]) -> None:
        _segment(ctx)["declared_start"] = {
            "kind": "checkpoint_anchor",
            "checkpoint_id": "11111111-3333-4444-5555-666666666666",
            "chain_scope": P.CHAIN_SCOPE,
            "sequence_number": 9,
            "last_record_hash": "0" * 64,
        }

    def forged_predicate(ctx: dict[str, Any]) -> None:
        _segment(ctx)["chain_evidence"]["disclosure_records"][0]["payload_json"]["permit_id"] = "permit-forged"

    def sidecar_missing(ctx: dict[str, Any]) -> None:
        ctx["write_sidecar"] = False

    def sidecar_tampered(ctx: dict[str, Any]) -> None:
        ctx["sidecar"]["tree_size"] = int(ctx["sidecar"]["tree_size"]) + 1

    def cardinality_mismatch(ctx: dict[str, Any]) -> None:
        _segment(ctx)["chain_evidence"]["disclosure_records"].pop()

    def membership_root_mismatch(ctx: dict[str, Any]) -> None:
        _segment(ctx)["chain_evidence"]["disclosure_records"][0]["event_id"] += "-tampered"

    def duplicate_commitment(ctx: dict[str, Any]) -> None:
        ctx["sidecar"]["scope_commitments"].append(copy.deepcopy(ctx["sidecar"]["scope_commitments"][0]))
        _sign_sidecar(ctx["sidecar"])

    def empty_scope(ctx: dict[str, Any]) -> None:
        seg = _segment(ctx)
        seg["chain_evidence"]["disclosure_records"] = []
        seg["chain_evidence"]["proof_bridge_records"] = []
        pred = seg["declared_scope"]["predicate"]
        _set_sidecar_commitment_for_predicate(ctx, pred, [])

    def grammar_mismatch(ctx: dict[str, Any]) -> None:
        ctx["sidecar"]["predicate_grammar_version"] = "keel.scope_predicate.v2"
        _sign_sidecar(ctx["sidecar"])

    def unknown_profile(ctx: dict[str, Any]) -> None:
        ctx["sidecar"]["commitment_profile"] = "keel.scope_state.merkle.v2"
        _sign_sidecar(ctx["sidecar"])

    def chain_scope_mismatch(ctx: dict[str, Any]) -> None:
        _segment(ctx)["chain_evidence"]["proof_bridge_records"][0]["chain_scope"] = "project:00000000-0000-0000-0000-000000000099"

    def multiple_segments(ctx: dict[str, Any]) -> None:
        chain_scope = "project:00000000-0000-0000-0000-000000000002"
        seg1 = _segment(ctx)
        seg2 = copy.deepcopy(seg1)
        for field in (
            seg2["declared_scope"],
            seg2["declared_start"],
            seg2["declared_end"],
            seg2["scope_state_reference"],
        ):
            field["chain_scope"] = chain_scope
        seg2["segment_id"] = f"{seg1['segment_id']}-secondary"
        for list_name in ("disclosure_records", "proof_bridge_records"):
            for record in seg2["chain_evidence"][list_name]:
                record["chain_scope"] = chain_scope
                record["payload_json"]["project_id"] = "00000000-0000-0000-0000-000000000002"
        sidecar2 = copy.deepcopy(ctx["sidecar"])
        chain_scope_hash = P.sha256_hex(P.canonical_json_bytes({"chain_scope": chain_scope}))
        sidecar2["chain_scope"] = chain_scope
        sidecar2["scope_state_id"] = f"keel.scope_state.v1:{chain_scope_hash}:{P.CHECKPOINT_ID}"
        sidecar2["scope_commitments"][0]["predicate_value"]["equals"]["permit_id"] = "permit-alpha"
        _sign_sidecar(sidecar2)
        storage_uri = f"sidecars/{seg2['segment_id']}-checkpoint-scope-state-v1.json"
        seg2["scope_state_reference"].update(
            {
                "scope_state_id": sidecar2["scope_state_id"],
                "artifact_hash": P.sha256_prefixed(P.pretty_json_bytes(sidecar2)),
                "storage_uri": storage_uri,
            }
        )
        ctx["checkpoint"]["chain_heads"][chain_scope] = copy.deepcopy(
            ctx["checkpoint"]["chain_heads"][P.CHAIN_SCOPE]
        )
        _sign_checkpoint(ctx["checkpoint"])
        ctx["export"]["scope_faithfulness"]["segments"].append(seg2)
        ctx["extra_sidecars"].append((storage_uri, sidecar2))

    def no_op(ctx: dict[str, Any]) -> None:
        return None

    cases = [
        Case("scope-faithfulness-neg-head-truncate", "disproved", "EXPORT_BOUNDARY_START_MISMATCH", "Head truncate", head_truncate),
        Case("scope-faithfulness-neg-tail-truncate", "disproved", "EXPORT_BOUNDARY_CHECKPOINT_MISMATCH", "Tail truncate", tail_truncate),
        Case("scope-faithfulness-neg-scope-relabel", "insufficient_evidence", "EXPORT_SCOPE_COMMITMENT_MISSING", "Scope relabel", scope_relabel),
        Case("scope-faithfulness-neg-stale-checkpoint-latest-policy", "disproved", "EXPORT_BOUNDARY_STALE_CHECKPOINT", "Stale checkpoint", stale_checkpoint),
        Case("scope-faithfulness-neg-reordered-bounds", "disproved", "EXPORT_BOUNDARY_START_AFTER_END", "Reordered bounds", reordered_bounds),
        Case("scope-faithfulness-neg-forged-predicate", "disproved", "EXPORT_SCOPE_PREDICATE_VIOLATED", "Forged predicate", forged_predicate),
        Case("scope-faithfulness-neg-sidecar-missing", "insufficient_evidence", "CHECKPOINT_SCOPE_STATE_MISSING", "Sidecar missing", sidecar_missing),
        Case("scope-faithfulness-neg-sidecar-tampered", "disproved", "CHECKPOINT_SCOPE_STATE_SIGNATURE_INVALID", "Sidecar tampered", sidecar_tampered),
        Case("scope-faithfulness-neg-cardinality-mismatch", "disproved", "EXPORT_SCOPE_CARDINALITY_MISMATCH", "Cardinality mismatch", cardinality_mismatch, predicate={"version": "keel.scope_predicate.v1", "operator": "and", "equals": {"event_type": "audit.integrity_digest"}, "ranges": {}}, raw_filters={"event_type": "audit.integrity_digest"}),
        Case("scope-faithfulness-neg-membership-root-mismatch", "disproved", "EXPORT_SCOPE_MEMBERSHIP_ROOT_MISMATCH", "Membership root mismatch", membership_root_mismatch),
        Case("scope-faithfulness-neg-sidecar-duplicate-predicate-commitment", "disproved", "CHECKPOINT_SCOPE_STATE_COMMITMENT_PREDICATE_DUPLICATE", "Duplicate commitment", duplicate_commitment),
        Case("scope-faithfulness-edge-empty-scope-cardinality-zero", "supported", None, "Empty scope", empty_scope, predicate={"version": "keel.scope_predicate.v1", "operator": "and", "equals": {"category": "nonexistent"}, "ranges": {}}, raw_filters={"category": "nonexistent"}),
        Case("scope-faithfulness-edge-single-entry-scope", "supported", None, "Single entry", no_op, predicate={"version": "keel.scope_predicate.v1", "operator": "and", "equals": {"event_type": "audit.integrity_digest"}, "ranges": {}}, raw_filters={"event_type": "audit.integrity_digest"}),
        Case("scope-faithfulness-edge-multiple-chain-scope-segments", "supported", None, "Multiple segments", multiple_segments),
        Case("scope-faithfulness-edge-key-rotation-sidecar-export", "supported", None, "Key rotation", no_op, trust_root="trust_roots/key-rotation-trust-root.json"),
        Case("scope-faithfulness-edge-predicate-grammar-version-mismatch", "unverifiable_scope", "CHECKPOINT_SCOPE_STATE_GRAMMAR_UNSUPPORTED", "Grammar mismatch", grammar_mismatch),
        Case("scope-faithfulness-edge-unknown-commitment-profile", "unverifiable_scope", "CHECKPOINT_SCOPE_STATE_COMMITMENT_PROFILE_UNKNOWN", "Unknown profile", unknown_profile),
        Case("scope-faithfulness-edge-bridge-records-not-members", "supported", None, "Bridge records", no_op),
        Case("scope-faithfulness-edge-single-segment-with-two-chain-scopes", "disproved", "EXPORT_SCOPE_CHAIN_SCOPE_MISMATCH", "Chain-scope mismatch", chain_scope_mismatch),
    ]
    _build_trust_root(OUT_ROOT / "trust_roots" / "key-rotation-trust-root.json", rotated=True)
    records = [_write_case(case) for case in cases]
    _write_json(
        OUT_ROOT / "corpus.json",
        {
            "corpus_version": "scope-faithfulness-pr3-local-v1",
            "soundness_rule": "Expected verdicts and failure codes are derived from Step 2 design Section 8/10 before verifier execution.",
            "records": records,
        },
    )
    print(f"Generated {len(records)} verifier-local scope-faithfulness fixtures.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
