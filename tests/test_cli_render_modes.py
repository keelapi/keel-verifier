from __future__ import annotations

import json

from keel_verifier.verifier_output_render import OUTCOME_RENDER_MAPPINGS


def _fixture() -> dict:
    return {
        "schema_version": "verifier_output.v3.0",
        "verifier_version": "v3.0.0",
        "verified_at": "2026-06-02T22:00:00Z",
        "overall_outcome": "WARN_RECEIPT_REPLAY",
        "evidence_graph": {
            "nodes": [
                {
                    "id": "permit:pmt_pr5",
                    "type": "permit",
                    "label": "Permit pmt_pr5",
                    "trust_domain": "issuer",
                    "verification_outcome": "WARN_RECEIPT_REPLAY",
                    "details": {},
                },
                {
                    "id": "execution:exe_pr5",
                    "type": "execution",
                    "label": "Execution exe_pr5",
                    "trust_domain": "issuer",
                    "verification_outcome": "allowed_and_paid",
                    "details": {},
                },
                {
                    "id": "attestation:provider_attestation:pmt_pr5:0",
                    "type": "provider_attestation",
                    "label": "Provider Attestation",
                    "trust_domain": "provider_principal",
                    "verification_outcome": "WARN_RECEIPT_REPLAY",
                    "severity": "OPTIONAL",
                    "provider": "stripe",
                    "rail_class": "stripe.mpp.v1",
                    "signer_id": "profile_live_pr5",
                    "details": {
                        "replay_class": "cross_execution_replay",
                        "bound_execution_record_hash": "2" * 64,
                        "rendered_findings": [
                            {
                                "outcome": "WARN_RECEIPT_REPLAY",
                                "category": "REPLAY",
                                "severity": "OPTIONAL",
                                "replay_class": "cross_execution_replay",
                                "title": "Optional receipt replay check failed",
                                "badge": "[WARN_RECEIPT_REPLAY]",
                                "color": "yellow",
                                "recommended_action": "Review replay provenance before relying on optional evidence.",
                                "spec_section_anchor": "pr5-20-outcome-render-mappings-replay",
                            }
                        ],
                    },
                },
            ],
            "edges": [
                {
                    "from_id": "permit:pmt_pr5",
                    "to_id": "execution:exe_pr5",
                    "binding_type": "permit_decides",
                    "binding_hash": "c" * 64,
                },
                {
                    "from_id": "execution:exe_pr5",
                    "to_id": "attestation:provider_attestation:pmt_pr5:0",
                    "binding_type": "provider_receipt_binds",
                    "binding_hash": "2" * 64,
                    "trust_domain_crossing": True,
                },
            ],
        },
        "verifier": {
            "primary_outcome": "WARN_RECEIPT_REPLAY",
            "status": "WARN",
            "findings": [
                {
                    "outcome": "WARN_RECEIPT_REPLAY",
                    "category": "REPLAY",
                    "severity": "OPTIONAL",
                    "replay_class": "cross_execution_replay",
                }
            ],
            "highest_severity": "OPTIONAL",
            "parse_valid": True,
            "signature_valid": True,
            "binding_valid": True,
            "policy_satisfied": True,
            "replay_check_authoritative": True,
            "replay_class": "cross_execution_replay",
        },
        "execution": {
            "status": "completed",
            "permit_outcome": "allowed",
            "rail_outcome": "paid",
            "settlement_status": "settled",
            "primary_outcome": "allowed_and_paid",
        },
        "verification_semantics_version": "3B.v1.5",
        "semantics_compatibility": {
            "status": "current",
            "record_version": "3B.v1.5",
            "verifier_max_supported": "3B.v1.5",
        },
    }


def test_outcome_table_is_complete() -> None:
    assert len(OUTCOME_RENDER_MAPPINGS) == 20
    assert OUTCOME_RENDER_MAPPINGS["WARN_RECEIPT_REPLAY"]["color"] == "yellow"


def test_render_cli_json_tree_graph_html(run_cli, tmp_path) -> None:
    path = tmp_path / "verifier-output.json"
    path.write_text(json.dumps(_fixture()), encoding="utf-8")

    json_result = run_cli("render", str(path))
    assert json_result.returncode == 0, json_result.stderr
    payload = json.loads(json_result.stdout)
    assert payload["schema_version"] == "verifier_output.v3.0"
    assert payload["outcome_render_mappings"]["WARN_RECEIPT_REPLAY"]["badge"] == (
        "[WARN_RECEIPT_REPLAY]"
    )

    tree_result = run_cli("render", str(path), "--format", "tree", "--plain")
    assert tree_result.returncode == 0, tree_result.stderr
    assert "Provider Attestation [WARN_RECEIPT_REPLAY]" in tree_result.stdout
    assert "trust_domain=provider_principal" in tree_result.stdout
    assert "replay_class: cross_execution_replay" in tree_result.stdout

    graph_result = run_cli("render", str(path), "--format", "graph")
    assert graph_result.returncode == 0, graph_result.stderr
    assert "digraph keel_verifier_evidence" in graph_result.stdout
    assert "provider_receipt_binds" in graph_result.stdout

    html_result = run_cli("render", str(path), "--format", "html")
    assert html_result.returncode == 0, html_result.stderr
    assert 'class="keel-verifier-output"' in html_result.stdout
    assert "WARN_RECEIPT_REPLAY" in html_result.stdout


def test_render_cli_rejects_unknown_schema(run_cli, tmp_path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"schema_version": "legacy"}), encoding="utf-8")
    result = run_cli("render", str(path), "--format", "tree")
    assert result.returncode != 0
    assert "unsupported verifier output schema_version" in result.stderr


def test_render_help_embeds_all_outcome_codes(run_cli) -> None:
    result = run_cli("render", "--help")
    assert result.returncode == 0
    for outcome in OUTCOME_RENDER_MAPPINGS:
        assert outcome in result.stdout
