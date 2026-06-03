"""PR 5 verifier output rendering for keel-verifier."""

from __future__ import annotations

import json
from html import escape
from pathlib import Path
from typing import Any, Final

VERIFIER_OUTPUT_SCHEMA_VERSION: Final[str] = "verifier_output.v3.0"
VERIFICATION_SEMANTICS_VERSION: Final[str] = "3B.v1.5"

OUTCOME_RENDER_MAPPINGS: Final[dict[str, dict[str, str | None]]] = {
    "PASS": {
        "title": "Provider attestation verified",
        "badge": "[PASS]",
        "color": "green",
        "recommended_action": None,
        "spec_section_anchor": "pr5-20-outcome-render-mappings-pass",
    },
    "PASS_WITH_INFO": {
        "title": "Provider attestation verified with informational notes",
        "badge": "[PASS_WITH_INFO]",
        "color": "green",
        "recommended_action": "Review informational finding details; no blocking action is required.",
        "spec_section_anchor": "pr5-20-outcome-render-mappings-pass-with-info",
    },
    "FAIL_MISSING_PROVIDER_ATTESTATION": {
        "title": "Required provider attestation is missing",
        "badge": "[FAIL_MISSING_PROVIDER_ATTESTATION]",
        "color": "red",
        "recommended_action": "Attach the required provider attestation before accepting the execution record.",
        "spec_section_anchor": "pr5-20-outcome-render-mappings-missing",
    },
    "WARN_MISSING_PROVIDER_ATTESTATION": {
        "title": "Optional provider attestation is missing",
        "badge": "[WARN_MISSING_PROVIDER_ATTESTATION]",
        "color": "yellow",
        "recommended_action": "Collect the optional provider attestation when available.",
        "spec_section_anchor": "pr5-20-outcome-render-mappings-missing",
    },
    "INFO_MISSING_PROVIDER_ATTESTATION": {
        "title": "Advisory provider attestation is missing",
        "badge": "[INFO_MISSING_PROVIDER_ATTESTATION]",
        "color": "blue",
        "recommended_action": "No blocking action; advisory evidence was not present.",
        "spec_section_anchor": "pr5-20-outcome-render-mappings-missing",
    },
    "FAIL_PROVIDER_SIGNATURE": {
        "title": "Required provider signature failed",
        "badge": "[FAIL_PROVIDER_SIGNATURE]",
        "color": "red",
        "recommended_action": "Reject the attestation and request a fresh provider-signed receipt.",
        "spec_section_anchor": "pr5-20-outcome-render-mappings-signature",
    },
    "WARN_PROVIDER_SIGNATURE": {
        "title": "Optional provider signature failed",
        "badge": "[WARN_PROVIDER_SIGNATURE]",
        "color": "yellow",
        "recommended_action": "Treat the optional provider evidence as untrusted.",
        "spec_section_anchor": "pr5-20-outcome-render-mappings-signature",
    },
    "INFO_PROVIDER_SIGNATURE": {
        "title": "Advisory provider signature failed",
        "badge": "[INFO_PROVIDER_SIGNATURE]",
        "color": "blue",
        "recommended_action": "Record the signature issue for audit review.",
        "spec_section_anchor": "pr5-20-outcome-render-mappings-signature",
    },
    "FAIL_PROVIDER_KEY_PROVENANCE": {
        "title": "Required provider key provenance failed",
        "badge": "[FAIL_PROVIDER_KEY_PROVENANCE]",
        "color": "red",
        "recommended_action": "Resolve provider key registration, validity, revocation, or compromise state.",
        "spec_section_anchor": "pr5-20-outcome-render-mappings-key-provenance",
    },
    "WARN_PROVIDER_KEY_PROVENANCE": {
        "title": "Optional provider key provenance failed",
        "badge": "[WARN_PROVIDER_KEY_PROVENANCE]",
        "color": "yellow",
        "recommended_action": "Review provider key provenance before relying on optional evidence.",
        "spec_section_anchor": "pr5-20-outcome-render-mappings-key-provenance",
    },
    "INFO_PROVIDER_KEY_PROVENANCE": {
        "title": "Advisory provider key provenance failed",
        "badge": "[INFO_PROVIDER_KEY_PROVENANCE]",
        "color": "blue",
        "recommended_action": "Record the key provenance issue for audit review.",
        "spec_section_anchor": "pr5-20-outcome-render-mappings-key-provenance",
    },
    "FAIL_ATTESTATION_BINDING": {
        "title": "Required attestation binding failed",
        "badge": "[FAIL_ATTESTATION_BINDING]",
        "color": "red",
        "recommended_action": "Reject the attestation; it does not bind to the captured execution record.",
        "spec_section_anchor": "pr5-20-outcome-render-mappings-binding",
    },
    "WARN_ATTESTATION_BINDING": {
        "title": "Optional attestation binding failed",
        "badge": "[WARN_ATTESTATION_BINDING]",
        "color": "yellow",
        "recommended_action": "Do not rely on the optional attestation binding without remediation.",
        "spec_section_anchor": "pr5-20-outcome-render-mappings-binding",
    },
    "INFO_ATTESTATION_BINDING": {
        "title": "Advisory attestation binding failed",
        "badge": "[INFO_ATTESTATION_BINDING]",
        "color": "blue",
        "recommended_action": "Record the advisory binding issue for audit review.",
        "spec_section_anchor": "pr5-20-outcome-render-mappings-binding",
    },
    "FAIL_RECEIPT_REPLAY": {
        "title": "Required receipt replay check failed",
        "badge": "[FAIL_RECEIPT_REPLAY]",
        "color": "red",
        "recommended_action": "Reject the replayed receipt and require a receipt unique to this execution.",
        "spec_section_anchor": "pr5-20-outcome-render-mappings-replay",
    },
    "WARN_RECEIPT_REPLAY": {
        "title": "Optional receipt replay check failed",
        "badge": "[WARN_RECEIPT_REPLAY]",
        "color": "yellow",
        "recommended_action": "Review replay provenance before relying on optional evidence.",
        "spec_section_anchor": "pr5-20-outcome-render-mappings-replay",
    },
    "INFO_RECEIPT_REPLAY": {
        "title": "Advisory receipt replay check failed",
        "badge": "[INFO_RECEIPT_REPLAY]",
        "color": "blue",
        "recommended_action": "Record replay provenance for audit review.",
        "spec_section_anchor": "pr5-20-outcome-render-mappings-replay",
    },
    "FAIL_OUT_OF_AUTHORITY_WINDOW": {
        "title": "Required provider event is outside the authority window",
        "badge": "[FAIL_OUT_OF_AUTHORITY_WINDOW]",
        "color": "red",
        "recommended_action": "Reject the attestation; obtain evidence within the permit authority window.",
        "spec_section_anchor": "pr5-20-outcome-render-mappings-timing",
    },
    "WARN_OUT_OF_AUTHORITY_WINDOW": {
        "title": "Optional provider event is outside the authority window",
        "badge": "[WARN_OUT_OF_AUTHORITY_WINDOW]",
        "color": "yellow",
        "recommended_action": "Review timing evidence before relying on optional evidence.",
        "spec_section_anchor": "pr5-20-outcome-render-mappings-timing",
    },
    "INFO_OUT_OF_AUTHORITY_WINDOW": {
        "title": "Advisory provider event is outside the authority window",
        "badge": "[INFO_OUT_OF_AUTHORITY_WINDOW]",
        "color": "blue",
        "recommended_action": "Record timing evidence for audit review.",
        "spec_section_anchor": "pr5-20-outcome-render-mappings-timing",
    },
}


def load_verifier_output(path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("verifier output must be a JSON object")
    if payload.get("schema_version") != VERIFIER_OUTPUT_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported verifier output schema_version={payload.get('schema_version')!r}"
        )
    return payload


def _nodes(payload: dict[str, Any]) -> list[dict[str, Any]]:
    graph = payload.get("evidence_graph")
    nodes = graph.get("nodes") if isinstance(graph, dict) else None
    return [node for node in nodes if isinstance(node, dict)] if isinstance(nodes, list) else []


def _edges(payload: dict[str, Any]) -> list[dict[str, Any]]:
    graph = payload.get("evidence_graph")
    edges = graph.get("edges") if isinstance(graph, dict) else None
    return [edge for edge in edges if isinstance(edge, dict)] if isinstance(edges, list) else []


def render_json(payload: dict[str, Any]) -> str:
    enriched = dict(payload)
    enriched.setdefault("outcome_render_mappings", OUTCOME_RENDER_MAPPINGS)
    return json.dumps(enriched, indent=2, sort_keys=True)


def render_tree(payload: dict[str, Any], *, plain: bool = False) -> str:
    verifier = payload.get("verifier") if isinstance(payload.get("verifier"), dict) else {}
    execution = payload.get("execution") if isinstance(payload.get("execution"), dict) else {}
    lines = [
        f"Verifier output {payload.get('schema_version')} - {payload.get('overall_outcome')}",
        (
            "Health: "
            f"parse {verifier.get('parse_valid')} · "
            f"signature {verifier.get('signature_valid')} · "
            f"binding {verifier.get('binding_valid')} · "
            f"policy {verifier.get('policy_satisfied')} · "
            f"replay_authoritative {verifier.get('replay_check_authoritative')}"
        ),
        (
            "Execution: "
            f"{execution.get('primary_outcome')} "
            f"(permit={execution.get('permit_outcome')}, rail={execution.get('rail_outcome')}, "
            f"settlement={execution.get('settlement_status')})"
        ),
    ]
    compatibility = payload.get("semantics_compatibility")
    if isinstance(compatibility, dict) and compatibility.get("status") != "current":
        lines.append(
            "[WARN] Semantics version mismatch "
            f"record={compatibility.get('record_version')} "
            f"verifier={compatibility.get('verifier_max_supported')}"
        )

    child_ids = {str(edge.get("to_id")) for edge in _edges(payload)}
    roots = [node for node in _nodes(payload) if str(node.get("id")) not in child_ids]
    children: dict[str, list[dict[str, Any]]] = {}
    for edge in _edges(payload):
        to_id = str(edge.get("to_id"))
        child = next((node for node in _nodes(payload) if str(node.get("id")) == to_id), None)
        if child is not None:
            children.setdefault(str(edge.get("from_id")), []).append(child)
    for root in roots:
        lines.extend(_render_node(root, children, depth=0, plain=plain))
    return "\n".join(lines)


def _render_node(
    node: dict[str, Any],
    children: dict[str, list[dict[str, Any]]],
    *,
    depth: int,
    plain: bool,
) -> list[str]:
    prefix = "  " * depth
    branch = "- " if plain else "├─ "
    detail = node.get("details") if isinstance(node.get("details"), dict) else {}
    fields = [
        f"trust_domain={node.get('trust_domain')}",
        f"severity={node.get('severity')}" if node.get("severity") else "",
        f"provider={node.get('provider')}" if node.get("provider") else "",
        f"rail={node.get('rail_class')}" if node.get("rail_class") else "",
        f"signer={node.get('signer_id')}" if node.get("signer_id") else "",
    ]
    lines = [
        (
            f"{prefix}{branch}{node.get('label')} "
            f"[{node.get('verification_outcome')}] "
            f"{' '.join(field for field in fields if field)}"
        ).rstrip()
    ]
    for key in ("replay_class", "key_state_reason", "binding_reason", "timing_reason"):
        if detail.get(key):
            lines.append(f"{prefix}  {key}: {detail[key]}")
    rendered_findings = detail.get("rendered_findings")
    if isinstance(rendered_findings, list):
        for finding in rendered_findings:
            if isinstance(finding, dict):
                title = finding.get("title") or finding.get("outcome")
                badge = finding.get("badge") or f"[{finding.get('outcome')}]"
                reason = f" reason={finding['reason']}" if finding.get("reason") else ""
                lines.append(f"{prefix}  finding {badge}: {title}{reason}")
    for child in children.get(str(node.get("id")), []):
        lines.extend(_render_node(child, children, depth=depth + 1, plain=plain))
    return lines


def render_graph(payload: dict[str, Any]) -> str:
    lines = ["digraph keel_verifier_evidence {"]
    for node in _nodes(payload):
        label = f"{node.get('label')}\\n{node.get('trust_domain')}\\n{node.get('verification_outcome')}"
        lines.append(f'  "{node.get("id")}" [label="{escape(label)}"];')
    for edge in _edges(payload):
        label = str(edge.get("binding_type") or "")
        if edge.get("binding_hash"):
            label = f"{label}\\n{edge['binding_hash']}"
        lines.append(f'  "{edge.get("from_id")}" -> "{edge.get("to_id")}" [label="{escape(label)}"];')
    lines.append("}")
    return "\n".join(lines)


def render_html(payload: dict[str, Any]) -> str:
    items = []
    for node in _nodes(payload):
        items.append(
            "<li>"
            f"<strong>{escape(str(node.get('label')))}</strong> "
            f"<span>{escape(str(node.get('verification_outcome')))}</span> "
            f"<code>{escape(str(node.get('trust_domain')))}</code>"
            "</li>"
        )
    return (
        '<section class="keel-verifier-output" data-schema-version="'
        f"{escape(str(payload.get('schema_version')))}\">"
        f"<h2>Verifier outcome: {escape(str(payload.get('overall_outcome')))}</h2>"
        f"<ul>{''.join(items)}</ul>"
        "</section>"
    )


def render_output(payload: dict[str, Any], *, output_format: str, plain: bool = False) -> str:
    if output_format == "json":
        return render_json(payload)
    if output_format == "tree":
        return render_tree(payload, plain=plain)
    if output_format == "graph":
        return render_graph(payload)
    if output_format == "html":
        return render_html(payload)
    raise ValueError(f"unsupported format {output_format!r}")
