"""Offline re-derivation of an authorized_action from a signed classification fact.

Reference implementation of the normative decision_algorithm in
keel.permit.action_classification_derivation.v1. Given a permit's signed
classification facts and an immutable trust configuration (the set of accepted
classification-registry digests), it re-derives the authorized_action the whole
chain — (connector, tool) -> value_movement -> payment.execute — from signed
facts plus the versioned, hash-pinned keel-permit artifacts alone.

Display-only and strictly non-authorizing, like permit_presentation: the result
never flows into verdicts, claim adjudication, cryptographic checks, or exit
codes. A wrong derivation degrades a title; it cannot escalate authorization.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from importlib import resources
from typing import Any, Mapping

import rfc8785

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_DATA = "data/permit_to_x"

Outcome = str  # "valid" | "no_derivation" | "invalid" | "unverifiable"


@dataclass(frozen=True)
class TrustConfig:
    """Explicit, immutable verifier input (decision_algorithm verification_inputs).

    ``trusted_registry_digests`` maps an accepted classification-registry digest
    to the validated artifact bytes it resolves to. Membership alone is not
    enough — step 3 hash-verifies, so the store returns bytes, not just a flag.
    """

    trusted_registry_digests: Mapping[str, bytes] = field(default_factory=dict)


@dataclass(frozen=True)
class DerivationResult:
    outcome: Outcome
    authorized_action: str | None = None
    reason: str | None = None
    trace: tuple[str, ...] = ()


def _load(name: str) -> dict[str, Any]:
    raw = resources.files("keel_verifier").joinpath(f"{_DATA}/{name}").read_bytes()
    return json.loads(raw.decode("utf-8"))


_RULESET = _load("semantics/permit/action_classification_derivation_v1.json")["body"]
_GRAMMAR = re.compile(_RULESET["identifier_grammar"]["grammar"])
_KNOWN_KINDS = frozenset(_RULESET["classification_subject_variants"].keys())
_KNOWN_PREDICATES = frozenset({"classification_registry_membership"})


def canonical_pinned_registry() -> tuple[dict[str, Any], str]:
    """The one classification registry this verifier build vendors, and its digest."""
    raw = resources.files("keel_verifier").joinpath(
        f"{_DATA}/semantics/permit/value_movement_classification_v1.json"
    ).read_bytes()
    return json.loads(raw.decode("utf-8")), "sha256:" + hashlib.sha256(raw).hexdigest()


def default_trust_config() -> TrustConfig:
    """Trust exactly the vendored, pinned registry — the build's single trust anchor."""
    raw = resources.files("keel_verifier").joinpath(
        f"{_DATA}/semantics/permit/value_movement_classification_v1.json"
    ).read_bytes()
    return TrustConfig({"sha256:" + hashlib.sha256(raw).hexdigest(): raw})


def _input_digest(connector_identity: str, canonical_tool_name: str) -> str:
    obj = {
        "profile": "keel.registered_tool_classification_input.v1",
        "connector_identity": connector_identity,
        "canonical_tool_name": canonical_tool_name,
    }
    return "sha256:" + hashlib.sha256(rfc8785.dumps(obj)).hexdigest()


def _validate_registry_bytes(raw: bytes) -> dict[str, Any] | None:
    """Step 4: is B a valid classification registry? Returns parsed body or None."""
    try:
        doc = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    if doc.get("version") != "v1" or doc.get("kind") != "value_movement_tool_classification":
        return None
    body = doc.get("body")
    if not isinstance(body, dict) or body.get("classification") != "value_movement":
        return None
    entries = body.get("entries")
    if not isinstance(entries, list):
        return None
    seen: set[tuple[str, str]] = set()
    for e in entries:
        if not isinstance(e, dict):
            return None
        key = (e.get("connector_identity"), e.get("canonical_tool_name"))
        if None in key or key in seen:  # duplicate or missing -> invalid registry
            return None
        if not _GRAMMAR.match(key[0]) or not _GRAMMAR.match(key[1]):
            return None
        seen.add(key)
    return body


def derive(facts: Mapping[str, Any], trust: TrustConfig) -> DerivationResult:
    """Execute the normative decision_algorithm. First terminal step wins."""
    t: list[str] = []
    cls = facts.get("classification", {}) or {}
    subject = cls.get("subject", {}) or {}
    prov = cls.get("provenance", {}) or {}
    reg_digest = str(prov.get("registry", {}).get("artifact_digest", ""))
    in_digest = str(prov.get("input", {}).get("digest", ""))

    def done(outcome, **kw):
        return DerivationResult(outcome=outcome, trace=tuple(t), **kw)

    # 1. COMMON ENVELOPE — common signed-field syntax before variant dispatch.
    if not _DIGEST_RE.match(reg_digest) or not _DIGEST_RE.match(in_digest):
        return done("invalid", reason="malformed_common_digest")
    t.append("1:common envelope ok")

    # 2. SUBJECT DISPATCH
    kind = subject.get("kind")
    if kind in _KNOWN_KINDS:
        ci, tn = subject.get("connector_identity"), subject.get("canonical_tool_name")
        if not ci or not tn or not _GRAMMAR.match(ci) or not _GRAMMAR.match(tn):
            return done("invalid", reason="malformed_identifier")
        t.append("2:known variant ok")
    else:
        return done("no_derivation", reason="unsupported_derivation_subject")

    # 3. DEPENDENCY RESOLUTION (hash-verifying)
    if reg_digest not in trust.trusted_registry_digests:
        return done("unverifiable", reason="artifact_unavailable")
    reg_bytes = trust.trusted_registry_digests[reg_digest]
    if "sha256:" + hashlib.sha256(reg_bytes).hexdigest() != reg_digest:
        return done("invalid", reason="dependency_integrity")
    t.append("3:resolved, hash-verified")

    # 4. DEPENDENCY VALIDATION
    reg_body = _validate_registry_bytes(reg_bytes)
    if reg_body is None:
        return done("invalid", reason="dependency_artifact_invalid")
    members = {(e["connector_identity"], e["canonical_tool_name"]) for e in reg_body["entries"]}
    t.append("4:registry valid")

    # 5. INTERNAL DIGEST AGREEMENT — v1 no-op (single authoritative ref).

    # 6. INPUT DIGEST (self-contained)
    if in_digest != _input_digest(ci, tn):
        return done("invalid", reason="input_digest_mismatch")
    t.append("6:input_digest ok")

    # 7. RULE MATCH SET
    def fact_at(path):
        node: Any = facts
        for part in path.split("."):
            if not isinstance(node, dict):
                return None
            node = node.get(part)
        return node

    matched = [
        r for r in _RULESET["rules"]
        if all(fact_at(c["fact"]) == c["value"] for c in r["applies_when"]["all"])
    ]
    if len(matched) == 0:
        return done("no_derivation", reason="no_rule_match")
    if len(matched) > 1:
        return done("invalid", reason="multiple_rule_match")
    rule = matched[0]
    t.append(f"7:one rule ({rule['rule_id']})")

    # 8. REQUIRES — 8a evaluability, 8b membership, 8c enforcement.
    for req in rule["requires"]:
        if "predicate" in req and req["predicate"] not in _KNOWN_PREDICATES:
            return done("invalid", reason="unevaluable_predicate")
    for req in rule["requires"]:
        if req.get("predicate") == "classification_registry_membership":
            if (ci, tn) not in members:
                return done("no_derivation", reason="membership_absent")
    for req in rule["requires"]:
        if "fact" in req and fact_at(req["fact"]) != req["value"]:
            return done("no_derivation", reason="not_enforced_in_path")
    t.append("8:requires ok")

    # 9. DERIVE
    return done("valid", authorized_action=rule["derives"]["authorized_action"])
