#!/usr/bin/env python3
"""Run the verifier-claim golden fixture corpus against a verifier CLI.

The corpus stores durable doctrine verdicts per claim, but today's verifier
CLIs expose whole-pack PASS/FAIL plus reason text. This runner asserts that
temporary surface while preserving the doctrine verdicts in its JSON report.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
PRODUCT_ROOT = REPO_ROOT.parent
DEFAULT_CORPUS = (
    PRODUCT_ROOT
    / "keel-permit"
    / "test_vectors"
    / "verifier_claims"
    / "v0"
    / "corpus.json"
)
DEFAULT_ALTERNATE_SCRIPT = PRODUCT_ROOT / "keel-api" / "scripts" / "keel_verify.py"


@dataclass(frozen=True)
class VerifierTarget:
    profile: str
    command_prefix: list[str]
    cwd: Path


def _abs(corpus_root: Path, value: str) -> Path:
    return (corpus_root / value).resolve()


def _record_pack_path(record: dict[str, Any], *, corpus_root: Path) -> Path:
    pack = record.get("pack")
    if not isinstance(pack, dict):
        raise ValueError(f"{record.get('id')}: pack must be an object")

    kind = record.get("kind")
    if kind == "export":
        manifest = pack.get("manifest")
        if not isinstance(manifest, str):
            raise ValueError(f"{record.get('id')}: export pack requires manifest")
        return _abs(corpus_root, manifest)

    if kind == "checkpoint":
        checkpoint_file = pack.get("checkpoint_file")
        if not isinstance(checkpoint_file, str):
            raise ValueError(f"{record.get('id')}: checkpoint pack requires checkpoint_file")
        return _abs(corpus_root, checkpoint_file)

    if kind == "claim":
        evidence_file = pack.get("evidence_file")
        if not isinstance(evidence_file, str):
            raise ValueError(f"{record.get('id')}: claim pack requires evidence_file")
        return _abs(corpus_root, evidence_file)

    raise ValueError(f"{record.get('id')}: unsupported kind {kind!r}")


def _expected_semantics_mode(record: dict[str, Any], *, corpus_root: Path) -> str:
    explicit = record.get("expected_mode")
    if explicit in {"legacy_unpinned", "pinned"}:
        return str(explicit)
    if explicit is not None:
        raise ValueError(
            f"{record.get('id')}: expected_mode must be legacy_unpinned or pinned"
        )

    pack_path = _record_pack_path(record, corpus_root=corpus_root)
    try:
        pack = json.loads(pack_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(
            f"{record.get('id')}: could not infer semantics mode from {pack_path}: {exc}"
        ) from exc
    if not isinstance(pack, dict):
        raise ValueError(f"{record.get('id')}: pack JSON must be an object")
    if "claim_set" in pack or "semantics_pins" in pack:
        return "pinned"
    return "legacy_unpinned"


def _record_command_args(
    record: dict[str, Any],
    *,
    corpus_root: Path,
    as_json: bool = False,
) -> list[str]:
    pack = record.get("pack")
    if not isinstance(pack, dict):
        raise ValueError(f"{record.get('id')}: pack must be an object")

    kind = record.get("kind")
    features = pack.get("features") or []
    if not isinstance(features, list):
        raise ValueError(f"{record.get('id')}: pack.features must be a list")

    if kind == "export":
        export_file = pack.get("export_file")
        manifest = pack.get("manifest")
        if not isinstance(export_file, str) or not isinstance(manifest, str):
            raise ValueError(f"{record.get('id')}: export pack requires export_file and manifest")
        args = [
            "export",
            "--export-file",
            str(_abs(corpus_root, export_file)),
            "--manifest",
            str(_abs(corpus_root, manifest)),
        ]
        key_manifest = pack.get("key_manifest")
        if isinstance(key_manifest, str) and key_manifest:
            args.extend(["--key-manifest", str(_abs(corpus_root, key_manifest))])
        if "walk_events" in features:
            args.append("--walk-events")
        if "verify_closure" in features:
            args.append("--verify-closure")
        if as_json:
            args.insert(1, "--json")
        return args

    if kind == "checkpoint":
        checkpoint_file = pack.get("checkpoint_file")
        if not isinstance(checkpoint_file, str):
            raise ValueError(f"{record.get('id')}: checkpoint pack requires checkpoint_file")
        args = [
            "checkpoint",
            "--checkpoint-file",
            str(_abs(corpus_root, checkpoint_file)),
        ]
        key_manifest = pack.get("key_manifest")
        if isinstance(key_manifest, str) and key_manifest:
            args.extend(["--key-manifest", str(_abs(corpus_root, key_manifest))])
        if as_json:
            args.insert(1, "--json")
        return args

    if kind == "claim":
        claim = record.get("claim")
        if claim != "delegation_denied_correctly":
            raise ValueError(f"{record.get('id')}: unsupported claim {claim!r}")
        evidence_file = pack.get("evidence_file")
        if not isinstance(evidence_file, str):
            raise ValueError(f"{record.get('id')}: claim pack requires evidence_file")
        args = [
            "claim",
            "delegation_denied_correctly",
            "--evidence-file",
            str(_abs(corpus_root, evidence_file)),
        ]
        event_id = pack.get("event_id")
        if isinstance(event_id, str) and event_id:
            args.extend(["--event-id", event_id])
        return args

    raise ValueError(f"{record.get('id')}: unsupported kind {kind!r}")


def _reason_classes(stdout: str, stderr: str) -> list[str]:
    text = f"{stdout}\n{stderr}"
    classes: set[str] = set()

    for match in re.finditer(r"\b[A-Z][A-Z0-9]+(?:_[A-Z0-9]+)+\b", text):
        classes.add(match.group(0))

    lowered = text.lower()
    if "content hash mismatch" in lowered:
        classes.add("CONTENT_HASH_MISMATCH")
    if "signature verification failed" in lowered:
        classes.add("SIGNATURE_VERIFICATION_FAILED")
    if "export manifest is unsigned" in lowered:
        classes.add("MANIFEST_SIGNATURE_MISSING")
    if (
        "no trust key available" in lowered
        or "could not resolve trust root" in lowered
        or "contains no entry with purpose" in lowered
        or ("key_id" in lowered and "not found" in lowered)
    ):
        classes.add("TRUST_ROOT_UNRESOLVABLE")
    if (
        "composite_hash mismatch" in lowered
        or "composite_hash does not match" in lowered
        or "chain_heads have been altered" in lowered
    ):
        classes.add("CHECKPOINT_COMPOSITE_HASH_MISMATCH")
    if "tsa" in lowered and "does not match composite_hash" in lowered:
        classes.add("CHECKPOINT_TSA_IMPRINT_MISMATCH")
    if "export is not json" in lowered:
        classes.add("EXPORT_STRUCTURE_INVALID")

    return sorted(classes)


def _structured_report(stdout: str) -> dict[str, Any] | None:
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict):
        return None
    if value.get("schema") != "keel.verifier.verdicts/v0":
        return None
    return value


def _claim_result(stdout: str) -> dict[str, Any] | None:
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict):
        return None
    if value.get("claim_type") != "delegation_denied_correctly":
        return None
    if not isinstance(value.get("status"), str):
        return None
    return value


def _structured_reason_classes(report: dict[str, Any] | None) -> list[str]:
    if report is None:
        return []
    classes: set[str] = set()
    for claim in report.get("claims", []):
        if not isinstance(claim, dict):
            continue
        reason_code = claim.get("reason_code")
        if isinstance(reason_code, str) and reason_code:
            classes.add(reason_code)
        for subject in claim.get("subjects", []):
            if not isinstance(subject, dict):
                continue
            subject_reason = subject.get("reason_code")
            if isinstance(subject_reason, str) and subject_reason:
                classes.add(subject_reason)
    error = report.get("error")
    if isinstance(error, str):
        classes.update(_reason_classes("", error))
    return sorted(classes)


def _expected_current(record: dict[str, Any]) -> tuple[str, list[str]]:
    expected = record.get("expected_current")
    if not isinstance(expected, dict):
        raise ValueError(f"{record.get('id')}: expected_current must be an object")
    outcome = expected.get("outcome")
    if outcome not in {"PASS", "FAIL"}:
        raise ValueError(f"{record.get('id')}: expected_current.outcome must be PASS or FAIL")
    reason_classes = expected.get("reason_classes") or []
    if not isinstance(reason_classes, list) or not all(
        isinstance(item, str) for item in reason_classes
    ):
        raise ValueError(f"{record.get('id')}: expected_current.reason_classes must be strings")
    return outcome, list(reason_classes)


def _expected_claim_verdicts(record: dict[str, Any]) -> dict[str, str]:
    claims = record.get("claims") or []
    if not isinstance(claims, list):
        raise ValueError(f"{record.get('id')}: claims must be a list")
    expected: dict[str, str] = {}
    for claim in claims:
        if not isinstance(claim, dict):
            raise ValueError(f"{record.get('id')}: claims entries must be objects")
        name = claim.get("name")
        verdict = claim.get("expected_verdict")
        if not isinstance(name, str) or not isinstance(verdict, str):
            raise ValueError(
                f"{record.get('id')}: claims entries require name and expected_verdict"
            )
        expected[name] = verdict
    return expected


def _actual_claim_verdicts(
    report: dict[str, Any] | None,
    claim_result: dict[str, Any] | None = None,
) -> dict[str, str]:
    if claim_result is not None:
        return {
            "permit_chain.delegation_denied_correctly.v1": str(
                claim_result["status"]
            )
        }
    if report is None:
        return {}
    actual: dict[str, str] = {}
    for claim in report.get("claims", []):
        if not isinstance(claim, dict):
            continue
        name = claim.get("name")
        verdict = claim.get("verdict")
        if isinstance(name, str) and isinstance(verdict, str):
            actual[name] = verdict
    return actual


def _actual_semantics_mode(
    report: dict[str, Any] | None,
    claim_result: dict[str, Any] | None = None,
) -> str | None:
    source = report if report is not None else claim_result
    if source is None:
        return None
    semantics = source.get("semantics")
    if not isinstance(semantics, dict):
        return None
    mode = semantics.get("mode")
    return mode if isinstance(mode, str) else None


def _run_record(
    record: dict[str, Any],
    *,
    corpus_root: Path,
    target: VerifierTarget,
    timeout_seconds: int,
) -> dict[str, Any]:
    request_json = target.profile == "public"
    args = _record_command_args(
        record,
        corpus_root=corpus_root,
        as_json=request_json,
    )
    command = [*target.command_prefix, *args]
    completed = subprocess.run(
        command,
        cwd=str(target.cwd),
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout_seconds,
    )
    structured = _structured_report(completed.stdout)
    claim_result = _claim_result(completed.stdout)
    actual_outcome = "PASS" if completed.returncode == 0 else "FAIL"
    actual_reasons = sorted(
        set(_reason_classes(completed.stdout, completed.stderr))
        | set(_structured_reason_classes(structured))
    )
    expected_outcome, expected_reasons = _expected_current(record)
    expected_claims = _expected_claim_verdicts(record)
    actual_claims = _actual_claim_verdicts(structured, claim_result)
    expected_mode = _expected_semantics_mode(record, corpus_root=corpus_root)
    actual_mode = _actual_semantics_mode(structured, claim_result)
    claim_mismatches = []
    machine_readable = structured is not None or claim_result is not None
    if machine_readable:
        for name, expected_verdict in expected_claims.items():
            actual_verdict = actual_claims.get(name)
            if actual_verdict != expected_verdict:
                claim_mismatches.append(
                    {
                        "name": name,
                        "expected_verdict": expected_verdict,
                        "actual_verdict": actual_verdict,
                    }
                )
    missing_reasons = [
        reason for reason in expected_reasons if reason not in actual_reasons
    ]
    outcome_mismatch = actual_outcome != expected_outcome
    reason_mismatch = actual_outcome == "FAIL" and bool(missing_reasons)
    claim_mismatch = machine_readable and bool(claim_mismatches)
    mode_mismatch = machine_readable and actual_mode != expected_mode
    status = (
        "PASS"
        if not outcome_mismatch
        and not reason_mismatch
        and not claim_mismatch
        and not mode_mismatch
        else "MISMATCH"
    )

    return {
        "id": record.get("id"),
        "title": record.get("title"),
        "kind": record.get("kind"),
        "status": status,
        "command": command,
        "cwd": str(target.cwd),
        "returncode": completed.returncode,
        "expected_outcome": expected_outcome,
        "actual_outcome": actual_outcome,
        "expected_reason_classes": expected_reasons,
        "actual_reason_classes": actual_reasons,
        "missing_reason_classes": missing_reasons,
        "expected_semantics_mode": expected_mode,
        "actual_semantics_mode": actual_mode,
        "mode_mismatch": mode_mismatch,
        "used_structured_verdicts": machine_readable,
        "expected_claim_verdicts": expected_claims,
        "actual_claim_verdicts": actual_claims,
        "claim_mismatches": claim_mismatches,
        "doctrine_claims": record.get("claims", []),
        "negative": record.get("negative"),
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _make_target(
    *,
    verifier: str,
    python_executable: str,
    verifier_root: Path,
    alternate_script: Path,
) -> VerifierTarget:
    if verifier == "public":
        return VerifierTarget(
            profile="public",
            command_prefix=[python_executable, "-m", "keel_verifier"],
            cwd=verifier_root,
        )
    if verifier == "alternate":
        return VerifierTarget(
            profile="alternate",
            command_prefix=[python_executable, str(alternate_script)],
            cwd=alternate_script.parents[1],
        )
    raise ValueError(f"unknown verifier profile: {verifier}")


def run_corpus(
    *,
    corpus_path: Path = DEFAULT_CORPUS,
    verifier: str = "public",
    python_executable: str = sys.executable,
    verifier_root: Path = REPO_ROOT,
    alternate_script: Path = DEFAULT_ALTERNATE_SCRIPT,
    fixture_ids: set[str] | None = None,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    corpus_path = corpus_path.resolve()
    corpus_root = corpus_path.parent
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    records = corpus.get("records")
    if not isinstance(records, list):
        raise ValueError("corpus.records must be a list")

    selected = [
        record
        for record in records
        if fixture_ids is None or record.get("id") in fixture_ids
    ]
    if fixture_ids is not None:
        found = {str(record.get("id")) for record in selected}
        missing = sorted(fixture_ids - found)
        if missing:
            raise ValueError(f"unknown fixture id(s): {', '.join(missing)}")

    target = _make_target(
        verifier=verifier,
        python_executable=python_executable,
        verifier_root=verifier_root.resolve(),
        alternate_script=alternate_script.resolve(),
    )
    results = [
        _run_record(
            record,
            corpus_root=corpus_root,
            target=target,
            timeout_seconds=timeout_seconds,
        )
        for record in selected
    ]
    mismatches = [result for result in results if result["status"] != "PASS"]
    soundness_findings = [
        result
        for result in results
        if result["expected_outcome"] == "FAIL" and result["actual_outcome"] == "PASS"
    ]
    return {
        "corpus": str(corpus_path),
        "corpus_version": corpus.get("corpus_version"),
        "verifier": verifier,
        "verifier_command": target.command_prefix,
        "total": len(results),
        "passed": len(results) - len(mismatches),
        "mismatches": len(mismatches),
        "soundness_findings": len(soundness_findings),
        "results": results,
    }


def _print_summary(report: dict[str, Any]) -> None:
    print(
        "{verifier}: {passed}/{total} fixtures matched ({mismatches} mismatches, "
        "{soundness_findings} soundness findings)".format(**report)
    )
    for result in report["results"]:
        if result["status"] == "PASS":
            continue
        print(
            "MISMATCH {id}: expected {expected_outcome} {expected_reason_classes}, "
            "got {actual_outcome} {actual_reason_classes}".format(**result)
        )
        if result.get("claim_mismatches"):
            print(f"  claim_mismatches: {result['claim_mismatches']}")
        if result.get("mode_mismatch"):
            print(
                "  semantics_mode: expected {expected_semantics_mode}, got "
                "{actual_semantics_mode}".format(**result)
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--verifier", choices=["public", "alternate"], default="public")
    parser.add_argument("--python", default=sys.executable, dest="python_executable")
    parser.add_argument("--verifier-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--alternate-script", type=Path, default=DEFAULT_ALTERNATE_SCRIPT)
    parser.add_argument("--fixture", action="append", default=[])
    parser.add_argument("--timeout-seconds", type=int, default=30)
    parser.add_argument("--report-json", type=Path)
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Always exit 0 after writing/printing the report.",
    )
    args = parser.parse_args(argv)

    report = run_corpus(
        corpus_path=args.corpus,
        verifier=args.verifier,
        python_executable=args.python_executable,
        verifier_root=args.verifier_root,
        alternate_script=args.alternate_script,
        fixture_ids=set(args.fixture) if args.fixture else None,
        timeout_seconds=args.timeout_seconds,
    )
    _print_summary(report)
    if args.report_json:
        args.report_json.parent.mkdir(parents=True, exist_ok=True)
        args.report_json.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return 0 if args.report_only or report["mismatches"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
