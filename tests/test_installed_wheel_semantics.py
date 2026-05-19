from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any
from zipfile import ZipFile

from conftest import write_json
from keel_verifier import verifier
from keel_verifier.semantics import (
    AUTHORITY_ENVELOPE_V0_HASH,
    AUTHORITY_ENVELOPE_V0_ID,
    CLAIM_REGISTRY_HASH,
    CLAIM_REGISTRY_ID,
    GOVERNANCE_EVENT_INTEGRITY_DIGEST_HASH,
    GOVERNANCE_EVENT_INTEGRITY_DIGEST_ID,
    GOVERNANCE_RECORD_HASH_HASH,
    GOVERNANCE_RECORD_HASH_ID,
    RELEASED_ARTIFACT_PATHS,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def _run(
    args: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, (
        f"command failed: {' '.join(args)}\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )
    return result


def _clean_env() -> dict[str, str]:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env.pop("KEEL_CLAIM_REGISTRY", None)
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["PYTHONNOUSERSITE"] = "1"
    return env


def _venv_python(venv: Path) -> Path:
    if os.name == "nt":
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"


def _event(payload: dict[str, Any]) -> dict[str, Any]:
    event = {
        "event_id": "gev_permit_chain_test",
        "event_type": "permit.delegated_denied",
        "category": "permit",
        "severity": "warning",
        "occurred_at": "2026-05-20T12:00:00.000000+00:00",
        "sequence_number": 1,
        "prev_hash": verifier._GENESIS_HASH,
        "chain_scope": "project:11111111-1111-1111-1111-111111111111",
        "resource_type": "permit_delegation",
        "resource_id": "22222222-2222-2222-2222-222222222222",
        "outcome": "denied",
        "source_stage": "permit",
        "decision": "deny",
        "schema_version": 1,
        "payload_json": payload,
    }
    event["record_hash"] = verifier._compute_record_hash(
        event_id=event["event_id"],
        event_type=event["event_type"],
        resource_type=event["resource_type"],
        resource_id=event["resource_id"],
        outcome=event["outcome"],
        severity=event["severity"],
        occurred_at=event["occurred_at"],
        prev_hash=event["prev_hash"],
        sequence_number=event["sequence_number"],
    )
    return event


def _path_ref(artifact_id: str, artifact_hash: str) -> dict[str, str]:
    return {
        "id": artifact_id,
        "hash": artifact_hash,
        "path": RELEASED_ARTIFACT_PATHS[artifact_id],
    }


def _path_only_delegation_denied_evidence() -> dict[str, Any]:
    parent = {
        "actions": ["ai.generate.summary"],
        "tools": [],
        "providers": ["openai"],
        "models": ["gpt-4o-mini"],
        "data_classes": ["public"],
        "regions": ["us"],
        "expires_at": "2026-05-20T12:00:00Z",
    }
    child = {
        "actions": ["ai.generate.summary"],
        "tools": [],
        "providers": ["openai", "anthropic"],
        "models": ["gpt-4o-mini"],
        "data_classes": ["public"],
        "regions": ["us"],
        "expires_at": "2026-05-20T11:30:00Z",
    }
    event = _event(
        {
            "reason_code": "authority_envelope.scope_broadened",
            "authority_envelope_version": "authority-envelope.v0",
            "parent_authority_envelope": parent,
            "child_requested_authority_envelope": child,
            "failed_fields": ["providers"],
        }
    )
    covered_events = [
        {
            "event_id": event["event_id"],
            "event_type": event["event_type"],
            "event_hash": verifier._compute_governance_event_integrity_hash(event),
        }
    ]
    batch_hash = verifier._compute_integrity_batch_hash(covered_events)
    digest = {
        "event_id": "gev_permit_chain_digest",
        "event_type": "audit.integrity_digest",
        "category": "audit",
        "severity": "info",
        "occurred_at": "2026-05-20T12:00:01.000000+00:00",
        "sequence_number": 2,
        "prev_hash": event["record_hash"],
        "chain_scope": event["chain_scope"],
        "resource_type": "governance_event_batch",
        "resource_id": batch_hash[:32],
        "outcome": "success",
        "source_stage": "audit",
        "schema_version": 2,
        "payload_json": {
            "coverage_type": "unchained_governance_events",
            "coverage_mode": "commit_batch",
            "covered_event_count": 1,
            "covered_events": covered_events,
            "batch_hash": batch_hash,
        },
    }
    digest["record_hash"] = verifier._compute_record_hash(
        event_id=digest["event_id"],
        event_type=digest["event_type"],
        resource_type=digest["resource_type"],
        resource_id=digest["resource_id"],
        outcome=digest["outcome"],
        severity=digest["severity"],
        occurred_at=digest["occurred_at"],
        prev_hash=digest["prev_hash"],
        sequence_number=digest["sequence_number"],
    )
    evidence = {
        "events": [event, digest],
        "claim_set": {
            "version": "verifier-claims.v0",
            "registry": _path_ref(CLAIM_REGISTRY_ID, CLAIM_REGISTRY_HASH),
            "claims": [
                {
                    "name": verifier.DELEGATION_DENIED_CLAIM_NAME,
                    "required": True,
                }
            ],
        },
        "semantics_pins": {
            "version": "keel-semantics-pins.v0",
            "mode": "pinned",
            "artifacts": [
                _path_ref(GOVERNANCE_RECORD_HASH_ID, GOVERNANCE_RECORD_HASH_HASH),
                _path_ref(
                    GOVERNANCE_EVENT_INTEGRITY_DIGEST_ID,
                    GOVERNANCE_EVENT_INTEGRITY_DIGEST_HASH,
                ),
                _path_ref(AUTHORITY_ENVELOPE_V0_ID, AUTHORITY_ENVELOPE_V0_HASH),
            ],
        },
    }
    assert "content_b64" not in json.dumps(evidence)
    return evidence


def test_installed_wheel_resolves_path_only_semantic_pins(
    tmp_path: Path,
) -> None:
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    _run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--skip-dependency-check",
            "--outdir",
            str(wheelhouse),
        ],
        cwd=REPO_ROOT,
        env=_clean_env(),
    )
    wheels = sorted(wheelhouse.glob("keel_verifier-*.whl"))
    assert len(wheels) == 1, wheels
    wheel = wheels[0]

    with ZipFile(wheel) as wheel_file:
        wheel_names = set(wheel_file.namelist())
    for relative_path in RELEASED_ARTIFACT_PATHS.values():
        assert f"keel_verifier/data/{relative_path}" in wheel_names
    assert "keel_verifier/data/claim_registry_v0.json" in wheel_names
    assert "keel_verifier/data/trust_root.json" in wheel_names

    venv = tmp_path / "venv"
    _run(
        [sys.executable, "-m", "venv", "--system-site-packages", str(venv)],
        cwd=tmp_path,
        env=_clean_env(),
    )
    venv_python = _venv_python(venv)
    _run(
        [str(venv_python), "-m", "pip", "install", "--no-deps", str(wheel)],
        cwd=tmp_path,
        env=_clean_env(),
    )

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    evidence_file = write_json(
        evidence_dir / "path_only_delegation_denied.json",
        _path_only_delegation_denied_evidence(),
    )

    probe = _run(
        [
            str(venv_python),
            "-c",
            (
                "from pathlib import Path; "
                "import keel_verifier, keel_verifier.semantics as semantics; "
                "assert not str(Path(keel_verifier.__file__).resolve()).startswith("
                f"{str(REPO_ROOT)!r}"
                "); "
                "assert not semantics._keel_permit_root().exists(), "
                "semantics._keel_permit_root()"
            ),
        ],
        cwd=run_dir,
        env=_clean_env(),
    )
    assert not probe.stderr

    result = _run(
        [
            str(venv_python),
            "-m",
            "keel_verifier",
            "claim",
            "delegation_denied_correctly",
            "--evidence-file",
            str(evidence_file),
        ],
        cwd=run_dir,
        env=_clean_env(),
    )
    payload = json.loads(result.stdout)

    assert payload["status"] == "supported"
    assert payload["semantics"]["mode"] == "pinned"
    assert {pin["id"] for pin in payload["semantics"]["pins"]} >= {
        CLAIM_REGISTRY_ID,
        GOVERNANCE_RECORD_HASH_ID,
        GOVERNANCE_EVENT_INTEGRITY_DIGEST_ID,
        AUTHORITY_ENVELOPE_V0_ID,
    }
