import os
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
AUTHORITATIVE_WORKFLOW = WORKFLOWS / "tsa-trust-maintenance.yml"
LEGACY_WORKFLOW = WORKFLOWS / "refresh-tsa-trust.yml"
PROPOSAL_SCRIPT = ROOT / "scripts" / "propose_tsa_trust_refresh.sh"
STANDING_BRANCH = "chore/tsa-trust-refresh"


def test_only_proof_complete_tsa_refresh_workflow_remains() -> None:
    assert AUTHORITATIVE_WORKFLOW.is_file()
    assert not LEGACY_WORKFLOW.exists()

    workflow = AUTHORITATIVE_WORKFLOW.read_text(encoding="utf-8")
    required_proofs = (
        "repository: keelapi/keel-permit",
        "refresh_tsa_trust_bundle.py --dry-run",
        "generate_release_manifest.py embedded",
        "ruff check .",
        "check_historical_compatibility_corpus.py --run",
        "pytest -q tests/test_tsa_trust.py -rs",
        "pytest -q",
        "scripts/propose_tsa_trust_refresh.sh",
    )
    assert all(proof in workflow for proof in required_proofs)

    proposal = PROPOSAL_SCRIPT.read_text(encoding="utf-8")
    assert "gh pr create --base main" in proposal
    assert "This job never merges. A human merges trust material." in proposal
    assert "gh pr merge" not in proposal


def test_tsa_refresh_workflow_has_required_pr_permissions() -> None:
    workflow = AUTHORITATIVE_WORKFLOW.read_text(encoding="utf-8")
    assert "contents: write" in workflow
    assert "pull-requests: write" in workflow
    # The fallback when the token may not open pull requests is an issue.
    assert "issues: write" in workflow


# The proposal script runs against a throwaway repository and a local bare
# remote, with a stub `gh` that records each call and answers from
# environment knobs.
STUB_GH = """#!/usr/bin/env bash
printf '%s\\n' "$*" >> "${STUB_LOG}"
case "$1 $2" in
  "pr list") printf '%s' "${STUB_EXISTING_PR:-}" ;;
  "pr edit") exit 0 ;;
  "pr create") exit "${STUB_PR_CREATE_EXIT:-0}" ;;
  "issue list") printf '%s' "${STUB_EXISTING_ISSUE:-}" ;;
  "issue comment"|"issue create") exit 0 ;;
  *) echo "unexpected gh call: $*" >&2; exit 2 ;;
esac
"""


def _git(cwd: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    )
    return completed.stdout.strip()


@pytest.fixture
def workspace(tmp_path: Path) -> dict[str, Path]:
    remote = tmp_path / "remote.git"
    repo = tmp_path / "repo"
    bin_dir = tmp_path / "bin"
    subprocess.run(
        ["git", "init", "--bare", "-b", "main", str(remote)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "init", "-b", "main", str(repo)], check=True, capture_output=True
    )
    _git(repo, "config", "user.name", "test")
    _git(repo, "config", "user.email", "test@example.com")
    (repo / "bundle.json").write_text("stale\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "base")
    _git(repo, "remote", "add", "origin", str(remote))
    _git(repo, "push", "origin", "main")
    bin_dir.mkdir()
    stub = bin_dir / "gh"
    stub.write_text(STUB_GH, encoding="utf-8")
    stub.chmod(0o755)
    return {"repo": repo, "remote": remote, "bin": bin_dir, "log": tmp_path / "gh.log"}


def _propose(
    workspace: dict[str, Path], content: str, **knobs: str
) -> subprocess.CompletedProcess[str]:
    repo = workspace["repo"]
    # Each scheduled run starts from a fresh checkout of main.
    _git(repo, "checkout", "-q", "main")
    (repo / "bundle.json").write_text(content, encoding="utf-8")
    env = {
        **os.environ,
        "PATH": f"{workspace['bin']}{os.pathsep}{os.environ['PATH']}",
        "STUB_LOG": str(workspace["log"]),
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_REPOSITORY": "keelapi/keel-verifier",
        **knobs,
    }
    return subprocess.run(
        ["bash", str(PROPOSAL_SCRIPT)],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
    )


def _gh_calls(workspace: dict[str, Path]) -> list[str]:
    log = workspace["log"]
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


def test_first_proposal_opens_a_pull_request(workspace: dict[str, Path]) -> None:
    result = _propose(workspace, "fresh\n")

    assert result.returncode == 0, result.stderr
    calls = _gh_calls(workspace)
    assert any(call.startswith("pr create --base main") for call in calls)
    assert not any(call.startswith("issue ") for call in calls)
    assert _git(workspace["remote"], "show", f"{STANDING_BRANCH}:bundle.json") == "fresh"


def test_blocked_pull_request_falls_back_to_one_issue(
    workspace: dict[str, Path],
) -> None:
    result = _propose(workspace, "fresh\n", STUB_PR_CREATE_EXIT="1")

    assert result.returncode == 0, result.stderr
    calls = _gh_calls(workspace)
    assert any(call.startswith("issue create --title") for call in calls)
    assert f"compare/main...{STANDING_BRANCH}?expand=1" in result.stdout


def test_existing_issue_is_updated_not_duplicated(
    workspace: dict[str, Path],
) -> None:
    result = _propose(
        workspace, "fresh\n", STUB_PR_CREATE_EXIT="1", STUB_EXISTING_ISSUE="12"
    )

    assert result.returncode == 0, result.stderr
    calls = _gh_calls(workspace)
    assert any(call.startswith("issue comment 12") for call in calls)
    assert not any(call.startswith("issue create") for call in calls)


def test_open_pull_request_is_refreshed_not_duplicated(
    workspace: dict[str, Path],
) -> None:
    result = _propose(workspace, "fresh\n", STUB_EXISTING_PR="7")

    assert result.returncode == 0, result.stderr
    calls = _gh_calls(workspace)
    assert any(call.startswith("pr edit 7") for call in calls)
    assert not any(call.startswith("pr create") for call in calls)


def test_repeated_runs_replace_the_standing_branch(
    workspace: dict[str, Path],
) -> None:
    first = _propose(workspace, "fresh\n")
    second = _propose(workspace, "fresher\n", STUB_EXISTING_PR="7")

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    remote = workspace["remote"]
    branches = _git(remote, "for-each-ref", "--format=%(refname:short)", "refs/heads")
    assert sorted(branches.splitlines()) == sorted(["main", STANDING_BRANCH])
    assert _git(remote, "show", f"{STANDING_BRANCH}:bundle.json") == "fresher"
    assert _git(remote, "rev-list", "--count", f"main..{STANDING_BRANCH}") == "1"
