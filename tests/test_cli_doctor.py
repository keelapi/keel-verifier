from __future__ import annotations

import json


def test_cli_doctor_help_lists_check_network_and_fail_on_problem(run_cli) -> None:
    result = run_cli("doctor", "--help")

    assert result.returncode == 0
    assert "--check-network" in result.stdout
    assert "--fail-on-problem" in result.stdout


def test_cli_doctor_json_output_parseable(run_cli) -> None:
    result = run_cli("doctor", "--json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert "checks" in payload
    assert any(check["name"] == "self_check_preview" for check in payload["checks"])
