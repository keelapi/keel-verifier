from __future__ import annotations

from keel_verifier import cli


class DummySelfCheckResult:
    def __init__(self, ok: bool) -> None:
        self.ok = ok

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "form": "wheel",
            "summary": "dummy",
            "stages": [
                {
                    "name": "form",
                    "ok": self.ok,
                    "code": None if self.ok else "SELF_CHECK_FORM_UNSUPPORTED",
                    "message": "dummy",
                }
            ],
        }

    def format_human(self) -> str:
        return "PASS: dummy" if self.ok else "FAILED: dummy"


def test_cli_self_check_json_success_exit_zero(monkeypatch, capsys) -> None:
    captured_args = {}

    def fake_run(args):
        captured_args["offline"] = args.offline
        captured_args["cache_dir"] = args.cache_dir
        return DummySelfCheckResult(ok=True)

    monkeypatch.setattr(cli, "run_self_check", fake_run)

    exit_code = cli.main(
        [
            "self-check",
            "--form",
            "wheel",
            "--offline",
            "--cache-dir",
            "/tmp/keel-cache",
            "--json",
        ]
    )

    assert exit_code == 0
    assert captured_args == {"offline": True, "cache_dir": "/tmp/keel-cache"}
    assert '"ok": true' in capsys.readouterr().out


def test_cli_self_check_failure_exit_one(monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "run_self_check", lambda args: DummySelfCheckResult(ok=False))

    exit_code = cli.main(["self-check", "--form", "wheel"])

    assert exit_code == 1
    assert "FAILED: dummy" in capsys.readouterr().err


def test_cli_self_check_help_lists_offline_and_no_cache(run_cli) -> None:
    result = run_cli("self-check", "--help")

    assert result.returncode == 0
    assert "--offline" in result.stdout
    assert "--no-cache" in result.stdout
