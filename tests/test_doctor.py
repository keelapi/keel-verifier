from __future__ import annotations

import importlib.metadata
import json
import sys
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest

import keel_verifier
from keel_verifier import cli, doctor, install_diagnostics


class FakeDistribution:
    def __init__(
        self,
        *,
        texts: dict[str, str | None] | None = None,
        files: list[PurePosixPath] | None = None,
        root: Path | None = None,
    ) -> None:
        self._texts = texts or {}
        self.files = files
        self._root = root or Path("/site-packages")

    def read_text(self, name: str) -> str | None:
        return self._texts.get(name)

    def locate_file(self, path: PurePosixPath) -> Path:
        return self._root.joinpath(*path.parts)


@pytest.fixture(autouse=True)
def clean_doctor_environment(monkeypatch, tmp_path: Path):
    monkeypatch.delenv("PYTHONPATH", raising=False)
    monkeypatch.setattr(doctor, "_site_roots", lambda: [])
    monkeypatch.setattr(doctor, "DEFAULT_DOCTOR_CACHE_DIR", tmp_path / "cache")


def _args(*, check_network: bool = False) -> SimpleNamespace:
    return SimpleNamespace(check_network=check_network)


def _by_name(result: doctor.DoctorResult) -> dict[str, doctor.DoctorCheck]:
    return {check.name: check for check in result.checks}


def _fake_wheel_install(monkeypatch, tmp_path: Path) -> FakeDistribution:
    dist_root = tmp_path / "venv" / "site-packages"
    imported_file = dist_root / "keel_verifier" / "__init__.py"
    imported_file.parent.mkdir(parents=True)
    imported_file.write_text("__version__ = 'test'\n", encoding="utf-8")
    dist = FakeDistribution(
        texts={"WHEEL": "Wheel-Version: 1.0\n"},
        files=[PurePosixPath("keel_verifier/__init__.py")],
        root=dist_root,
    )
    monkeypatch.setattr(
        install_diagnostics.importlib.metadata,
        "distribution",
        lambda name: dist,
    )
    monkeypatch.setattr(keel_verifier, "__file__", str(imported_file))
    return dist


def test_doctor_wheel_install_all_ok(monkeypatch, tmp_path: Path) -> None:
    _fake_wheel_install(monkeypatch, tmp_path)

    result = doctor.run_doctor(_args())
    checks = _by_name(result)

    assert result.any_problems is False
    assert result.any_warnings is False
    assert checks["install_form"].status == "ok"
    assert checks["import_location"].status == "ok"
    assert checks["distribution_location"].status == "ok"
    assert checks["import_isolation"].status == "ok"
    assert checks["sys_path_summary"].status == "ok"
    assert checks["pth_shadow_check"].status == "ok"
    assert checks["self_check_preview"].status == "ok"


def test_doctor_editable_install_reports_info_with_self_check_preview(
    monkeypatch,
    tmp_path: Path,
) -> None:
    dist_root = tmp_path / "src"
    imported_file = dist_root / "keel_verifier" / "__init__.py"
    imported_file.parent.mkdir(parents=True)
    imported_file.write_text("__version__ = 'test'\n", encoding="utf-8")
    dist = FakeDistribution(
        texts={
            "direct_url.json": '{"dir_info":{"editable":true}}',
            "WHEEL": "Wheel-Version: 1.0\n",
        },
        files=[PurePosixPath("keel_verifier/__init__.py")],
        root=dist_root,
    )
    monkeypatch.setattr(
        install_diagnostics.importlib.metadata,
        "distribution",
        lambda name: dist,
    )
    monkeypatch.setattr(keel_verifier, "__file__", str(imported_file))

    checks = _by_name(doctor.run_doctor(_args()))

    assert checks["install_form"].status == "info"
    assert checks["self_check_preview"].status == "warn"
    assert "pip uninstall" in str(checks["self_check_preview"].remediation)


def test_doctor_shadow_import_reports_problem(monkeypatch, tmp_path: Path) -> None:
    dist_root = tmp_path / "venv" / "site-packages"
    shadow_root = tmp_path / "shadow"
    imported_file = shadow_root / "keel_verifier" / "__init__.py"
    imported_file.parent.mkdir(parents=True)
    imported_file.write_text("__version__ = 'shadow'\n", encoding="utf-8")
    dist = FakeDistribution(
        texts={"WHEEL": "Wheel-Version: 1.0\n"},
        files=[PurePosixPath("keel_verifier/__init__.py")],
        root=dist_root,
    )
    monkeypatch.setattr(
        install_diagnostics.importlib.metadata,
        "distribution",
        lambda name: dist,
    )
    monkeypatch.setattr(keel_verifier, "__file__", str(imported_file))

    checks = _by_name(doctor.run_doctor(_args()))

    assert checks["import_isolation"].status == "problem"
    assert checks["self_check_preview"].status == "problem"
    assert "SELF_CHECK_SHADOW_IMPORT" in checks["self_check_preview"].message


def test_doctor_missing_dist_reports_problem(monkeypatch, tmp_path: Path) -> None:
    imported_file = tmp_path / "keel_verifier" / "__init__.py"
    imported_file.parent.mkdir()
    imported_file.write_text("__version__ = 'test'\n", encoding="utf-8")

    def missing_distribution(name: str):
        del name
        raise importlib.metadata.PackageNotFoundError

    monkeypatch.setattr(
        install_diagnostics.importlib.metadata,
        "distribution",
        missing_distribution,
    )
    monkeypatch.setattr(keel_verifier, "__file__", str(imported_file))

    checks = _by_name(doctor.run_doctor(_args()))

    assert checks["install_form"].status == "problem"
    assert checks["self_check_preview"].status == "problem"
    assert "pip install keel-verifier" in str(checks["install_form"].remediation)


def test_doctor_pythonpath_shadow_detected(monkeypatch, tmp_path: Path) -> None:
    _fake_wheel_install(monkeypatch, tmp_path)
    shadow_parent = tmp_path / "pythonpath-shadow"
    (shadow_parent / "keel_verifier").mkdir(parents=True)
    monkeypatch.setenv("PYTHONPATH", str(shadow_parent))
    monkeypatch.setattr(sys, "path", [str(shadow_parent), *sys.path])

    checks = _by_name(doctor.run_doctor(_args()))

    assert checks["sys_path_summary"].status == "warn"
    assert checks["pythonpath_env"].status == "warn"
    assert "PYTHONPATH" in str(checks["pythonpath_env"].remediation)


def test_doctor_pth_shadow_detected(monkeypatch, tmp_path: Path) -> None:
    _fake_wheel_install(monkeypatch, tmp_path)
    site_root = tmp_path / "user-site"
    site_root.mkdir()
    (site_root / "shadow.pth").write_text("/tmp/example/keel_verifier\n", encoding="utf-8")
    monkeypatch.setattr(doctor, "_site_roots", lambda: [("user-site", site_root)])

    checks = _by_name(doctor.run_doctor(_args()))

    assert checks["pth_shadow_check"].status == "warn"
    assert checks["pth_shadow_check"].value[0]["file"] == site_root / "shadow.pth"


def test_doctor_check_network_pypi_reachable(monkeypatch, tmp_path: Path) -> None:
    _fake_wheel_install(monkeypatch, tmp_path)

    def reachable(url: str, *, timeout: int = 5) -> doctor._HeadResult:
        del url, timeout
        return doctor._HeadResult(status_code=200)

    monkeypatch.setattr(doctor, "_head_url", reachable)

    checks = _by_name(doctor.run_doctor(_args(check_network=True)))

    assert checks["pypi_reachability"].status == "ok"


def test_doctor_check_network_pypi_unreachable(monkeypatch, tmp_path: Path) -> None:
    _fake_wheel_install(monkeypatch, tmp_path)

    def maybe_timeout(url: str, *, timeout: int = 5) -> doctor._HeadResult:
        del timeout
        if url == doctor.PYPI_SIMPLE_URL:
            raise TimeoutError("timed out")
        return doctor._HeadResult(status_code=200)

    monkeypatch.setattr(doctor, "_head_url", maybe_timeout)

    checks = _by_name(doctor.run_doctor(_args(check_network=True)))

    assert checks["pypi_reachability"].status == "problem"
    assert "timed out" in checks["pypi_reachability"].message


def test_doctor_fail_on_problem_returns_exit_1(monkeypatch) -> None:
    result = doctor.DoctorResult(
        checks=[
            doctor.DoctorCheck(
                name="install_form",
                status="problem",
                message="missing",
                value=None,
            )
        ]
    )
    monkeypatch.setattr(cli, "run_doctor", lambda args: result)

    assert cli.main(["doctor", "--fail-on-problem"]) == 1


def test_doctor_default_exit_0_regardless(monkeypatch) -> None:
    result = doctor.DoctorResult(
        checks=[
            doctor.DoctorCheck(
                name="install_form",
                status="problem",
                message="missing",
                value=None,
            )
        ]
    )
    monkeypatch.setattr(cli, "run_doctor", lambda args: result)

    assert cli.main(["doctor"]) == 0


def test_doctor_json_output_schema(monkeypatch, capsys) -> None:
    result = doctor.DoctorResult(
        checks=[
            doctor.DoctorCheck(
                name="install_form",
                status="ok",
                message="wheel",
                value="wheel",
            )
        ]
    )
    monkeypatch.setattr(cli, "run_doctor", lambda args: result)

    exit_code = cli.main(["doctor", "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["ok"] is True
    assert payload["any_problems"] is False
    assert payload["any_warnings"] is False
    assert payload["checks"] == [
        {
            "name": "install_form",
            "status": "ok",
            "message": "wheel",
            "value": "wheel",
        }
    ]
