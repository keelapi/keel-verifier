"""Pure-local environment diagnostics for keel-verifier."""

from __future__ import annotations

import os
import site
import sys
import sysconfig
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Literal

import keel_verifier
from keel_verifier.install_diagnostics import (
    EDITABLE_INSTALL_REMEDIATION,
    MISSING_INSTALL_REMEDIATION,
    PACKAGE_NAME,
    SDIST_INSTALL_REMEDIATION,
    SHADOW_IMPORT_REMEDIATION,
    ImportIsolationDiagnostic,
    InstallFormDiagnostic,
    inspect_import_isolation,
    inspect_install_form,
)


DoctorStatus = Literal["ok", "info", "warn", "problem"]
DEFAULT_DOCTOR_CACHE_DIR = Path.home() / ".keel-verifier" / "cache"
PYPI_SIMPLE_URL = "https://pypi.org/simple/keel-verifier/"
SIGSTORE_REKOR_URL = "https://rekor.sigstore.dev/api/v1/log/"
DEFAULT_TSA_ENDPOINTS: tuple[tuple[str, str], ...] = (
    ("digicert", "http://timestamp.digicert.com"),
    ("globalsign", "http://timestamp.globalsign.com/tsa/r6advanced1"),
)


@dataclass
class DoctorCheck:
    name: str
    status: DoctorStatus
    message: str
    value: Any
    remediation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self.name,
            "status": self.status,
            "message": self.message,
            "value": _jsonable(self.value),
        }
        if self.remediation is not None:
            payload["remediation"] = self.remediation
        return payload


@dataclass
class DoctorResult:
    checks: list[DoctorCheck]
    any_problems: bool = field(init=False)
    any_warnings: bool = field(init=False)

    def __post_init__(self) -> None:
        self.any_problems = any(check.status == "problem" for check in self.checks)
        self.any_warnings = any(check.status == "warn" for check in self.checks)

    @property
    def ok(self) -> bool:
        return not self.any_problems

    @property
    def summary(self) -> str:
        counts = self.status_counts()
        return (
            f"Summary: {counts['ok']} ok, {counts['info']} info, "
            f"{counts['warn']} warnings, {counts['problem']} problems"
        )

    def status_counts(self) -> dict[str, int]:
        return {
            status: sum(1 for check in self.checks if check.status == status)
            for status in ("ok", "info", "warn", "problem")
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "summary": self.summary,
            "any_problems": self.any_problems,
            "any_warnings": self.any_warnings,
            "checks": [check.to_dict() for check in self.checks],
        }

    def format_human(self) -> str:
        markers = {
            "ok": "OK",
            "info": "INFO",
            "warn": "WARN",
            "problem": "PROBLEM",
        }
        lines = ["keel-verify doctor \u2014 environment diagnostic", ""]
        for check in self.checks:
            lines.append(f"[{markers[check.status]}] {check.name}: {check.message}")
            if check.remediation is not None and check.status in {"warn", "problem"}:
                lines.append("  To fix this:")
                lines.extend(
                    f"    {line}" if line else "    "
                    for line in check.remediation.splitlines()
                )
        lines.extend(["", self.summary])
        return "\n".join(lines)


@dataclass(frozen=True)
class _HeadResult:
    status_code: int


def _jsonable(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, set):
        return sorted(_jsonable(item) for item in value)
    return value


def _safe_resolve(path: Path) -> Path:
    try:
        return path.expanduser().resolve()
    except OSError:
        return path.expanduser()


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _same_path(left: Path, right: Path) -> bool:
    return _safe_resolve(left) == _safe_resolve(right)


def _display_path(path: Path) -> str:
    home = Path.home()
    try:
        return "~/" + path.expanduser().relative_to(home).as_posix()
    except ValueError:
        return str(path)


def _format_bytes(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{round(size / 1024)} KB"
    return f"{size / (1024 * 1024):.1f} MB"


def _format_age(mtime: float | None) -> str:
    if mtime is None:
        return "never"
    age = max(0, int(time.time() - mtime))
    if age < 60:
        return f"{age} seconds ago"
    if age < 60 * 60:
        return f"{age // 60} minutes ago"
    if age < 24 * 60 * 60:
        return f"{age // (60 * 60)} hours ago"
    return f"{age // (24 * 60 * 60)} days ago"


def _path_contains_package(path: Path) -> bool:
    candidate = _safe_resolve(path)
    return (candidate / PACKAGE_NAME).exists() or (candidate / f"{PACKAGE_NAME}.py").exists()


def _pythonpath_entries() -> list[Path]:
    raw = os.environ.get("PYTHONPATH", "")
    return [_safe_resolve(Path(part)) for part in raw.split(os.pathsep) if part]


def _pythonpath_shadow_entries() -> list[Path]:
    return [path for path in _pythonpath_entries() if _path_contains_package(path)]


def _site_roots() -> list[tuple[str, Path]]:
    roots: list[tuple[str, Path]] = []
    try:
        user_site = site.getusersitepackages()
    except (AttributeError, OSError):
        user_site = None
    if user_site:
        roots.append(("user-site", _safe_resolve(Path(user_site))))

    system_sites: list[str] = []
    try:
        system_sites.extend(site.getsitepackages())
    except (AttributeError, OSError):
        pass
    for key in ("purelib", "platlib"):
        path = sysconfig.get_paths().get(key)
        if path:
            system_sites.append(path)

    for raw in system_sites:
        roots.append(("site-packages", _safe_resolve(Path(raw))))

    deduped: list[tuple[str, Path]] = []
    seen: set[Path] = set()
    for label, root in roots:
        if root in seen:
            continue
        seen.add(root)
        deduped.append((label, root))
    return deduped


def _sys_path_entry_path(entry: str) -> Path:
    return _safe_resolve(Path.cwd() if entry == "" else Path(entry))


def _classify_sys_path_entry(path: Path, pythonpath_entries: list[Path]) -> str:
    if any(_same_path(path, injected) for injected in pythonpath_entries):
        return "PYTHONPATH-injected"
    if _same_path(path, Path.cwd()):
        return "cwd"
    for label, root in _site_roots():
        if _same_path(path, root) or _is_relative_to(path, root):
            return label
    return "other"


def _directory_size(path: Path) -> int:
    if path.is_file():
        try:
            return path.stat().st_size
        except OSError:
            return 0
    total = 0
    if not path.exists():
        return total
    for child in path.rglob("*"):
        if not child.is_file():
            continue
        try:
            total += child.stat().st_size
        except OSError:
            continue
    return total


def _latest_mtime(path: Path) -> float | None:
    mtimes: list[float] = []
    if not path.exists():
        return None
    for child in [path, *path.rglob("*")]:
        try:
            mtimes.append(child.stat().st_mtime)
        except OSError:
            continue
    return max(mtimes) if mtimes else None


def _check_install_form(diagnostic: InstallFormDiagnostic) -> DoctorCheck:
    status_by_form: dict[str, DoctorStatus] = {
        "wheel": "ok",
        "editable": "info",
        "sdist": "warn",
        "missing": "problem",
    }
    message_by_form = {
        "wheel": "wheel (installed distribution has WHEEL metadata)",
        "editable": "editable install",
        "sdist": "sdist or non-wheel install",
        "missing": diagnostic.message,
    }
    return DoctorCheck(
        name="install_form",
        status=status_by_form[diagnostic.form],
        message=message_by_form[diagnostic.form],
        value=diagnostic.form,
        remediation=diagnostic.remediation
        if status_by_form[diagnostic.form] in {"warn", "problem"}
        else None,
    )


def _check_python_interpreter() -> DoctorCheck:
    value = {
        "executable": sys.executable,
        "version": sys.version,
        "platform": sys.platform,
    }
    return DoctorCheck(
        name="python_interpreter",
        status="ok",
        message=f"Python {sys.version.split()[0]} at {sys.executable}",
        value=value,
    )


def _check_import_location() -> DoctorCheck:
    imported_file = getattr(keel_verifier, "__file__", None)
    if imported_file is None:
        return DoctorCheck(
            name="import_location",
            status="problem",
            message="keel_verifier is importable but does not expose __file__",
            value=None,
            remediation=SHADOW_IMPORT_REMEDIATION,
        )
    path = Path(imported_file).resolve()
    if not path.exists():
        return DoctorCheck(
            name="import_location",
            status="problem",
            message=f"{path} does not exist",
            value=path,
            remediation=SHADOW_IMPORT_REMEDIATION,
        )
    return DoctorCheck(
        name="import_location",
        status="ok",
        message=str(path),
        value=path,
    )


def _check_distribution_location(dist: Any | None) -> DoctorCheck:
    if dist is None:
        return DoctorCheck(
            name="distribution_location",
            status="info",
            message="distribution metadata unavailable",
            value=None,
        )
    try:
        path = Path(dist.locate_file(PurePosixPath(f"{PACKAGE_NAME}/__init__.py")))
    except Exception as exc:
        return DoctorCheck(
            name="distribution_location",
            status="info",
            message=f"distribution metadata location unavailable: {exc}",
            value=None,
        )
    return DoctorCheck(
        name="distribution_location",
        status="ok",
        message=str(path.parent),
        value=path,
    )


def _check_import_isolation(diagnostic: ImportIsolationDiagnostic) -> DoctorCheck:
    value = {
        "imported_path": diagnostic.imported_path,
        "checked": diagnostic.checked,
        "expected_dirs": list(diagnostic.expected_dirs),
    }
    if diagnostic.code == "SELF_CHECK_FORM_UNSUPPORTED":
        return DoctorCheck(
            name="import_isolation",
            status="info",
            message="distribution metadata unavailable, comparison skipped",
            value=value,
        )
    if diagnostic.aligned is False:
        return DoctorCheck(
            name="import_isolation",
            status="problem",
            message=diagnostic.message,
            value=value,
            remediation=diagnostic.remediation,
        )
    if diagnostic.checked is False:
        return DoctorCheck(
            name="import_isolation",
            status="info",
            message=diagnostic.message,
            value=value,
        )
    return DoctorCheck(
        name="import_isolation",
        status="ok",
        message="import location matches distribution metadata",
        value=value,
    )


def _check_sys_path_summary() -> DoctorCheck:
    pythonpath_entries = _pythonpath_entries()
    entries = []
    for index, raw in enumerate(sys.path):
        path = _sys_path_entry_path(raw)
        entries.append(
            {
                "index": index,
                "path": str(path),
                "annotation": _classify_sys_path_entry(path, pythonpath_entries),
                "exists": path.exists(),
                "contains_keel_verifier": _path_contains_package(path),
            }
        )
    shadows = _pythonpath_shadow_entries()
    if shadows:
        return DoctorCheck(
            name="sys_path_summary",
            status="warn",
            message=f"{len(entries)} entries, {len(shadows)} PYTHONPATH shadow candidate(s)",
            value=entries,
            remediation=SHADOW_IMPORT_REMEDIATION,
        )
    return DoctorCheck(
        name="sys_path_summary",
        status="ok",
        message=f"{len(entries)} entries, no PYTHONPATH shadows",
        value=entries,
    )


def _check_pythonpath_env() -> DoctorCheck:
    raw = os.environ.get("PYTHONPATH", "")
    shadows = _pythonpath_shadow_entries()
    if not raw:
        return DoctorCheck(
            name="pythonpath_env",
            status="info",
            message="not set",
            value="",
        )
    if shadows:
        return DoctorCheck(
            name="pythonpath_env",
            status="warn",
            message=f"set with {len(shadows)} keel_verifier shadow candidate(s)",
            value=raw,
            remediation=SHADOW_IMPORT_REMEDIATION,
        )
    return DoctorCheck(
        name="pythonpath_env",
        status="info",
        message="set, no keel_verifier shadow candidates",
        value=raw,
    )


def _check_pth_shadow() -> DoctorCheck:
    source_root = Path(__file__).resolve().parents[1]
    findings: list[dict[str, Any]] = []
    for _label, root in _site_roots():
        if not root.exists():
            continue
        for pth_file in sorted(root.glob("*.pth")):
            try:
                lines = pth_file.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for line_number, line in enumerate(lines, start=1):
                if PACKAGE_NAME in line or str(source_root) in line:
                    findings.append(
                        {
                            "file": pth_file,
                            "line": line_number,
                            "content": line,
                        }
                    )
    if findings:
        return DoctorCheck(
            name="pth_shadow_check",
            status="warn",
            message=f"{len(findings)} .pth reference(s) can affect keel_verifier imports",
            value=findings,
            remediation=SHADOW_IMPORT_REMEDIATION,
        )
    return DoctorCheck(
        name="pth_shadow_check",
        status="ok",
        message="0 .pth files reference keel_verifier",
        value=[],
    )


def _check_cache_state() -> DoctorCheck:
    cache_dir = DEFAULT_DOCTOR_CACHE_DIR.expanduser()
    entries: list[dict[str, Any]] = []
    if cache_dir.exists():
        for child in sorted(cache_dir.iterdir()):
            if not child.is_dir():
                continue
            entries.append(
                {
                    "name": child.name,
                    "path": child,
                    "size_bytes": _directory_size(child),
                    "last_modified": _latest_mtime(child),
                }
            )
    total_size = sum(int(entry["size_bytes"]) for entry in entries)
    latest = max((entry["last_modified"] for entry in entries), default=None)
    value = {
        "path": cache_dir,
        "exists": cache_dir.exists(),
        "entry_count": len(entries),
        "total_bytes": total_size,
        "last_modified": latest,
        "entries": entries,
    }
    if not cache_dir.exists():
        message = f"{_display_path(cache_dir)} is not present"
    else:
        message = (
            f"{_display_path(cache_dir)} contains {len(entries)} entries, "
            f"total {_format_bytes(total_size)}, last modified {_format_age(latest)}"
        )
    return DoctorCheck(
        name="cache_state",
        status="info",
        message=message,
        value=value,
    )


def _check_self_check_preview(
    install_form: InstallFormDiagnostic,
    import_isolation: DoctorCheck,
) -> DoctorCheck:
    if install_form.form == "missing":
        return DoctorCheck(
            name="self_check_preview",
            status="problem",
            message="self-check would fail at form detection (SELF_CHECK_FORM_UNSUPPORTED)",
            value={"blocking_check": "install_form"},
            remediation=MISSING_INSTALL_REMEDIATION,
        )
    if install_form.form == "editable":
        return DoctorCheck(
            name="self_check_preview",
            status="warn",
            message="self-check would fail at form detection (SELF_CHECK_FORM_UNSUPPORTED)",
            value={"blocking_check": "install_form"},
            remediation=EDITABLE_INSTALL_REMEDIATION,
        )
    if install_form.form == "sdist":
        return DoctorCheck(
            name="self_check_preview",
            status="warn",
            message="self-check would fail at form detection (SELF_CHECK_FORM_UNSUPPORTED)",
            value={"blocking_check": "install_form"},
            remediation=SDIST_INSTALL_REMEDIATION,
        )
    if import_isolation.status == "problem":
        return DoctorCheck(
            name="self_check_preview",
            status="problem",
            message="self-check would fail at import_isolation (SELF_CHECK_SHADOW_IMPORT)",
            value={"blocking_check": "import_isolation"},
            remediation=import_isolation.remediation,
        )
    return DoctorCheck(
        name="self_check_preview",
        status="ok",
        message="self-check should proceed through all stages.",
        value={"blocking_check": None},
    )


def _head_url(url: str, *, timeout: int = 5) -> _HeadResult:
    request = urllib.request.Request(url, method="HEAD")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return _HeadResult(status_code=int(response.status))


def _reachability_check(name: str, url: str, label: str) -> DoctorCheck:
    try:
        result = _head_url(url, timeout=5)
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        return DoctorCheck(
            name=name,
            status="problem",
            message=f"{label} unreachable: {exc}",
            value={"url": url, "error": str(exc)},
            remediation="Check outbound network access, proxy settings, or service status.",
        )
    if 200 <= result.status_code < 400:
        return DoctorCheck(
            name=name,
            status="ok",
            message=f"{label} reachable (HTTP {result.status_code})",
            value={"url": url, "status_code": result.status_code},
        )
    return DoctorCheck(
        name=name,
        status="problem",
        message=f"{label} returned HTTP {result.status_code}",
        value={"url": url, "status_code": result.status_code},
        remediation="Check outbound network access, proxy settings, or service status.",
    )


def _configured_tsa_endpoints(args: Any) -> list[tuple[str, str]]:
    configured = getattr(args, "tsa_endpoints", None)
    if configured is None:
        return list(DEFAULT_TSA_ENDPOINTS)
    endpoints: list[tuple[str, str]] = []
    for index, item in enumerate(configured, start=1):
        if isinstance(item, dict):
            provider = str(item.get("provider") or f"tsa_{index}")
            url = str(item.get("url") or "")
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            provider, url = str(item[0]), str(item[1])
        else:
            provider, url = f"tsa_{index}", str(item)
        if url:
            endpoints.append((provider, url))
    return endpoints


def _network_checks(args: Any) -> list[DoctorCheck]:
    checks = [
        _reachability_check("pypi_reachability", PYPI_SIMPLE_URL, "PyPI"),
        _reachability_check("sigstore_reachability", SIGSTORE_REKOR_URL, "Sigstore Rekor"),
    ]
    for provider, url in _configured_tsa_endpoints(args):
        safe_provider = provider.lower().replace("-", "_")
        checks.append(
            _reachability_check(
                f"tsa_reachability_{safe_provider}",
                url,
                f"TSA endpoint {provider}",
            )
        )
    return checks


def run_doctor(args: Any) -> DoctorResult:
    install_form = inspect_install_form()
    import_isolation_diagnostic = inspect_import_isolation(
        distribution=install_form.distribution,
    )
    import_isolation = _check_import_isolation(import_isolation_diagnostic)

    checks = [
        _check_install_form(install_form),
        _check_python_interpreter(),
        _check_import_location(),
        _check_distribution_location(install_form.distribution),
        import_isolation,
        _check_sys_path_summary(),
        _check_pythonpath_env(),
        _check_pth_shadow(),
        _check_cache_state(),
        _check_self_check_preview(install_form, import_isolation),
    ]
    if bool(getattr(args, "check_network", False)):
        checks.extend(_network_checks(args))
    return DoctorResult(checks=checks)
