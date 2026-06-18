"""Audit binding/envelope version selectors before binding-version flips."""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

VERSION_RE = re.compile(r"^v([1-9][0-9]*)$")
CONTEXT_RE = re.compile(
    r"\b("
    r"binding_version|envelope_version|BINDING_VERSION|SUPPORTED_BINDING_VERSIONS|"
    r"CANONICAL_PAYLOAD_BUILDERS"
    r")\b"
)
DEFAULT_SOURCE_ROOTS = ("keel_verifier", "scripts", "tools")
JSON_AUDIT_PATHS = ("keel_verifier/data/semantics/permit/decision_v1.json",)
EXCLUDED_FILES = {"scripts/selector_audit.py"}
DEFAULT_REQUIRED_BINDING_VERSION = "v7"


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    kind: str
    qualname: str
    versions: tuple[str, ...]
    source: str


@dataclass(frozen=True)
class AllowlistEntry:
    path: str
    reason: str
    owner: str
    kind: str | None = None
    qualname: str | None = None
    source_contains: tuple[str, ...] = ()

    def matches(self, finding: Finding) -> bool:
        if finding.path != self.path:
            return False
        if self.kind is not None and finding.kind != self.kind:
            return False
        if self.qualname is not None and finding.qualname != self.qualname:
            return False
        return all(needle in finding.source for needle in self.source_contains)


ALLOWLIST: tuple[AllowlistEntry, ...] = ()
FORCE_ALLOWLIST: tuple[AllowlistEntry, ...] = ()


@dataclass(frozen=True)
class AuditResult:
    findings: tuple[Finding, ...]
    failures: tuple[str, ...]
    matched_allowlist: tuple[AllowlistEntry, ...]
    unused_allowlist: tuple[AllowlistEntry, ...]


def _version_key(version: str) -> int:
    match = VERSION_RE.match(version)
    return int(match.group(1)) if match is not None else -1


def _version_literals(node: ast.AST) -> tuple[str, ...]:
    versions: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            if VERSION_RE.match(child.value):
                versions.add(child.value)
    return tuple(sorted(versions, key=_version_key))


def _source_segment(source: str, node: ast.AST) -> str:
    return " ".join((ast.get_source_segment(source, node) or "").split())


def _assignment_names(parent: ast.AST | None) -> str:
    if not isinstance(parent, (ast.Assign, ast.AnnAssign)):
        return ""
    targets = parent.targets if isinstance(parent, ast.Assign) else [parent.target]
    names: list[str] = []
    for target in targets:
        for child in ast.walk(target):
            if isinstance(child, ast.Name):
                names.append(child.id)
            elif isinstance(child, ast.Attribute):
                names.append(child.attr)
    return " ".join(names)


def _has_selector_context(source: str, qualname: str, assignment_names: str = "") -> bool:
    haystack = f"{source} {qualname} {assignment_names}"
    if CONTEXT_RE.search(haystack):
        return True
    return "permit_decision_binding" in haystack or "canonical_binding" in haystack


def _dict_version_keys(node: ast.Dict) -> tuple[str, ...]:
    versions: set[str] = set()
    for key in node.keys:
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            if VERSION_RE.match(key.value):
                versions.add(key.value)
    return tuple(sorted(versions, key=_version_key))


def _parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    return parents


class SelectorVisitor(ast.NodeVisitor):
    def __init__(self, *, path: str, source: str) -> None:
        self.path = path
        self.source = source
        self.parents: dict[ast.AST, ast.AST] = {}
        self.stack: list[str] = []
        self.findings: list[Finding] = []

    def visit_Module(self, node: ast.Module) -> Any:
        self.parents = _parent_map(node)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self.visit_FunctionDef(node)

    def visit_Compare(self, node: ast.Compare) -> Any:
        versions = _version_literals(node)
        if versions and any(
            isinstance(op, (ast.Eq, ast.NotEq, ast.In, ast.NotIn)) for op in node.ops
        ):
            source = _source_segment(self.source, node)
            qualname = self._qualname()
            if _has_selector_context(
                source, qualname
            ) or _force_allowlist_candidate(
                path=self.path,
                kind="compare",
                qualname=qualname,
                source=source,
            ):
                self._add(node, "compare", versions, source)
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> Any:
        versions = _dict_version_keys(node)
        if versions:
            source = _source_segment(self.source, node)
            assignment_names = _assignment_names(self.parents.get(node))
            map_context = (
                "CANONICAL_PAYLOAD_BUILDERS" in assignment_names
                or "SUPPORTED_BINDING_VERSIONS" in assignment_names
                or "FIELDS_BY_VERSION" in assignment_names
                or "field_map" in source
                or "versioned_fields" in source
            )
            if map_context and (
                _has_selector_context(source, self._qualname(), assignment_names)
                or "PERMIT_DECISION" in assignment_names
            ):
                self._add(node, "version_map", versions, source)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> Any:
        versions = _version_literals(node)
        if versions:
            source = _source_segment(self.source, node)
            assignment_names = _assignment_names(self.parents.get(node))
            if "SUPPORTED_BINDING_VERSIONS" in assignment_names and _has_selector_context(
                source, self._qualname(), assignment_names
            ):
                self._add(node, "version_collection", versions, source)
        self.generic_visit(node)

    def visit_Match(self, node: ast.Match) -> Any:
        versions = _version_literals(node)
        if versions:
            source = _source_segment(self.source, node)
            if _has_selector_context(source, self._qualname()):
                self._add(node, "match", versions, source)
        self.generic_visit(node)

    def visit_keyword(self, node: ast.keyword) -> Any:
        if node.arg in {"binding_version", "envelope_version"}:
            versions = _version_literals(node.value)
            if versions:
                self._add(node, "version_keyword", versions, _source_segment(self.source, node))
        self.generic_visit(node)

    def _qualname(self) -> str:
        return ".".join(self.stack)

    def _add(
        self,
        node: ast.AST,
        kind: str,
        versions: Iterable[str],
        source: str,
    ) -> None:
        self.findings.append(
            Finding(
                path=self.path,
                line=getattr(node, "lineno", 1),
                kind=kind,
                qualname=self._qualname(),
                versions=tuple(versions),
                source=source,
            )
        )


def _iter_python_files(root: Path) -> Iterable[Path]:
    for source_root in DEFAULT_SOURCE_ROOTS:
        base = root / source_root
        if not base.exists():
            continue
        for path in base.rglob("*.py"):
            relative = path.relative_to(root).as_posix()
            if relative in EXCLUDED_FILES or "__pycache__" in path.parts:
                continue
            text = path.read_text(encoding="utf-8")
            if "binding_version" not in text and "envelope_version" not in text:
                continue
            yield path


def _scan_python(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in _iter_python_files(root):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        visitor = SelectorVisitor(path=path.relative_to(root).as_posix(), source=source)
        visitor.visit(tree)
        findings.extend(visitor.findings)
    return findings


def _json_findings(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for relative in JSON_AUDIT_PATHS:
        path = root / relative
        if path.exists():
            findings.extend(_walk_json(relative, json.loads(path.read_text()), ()))
    return findings


def _walk_json(path: str, value: Any, breadcrumbs: tuple[str, ...]) -> list[Finding]:
    findings: list[Finding] = []
    if isinstance(value, dict):
        key_versions = tuple(
            sorted(
                {key for key in value if isinstance(key, str) and VERSION_RE.match(key)},
                key=_version_key,
            )
        )
        if key_versions and _json_context(breadcrumbs, value):
            findings.append(
                Finding(
                    path=path,
                    line=1,
                    kind="json_version_map",
                    qualname=".".join(breadcrumbs),
                    versions=key_versions,
                    source=json.dumps(value, sort_keys=True),
                )
            )
        enum_value = value.get("enum")
        if isinstance(enum_value, list):
            enum_versions = tuple(
                sorted(
                    {
                        item
                        for item in enum_value
                        if isinstance(item, str) and VERSION_RE.match(item)
                    },
                    key=_version_key,
                )
            )
            if enum_versions and _json_context(breadcrumbs, value):
                findings.append(
                    Finding(
                        path=path,
                        line=1,
                        kind="json_enum",
                        qualname=".".join(breadcrumbs + ("enum",)),
                        versions=enum_versions,
                        source=json.dumps(enum_value),
                    )
                )
        for key, item in value.items():
            findings.extend(_walk_json(path, item, breadcrumbs + (str(key),)))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(_walk_json(path, item, breadcrumbs + (str(index),)))
    return findings


def _json_context(breadcrumbs: tuple[str, ...], value: dict[str, Any]) -> bool:
    joined = ".".join(breadcrumbs)
    if "binding_version" in joined or "versioned_fields" in joined:
        return True
    return "binding_version" in json.dumps(value, sort_keys=True)


def _previous_version(required_version: str) -> str:
    number = _version_key(required_version)
    if number <= 1:
        raise ValueError(f"Cannot compute previous version for {required_version!r}")
    return f"v{number - 1}"


def _matches_any(entries: Iterable[AllowlistEntry], finding: Finding) -> bool:
    return any(entry.matches(finding) for entry in entries)


def _force_allowlist_candidate(
    *,
    path: str,
    kind: str,
    qualname: str,
    source: str,
) -> bool:
    return _matches_any(
        FORCE_ALLOWLIST,
        Finding(path=path, line=1, kind=kind, qualname=qualname, versions=(), source=source),
    )


def _requires_allowlist(finding: Finding, required_version: str) -> bool:
    if _matches_any(FORCE_ALLOWLIST, finding):
        return True
    previous = _previous_version(required_version)
    return previous in finding.versions and required_version not in finding.versions


def _matching_allowlist(finding: Finding) -> AllowlistEntry | None:
    for entry in ALLOWLIST:
        if entry.matches(finding):
            return entry
    return None


def audit_repo(
    root: Path,
    *,
    required_binding_version: str | None = None,
) -> AuditResult:
    root = root.resolve()
    required_binding_version = required_binding_version or DEFAULT_REQUIRED_BINDING_VERSION

    findings = tuple(_scan_python(root) + _json_findings(root))
    failures: list[str] = []
    matched: set[AllowlistEntry] = set()
    for finding in findings:
        if not _requires_allowlist(finding, required_binding_version):
            continue
        entry = _matching_allowlist(finding)
        if entry is None:
            failures.append(_format_finding(finding, required_binding_version))
        else:
            matched.add(entry)
    unused = tuple(entry for entry in ALLOWLIST if entry not in matched)
    failures.extend(
        f"unused allowlist entry: {entry.path} {entry.qualname or '*'} "
        f"{entry.kind or '*'} reason={entry.reason} owner={entry.owner}"
        for entry in unused
    )
    return AuditResult(
        findings=findings,
        failures=tuple(failures),
        matched_allowlist=tuple(sorted(matched, key=lambda item: item.path)),
        unused_allowlist=unused,
    )


def _format_finding(finding: Finding, required_version: str) -> str:
    versions = ", ".join(finding.versions)
    return (
        f"{finding.path}:{finding.line}: {finding.kind} {finding.qualname or '<module>'} "
        f"uses {{{versions}}} without {required_version}: {finding.source}"
    )


def format_failures(result: AuditResult) -> str:
    return "\n".join(result.failures)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--required-binding-version",
        default=DEFAULT_REQUIRED_BINDING_VERSION,
    )
    args = parser.parse_args(argv)
    result = audit_repo(args.root, required_binding_version=args.required_binding_version)
    if result.failures:
        print(format_failures(result), file=sys.stderr)
        return 1
    print(
        "selector audit ok: "
        f"{len(result.findings)} findings, "
        f"{len(result.matched_allowlist)} allowlisted"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
