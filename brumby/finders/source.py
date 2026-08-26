"""Source-code analysis finders — read .py file content."""

import ast
import math
import re
from collections import Counter

from ..artifact import ArtifactView
from ..finding import Finding
from ..registry import register

_PY = frozenset({".py"})

_BASE64_PAT = re.compile(rb"^\s*(?:import base64|from base64\b)", re.MULTILINE)

_NO_RECURSE = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_OS_SPAWN_ATTRS = {"system", "popen", "execv"}


def _import_time_nodes(node: ast.AST):
    """Depth-first walk of nodes that run unconditionally when the module is
    imported: the module body plus anything nested in it (if/try/with/class/
    loop bodies), but not the inside of a function or lambda -- those only
    run when called, not on import.
    """
    for child in ast.iter_child_nodes(node):
        yield child
        if not isinstance(child, _NO_RECURSE):
            yield from _import_time_nodes(child)


def _is_spawn_call(call: ast.Call, aliases: dict[str, str]) -> bool:
    func = call.func
    if isinstance(func, ast.Name) and func.id == "__import__":
        return True
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        root = aliases.get(func.value.id, func.value.id)
        if root == "subprocess":
            return True
        if root == "os" and func.attr in _OS_SPAWN_ATTRS:
            return True
    return False


def _has_import_time_spawn(content: bytes) -> bool:
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError, RecursionError):
        return False

    aliases: dict[str, str] = {}
    for node in _import_time_nodes(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname and alias.name in ("os", "subprocess"):
                    aliases[alias.asname] = alias.name
        elif isinstance(node, ast.Call) and _is_spawn_call(node, aliases):
            return True
    return False


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


@register(
    "imports_base64",
    "A .py file imports base64 (common in obfuscated payloads)",
    kind="informational",
    needs_content=True,
)
def find_imports_base64(view: ArtifactView, cfg: dict) -> list[Finding]:
    findings: list[Finding] = []
    for name, content in view.iter_files(exts=_PY):
        if _BASE64_PAT.search(content):
            findings.append(Finding("imports_base64", view.relative_name(name), view.filename, view.resource))
    return findings


@register(
    "spawns_at_import",
    "A .py file spawns a subprocess/shell/exec from top-level code (runs the moment the module is imported, not just when a function is called)",
    kind="sketchy",
    needs_content=True,
)
def find_spawns_at_import(view: ArtifactView, cfg: dict) -> list[Finding]:
    findings: list[Finding] = []
    for name, content in view.iter_files(exts=_PY):
        if _has_import_time_spawn(content):
            findings.append(Finding("spawns_at_import", view.relative_name(name), view.filename, view.resource))
    return findings


@register(
    "long_source_line",
    "A .py file contains a line longer than threshold characters (obfuscation indicator)",
    kind="sketchy",
    needs_content=True,
)
def find_long_source_line(view: ArtifactView, cfg: dict) -> list[Finding]:
    threshold = cfg.get("threshold", 500)
    findings: list[Finding] = []
    for name, content in view.iter_files(exts=_PY):
        for line in content.split(b"\n"):
            if len(line) > threshold:
                findings.append(Finding("long_source_line", view.relative_name(name), view.filename, view.resource))
                break
    return findings


@register(
    "high_entropy_source",
    "A .py file contains a high-entropy line (encoded/obfuscated data)",
    kind="sketchy",
    needs_content=True,
)
def find_high_entropy_source(view: ArtifactView, cfg: dict) -> list[Finding]:
    threshold = cfg.get("threshold", 5.5)
    max_line_length = cfg.get("max_line_length", 8192)
    findings: list[Finding] = []
    for name, content in view.iter_files(exts=_PY):
        for line in content.split(b"\n"):
            if len(line) > max_line_length:
                continue
            entropy = _shannon_entropy(line)
            if entropy > threshold:
                findings.append(Finding("high_entropy_source", view.relative_name(name), view.filename, view.resource))
                break
    return findings


@register(
    "high_entropy_blob",
    "A .py file contains a very long line (likely an embedded blob)",
    kind="sketchy",
    needs_content=True,
)
def find_high_entropy_blob(view: ArtifactView, cfg: dict) -> list[Finding]:
    max_line_length = cfg.get("max_line_length", 8192)
    findings: list[Finding] = []
    for name, content in view.iter_files(exts=_PY):
        if any(len(line) > max_line_length for line in content.split(b"\n")):
            findings.append(Finding("high_entropy_blob", view.relative_name(name), view.filename, view.resource))
    return findings
