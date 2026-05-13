"""Source-code analysis finders — read .py file content."""

import math
import re
from collections import Counter

from ..artifact import ArtifactView
from ..finding import Finding
from ..registry import register

_PY = frozenset({".py"})

_BASE64_PAT = re.compile(rb"^\s*(?:import base64|from base64\b)", re.MULTILINE)
_SPAWN_PAT = re.compile(
    rb"(?m)(?:^|;)[ \t]*(?:subprocess\.|os\.system\b|os\.popen\b|os\.execv\b|__import__\s*\()",
    re.MULTILINE,
)


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _leaf_name(path: str) -> str:
    return path.rsplit("/", 1)[-1]


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
            findings.append(Finding("imports_base64", _leaf_name(name), view.filename, view.resource))
    return findings


@register(
    "spawns_from_init",
    "__init__.py calls subprocess or os.system/popen (runs code on import)",
    kind="sketchy",
    needs_content=True,
)
def find_spawns_from_init(view: ArtifactView, cfg: dict) -> list[Finding]:
    for name, content in view.iter_files(exts=_PY):
        if not name.endswith("__init__.py"):
            continue
        if _SPAWN_PAT.search(content):
            return [Finding("spawns_from_init", True, view.filename, view.resource)]
    return []


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
                findings.append(Finding("long_source_line", _leaf_name(name), view.filename, view.resource))
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
                findings.append(Finding("high_entropy_source", _leaf_name(name), view.filename, view.resource))
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
            findings.append(Finding("high_entropy_blob", _leaf_name(name), view.filename, view.resource))
    return findings
