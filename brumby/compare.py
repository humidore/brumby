from typing import Any, Callable

from .finding import Finding

# (package, old_version, new_version, finding_name, resource, old_values, new_values, old_sources, new_sources, kind)
DiffCallback = Callable[
    [
        str,
        str,
        str,
        str,
        str | None,
        frozenset[Any],
        frozenset[Any],
        frozenset[str | None],
        frozenset[str | None],
        str,
    ],
    None,
]

Diff = tuple[
    str,
    str | None,
    frozenset[Any],
    frozenset[Any],
    frozenset[str | None],
    frozenset[str | None],
    str,
]  # (name, resource, old, new, old_sources, new_sources, kind)


def compare_releases(
    package: str,
    old_version: str,
    old_findings: list[Finding],
    new_version: str,
    new_findings: list[Finding],
    callback: DiffCallback,
    kinds: dict[str, str] | None = None,
) -> list[Diff]:
    """Compare findings between two releases and fire callback on differences.

    For informational findings: fires when the value set changes in either direction.
    For sketchy findings: fires only when new values appear (new - old ≠ ∅).
    Sketchy findings going away is fine and does not fire.
    """
    old_by_key: dict[tuple[str, str | None], set[Any]] = {}
    new_by_key: dict[tuple[str, str | None], set[Any]] = {}
    old_sources_by_key: dict[tuple[str, str | None], set[str | None]] = {}
    new_sources_by_key: dict[tuple[str, str | None], set[str | None]] = {}

    for f in old_findings:
        old_by_key.setdefault((f.name, f.resource), set()).add(f.value)
        old_sources_by_key.setdefault((f.name, f.resource), set()).add(f.source)
    for f in new_findings:
        new_by_key.setdefault((f.name, f.resource), set()).add(f.value)
        new_sources_by_key.setdefault((f.name, f.resource), set()).add(f.source)

    all_keys = sorted(set(old_by_key) | set(new_by_key), key=lambda x: (x[0], str(x[1])))
    diffs: list[Diff] = []
    _kinds = kinds or {}

    for name, resource in all_keys:
        old_vals = frozenset(old_by_key.get((name, resource), set()))
        new_vals = frozenset(new_by_key.get((name, resource), set()))
        old_sources = frozenset(old_sources_by_key.get((name, resource), set()))
        new_sources = frozenset(new_sources_by_key.get((name, resource), set()))
        if old_vals == new_vals:
            continue

        kind = _kinds.get(name, "informational")

        if kind == "sketchy":
            added = new_vals - old_vals
            if not added:
                continue  # only went away — that's fine
            callback(
                package,
                old_version,
                new_version,
                name,
                resource,
                old_vals,
                new_vals,
                old_sources,
                new_sources,
                kind,
            )
            diffs.append((name, resource, old_vals, new_vals, old_sources, new_sources, kind))
        else:
            callback(
                package,
                old_version,
                new_version,
                name,
                resource,
                old_vals,
                new_vals,
                old_sources,
                new_sources,
                kind,
            )
            diffs.append((name, resource, old_vals, new_vals, old_sources, new_sources, kind))

    return diffs
