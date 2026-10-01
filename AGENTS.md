# Development guide

Brumby compares Python release artifacts and reports signals that become worse in a new release. Most changes add or refine a finder.

## Find a finder

List the runtime registry before searching by hand:

```bash
uv run brumby finders
uv run brumby finders --config path/to/brumby.toml
```

This prints each finder's name, scope, kind, content requirement, enabled state, and description. Finder implementations live in `brumby/finders/`:

- `archive.py`: archive structure, names, timestamps, and permissions
- `binary.py`: native executable formats and shared libraries
- `distribution.py`: artifact sets and comparisons between releases
- `metadata.py`: package metadata, versions, and wheel properties
- `source.py`: suspicious Python and JavaScript source patterns
- `zipforensics.py`: ZIP records and layout

For an exact source search, look for `@register("finder_name"` or the finding name. Tests follow the same subject split, for example `binary.py` uses `tests/test_binary_findings.py`.

Run one artifact finder against a package or local archive with:

```bash
uv run brumby inspect PACKAGE --finder finder_name
uv run brumby inspect path/to/package.whl --finder finder_name
```

`--finder` accepts only artifact-scoped finders. It exits with status 1 when the finder reports anything.

## Register a finder

`brumby/registry.py` owns the registry. `@register(...)` appends a `FinderSpec` when its module is imported. `brumby/analyze.py` imports `brumby.finders`, whose `__init__.py` imports every finder module for this side effect.

A finder added to an existing module needs only the decorator. If you add a new module, also import it and add it to `__all__` in `brumby/finders/__init__.py`; otherwise it never enters the registry.

```python
@register(
    "has_example",
    "Archive contains an example",
    scope="artifact",
    kind="sketchy",
    default_enabled=True,
    needs_content=True,
)
def find_example(view: ArtifactView, cfg: dict) -> list[Finding]:
    ...
```

Decorator fields:

- `name`: stable config and output key; keep it unique.
- `description`: shown by `brumby finders`.
- `scope`: `artifact` by default, or `release`, `metadata`, or `comparison`.
- `kind`: `informational` by default or `sketchy`; this controls display and risk thresholds.
- `default_enabled`: defaults to `True`.
- `needs_content`: mark finders that read member bytes. `--fast` skips these.

Scope determines the callable signature:

- artifact: `(view: ArtifactView, cfg: dict) -> list[Finding]`
- release: `(views: list[ArtifactView], cfg: dict) -> list[Finding]`
- metadata: `(info: dict, version: str, cfg: dict) -> list[Finding]`
- comparison: `(package, old_version, old_artifacts, new_version, new_artifacts, cfg) -> list[tuple[name, old_value, new_value]]`

`analyze_artifacts()` runs artifact finders once per selected artifact. `analyze_release()` then runs metadata and release finders. The package comparison path runs comparison finders after ordinary findings have been diffed.

## Configure a finder

Brumby reads `brumby.toml` in the working directory, then `~/.config/brumby/brumby.toml`. `--config FILE` selects an explicit file. The library API does not search for a file; callers pass an already loaded config dict.

Use a boolean to toggle a finder:

```toml
[finders]
has_example = false
```

Use a table when the finder has settings:

```toml
[finders.long_source_line]
enabled = true
threshold = 500
```

`is_enabled()` applies `default_enabled`; `get_settings()` removes `enabled` and passes the remaining keys as `cfg`. Read options with defaults inside the finder, such as `cfg.get("threshold", 500)`. Document user-facing options in `brumby.toml.example`.

Risk thresholds are separate from finder settings:

```toml
[thresholds]
sus = 1
informational = 0
```

## Finding invariants

Finding values are comparison keys. They must stay stable across routine rebuilds or `compare.py` reports a false new/gone pair.

- Compare like resources with like resources: wheel findings must not silently stand in for sdist findings.
- Normalize generated names only when the convention is specific enough not to merge unrelated files.
- Preserve meaningful paths and suffixes while removing build-specific ABI, platform, or content-hash components.
- Set `source` to the artifact filename and preserve the `resource` grouping key for artifact findings.
- Add a regression test for the unstable form and a negative test for a nearby value that must remain unchanged.
- Avoid network access in unit tests. Use a dummy `ArtifactView` or a fixture.

## Setup and checks

```bash
uv sync --all-extras
uv run pytest tests/
uv run ruff check brumby tests
uv run mypy brumby
```

Run the narrow test file while developing, then the full suite before finishing. `brumby.api.__all__` is the supported library interface; other imports are implementation details.
