# brumby

Analyzes fresh Python releases for worsening aspects.

## Usage

```bash
uv venv .venv
. .venv/bin/activate
uv sync
scripts/poll_updates.py --include-first --interval 5 | xargs -n1 -P4 brumby assess
```

## Library API

Use `brumby.api` to run the same operations as the CLI without parsing terminal
output. Each operation accepts a loaded config dict and returns a result object:

```python
import tomllib

from brumby import api

with open("brumby.toml", "rb") as config_file:
    config = tomllib.load(config_file)

result = api.check("example-package", config=config)
for difference in result.diffs:
    print(difference)
```

Pass `config=None` to use built-in defaults. Unlike the CLI, the library API does
not search for a config file; callers that need non-default settings should load
and pass them explicitly.

Only the names listed in `brumby.api.__all__` carry a compatibility guarantee.
Every other module and package-root convenience import is an implementation detail
and may change without notice.

## Assessment results

Brumby rates change, not safety. For the usual two-release assessment, `average`
means the new release looks no worse than yesterday's baseline. `high` means it has
enough newly introduced signals to look plausibly worse than that baseline. There is
no `low` result: failing to find a regression does not prove that either release is
safe.

The `sus` and `informational` thresholds set how many changed findings are enough
to report `high`. Assessments without a usable baseline report `too new` rather
than treating one release as evidence of improvement. Callers must handle `too new`
as a third result; a conservative admission policy should treat it like `high` while
preserving the distinct reason.

## Test

```bash
uv run pytest tests/
```

## Version Compat

This library is compatible with Python 3.11+, but should be linted under the newest stable version.

## Versioning

This library follows [meanver](https://meanver.org/) which basically means [semver](https://semver.org/) along with a promise to rename when the major version changes.

## License

brumby is copyright [Tim Hatch](https://timhatch.com/), and licensed under the MIT license. See the `LICENSE` file for details.
