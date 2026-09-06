# brumby

Analyzes fresh Python releases for worsening aspects.

## Usage

```bash
uv venv .venv
. .venv/bin/activate
uv sync
scripts/poll_updates.py --include-first --interval 5 | xargs -n1 -P4 brumby assess
```

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
