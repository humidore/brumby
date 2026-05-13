Try:

```
uv venv .venv
. .venv/bin/activate
uv sync
scripts/poll_updates.py  --include-first --interval 5 | xargs -n1 -P4 brumby assess
```

Test

```
uv run pytest tests/
```
