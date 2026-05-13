import tomllib
from pathlib import Path
from typing import Any


def load_config(path: Path | None = None) -> dict[str, Any]:
    """Load brumby.toml; return {} if not found."""
    candidates = [path] if path else [Path("brumby.toml"), Path.home() / ".config" / "brumby" / "brumby.toml"]
    for p in candidates:
        if p and p.exists():
            with open(p, "rb") as f:
                return tomllib.load(f)
    return {}


def is_enabled(config: dict[str, Any], name: str, default: bool = True) -> bool:
    finders = config.get("finders", {})
    entry = finders.get(name, default)
    if isinstance(entry, bool):
        return entry
    if isinstance(entry, dict):
        return entry.get("enabled", default)
    return default


def get_settings(config: dict[str, Any], name: str) -> dict[str, Any]:
    finders = config.get("finders", {})
    entry = finders.get(name, {})
    if isinstance(entry, dict):
        return {k: v for k, v in entry.items() if k != "enabled"}
    return {}


def get_thresholds(config: dict[str, Any]) -> tuple[int, int]:
    """Return (sus_threshold, informational_threshold) for risk classification."""
    thresholds = config.get("thresholds", {})
    return thresholds.get("sus", 1), thresholds.get("informational", 0)
