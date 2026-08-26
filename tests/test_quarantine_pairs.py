"""Regression test against real PyPI release pairs that PyPI itself quarantined.

tests/fixtures/quarantine_test_pairs.json lists (old, new) release pairs by
download URL for two groups:

  malware-cluster           accounts publishing a burst of nothing-but-malicious
                             releases (e.g. bramin 0.0.1 -> 0.0.2 within minutes)
  legit-single-bad-release  established projects (mistralai, guardrails-ai, ...)
                             that had one release quarantined by PyPI

Both groups are real PyPI quarantine actions, so both are expected to come out
"high" risk from brumby's own pipeline -- this is a true-positive regression
guard, not a false-positive control.

The artifact files themselves are NOT checked into git (some releases carry
tens of megabytes of platform wheels). Run scripts/fetch_quarantine_fixtures.py
once to populate tests/fixtures/quarantine/ before running this file; it's
skipped automatically if that cache is empty.
"""
import json
from pathlib import Path

import pytest

from brumby.analyze import check_artifacts
from brumby.artifact import make_local_artifact
from brumby.cli import _risk_from_diffs

FIXTURES_DIR = Path(__file__).parent / "fixtures"
PAIRS_PATH = FIXTURES_DIR / "quarantine_test_pairs.json"
CACHE_DIR = FIXTURES_DIR / "quarantine"

_CONFIG: dict = {}  # explicit empty config: default thresholds (sus=1, informational=0)


def _load_pairs() -> list[dict]:
    return json.loads(PAIRS_PATH.read_text())


def _pair_id(pair: dict) -> str:
    return f"{pair['project']}-{pair['old']['version']}-to-{pair['new']['version']}"


def _local_artifacts(project: str, side: dict):
    version_dir = CACHE_DIR / project / side["version"]
    return [make_local_artifact(version_dir / f["filename"]) for f in side["files"]]


def _explain(pair: dict, diffs: list[tuple]) -> str:
    lines = [
        f"{pair['project']} {pair['old']['version']} -> {pair['new']['version']} "
        f"(group={pair['group']}): {len(diffs)} diff(s)"
    ]
    for name, resource, old_vals, new_vals, _old_sources, _new_sources, kind in diffs:
        added = new_vals - old_vals
        removed = old_vals - new_vals
        detail = []
        if added:
            detail.append(f"new={sorted(map(str, added))}")
        if removed:
            detail.append(f"gone={sorted(map(str, removed))}")
        lines.append(f"  [{kind}] {name} @ {resource or '(release)'}: {', '.join(detail)}")
    return "\n".join(lines)


def _missing_fixtures(pairs: list[dict]) -> list[str]:
    missing = []
    for pair in pairs:
        for side in ("old", "new"):
            version_dir = CACHE_DIR / pair["project"] / pair[side]["version"]
            for f in pair[side]["files"]:
                if not (version_dir / f["filename"]).exists():
                    missing.append(str(version_dir / f["filename"]))
    return missing


_PAIRS = _load_pairs() if PAIRS_PATH.exists() else []


@pytest.fixture(scope="module", autouse=True)
def _require_fixture_cache():
    missing = _missing_fixtures(_PAIRS)
    if missing:
        pytest.skip(
            f"{len(missing)} quarantine fixture file(s) not downloaded; run "
            "scripts/fetch_quarantine_fixtures.py first"
        )


@pytest.mark.parametrize("pair", _PAIRS, ids=[_pair_id(p) for p in _PAIRS])
def test_quarantined_pair_is_high_risk(pair: dict) -> None:
    old_artifacts = _local_artifacts(pair["project"], pair["old"])
    new_artifacts = _local_artifacts(pair["project"], pair["new"])

    _old_findings, _new_findings, diffs = check_artifacts(
        old_artifacts,
        new_artifacts,
        old_label=pair["old"]["version"],
        new_label=pair["new"]["version"],
        callback=lambda *args, **kwargs: None,
        config=_CONFIG,
        content=True,
    )

    risk = _risk_from_diffs(diffs, _CONFIG)
    print(_explain(pair, diffs))  # only shown with -s, or for failures by default
    assert risk == "high", _explain(pair, diffs)
