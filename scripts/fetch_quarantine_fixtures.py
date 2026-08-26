#!/usr/bin/env python3
"""Download the artifact files referenced by tests/fixtures/quarantine_test_pairs.json
into tests/fixtures/quarantine/<project>/<version>/<filename>, skipping files already
on disk. Re-run after editing the pairs file to fetch anything new.
"""
import json
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
PAIRS_PATH = ROOT / "tests" / "fixtures" / "quarantine_test_pairs.json"
FIXTURES_DIR = ROOT / "tests" / "fixtures" / "quarantine"


def main() -> int:
    pairs = json.loads(PAIRS_PATH.read_text())

    seen: set[str] = set()
    fetched = 0
    skipped = 0
    for pair in pairs:
        for side in ("old", "new"):
            version_dir = FIXTURES_DIR / pair["project"] / pair[side]["version"]
            for f in pair[side]["files"]:
                dest = version_dir / f["filename"]
                if str(dest) in seen:
                    continue
                seen.add(str(dest))
                if dest.exists():
                    skipped += 1
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                print(f"fetching {f['url']} -> {dest.relative_to(ROOT)}")
                resp = requests.get(f["url"], timeout=120)
                resp.raise_for_status()
                dest.write_bytes(resp.content)
                fetched += 1

    print(f"fetched {fetched}, already present {skipped}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
