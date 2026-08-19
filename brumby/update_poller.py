from __future__ import annotations

import argparse
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Callable, TextIO
from urllib.parse import unquote, urlparse

import requests

FEED_URL = "https://pypi.org/rss/updates.xml"


@dataclass(frozen=True)
class UpdateItem:
    project: str
    version: str | None


def _find_text(elem: ET.Element, tag: str) -> str:
    for child in elem:
        if child.tag.rsplit("}", 1)[-1] == tag:
            return (child.text or "").strip()
    return ""


def _parse_project_version_from_link(link: str) -> tuple[str | None, str | None]:
    path = unquote(urlparse(link).path).strip("/")
    parts = [part for part in path.split("/") if part]
    if len(parts) >= 2 and parts[0] == "project":
        project = parts[1]
        version = parts[2] if len(parts) >= 3 else None
        if version == "releases":
            version = None
        return project, version
    return None, None


def _parse_project_version_from_title(title: str) -> tuple[str | None, str | None]:
    parts = title.split()
    if len(parts) < 2:
        return None, None
    project, version = parts[0], parts[1]
    if any(ch.isdigit() for ch in version):
        return project, version
    return None, None


def parse_updates_xml(xml_text: str) -> list[UpdateItem]:
    root = ET.fromstring(xml_text)
    items: list[UpdateItem] = []
    for elem in root.iter():
        if elem.tag.rsplit("}", 1)[-1] != "item":
            continue
        link = _find_text(elem, "link")
        title = _find_text(elem, "title")
        project, version = _parse_project_version_from_link(link) if link else (None, None)
        if project is None:
            project, version = _parse_project_version_from_title(title)
        elif version is None and title:
            _title_project, title_version = _parse_project_version_from_title(title)
            if title_version:
                version = title_version
        if project:
            items.append(UpdateItem(project=project, version=version))
    return items


def fetch_updates(feed_url: str = FEED_URL, timeout: float = 30.0) -> list[UpdateItem]:
    response = requests.get(feed_url, timeout=timeout)
    response.raise_for_status()
    return parse_updates_xml(response.text)


def _format_item(item: UpdateItem, with_version: bool) -> str:
    if with_version and item.version:
        return f"{item.project}=={item.version}"
    return item.project


def poll_updates(
    *,
    feed_url: str = FEED_URL,
    interval: int = 10,
    with_version: bool = False,
    include_first: bool = False,
    stream: TextIO | None = None,
    fetcher: Callable[[], list[UpdateItem]] | None = None,
    sleeper: Callable[[float], None] = time.sleep,
    iterations: int | None = None,
) -> int:
    stream = sys.stdout if stream is None else stream
    fetch = fetcher or (lambda: fetch_updates(feed_url))
    previous: set[tuple[str, str | None]] | None = None
    emitted = 0
    done = 0

    while iterations is None or done < iterations:
        current_items = fetch()
        current_order: list[str] = []
        current_versions: dict[str, str | None] = {}
        for item in current_items:
            if item.project in current_versions:
                continue
            current_versions[item.project] = item.version
            current_order.append(item.project)

        wrote = False
        if previous is None and include_first:
            for project in current_order:
                print(
                    _format_item(UpdateItem(project, current_versions[project]), with_version),
                    file=stream,
                )
                emitted += 1
                wrote = True
        elif previous is not None:
            for project in current_order:
                if (project, current_versions[project]) in previous:
                    continue
                print(
                    _format_item(UpdateItem(project, current_versions[project]), with_version),
                    file=stream,
                )
                emitted += 1
                wrote = True

        previous = {(project, current_versions[project]) for project in current_order}
        if wrote:
            stream.flush()
        done += 1
        if iterations is not None and done >= iterations:
            break
        sleeper(interval)

    return emitted


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Poll PyPI's updates feed and print projects that are new since the previous update.",
    )
    parser.add_argument("--interval", type=int, default=600, metavar="SECONDS")
    parser.add_argument("--with-version", action="store_true", help="Print project==version")
    parser.add_argument("--include-first", action="store_true",
                        help="Treat the first snapshot as new instead of seeding the baseline")
    parser.add_argument("--feed-url", default=FEED_URL, metavar="URL")
    args = parser.parse_args(argv)

    poll_updates(
        feed_url=args.feed_url,
        interval=args.interval,
        with_version=args.with_version,
        include_first=args.include_first,
    )
    return 0

if __name__ == "__main__":
    main(sys.argv[1:])
