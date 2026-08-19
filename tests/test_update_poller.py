import io

from brumby.update_poller import UpdateItem, parse_updates_xml, poll_updates


def _xml(*items: tuple[str, str]) -> str:
    inner = "".join(
        f"<item><title>{title}</title><link>{link}</link></item>"
        for title, link in items
    )
    return f"<?xml version='1.0'?><rss><channel>{inner}</channel></rss>"


def test_parse_updates_xml_extracts_project_and_version_from_release_link() -> None:
    items = parse_updates_xml(_xml(("demo 1.2.3", "https://pypi.org/project/demo/1.2.3/")))

    assert items == [UpdateItem("demo", "1.2.3")]


def test_parse_updates_xml_falls_back_to_title_when_link_is_unversioned() -> None:
    items = parse_updates_xml(_xml(("demo 1.2.3", "https://pypi.org/project/demo/")))

    assert items == [UpdateItem("demo", "1.2.3")]


def test_poll_updates_with_version_reports_new_versions_of_seen_projects() -> None:
    # With --with-version, "already seen" is keyed on (project, version), so a
    # project releasing again is reported even though its name was seen before.
    snapshots = iter(
        [
            [UpdateItem("demo", "1.0"), UpdateItem("alpha", "2.0")],
            [UpdateItem("demo", "1.1"), UpdateItem("beta", "3.0")],
            [UpdateItem("beta", "3.1"), UpdateItem("gamma", "4.0")],
        ]
    )
    stream = io.StringIO()
    flushes = []

    class _Stream:
        def write(self, text: str) -> int:
            return stream.write(text)

        def flush(self) -> None:
            flushes.append("flush")

    emitted = poll_updates(
        fetcher=lambda: next(snapshots),
        sleeper=lambda seconds: None,
        iterations=3,
        stream=_Stream(),
        with_version=True,
    )

    assert emitted == 4
    assert stream.getvalue() == "demo==1.1\nbeta==3.0\nbeta==3.1\ngamma==4.0\n"
    assert flushes == ["flush", "flush"]


def test_poll_updates_without_version_can_reprint_a_project_name() -> None:
    # Dedup is always keyed on (project, version), even when --with-version
    # isn't passed and the version doesn't appear in the output. So a project
    # that ships again between polls prints its bare name a second time.
    snapshots = iter(
        [
            [UpdateItem("demo", "1.0"), UpdateItem("alpha", "2.0")],
            [UpdateItem("demo", "1.1"), UpdateItem("beta", "3.0")],
        ]
    )
    stream = io.StringIO()

    class _Stream:
        def write(self, text: str) -> int:
            return stream.write(text)

        def flush(self) -> None:
            pass

    emitted = poll_updates(
        fetcher=lambda: next(snapshots),
        sleeper=lambda seconds: None,
        iterations=2,
        stream=_Stream(),
        with_version=False,
    )

    assert emitted == 2
    assert stream.getvalue() == "demo\nbeta\n"

def test_poll_updates_can_include_first_snapshot() -> None:
    snapshots = iter(
        [
            [UpdateItem("demo", "1.0"), UpdateItem("alpha", "2.0")],
            [UpdateItem("demo", "1.1"), UpdateItem("beta", "3.0")],
        ]
    )
    stream = io.StringIO()
    flushes = []

    class _Stream:
        def write(self, text: str) -> int:
            return stream.write(text)

        def flush(self) -> None:
            flushes.append("flush")

    emitted = poll_updates(
        fetcher=lambda: next(snapshots),
        sleeper=lambda seconds: None,
        iterations=2,
        stream=_Stream(),
        with_version=True,
        include_first=True,
    )

    assert emitted == 4
    assert stream.getvalue() == "demo==1.0\nalpha==2.0\ndemo==1.1\nbeta==3.0\n"
    assert flushes == ["flush", "flush"]
