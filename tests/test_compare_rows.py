from brumby.compare import compare_releases
from brumby.finding import Finding


def test_compare_rows_are_keyed_by_name_and_resource() -> None:
    rows = []

    def cb(
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
    ):
        rows.append((name, resource, old_vals, new_vals, old_sources, new_sources, kind))

    compare_releases(
        "pkg",
        "1.0",
        [Finding("foo", "x", "old.whl", "sdist-format=tar.gz")],
        "2.0",
        [Finding("foo", "x", "new.zip", "sdist-format=zip")],
        cb,
    )

    assert rows == [
        (
            "foo",
            "sdist-format=tar.gz",
            frozenset({"x"}),
            frozenset(),
            frozenset({"old.whl"}),
            frozenset(),
            "informational",
        ),
        (
            "foo",
            "sdist-format=zip",
            frozenset(),
            frozenset({"x"}),
            frozenset(),
            frozenset({"new.zip"}),
            "informational",
        ),
    ]


def test_compare_rows_keep_same_resource_together() -> None:
    rows = []

    def cb(
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
    ):
        rows.append((name, resource, old_vals, new_vals, old_sources, new_sources, kind))

    compare_releases(
        "pkg",
        "1.0",
        [Finding("foo", "x", "same.whl", "sdist-format=zip")],
        "2.0",
        [Finding("foo", "y", "same.whl", "sdist-format=zip")],
        cb,
    )

    assert rows == [
        (
            "foo",
            "sdist-format=zip",
            frozenset({"x"}),
            frozenset({"y"}),
            frozenset({"same.whl"}),
            frozenset({"same.whl"}),
            "informational",
        ),
    ]
