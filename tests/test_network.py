import pytest

from brumby import network


@pytest.fixture(autouse=True)
def _reset_network():
    network.configure({})
    yield
    network.configure({})


def test_prepare_request_defaults_to_no_proxy_no_rewrite():
    url, proxies = network.prepare_request("metadata", "https://pypi.org/pypi/foo/json")

    assert url == "https://pypi.org/pypi/foo/json"
    assert proxies is None


def test_configure_sets_proxy_per_purpose():
    network.configure(
        {
            "network": {
                "metadata": {"proxy": "http://127.0.0.1:8080"},
                "artifacts": {"proxy": "http://127.0.0.1:9090"},
            }
        }
    )

    _url, metadata_proxies = network.prepare_request("metadata", "https://pypi.org/pypi/foo/json")
    _url, artifact_proxies = network.prepare_request("artifacts", "https://files.pythonhosted.org/foo.whl")

    assert metadata_proxies == {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
    assert artifact_proxies == {"http": "http://127.0.0.1:9090", "https": "http://127.0.0.1:9090"}


def test_configure_purposes_are_independent():
    network.configure({"network": {"artifacts": {"proxy": "http://127.0.0.1:9090"}}})

    _url, metadata_proxies = network.prepare_request("metadata", "https://pypi.org/pypi/foo/json")

    assert metadata_proxies is None


def test_url_replace_applies_plain_substring_rewrite():
    network.configure(
        {"network": {"artifacts": {"url_replace": {"https://": "http://"}}}}
    )

    url, _proxies = network.prepare_request("artifacts", "https://files.pythonhosted.org/foo.whl")

    assert url == "http://files.pythonhosted.org/foo.whl"


def test_empty_network_config_is_a_no_op():
    network.configure({})

    url, proxies = network.prepare_request("artifacts", "https://files.pythonhosted.org/foo.whl")

    assert url == "https://files.pythonhosted.org/foo.whl"
    assert proxies is None
