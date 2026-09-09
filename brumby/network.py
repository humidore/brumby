"""Optional per-purpose HTTP proxy and URL rewriting for outbound requests.

brumby makes two kinds of outbound HTTP calls with different trust/latency
profiles: small PyPI JSON metadata lookups, and (often large) artifact
downloads. Some environments need to route one or both through a proxy, or
rewrite the URL first (e.g. a local mirror, or forcing plain HTTP through a
non-TLS mock proxy) -- configured separately per purpose via brumby.toml's
[network.metadata] / [network.artifacts] tables. Both default to no proxy
and no rewriting, matching plain unproxied internet access.
"""

from typing import Literal
import keke

Purpose = Literal["metadata", "artifacts"]

_SETTINGS: dict[Purpose, dict] = {
    "metadata": {"proxy": None, "url_replace": {}},
    "artifacts": {"proxy": None, "url_replace": {}},
}


def configure(config: dict) -> None:
    """Load [network.metadata] / [network.artifacts] from a loaded brumby.toml config."""
    network = config.get("network", {})
    for purpose in ("metadata", "artifacts"):
        section = network.get(purpose, {})
        _SETTINGS[purpose] = {
            "proxy": section.get("proxy") or None,
            "url_replace": section.get("url_replace", {}),
        }

@keke.ktrace("url")
def prepare_request(purpose: Purpose, url: str) -> tuple[str, dict[str, str] | None]:
    """Return (url, proxies) for a request of the given purpose.

    url_replace entries are applied in config order, each a plain substring
    replacement (not a regex). proxies is a requests-style dict, or None
    when no proxy is configured for this purpose.
    """
    settings = _SETTINGS[purpose]
    for search, replace in settings["url_replace"].items():
        url = url.replace(search, replace)
    proxy = settings["proxy"]
    proxies = {"http": proxy, "https": proxy} if proxy else None
    return url, proxies
