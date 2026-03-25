"""Input validation shared by tools. No DNS or network I/O."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel

from data.clean import normalize_domain, normalize_url

_HOST_LABEL = re.compile(r"[a-z0-9-]+")
_MAX_URL_LENGTH = 4096


class IndicatorInput(BaseModel):
    """A normalized URL or domain ready for a BigQuery lookup."""

    raw: str
    url: str | None = None
    host: str
    is_ip: bool


class UrlInput(BaseModel):
    """A parsed URL used only for local feature extraction."""

    normalized_url: str
    scheme: str
    host: str
    port: int | None = None
    path: str
    query: str
    is_ip: bool
    is_private_ip: bool
    has_userinfo: bool


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def parse_indicator(raw: str) -> IndicatorInput | None:
    """Parse a public URL or domain with the strict cleaning rules."""
    value = raw.strip()
    if not value or len(value) > _MAX_URL_LENGTH:
        return None
    if "://" in value:
        normalized = normalize_url(value)
        if normalized is None:
            return None
        host = urlsplit(normalized).hostname
        if host is None:
            return None
        return IndicatorInput(raw=value, url=normalized, host=host, is_ip=_is_ip(host))

    domain = normalize_domain(value)
    if domain is None:
        return None
    return IndicatorInput(raw=value, host=domain, is_ip=_is_ip(domain))


def domain_variants(host: str) -> list[str]:
    """Return the host plus its common www/non-www counterpart."""
    if _is_ip(host):
        return [host]
    if host.startswith("www."):
        return [host, host[4:]]
    return [host, f"www.{host}"]


def parse_url_for_features(raw: str) -> UrlInput | None:
    """Parse a URL for features without resolving or connecting to it.

    Unlike the strict lookup parser, this allows private IP hosts and URL
    userinfo so their presence can be reported as suspicious features.
    """
    value = raw.strip()
    if not value or len(value) > _MAX_URL_LENGTH:
        return None
    if any(ch.isspace() or ord(ch) < 32 for ch in value) or "\\" in value:
        return None
    if "://" not in value:
        value = f"http://{value}"

    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            return None
        host = parsed.hostname
        if not host:
            return None
        port = parsed.port
    except ValueError:
        return None

    host = host.strip().rstrip(".").lower()
    if not host:
        return None

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        normalized_host = ip.compressed
        is_private_ip = not ip.is_global
    else:
        try:
            normalized_host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
        labels = normalized_host.split(".")
        if any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or _HOST_LABEL.fullmatch(label) is None
            for label in labels
        ):
            return None
        is_private_ip = False

    has_userinfo = parsed.username is not None or parsed.password is not None
    userinfo = ""
    if has_userinfo:
        userinfo = parsed.username or ""
        if parsed.password is not None:
            userinfo = f"{userinfo}:{parsed.password}"
        userinfo = f"{userinfo}@"

    netloc = f"[{normalized_host}]" if ":" in normalized_host else normalized_host
    if port is not None:
        netloc = f"{netloc}:{port}"
    normalized = urlunsplit((scheme, f"{userinfo}{netloc}", parsed.path or "/", parsed.query, ""))
    return UrlInput(
        normalized_url=normalized,
        scheme=scheme,
        host=normalized_host,
        port=port,
        path=parsed.path or "/",
        query=parsed.query,
        is_ip=ip is not None,
        is_private_ip=is_private_ip,
        has_userinfo=has_userinfo,
    )
