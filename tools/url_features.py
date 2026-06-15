"""Pure URL feature extraction. No DNS or network access."""

from __future__ import annotations

import math
from collections import Counter
from typing import Literal
from urllib.parse import parse_qsl

import tldextract
from pydantic import BaseModel, Field

from tools.schemas import ToolResult
from tools.validation import parse_url_for_features

_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

_SUSPICIOUS_TLDS = frozenset(
    {
        "zip",
        "mov",
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "xyz",
        "top",
        "click",
        "work",
        "fit",
        "cam",
        "buzz",
        "rest",
        "monster",
        "quest",
        "cfd",
        "sbs",
        "icu",
        "cyou",
        "wang",
        "loan",
        "review",
        "date",
        "men",
        "stream",
        "download",
        "racing",
        "win",
        "bid",
        "trade",
        "party",
        "science",
        "faith",
        "accountant",
        "cricket",
        "webcam",
        "ren",
        "mom",
        "lol",
        "pics",
        "sexy",
        "gift",
    }
)

_SUSPICIOUS_KEYWORDS = frozenset(
    {
        "account",
        "apple",
        "bank",
        "confirm",
        "google",
        "invoice",
        "login",
        "microsoft",
        "password",
        "paypal",
        "secure",
        "signin",
        "update",
        "verify",
        "wallet",
    }
)


class UrlFeatures(BaseModel):
    url_length: int
    hostname_length: int
    path_length: int
    query_length: int
    num_dots: int
    num_hyphens: int
    num_underscores: int
    num_digits: int
    digit_ratio: float
    num_subdomains: int
    tld: str
    registered_domain: str | None
    suspicious_tld: bool
    has_ip_host: bool
    is_private_ip_host: bool
    is_https: bool
    has_userinfo: bool
    has_punycode: bool
    has_encoded_chars: bool
    num_query_params: int
    num_path_segments: int
    hostname_entropy: float
    url_entropy: float
    suspicious_keywords: list[str] = Field(default_factory=list)


class ExtractUrlFeaturesResult(ToolResult):
    tool: Literal["extract_url_features"] = "extract_url_features"
    host: str = ""
    features: UrlFeatures | None = None


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def extract_url_features(url: str) -> dict:
    """Extract structural URL features for triage.

    Features include length, subdomain count, digit ratio, suspicious TLD,
    IP-literal host, punycode, query/path shape, and Shannon entropy. This is
    a local, deterministic function: it never performs DNS resolution, fetches,
    or connects to the URL.
    """
    parsed = parse_url_for_features(url)
    if parsed is None:
        return ExtractUrlFeaturesResult(
            status="invalid",
            summary="Invalid input: expected an http(s) URL or domain.",
            error="input failed URL validation",
        ).model_dump(mode="json")

    host = parsed.host
    if parsed.is_ip:
        subdomain_count = 0
        tld = ""
        registered_domain = None
    else:
        extracted = _TLD_EXTRACT(host)
        subdomain_count = len(extracted.subdomain.split(".")) if extracted.subdomain else 0
        tld = extracted.suffix.lower()
        registered_domain = (
            f"{extracted.domain}.{extracted.suffix}"
            if extracted.domain and extracted.suffix
            else None
        )

    normalized = parsed.normalized_url
    num_digits = sum(ch.isdigit() for ch in normalized)
    has_punycode = any(label.startswith("xn--") for label in host.split("."))
    features = UrlFeatures(
        url_length=len(normalized),
        hostname_length=len(host),
        path_length=len(parsed.path),
        query_length=len(parsed.query),
        num_dots=host.count("."),
        num_hyphens=host.count("-"),
        num_underscores=host.count("_"),
        num_digits=num_digits,
        digit_ratio=num_digits / len(normalized) if normalized else 0.0,
        num_subdomains=subdomain_count,
        tld=tld,
        registered_domain=registered_domain,
        suspicious_tld=tld in _SUSPICIOUS_TLDS,
        has_ip_host=parsed.is_ip,
        is_private_ip_host=parsed.is_private_ip,
        is_https=parsed.scheme == "https",
        has_userinfo=parsed.has_userinfo,
        has_punycode=has_punycode,
        has_encoded_chars="%" in normalized,
        num_query_params=len(parse_qsl(parsed.query, keep_blank_values=True)),
        num_path_segments=sum(1 for part in parsed.path.split("/") if part),
        hostname_entropy=_entropy(host),
        url_entropy=_entropy(normalized),
        suspicious_keywords=sorted(
            keyword for keyword in _SUSPICIOUS_KEYWORDS if keyword in normalized.lower()
        ),
    )
    summary = (
        f"URL length {features.url_length}, {features.num_subdomains} subdomain(s), "
        f"suspicious TLD={features.suspicious_tld}, IP host={features.has_ip_host}, "
        f"hostname entropy={features.hostname_entropy:.2f}."
    )
    return ExtractUrlFeaturesResult(
        status="ok",
        host=host,
        features=features,
        summary=summary,
    ).model_dump(mode="json")
