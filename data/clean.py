"""Pure cleaning and normalization helpers for indicator data."""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from collections.abc import Iterable
from datetime import date
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict

Label = Literal["malicious", "benign"]

_ALLOWED_SCHEMES = {"http", "https"}
_DEFAULT_PORTS = {"http": 80, "https": 443}
_BLOCKED_HOSTS = {"localhost", "metadata.google.internal"}
_BLOCKED_SUFFIXES = (".local", ".internal", ".home.arpa", ".localhost")
_HOST_LABEL = re.compile(r"[a-z0-9-]+")
_MAX_URL_LENGTH = 4096


class Indicator(BaseModel):
    """One row in the ``triage.indicators`` table."""

    model_config = ConfigDict(frozen=True)

    url: str | None = None
    domain: str
    label: Label
    threat_type: str | None = None
    first_seen: date | None = None
    source: str

    def to_bq_row(self) -> dict[str, str | None]:
        """Return a JSON-serializable BigQuery row."""
        return {
            "url": self.url,
            "domain": self.domain,
            "label": self.label,
            "threat_type": self.threat_type,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "source": self.source,
        }


class ParseResult(BaseModel):
    """Rows accepted and rejected while parsing one raw feed."""

    indicators: list[Indicator]
    input_rows: int
    rejected: int


class CleanStats(BaseModel):
    """Counters for one cleaning run."""

    input_rows: int
    parsed: int
    rejected: int
    duplicates: int
    capped: int
    final: int
    malicious: int
    benign: int


class CleanResult(BaseModel):
    """Cleaned indicators plus run statistics."""

    indicators: list[Indicator]
    stats: CleanStats


def _normalize_host(raw_host: str | None) -> str | None:
    if not raw_host:
        return None

    host = raw_host.strip().rstrip(".").lower()
    if not host:
        return None

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        return ip.compressed if ip.is_global else None

    if host in _BLOCKED_HOSTS or host.endswith(_BLOCKED_SUFFIXES):
        return None

    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    if len(ascii_host) > 253:
        return None
    labels = ascii_host.split(".")
    if len(labels) < 2:
        return None
    for label in labels:
        if not label or len(label) > 63:
            return None
        if label.startswith("-") or label.endswith("-"):
            return None
        if _HOST_LABEL.fullmatch(label) is None:
            return None
    return ascii_host


def normalize_url(raw: str) -> str | None:
    """Normalize an http(s) URL or return ``None`` if it is not safe or valid.

    Fragments are dropped, the host is lowercased and IDNA-encoded, default
    ports are removed, and private/internal hosts are rejected. No network I/O
    is performed.
    """
    value = raw.strip()
    if not value or len(value) > _MAX_URL_LENGTH:
        return None
    if any(ch.isspace() or ord(ch) < 32 for ch in value) or "\\" in value:
        return None

    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        if scheme not in _ALLOWED_SCHEMES:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        host = _normalize_host(parsed.hostname)
        if host is None:
            return None
        port = parsed.port
    except ValueError:
        return None

    netloc = f"[{host}]" if ":" in host else host
    if port is not None and port != _DEFAULT_PORTS[scheme]:
        netloc = f"{netloc}:{port}"

    normalized = urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, ""))
    if len(normalized) > _MAX_URL_LENGTH:
        return None
    return normalized


def normalize_domain(raw: str) -> str | None:
    """Normalize a domain or URL to an ASCII hostname, without network I/O."""
    value = raw.strip()
    if not value or any(ch.isspace() for ch in value):
        return None
    if "://" in value:
        normalized_url = normalize_url(value)
        if normalized_url is None:
            return None
        return urlsplit(normalized_url).hostname
    if any(ch in value for ch in "/?#@"):
        return None
    try:
        parsed = urlsplit(f"//{value}")
        _ = parsed.port
        return _normalize_host(parsed.hostname)
    except ValueError:
        return None


def domain_from_url(url: str) -> str:
    """Extract the normalized hostname from an already-normalized URL."""
    host = urlsplit(url).hostname
    if host is None:
        raise ValueError(f"URL has no host: {url}")
    return host


def parse_openphish(text: str) -> ParseResult:
    """Parse the public OpenPhish feed, which contains one URL per line."""
    indicators: list[Indicator] = []
    input_rows = 0
    rejected = 0

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        input_rows += 1
        normalized_url = normalize_url(line)
        if normalized_url is None:
            rejected += 1
            continue
        indicators.append(
            Indicator(
                url=normalized_url,
                domain=domain_from_url(normalized_url),
                label="malicious",
                threat_type="phishing",
                first_seen=None,
                source="openphish",
            )
        )

    return ParseResult(indicators=indicators, input_rows=input_rows, rejected=rejected)


def parse_tranco(text: str, *, max_rows: int = 5000) -> ParseResult:
    """Parse a Tranco ``rank,domain`` CSV, keeping at most ``max_rows`` rows."""
    indicators: list[Indicator] = []
    input_rows = 0
    rejected = 0

    for row in csv.reader(io.StringIO(text)):
        if len(row) < 2:
            continue
        rank = row[0].strip()
        if not rank.isdigit():
            continue
        input_rows += 1
        domain = normalize_domain(row[1])
        if domain is None:
            rejected += 1
            continue
        indicators.append(Indicator(domain=domain, label="benign", source="tranco"))
        if len(indicators) >= max_rows:
            break

    return ParseResult(indicators=indicators, input_rows=input_rows, rejected=rejected)


def dedupe_indicators(indicators: Iterable[Indicator]) -> tuple[list[Indicator], int]:
    """Remove exact duplicate rows while preserving cross-label conflicts."""
    seen: set[tuple[str | None, str, str, str]] = set()
    unique: list[Indicator] = []
    duplicates = 0
    for indicator in indicators:
        key = (indicator.url, indicator.domain, indicator.label, indicator.source)
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        unique.append(indicator)
    return unique, duplicates


def clean_all(
    openphish_text: str,
    tranco_text: str,
    *,
    max_malicious: int = 5000,
    max_benign: int = 5000,
) -> CleanResult:
    """Parse, deduplicate, and cap both feeds into one indicator set."""
    openphish = parse_openphish(openphish_text)
    tranco = parse_tranco(tranco_text, max_rows=max_benign)

    unique, duplicates = dedupe_indicators([*openphish.indicators, *tranco.indicators])
    malicious = [row for row in unique if row.label == "malicious"][:max_malicious]
    benign = [row for row in unique if row.label == "benign"][:max_benign]
    kept = sorted(
        [*malicious, *benign],
        key=lambda row: (row.label, row.source, row.domain, row.url or ""),
    )

    stats = CleanStats(
        input_rows=openphish.input_rows + tranco.input_rows,
        parsed=len(openphish.indicators) + len(tranco.indicators),
        rejected=openphish.rejected + tranco.rejected,
        duplicates=duplicates,
        capped=len(unique) - len(kept),
        final=len(kept),
        malicious=len(malicious),
        benign=len(benign),
    )
    return CleanResult(indicators=kept, stats=stats)


def write_ndjson(indicators: Iterable[Indicator], path: Path) -> int:
    """Write BigQuery newline-delimited JSON atomically and return the count."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f"{path.name}.tmp")
    count = 0
    with tmp_path.open("w", encoding="utf-8") as handle:
        for indicator in indicators:
            handle.write(
                json.dumps(
                    indicator.to_bq_row(),
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            )
            handle.write("\n")
            count += 1
    tmp_path.replace(path)
    return count
