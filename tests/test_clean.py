import json
from datetime import date
from pathlib import Path

import pytest

from data.clean import (
    Indicator,
    clean_all,
    dedupe_indicators,
    normalize_domain,
    normalize_url,
    parse_openphish,
    parse_tranco,
    write_ndjson,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_normalize_url_canonicalizes() -> None:
    assert normalize_url("HTTP://Example.COM:80/a?b=1#frag") == "http://example.com/a?b=1"
    assert normalize_url("https://Example.COM:443/") == "https://example.com/"
    assert normalize_url("https://example.com:8443/x") == "https://example.com:8443/x"
    assert normalize_url("http://example.com") == "http://example.com/"
    assert normalize_url("http://example.com./") == "http://example.com/"
    assert normalize_url("http://example.com?x=1") == "http://example.com/?x=1"


def test_normalize_url_handles_idna_and_public_ips() -> None:
    assert normalize_url("https://bücher.example/") == "https://xn--bcher-kva.example/"
    assert normalize_url("http://8.8.8.8/x") == "http://8.8.8.8/x"
    assert normalize_url("http://[2606:4700:4700::1111]/x") == "http://[2606:4700:4700::1111]/x"


@pytest.mark.parametrize(
    "raw",
    [
        "ftp://example.com/x",
        "javascript:alert(1)",
        "http://user:pass@example.com/",
        "http://localhost/",
        "http://127.0.0.1/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://example.local/",
        "http://metadata.google.internal/",
        "http://example.com:bad/",
        "http://",
        "not a url",
        "http://example.com/a b",
        "http://-bad.example/",
        "http://bad..example/",
        "http://foo_bar.example/",
        "http://example.com\\@evil.example/",
    ],
)
def test_normalize_url_rejects_invalid(raw: str) -> None:
    assert normalize_url(raw) is None


def test_normalize_domain() -> None:
    assert normalize_domain("Example.COM.") == "example.com"
    assert normalize_domain("www.Example.com") == "www.example.com"
    assert normalize_domain("https://Example.com/path?x=1") == "example.com"
    assert normalize_domain("example.com:8443") == "example.com"
    assert normalize_domain("example.com/path") is None
    assert normalize_domain("http://127.0.0.1/") is None
    assert normalize_domain("not a domain") is None
    assert normalize_domain("example.com?x=1") is None


def test_parse_openphish() -> None:
    text = (FIXTURES / "openphish_sample.txt").read_text(encoding="utf-8")
    result = parse_openphish(text)

    assert result.input_rows == 5
    assert result.rejected == 2
    assert len(result.indicators) == 3

    first = result.indicators[0]
    assert first.url == "https://a.example/login"
    assert first.domain == "a.example"
    assert first.label == "malicious"
    assert first.threat_type == "phishing"
    assert first.first_seen is None
    assert first.source == "openphish"

    assert result.indicators[1].url == "http://b.example/x?y=1"


def test_parse_tranco() -> None:
    text = (FIXTURES / "tranco_sample.csv").read_text(encoding="utf-8")
    result = parse_tranco(text)

    assert result.input_rows == 5
    assert result.rejected == 2
    assert [row.domain for row in result.indicators] == [
        "example.com",
        "www.example.org",
        "example.com",
    ]
    assert all(row.label == "benign" for row in result.indicators)
    assert all(row.url is None for row in result.indicators)

    limited = parse_tranco(text, max_rows=2)
    assert len(limited.indicators) == 2
    assert limited.input_rows == 2
    assert limited.rejected == 0


def test_clean_all_counts_and_deduplicates() -> None:
    openphish = (FIXTURES / "openphish_sample.txt").read_text(encoding="utf-8")
    tranco = (FIXTURES / "tranco_sample.csv").read_text(encoding="utf-8")
    result = clean_all(openphish, tranco)

    assert result.stats.input_rows == 10
    assert result.stats.parsed == 6
    assert result.stats.rejected == 4
    assert result.stats.duplicates == 2
    assert result.stats.capped == 0
    assert result.stats.final == 4
    assert result.stats.malicious == 2
    assert result.stats.benign == 2
    assert [row.label for row in result.indicators].count("malicious") == 2


def test_clean_all_keeps_cross_label_conflicts() -> None:
    result = clean_all(
        "https://shared.example/evil\n",
        "1,shared.example\n",
    )

    domains = [row.domain for row in result.indicators]
    labels = {row.domain: row.label for row in result.indicators}
    assert domains.count("shared.example") == 2
    assert labels["shared.example"] in {"malicious", "benign"}
    assert {row.label for row in result.indicators} == {"malicious", "benign"}


def test_clean_all_caps_each_label() -> None:
    result = clean_all(
        "https://a.example/1\nhttps://b.example/2\n",
        "1,c.example\n2,d.example\n",
        max_malicious=1,
        max_benign=1,
    )

    assert result.stats.final == 2
    assert result.stats.capped == 1
    assert result.stats.malicious == 1
    assert result.stats.benign == 1


def test_dedupe_indicators_keeps_conflicts() -> None:
    rows = [
        Indicator(domain="example.com", label="benign", source="tranco"),
        Indicator(domain="example.com", label="malicious", source="openphish"),
        Indicator(domain="example.com", label="benign", source="tranco"),
    ]
    unique, duplicates = dedupe_indicators(rows)

    assert len(unique) == 2
    assert duplicates == 1


def test_to_bq_row_serializes_date() -> None:
    indicator = Indicator(
        domain="example.com",
        label="benign",
        first_seen=date(2026, 1, 2),
        source="test",
    )
    row = indicator.to_bq_row()

    assert row["first_seen"] == "2026-01-02"
    assert row["url"] is None
    assert row["label"] == "benign"


def test_write_ndjson(tmp_path: Path) -> None:
    indicators = [
        Indicator(domain="a.example", label="malicious", source="openphish"),
        Indicator(domain="b.example", label="benign", source="tranco"),
    ]
    path = tmp_path / "indicators.jsonl"

    assert write_ndjson(indicators, path) == 2
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["domain"] == "a.example"
    assert json.loads(lines[1])["label"] == "benign"
