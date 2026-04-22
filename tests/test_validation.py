from tools.validation import domain_variants, parse_indicator, parse_url_for_features


def test_parse_indicator_url_and_domain() -> None:
    url = parse_indicator("https://www.Example.com/login?x=1#frag")
    assert url is not None
    assert url.url == "https://www.example.com/login?x=1"
    assert url.host == "www.example.com"
    assert url.is_ip is False

    domain = parse_indicator("Example.COM.")
    assert domain is not None
    assert domain.url is None
    assert domain.host == "example.com"


def test_parse_indicator_rejects_unsafe_inputs() -> None:
    for raw in [
        "http://127.0.0.1/",
        "http://localhost/",
        "ftp://example.com/",
        "http://user@example.com/",
        "not a url",
    ]:
        assert parse_indicator(raw) is None


def test_domain_variants() -> None:
    assert domain_variants("example.com") == ["example.com", "www.example.com"]
    assert domain_variants("www.example.com") == ["www.example.com", "example.com"]
    assert domain_variants("8.8.8.8") == ["8.8.8.8"]


def test_parse_url_for_features_allows_private_ip_and_userinfo() -> None:
    parsed = parse_url_for_features("http://user:pass@192.168.1.1:8080/a?b=1")

    assert parsed is not None
    assert parsed.host == "192.168.1.1"
    assert parsed.is_ip is True
    assert parsed.is_private_ip is True
    assert parsed.has_userinfo is True
    assert parsed.port == 8080
    assert parsed.path == "/a"
    assert parsed.query == "b=1"


def test_parse_url_for_features_domain_only_and_idna() -> None:
    parsed = parse_url_for_features("bücher.example")

    assert parsed is not None
    assert parsed.host == "xn--bcher-kva.example"
    assert parsed.scheme == "http"


def test_parse_url_for_features_rejects_invalid() -> None:
    for raw in ["ftp://example.com/", "http://", "not a url", "http://example.com/a b"]:
        assert parse_url_for_features(raw) is None
