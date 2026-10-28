from tools.url_features import extract_url_features


def test_extract_features_for_suspicious_url() -> None:
    result = extract_url_features("http://paypal-login.xyz/verify/account?next=1")

    assert result["status"] == "ok"
    assert result["host"] == "paypal-login.xyz"
    features = result["features"]
    assert features["tld"] == "xyz"
    assert features["suspicious_tld"] is True
    assert features["num_subdomains"] == 0
    assert features["num_query_params"] == 1
    assert features["num_path_segments"] == 2
    assert "paypal" in features["suspicious_keywords"]
    assert "login" in features["suspicious_keywords"]
    assert "verify" in features["suspicious_keywords"]
    assert "account" in features["suspicious_keywords"]


def test_extract_features_for_private_ip_host() -> None:
    result = extract_url_features("http://192.168.1.1/admin")

    assert result["status"] == "ok"
    features = result["features"]
    assert features["has_ip_host"] is True
    assert features["is_private_ip_host"] is True
    assert features["tld"] == ""
    assert features["registered_domain"] is None
    assert features["num_subdomains"] == 0


def test_extract_features_for_idn_and_punycode() -> None:
    result = extract_url_features("http://xn--bcher-kva.example/")

    assert result["status"] == "ok"
    assert result["features"]["has_punycode"] is True


def test_extract_features_for_co_uk_domain() -> None:
    result = extract_url_features("https://sub.example.co.uk/path")

    assert result["status"] == "ok"
    features = result["features"]
    assert features["tld"] == "co.uk"
    assert features["registered_domain"] == "example.co.uk"
    assert features["num_subdomains"] == 1
    assert features["is_https"] is True


def test_extract_features_counts_digits_and_entropy() -> None:
    result = extract_url_features("http://1234abcd.com/5678")

    assert result["status"] == "ok"
    features = result["features"]
    assert features["num_digits"] == 8
    assert features["digit_ratio"] > 0
    assert features["hostname_entropy"] > 0
    assert features["url_entropy"] > 0


def test_extract_features_domain_only() -> None:
    result = extract_url_features("example.com")

    assert result["status"] == "ok"
    assert result["host"] == "example.com"
    assert result["features"]["is_https"] is False
    assert result["features"]["tld"] == "com"


def test_extract_features_userinfo() -> None:
    result = extract_url_features("http://user:pass@example.com/")

    assert result["status"] == "ok"
    assert result["features"]["has_userinfo"] is True


def test_extract_features_invalid() -> None:
    assert extract_url_features("ftp://example.com/")["status"] == "invalid"
    assert extract_url_features("not a url")["status"] == "invalid"
