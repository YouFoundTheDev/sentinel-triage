from data.build_features import feature_row, holdout_domains
from tools.feature_schema import FEATURE_COLUMNS, INT_FEATURES, feature_values
from tools.url_features import extract_url_features


def test_feature_row_is_flat_and_typed() -> None:
    row = feature_row(
        "https://paypal-login.xyz/verify",
        "paypal-login.xyz",
        "malicious",
        "test",
    )

    assert row is not None
    assert row["domain"] == "paypal-login.xyz"
    assert row["label"] == "malicious"
    assert set(FEATURE_COLUMNS).issubset(row)
    assert row["suspicious_tld"] == 1
    assert isinstance(row["digit_ratio"], float)
    assert row["suspicious_keyword_count"] >= 2


def test_feature_row_rejects_invalid_url() -> None:
    assert feature_row("ftp://example.com/", "example.com", "benign", "test") is None


def test_feature_values_cover_all_columns() -> None:
    result = extract_url_features("https://example.com/login")
    assert result["features"] is not None

    values = feature_values(result["features"])

    assert set(values) == set(FEATURE_COLUMNS)
    assert all(isinstance(values[column], int) for column in INT_FEATURES)


def test_holdout_contains_eval_domains() -> None:
    holdout = holdout_domains()

    assert "000-054343-info.weebly.com" in holdout
    assert "nyt.com" in holdout
