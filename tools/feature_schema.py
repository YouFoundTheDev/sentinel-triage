"""Shared URL feature column definitions for BigQuery and the ML tool."""

from __future__ import annotations

from typing import Any

INT_FEATURES = (
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_digits",
    "num_subdomains",
    "suspicious_tld",
    "has_ip_host",
    "is_private_ip_host",
    "is_https",
    "has_userinfo",
    "has_punycode",
    "has_encoded_chars",
    "num_query_params",
    "num_path_segments",
    "suspicious_keyword_count",
)

FLOAT_FEATURES = (
    "digit_ratio",
    "hostname_entropy",
    "url_entropy",
)

FEATURE_COLUMNS = (*INT_FEATURES, *FLOAT_FEATURES)


def bq_type(column: str) -> str:
    """Return the BigQuery parameter/column type for a feature."""
    if column in INT_FEATURES:
        return "INT64"
    if column in FLOAT_FEATURES:
        return "FLOAT64"
    raise KeyError(f"unknown feature column: {column}")


def feature_values(features: dict[str, Any]) -> dict[str, int | float]:
    """Convert extracted URL features into BQML-ready numeric values."""
    values: dict[str, int | float] = {}
    for column in INT_FEATURES:
        if column == "suspicious_keyword_count":
            values[column] = len(features.get("suspicious_keywords") or [])
        else:
            value = features[column]
            values[column] = int(value)
    for column in FLOAT_FEATURES:
        values[column] = float(features[column])
    return values
