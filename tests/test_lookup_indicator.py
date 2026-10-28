from datetime import date

import tools.lookup_indicator as lookup_module
from tools.lookup_indicator import lookup_indicator


class FakeJob:
    def __init__(self, rows: list[dict]) -> None:
        self._rows = rows

    def result(self) -> list[dict]:
        return self._rows


class FakeClient:
    project = "test-project"

    def __init__(self, rows: list[dict] | None = None, error: Exception | None = None) -> None:
        self.rows = rows or []
        self.error = error
        self.calls: list[tuple[str, object]] = []

    def query(self, sql: str, job_config: object = None) -> FakeJob:
        self.calls.append((sql, job_config))
        if self.error is not None:
            raise self.error
        return FakeJob(self.rows)


def test_lookup_ok_is_parameterized_and_detects_conflict(monkeypatch) -> None:
    rows = [
        {
            "url": "https://www.example.com/login",
            "domain": "www.example.com",
            "label": "malicious",
            "threat_type": "phishing",
            "first_seen": date(2026, 1, 2),
            "source": "openphish",
        },
        {
            "url": None,
            "domain": "example.com",
            "label": "benign",
            "threat_type": None,
            "first_seen": None,
            "source": "tranco",
        },
    ]
    fake = FakeClient(rows=rows)
    monkeypatch.setattr(lookup_module, "get_client", lambda: fake)
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "test-project")

    result = lookup_indicator("https://www.Example.com/login")

    assert result["status"] == "ok"
    assert result["sightings"] == 2
    assert result["malicious_count"] == 1
    assert result["benign_count"] == 1
    assert result["has_conflicting_labels"] is True
    assert result["matches"][0]["first_seen"] == "2026-01-02"

    sql, job_config = fake.calls[0]
    assert "test-project.triage.indicators" in sql
    assert "@domains" in sql
    assert "@url" in sql
    assert "www.example.com" not in sql

    params = {parameter.name: parameter for parameter in job_config.query_parameters}
    assert params["domains"].values == ["www.example.com", "example.com"]
    assert params["url"].value == "https://www.example.com/login"


def test_lookup_domain_only_uses_null_url(monkeypatch) -> None:
    fake = FakeClient(rows=[])
    monkeypatch.setattr(lookup_module, "get_client", lambda: fake)
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "test-project")

    result = lookup_indicator("example.com")

    assert result["status"] == "not_found"
    assert result["sightings"] == 0
    params = {parameter.name: parameter for parameter in fake.calls[0][1].query_parameters}
    assert params["url"].value is None
    assert params["domains"].values == ["example.com", "www.example.com"]


def test_lookup_unavailable_on_bigquery_error(monkeypatch) -> None:
    fake = FakeClient(error=RuntimeError("boom"))
    monkeypatch.setattr(lookup_module, "get_client", lambda: fake)
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "test-project")

    result = lookup_indicator("example.com")

    assert result["status"] == "unavailable"
    assert "RuntimeError" in result["error"]


def test_lookup_invalid_does_not_call_bigquery(monkeypatch) -> None:
    def fail() -> None:
        raise AssertionError("BigQuery should not be called for invalid input")

    monkeypatch.setattr(lookup_module, "get_client", fail)

    result = lookup_indicator("http://127.0.0.1/")

    assert result["status"] == "invalid"
    assert result["matches"] == []
