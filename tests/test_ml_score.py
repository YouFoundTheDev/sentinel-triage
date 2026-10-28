import tools.ml_score as ml_module
from tools.ml_score import ml_score


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


def test_ml_score_ok_and_parameterized(monkeypatch) -> None:
    fake = FakeClient(
        rows=[
            {
                "predicted_label": "malicious",
                "malicious_probability": 0.91,
                "benign_probability": 0.09,
            }
        ]
    )
    monkeypatch.setattr(ml_module, "get_client", lambda: fake)
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "test-project")

    result = ml_score("https://example.com/")

    assert result["status"] == "ok"
    assert result["predicted_label"] == "malicious"
    assert result["malicious_probability"] == 0.91
    assert result["benign_probability"] == 0.09

    sql, job_config = fake.calls[0]
    assert "ML.PREDICT" in sql
    assert "test-project.triage.url_classifier" in sql
    parameter_names = {parameter.name for parameter in job_config.query_parameters}
    assert "url_length" in parameter_names
    assert "suspicious_keyword_count" in parameter_names
    assert len(parameter_names) == 22


def test_ml_score_invalid_input_does_not_call_bigquery(monkeypatch) -> None:
    def fail() -> None:
        raise AssertionError("BigQuery should not be called")

    monkeypatch.setattr(ml_module, "get_client", fail)

    result = ml_score("ftp://example.com/")

    assert result["status"] == "invalid"


def test_ml_score_unavailable_on_bigquery_error(monkeypatch) -> None:
    fake = FakeClient(error=RuntimeError("model missing"))
    monkeypatch.setattr(ml_module, "get_client", lambda: fake)
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "test-project")

    result = ml_score("https://example.com/")

    assert result["status"] == "unavailable"
    assert "RuntimeError" in result["error"]
