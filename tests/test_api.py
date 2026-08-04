from fastapi.testclient import TestClient

import api.main as api_main
from agent.schemas import TriageResult, Verdict


def fake_result(indicator: str) -> TriageResult:
    return TriageResult(
        run_id="test-run",
        input=indicator,
        verdict=Verdict(
            severity="info",
            confidence=0.9,
            reasoning="Benign evidence.",
            evidence=[],
            recommended_action="Close as benign.",
            status="auto_closed",
            classification="benign",
        ),
        tools_called=[],
        policy_escalations=[],
        latency_ms=10.0,
        model="test-model",
    )


def test_healthz_and_cloud_run_alias() -> None:
    client = TestClient(api_main.app)

    for path in ("/healthz", "/health"):
        response = client.get(path)
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


def test_readyz_ok(monkeypatch) -> None:
    monkeypatch.setattr(
        api_main,
        "_cached_readiness",
        lambda: (True, {"config": "ok", "bigquery": "ok"}),
    )
    client = TestClient(api_main.app)

    for path in ("/readyz", "/ready"):
        response = client.get(path)
        assert response.status_code == 200
        assert response.json()["status"] == "ready"


def test_readyz_not_ready(monkeypatch) -> None:
    monkeypatch.setattr(
        api_main,
        "_cached_readiness",
        lambda: (False, {"error": "no credentials"}),
    )
    client = TestClient(api_main.app)

    response = client.get("/readyz")

    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"


def test_triage_endpoint(monkeypatch) -> None:
    async def fake_triage(indicator: str) -> TriageResult:
        return fake_result(indicator)

    monkeypatch.setattr(api_main, "triage", fake_triage)
    client = TestClient(api_main.app)

    response = client.post("/triage", json={"indicator": "https://example.com/"})

    assert response.status_code == 200
    body = response.json()
    assert body["run_id"] == "test-run"
    assert body["verdict"]["status"] == "auto_closed"
    assert body["verdict"]["classification"] == "benign"


def test_triage_rejects_empty_input() -> None:
    client = TestClient(api_main.app)

    response = client.post("/triage", json={"indicator": ""})

    assert response.status_code == 422


def test_triage_returns_503_on_unexpected_error(monkeypatch) -> None:
    async def broken_triage(indicator: str) -> TriageResult:
        raise RuntimeError("boom")

    monkeypatch.setattr(api_main, "triage", broken_triage)
    client = TestClient(api_main.app)

    response = client.post("/triage", json={"indicator": "https://example.com/"})

    assert response.status_code == 503


def test_frontend_is_served() -> None:
    client = TestClient(api_main.app)

    page = client.get("/ui/")
    assert page.status_code == 200
    assert "Sentinel Triage" in page.text
    assert "app.js" in page.text

    script = client.get("/ui/app.js")
    assert script.status_code == 200
    assert "javascript" in script.headers["content-type"]

    root = client.get("/", follow_redirects=False)
    assert root.status_code in {307, 308}
    assert root.headers["location"] == "/ui/"
