from datetime import date

import dns.exception
import dns.resolver
import httpx

import tools.enrich_domain as enrich_module
from tools.enrich_domain import (
    DnsLookup,
    RdapLookup,
    _fetch_rdap,
    _is_safe_rdap_url,
    _parse_rdap,
    _resolve_dns,
    enrich_domain,
)


class FakeA:
    def __init__(self, value: str) -> None:
        self.value = value

    def __str__(self) -> str:
        return self.value


class FakeMx:
    def __init__(self, exchange: str) -> None:
        self.exchange = exchange


class FakeNs:
    def __init__(self, target: str) -> None:
        self.target = target


class FakeResolver:
    def __init__(self, responses: dict | None = None) -> None:
        self.responses = responses or {"A": [FakeA("93.184.216.34")]}

    def resolve(self, name: str, rtype: str):
        value = self.responses.get(rtype)
        if isinstance(value, Exception):
            raise value
        if value is None:
            raise dns.resolver.NoAnswer()
        return value


RDAP_PAYLOAD = {
    "events": [{"eventAction": "registration", "eventDate": "2010-01-01T00:00:00Z"}],
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
        }
    ],
    "nameservers": [{"ldhName": "NS1.EXAMPLE.COM."}],
    "status": ["client transfer prohibited"],
}


def test_resolve_dns_ok() -> None:
    resolver = FakeResolver(
        {
            "A": [FakeA("93.184.216.34")],
            "MX": [FakeMx("mx.example.com.")],
            "NS": [FakeNs("ns1.example.com.")],
        }
    )

    result = _resolve_dns("example.com", resolver)

    assert result.status == "ok"
    assert result.a == ["93.184.216.34"]
    assert result.mx == ["mx.example.com"]
    assert result.ns == ["ns1.example.com"]


def test_resolve_dns_no_answer_is_ok() -> None:
    resolver = FakeResolver({"A": [FakeA("93.184.216.34")]})

    result = _resolve_dns("example.com", resolver)

    assert result.status == "ok"
    assert result.mx == []
    assert result.ns == []


def test_resolve_dns_partial_on_one_timeout() -> None:
    resolver = FakeResolver(
        {
            "A": dns.exception.Timeout(),
            "MX": [FakeMx("mx.example.com.")],
            "NS": None,
        }
    )

    result = _resolve_dns("example.com", resolver)

    assert result.status == "partial"
    assert result.errors == ["A: timeout"]


def test_resolve_dns_unavailable_when_all_fail() -> None:
    resolver = FakeResolver(
        {
            "A": dns.exception.Timeout(),
            "MX": dns.exception.Timeout(),
            "NS": dns.exception.Timeout(),
        }
    )

    result = _resolve_dns("example.com", resolver)

    assert result.status == "unavailable"
    assert len(result.errors) == 3


def test_resolve_dns_nxdomain() -> None:
    resolver = FakeResolver({"A": dns.resolver.NXDOMAIN()})

    result = _resolve_dns("missing.example", resolver)

    assert result.status == "nxdomain"
    assert result.errors == ["A: NXDOMAIN"]


def test_parse_rdap_registration() -> None:
    result = _parse_rdap(RDAP_PAYLOAD, rdap_url="https://rdap.example/domain/example.com")

    assert result.status == "ok"
    assert result.registrar == "Example Registrar"
    assert result.registered == date(2010, 1, 1)
    assert result.age_days is not None and result.age_days > 0
    assert result.nameservers == ["ns1.example.com"]
    assert result.domain_statuses == ["client transfer prohibited"]


def test_parse_rdap_missing_registration_is_partial() -> None:
    result = _parse_rdap({}, rdap_url="https://rdap.example/domain/example.com")

    assert result.status == "partial"
    assert result.registered is None
    assert "registration" in (result.error or "")


def test_is_safe_rdap_url() -> None:
    assert not _is_safe_rdap_url("http://rdap.org/domain/example.com")
    assert not _is_safe_rdap_url("https://127.0.0.1/domain/example.com")
    assert not _is_safe_rdap_url("https://localhost/domain/example.com")
    assert not _is_safe_rdap_url("https://user@rdap.org/domain/example.com")
    assert _is_safe_rdap_url(
        "https://rdap.org/domain/example.com",
        resolver=FakeResolver(),
    )
    assert not _is_safe_rdap_url(
        "https://rdap.org/domain/example.com",
        resolver=FakeResolver({"A": [FakeA("10.0.0.1")]}),
    )


def test_fetch_rdap_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "rdap.org"
        return httpx.Response(200, json=RDAP_PAYLOAD)

    client = httpx.Client(transport=httpx.MockTransport(handler), timeout=1.0)
    try:
        result = _fetch_rdap("example.com", client=client, resolver=FakeResolver())
    finally:
        client.close()

    assert result.status == "ok"
    assert result.registrar == "Example Registrar"
    assert result.rdap_url == "https://rdap.org/domain/example.com"


def test_fetch_rdap_404_is_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler), timeout=1.0)
    try:
        result = _fetch_rdap("example.com", client=client, resolver=FakeResolver())
    finally:
        client.close()

    assert result.status == "unavailable"
    assert "404" in (result.error or "")


def test_fetch_rdap_follows_safe_redirect() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "rdap.org":
            return httpx.Response(
                302,
                headers={"Location": "https://rdap.example/domain/example.com"},
            )
        return httpx.Response(200, json=RDAP_PAYLOAD)

    client = httpx.Client(transport=httpx.MockTransport(handler), timeout=1.0)
    try:
        result = _fetch_rdap("example.com", client=client, resolver=FakeResolver())
    finally:
        client.close()

    assert result.status == "ok"
    assert result.rdap_url == "https://rdap.example/domain/example.com"


def test_fetch_rdap_rejects_unsafe_redirect() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "http://127.0.0.1/steal"})

    client = httpx.Client(transport=httpx.MockTransport(handler), timeout=1.0)
    try:
        result = _fetch_rdap("example.com", client=client, resolver=FakeResolver())
    finally:
        client.close()

    assert result.status == "unavailable"
    assert "ValueError" in (result.error or "")


def test_fetch_rdap_timeout_is_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out", request=request)

    client = httpx.Client(transport=httpx.MockTransport(handler), timeout=1.0)
    try:
        result = _fetch_rdap("example.com", client=client, resolver=FakeResolver())
    finally:
        client.close()

    assert result.status == "unavailable"
    assert "timed out" in (result.error or "")


def test_fetch_rdap_invalid_json_is_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not-json")

    client = httpx.Client(transport=httpx.MockTransport(handler), timeout=1.0)
    try:
        result = _fetch_rdap("example.com", client=client, resolver=FakeResolver())
    finally:
        client.close()

    assert result.status == "unavailable"


def test_enrich_domain_ok(monkeypatch) -> None:
    monkeypatch.setattr(
        enrich_module,
        "_resolve_dns",
        lambda domain: DnsLookup(status="ok", a=["1.2.3.4"]),
    )
    monkeypatch.setattr(
        enrich_module,
        "_fetch_rdap",
        lambda domain: RdapLookup(
            status="ok",
            registered=date(2010, 1, 1),
            age_days=100,
            registrar="Example Registrar",
        ),
    )

    result = enrich_domain("example.com")

    assert result["status"] == "ok"
    assert result["age_days"] == 100
    assert "registered" in result["summary"]


def test_enrich_domain_partial_when_rdap_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(
        enrich_module,
        "_resolve_dns",
        lambda domain: DnsLookup(status="ok", a=["1.2.3.4"]),
    )
    monkeypatch.setattr(
        enrich_module,
        "_fetch_rdap",
        lambda domain: RdapLookup(status="unavailable", error="timeout"),
    )

    result = enrich_domain("example.com")

    assert result["status"] == "partial"
    assert "RDAP" in (result["error"] or "")


def test_enrich_domain_unavailable_when_all_fail(monkeypatch) -> None:
    monkeypatch.setattr(
        enrich_module,
        "_resolve_dns",
        lambda domain: DnsLookup(status="unavailable", errors=["A: timeout"]),
    )
    monkeypatch.setattr(
        enrich_module,
        "_fetch_rdap",
        lambda domain: RdapLookup(status="unavailable", error="timeout"),
    )

    result = enrich_domain("example.com")

    assert result["status"] == "unavailable"


def test_enrich_domain_invalid_inputs() -> None:
    assert enrich_domain("http://127.0.0.1/")["status"] == "invalid"
    assert enrich_domain("8.8.8.8")["status"] == "invalid"
