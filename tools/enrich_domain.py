"""DNS + RDAP enrichment tool with timeouts and fail-closed results."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from datetime import UTC, date, datetime
from typing import Literal
from urllib.parse import quote, urljoin, urlsplit

import dns.exception
import dns.resolver
import httpx
from pydantic import BaseModel, Field

from config import Settings
from tools.schemas import ToolResult
from tools.validation import parse_indicator

_RDAP_BASE = "https://rdap.org/domain/"
_MAX_RDAP_BYTES = 1_000_000
_USER_AGENT = "soc-triage-agent/0.1 (portfolio project)"
_BLOCKED_HOSTS = {"localhost", "metadata.google.internal"}
_BLOCKED_SUFFIXES = (".local", ".internal", ".home.arpa", ".localhost")


class DnsLookup(BaseModel):
    status: Literal["ok", "partial", "unavailable", "nxdomain"]
    a: list[str] = Field(default_factory=list)
    mx: list[str] = Field(default_factory=list)
    ns: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class RdapLookup(BaseModel):
    status: Literal["ok", "partial", "unavailable"]
    registrar: str | None = None
    registered: date | None = None
    age_days: int | None = None
    nameservers: list[str] = Field(default_factory=list)
    domain_statuses: list[str] = Field(default_factory=list)
    rdap_url: str | None = None
    error: str | None = None


class EnrichDomainResult(ToolResult):
    tool: Literal["enrich_domain"] = "enrich_domain"
    domain: str
    dns: DnsLookup
    rdap: RdapLookup
    age_days: int | None = None


def _new_dns_resolver(settings: Settings) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = settings.dns_timeout_seconds
    resolver.timeout = min(2.0, settings.dns_timeout_seconds)
    return resolver


def _extract_records(rtype: str, answers: Iterable[object]) -> list[str]:
    values: list[str] = []
    for answer in answers:
        if rtype == "A":
            value = answer
        elif rtype == "MX":
            value = getattr(answer, "exchange", None)
        else:
            value = getattr(answer, "target", None)
        if value is None:
            continue
        text = str(value).rstrip(".")
        if rtype != "A":
            text = text.lower()
        if text:
            values.append(text)
    return list(dict.fromkeys(values))


def _resolve_dns(
    domain: str,
    resolver: dns.resolver.Resolver | None = None,
) -> DnsLookup:
    active = resolver or _new_dns_resolver(Settings())
    records: dict[str, list[str]] = {"A": [], "MX": [], "NS": []}
    errors: list[str] = []

    for rtype in ("A", "MX", "NS"):
        try:
            answers = active.resolve(domain, rtype)
        except dns.resolver.NXDOMAIN:
            return DnsLookup(status="nxdomain", errors=[f"{rtype}: NXDOMAIN"])
        except dns.resolver.NoAnswer:
            continue
        except dns.exception.Timeout:
            errors.append(f"{rtype}: timeout")
        except dns.exception.DNSException as exc:
            errors.append(f"{rtype}: {type(exc).__name__}")
        else:
            records[rtype] = _extract_records(rtype, answers)

    if len(errors) == 3:
        status: Literal["ok", "partial", "unavailable"] = "unavailable"
    elif errors:
        status = "partial"
    else:
        status = "ok"
    return DnsLookup(
        status=status,
        a=records["A"],
        mx=records["MX"],
        ns=records["NS"],
        errors=errors,
    )


def _new_rdap_client(settings: Settings) -> httpx.Client:
    return httpx.Client(
        timeout=httpx.Timeout(settings.rdap_timeout_seconds),
        follow_redirects=False,
        headers={
            "Accept": "application/rdap+json, application/json",
            "User-Agent": _USER_AGENT,
        },
    )


def _hostname_resolves_public(
    host: str,
    resolver: dns.resolver.Resolver | None = None,
) -> bool:
    active = resolver or _new_dns_resolver(Settings())
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for rtype in ("A", "AAAA"):
        try:
            answers = active.resolve(host, rtype)
        except dns.resolver.NoAnswer:
            continue
        except dns.exception.DNSException:
            return False
        for answer in answers:
            try:
                addresses.append(ipaddress.ip_address(str(answer)))
            except ValueError:
                return False
    return bool(addresses) and all(address.is_global for address in addresses)


def _is_safe_rdap_url(
    url: str,
    *,
    resolver: dns.resolver.Resolver | None = None,
) -> bool:
    try:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.username or parsed.password:
            return False
        if parsed.port not in (None, 443):
            return False
        host = parsed.hostname
    except ValueError:
        return False
    if not host:
        return False

    host = host.lower().rstrip(".")
    if host in _BLOCKED_HOSTS or host.endswith(_BLOCKED_SUFFIXES):
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        return ip.is_global
    return _hostname_resolves_public(host, resolver)


def _get_with_redirects(
    client: httpx.Client,
    url: str,
    *,
    max_redirects: int,
    resolver: dns.resolver.Resolver | None = None,
) -> httpx.Response:
    current = url
    for _ in range(max_redirects + 1):
        if not _is_safe_rdap_url(current, resolver=resolver):
            raise ValueError("unsafe RDAP URL")
        response = client.get(current)
        if response.is_redirect:
            location = response.headers.get("location")
            if not location:
                raise ValueError("RDAP redirect without Location")
            current = urljoin(str(response.url), location)
            continue
        return response
    raise ValueError("too many RDAP redirects")


def _parse_date(value: object) -> date | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(UTC)
    return parsed.date()


def _extract_nameservers(payload: dict) -> list[str]:
    nameservers: list[str] = []
    for item in payload.get("nameservers", []) or []:
        if not isinstance(item, dict):
            continue
        name = item.get("ldhName") or item.get("unicodeName")
        if isinstance(name, str) and name:
            nameservers.append(name.rstrip(".").lower())
    return list(dict.fromkeys(nameservers))


def _extract_registrar(payload: dict) -> str | None:
    for entity in payload.get("entities", []) or []:
        if not isinstance(entity, dict):
            continue
        if "registrar" not in (entity.get("roles") or []):
            continue
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) >= 2 and isinstance(vcard[1], list):
            for entry in vcard[1]:
                if isinstance(entry, list) and len(entry) >= 4 and entry[0] == "fn":
                    name = entry[3]
                    if isinstance(name, str) and name.strip():
                        return name.strip()
        handle = entity.get("handle")
        if isinstance(handle, str) and handle.strip():
            return handle.strip()
    return None


def _parse_rdap(payload: dict, *, rdap_url: str) -> RdapLookup:
    registered: date | None = None
    for event in payload.get("events", []) or []:
        if isinstance(event, dict) and event.get("eventAction") == "registration":
            registered = _parse_date(event.get("eventDate"))
            if registered is not None:
                break

    nameservers = _extract_nameservers(payload)
    statuses = [str(item) for item in payload.get("status", []) or [] if item]
    registrar = _extract_registrar(payload)

    if registered is None:
        return RdapLookup(
            status="partial",
            registrar=registrar,
            nameservers=nameservers,
            domain_statuses=statuses,
            rdap_url=rdap_url,
            error="registration date missing from RDAP response",
        )

    age_days = max(0, (datetime.now(UTC).date() - registered).days)
    return RdapLookup(
        status="ok",
        registrar=registrar,
        registered=registered,
        age_days=age_days,
        nameservers=nameservers,
        domain_statuses=statuses,
        rdap_url=rdap_url,
    )


def _fetch_rdap(
    domain: str,
    *,
    client: httpx.Client | None = None,
    resolver: dns.resolver.Resolver | None = None,
) -> RdapLookup:
    settings = Settings()
    owns_client = client is None
    active_client = client or _new_rdap_client(settings)
    try:
        url = f"{_RDAP_BASE}{quote(domain, safe='')}"
        response = _get_with_redirects(
            active_client,
            url,
            max_redirects=settings.rdap_max_redirects,
            resolver=resolver,
        )
        if response.status_code != 200:
            return RdapLookup(
                status="unavailable",
                rdap_url=str(response.url),
                error=f"RDAP returned HTTP {response.status_code}",
            )
        if len(response.content) > _MAX_RDAP_BYTES:
            return RdapLookup(
                status="unavailable",
                rdap_url=str(response.url),
                error="RDAP response exceeded size limit",
            )
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("RDAP payload is not a JSON object")
        return _parse_rdap(payload, rdap_url=str(response.url))
    except httpx.TimeoutException:
        return RdapLookup(status="unavailable", error="RDAP request timed out")
    except httpx.HTTPError as exc:
        return RdapLookup(
            status="unavailable",
            error=f"RDAP request failed: {type(exc).__name__}",
        )
    except (ValueError, TypeError, KeyError) as exc:
        return RdapLookup(
            status="unavailable",
            error=f"RDAP parse/redirect failed: {type(exc).__name__}",
        )
    finally:
        if owns_client:
            active_client.close()


def enrich_domain(domain: str) -> dict:
    """Enrich a domain with DNS (A, MX, NS) and RDAP registration data.

    Every DNS and HTTP call has a timeout. Failures are returned as structured
    "partial" or "unavailable" results, never raised. This tool only performs
    DNS queries and RDAP lookups against a fixed bootstrap endpoint; it never
    fetches or connects to the submitted URL itself.
    """
    parsed = parse_indicator(domain)
    if parsed is None:
        return EnrichDomainResult(
            status="invalid",
            domain=domain,
            dns=DnsLookup(status="unavailable", errors=["input invalid"]),
            rdap=RdapLookup(status="unavailable", error="input invalid"),
            summary="Invalid input: expected a public domain or URL host.",
            error="input failed domain validation",
        ).model_dump(mode="json")

    if parsed.is_ip:
        return EnrichDomainResult(
            status="invalid",
            domain=parsed.host,
            dns=DnsLookup(status="unavailable", errors=["IP host"]),
            rdap=RdapLookup(status="unavailable", error="IP host"),
            summary="IP hosts are not supported by this domain enrichment tool.",
            error="RDAP/DNS domain enrichment requires a domain name",
        ).model_dump(mode="json")

    try:
        dns_result = _resolve_dns(parsed.host)
        rdap_result = _fetch_rdap(parsed.host)
    except Exception as exc:
        return EnrichDomainResult(
            status="unavailable",
            domain=parsed.host,
            dns=DnsLookup(status="unavailable", errors=[type(exc).__name__]),
            rdap=RdapLookup(status="unavailable", error=type(exc).__name__),
            summary="Domain enrichment failed unexpectedly.",
            error=f"{type(exc).__name__}: {str(exc)[:300]}",
        ).model_dump(mode="json")

    if dns_result.status == "unavailable" and rdap_result.status == "unavailable":
        overall_status = "unavailable"
    elif dns_result.status == "ok" and rdap_result.status == "ok":
        overall_status = "ok"
    else:
        overall_status = "partial"

    errors = [*dns_result.errors]
    if rdap_result.error:
        errors.append(f"RDAP: {rdap_result.error}")

    if rdap_result.registered is not None:
        age_text = f"registered {rdap_result.registered.isoformat()} ({rdap_result.age_days} days)"
    else:
        age_text = f"RDAP {rdap_result.status}"
    summary = (
        f"DNS {dns_result.status} "
        f"(A={len(dns_result.a)}, MX={len(dns_result.mx)}, NS={len(dns_result.ns)}); "
        f"{age_text}."
    )

    return EnrichDomainResult(
        status=overall_status,
        domain=parsed.host,
        dns=dns_result,
        rdap=rdap_result,
        age_days=rdap_result.age_days,
        summary=summary,
        error="; ".join(errors)[:1000] if errors else None,
    ).model_dump(mode="json")
