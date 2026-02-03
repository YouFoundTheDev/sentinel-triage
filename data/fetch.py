"""Download the public feeds used by the Stage 1 pipeline."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import httpx

OPENPHISH_URL = "https://openphish.com/feed.txt"
TRANCO_URL = "https://tranco-list.eu/download/daily/top-1m.csv.zip"
USER_AGENT = "soc-triage-agent/0.1 (portfolio project)"
_TIMEOUT_SECONDS = 30.0
_MAX_BYTES = 25 * 1024 * 1024


def _client() -> httpx.Client:
    return httpx.Client(
        timeout=httpx.Timeout(_TIMEOUT_SECONDS),
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT},
    )


def fetch_bytes(url: str, *, max_bytes: int = _MAX_BYTES) -> bytes:
    """Download a URL with a timeout and a hard response-size cap."""
    with _client() as client:
        with client.stream("GET", url) as response:
            response.raise_for_status()
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError(f"response from {url} exceeds {max_bytes} bytes")
                chunks.append(chunk)
            return b"".join(chunks)


def fetch_text(url: str, *, max_bytes: int = _MAX_BYTES) -> str:
    """Download a UTF-8 text resource."""
    return fetch_bytes(url, max_bytes=max_bytes).decode("utf-8", errors="replace")


def _write_atomic(path: Path, content: str) -> None:
    tmp_path = path.with_name(f"{path.name}.tmp")
    tmp_path.write_text(content, encoding="utf-8")
    tmp_path.replace(path)


def download_raw(data_dir: Path) -> tuple[Path, Path]:
    """Download OpenPhish and Tranco, returning the cached file paths."""
    data_dir.mkdir(parents=True, exist_ok=True)

    openphish_text = fetch_text(OPENPHISH_URL)
    tranco_zip = fetch_bytes(TRANCO_URL)
    with zipfile.ZipFile(io.BytesIO(tranco_zip)) as archive:
        member = next(
            (name for name in archive.namelist() if name.endswith("top-1m.csv")),
            None,
        )
        if member is None:
            raise ValueError("Tranco archive does not contain top-1m.csv")
        tranco_text = archive.read(member).decode("utf-8", errors="replace")

    openphish_path = data_dir / "openphish.txt"
    tranco_path = data_dir / "tranco.csv"
    _write_atomic(openphish_path, openphish_text)
    _write_atomic(tranco_path, tranco_text)
    return openphish_path, tranco_path
