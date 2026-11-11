"""Minimal HTTPS GET transport for CI evidence scripts.

Ubuntu GitHub runners provide curl.  It supplies a maintained TLS stack without
reintroducing Python URL handlers or direct Python HTTPS connections.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit


CONNECT_TIMEOUT_SECONDS = 10
REQUEST_TIMEOUT_SECONDS = 30


class HttpsTransportError(RuntimeError):
    """The constrained HTTPS transport could not complete a request."""


def _validate_url(url: str) -> None:
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError as error:
        raise HttpsTransportError(f"refusing non-HTTPS URL: {url!r}") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or port not in {None, 443}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise HttpsTransportError(f"refusing non-HTTPS URL: {url!r}")


def _curl_config_headers(headers: Mapping[str, str]) -> str:
    lines = []
    for name, value in headers.items():
        if not name or "\r" in name or "\n" in name or "\r" in value or "\n" in value:
            raise HttpsTransportError("refusing HTTPS header with a line break")
        escaped = f"{name}: {value}".replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'header = "{escaped}"\n')
    return "".join(lines)


def _parse_status(output: str) -> int:
    status = output.strip()
    if not status.isdecimal() or not 100 <= int(status) <= 599:
        raise HttpsTransportError("curl did not return a valid HTTP status")
    return int(status)


def _parse_headers(path: Path) -> dict[str, str]:
    current: dict[str, str] | None = None
    completed: dict[str, str] | None = None
    for line in path.read_text(encoding="iso-8859-1").splitlines():
        if line.startswith("HTTP/"):
            current = {}
        elif not line:
            if current is not None:
                completed = current
                current = None
        elif current is not None:
            name, separator, value = line.partition(":")
            if not separator:
                raise HttpsTransportError("curl returned a malformed HTTP header")
            current[name.lower()] = value.strip()
    if completed is None:
        raise HttpsTransportError("curl did not return HTTP response headers")
    return completed


def https_get(url: str, headers: Mapping[str, str]) -> tuple[int, dict[str, str], bytes]:
    """GET one validated HTTPS URL without following redirects.

    Callers own their fixed-host or allowlist policy.  Headers are stored in a
    private curl config file so a bearer token is not exposed in process argv.
    """

    _validate_url(url)
    with tempfile.TemporaryDirectory(prefix="rust-gvm-api-https-") as directory:
        temporary = Path(directory)
        header_path = temporary / "headers"
        body_path = temporary / "body"
        config_path = temporary / "curl.conf"
        config_path.write_text(_curl_config_headers(headers), encoding="utf-8")
        command = [
            "curl",
            "--silent",
            "--show-error",
            "--no-location",
            "--request",
            "GET",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--connect-timeout",
            str(CONNECT_TIMEOUT_SECONDS),
            "--max-time",
            str(REQUEST_TIMEOUT_SECONDS),
            "--dump-header",
            str(header_path),
            "--output",
            str(body_path),
            "--write-out",
            "%{http_code}",
            "--config",
            str(config_path),
            "--",
            url,
        ]
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=REQUEST_TIMEOUT_SECONDS + CONNECT_TIMEOUT_SECONDS,
                shell=False,
            )
        except FileNotFoundError as error:
            raise HttpsTransportError("curl is required for HTTPS evidence retrieval") from error
        except subprocess.TimeoutExpired as error:
            raise HttpsTransportError("HTTPS request exceeded its timeout") from error
        if completed.returncode != 0:
            detail = completed.stderr.strip() or "curl failed without diagnostics"
            raise HttpsTransportError(f"HTTPS request failed: {detail}")
        return (
            _parse_status(completed.stdout),
            _parse_headers(header_path),
            body_path.read_bytes(),
        )
