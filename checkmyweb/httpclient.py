"""Small HTTP client on top of http.client.

urllib hides too much for a scanner (automatic redirects, merged headers,
no custom methods), so requests are made with http.client directly.
"""
from __future__ import annotations

import http.client
import re
import ssl
import time
import urllib.parse
from dataclasses import dataclass

from . import __version__

USER_AGENT = f"Mozilla/5.0 (compatible; checkmyweb/{__version__}; +https://wookly.dev/products/checkmyweb/)"


def verified_context(ca_file: str | None = None) -> ssl.SSLContext:
    """System trust store, plus an extra CA bundle for internal or test certificates."""
    ctx = ssl.create_default_context()
    if ca_file:
        ctx.load_verify_locations(cafile=ca_file)
    return ctx


@dataclass
class Response:
    url: str
    method: str
    status: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes
    elapsed: float
    insecure: bool = False  # TLS certificate verification was disabled

    def header(self, name: str, default: str | None = None) -> str | None:
        name = name.lower()
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return default

    def header_all(self, name: str) -> list[str]:
        name = name.lower()
        return [value for key, value in self.headers if key.lower() == name]

    @property
    def is_redirect(self) -> bool:
        return self.status in (301, 302, 303, 307, 308) and bool(self.header("location"))

    @property
    def location(self) -> str | None:
        loc = self.header("location")
        return urllib.parse.urljoin(self.url, loc.strip()) if loc else None

    @property
    def content_type(self) -> str:
        return (self.header("content-type") or "").split(";")[0].strip().lower()

    @property
    def looks_like_html(self) -> bool:
        head = self.body.lstrip()[:200].lower()
        return self.content_type == "text/html" or head.startswith((b"<!doctype", b"<html", b"<head"))

    @property
    def text(self) -> str:
        match = re.search(r"charset=[\"']?([\w-]+)", self.header("content-type") or "", re.I)
        encoding = match.group(1) if match else "utf-8"
        try:
            return self.body.decode(encoding, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")


class HttpClient:
    def __init__(self, timeout: float = 10.0, delay: float = 0.15,
                 user_agent: str = USER_AGENT, max_body: int = 2_000_000, ca_file: str | None = None):
        self.timeout = timeout
        self.delay = delay
        self.user_agent = user_agent
        self.max_body = max_body
        self.requests = 0
        # Hosts whose certificate failed verification; later requests skip
        # verification so the remaining checks can still run.
        self.insecure_hosts: set[str] = set()
        self._last = 0.0
        self._verified_ctx = verified_context(ca_file)
        self._insecure_ctx = ssl.create_default_context()
        self._insecure_ctx.check_hostname = False
        self._insecure_ctx.verify_mode = ssl.CERT_NONE

    def _throttle(self) -> None:
        wait = self._last + self.delay - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()

    def request(self, method: str, url: str, headers: dict | None = None,
                body: bytes | None = None, max_body: int | None = None) -> Response:
        parts = urllib.parse.urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(f"unsupported URL: {url}")
        host = parts.hostname
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query

        hdrs = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        if headers:
            hdrs.update(headers)

        insecure = host in self.insecure_hosts
        try:
            return self._send(scheme, parts, path, method, hdrs, body, max_body, insecure, url)
        except ssl.SSLCertVerificationError:
            if insecure or scheme != "https":
                raise
            self.insecure_hosts.add(host)
            return self._send(scheme, parts, path, method, hdrs, body, max_body, True, url)

    def _send(self, scheme, parts, path, method, headers, body, max_body, insecure, url) -> Response:
        self._throttle()
        self.requests += 1
        if scheme == "https":
            ctx = self._insecure_ctx if insecure else self._verified_ctx
            conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443,
                                               timeout=self.timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=self.timeout)
        start = time.monotonic()
        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read(max_body or self.max_body)
            return Response(
                url=url,
                method=method,
                status=resp.status,
                reason=resp.reason,
                headers=resp.getheaders(),
                body=data,
                elapsed=time.monotonic() - start,
                insecure=insecure,
            )
        finally:
            conn.close()
