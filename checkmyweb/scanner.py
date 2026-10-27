from __future__ import annotations

import datetime as dt
import http.client
import secrets
import socket
import ssl
import time
import traceback
import urllib.parse
from dataclasses import dataclass

from . import fingerprint, remedies, verify
from .httpclient import HttpClient, Response
from .models import CheckRun, Finding, ScanResult, Severity
from .resolver import Resolver
from .target import Target, all_loopback, org_domain  # noqa: F401  (org_domain re-exported)

NET_ERRORS = (OSError, http.client.HTTPException, ssl.SSLError, ValueError)


@dataclass
class Options:
    timeout: float = 10.0
    delay: float = 0.15
    http_port: int | None = None  # plain-HTTP port for the redirect check when HTTPS runs on a custom port
    ca_file: str | None = None  # extra trusted CA bundle (internal or test certificates)
    local_autoverify: bool = True  # targets that resolve only to this machine count as verified


def _apex(host: str) -> str:
    return host[4:] if host.startswith("www.") else host


class ScanContext:
    """Shared state handed to every check module."""

    def __init__(self, target: Target, options: Options,
                 client: HttpClient | None = None, resolver: Resolver | None = None):
        self.target = target
        self.host = target.host
        self.apex = target.apex
        self.org_domain = target.org_domain
        self.options = options
        self.client = client or HttpClient(timeout=options.timeout, delay=options.delay, ca_file=options.ca_file)
        self.resolver = resolver or Resolver(timeout=options.timeout)
        self.origin = target.origin
        self.base_url = target.url
        self.platform = fingerprint.Platform()
        self.verification = verify.Verification(False)
        self.findings: list[Finding] = []
        self.meta: dict = {}
        self.notes: list[str] = []
        self.current_check = ""
        self._cache: dict = {}
        self._homepage_chain: list[Response] | None = None

    def add(self, id: str, severity: Severity, title: str, detail: str = "",
            evidence: str = "", fix: str = "", refs: tuple | list = ()) -> None:
        self.findings.append(Finding(self.current_check, id, severity, title,
                                     detail, evidence, fix, list(refs)))

    def log(self, message: str) -> None:
        self.notes.append(f"[{self.current_check or 'scan'}] {message}")

    def fix(self, topic: str) -> str:
        """Remediation text for the detected server/CDN (see remedies.FIXES)."""
        return remedies.render(topic, self.platform, host=self.host)

    @property
    def tls_port(self) -> int | None:
        if self.target.scheme == "https":
            return self.target.port
        return 443 if self.target.default_port else None

    @property
    def http_url(self) -> str | None:
        """Plain-HTTP address for the redirect check, if it can be known."""
        t = self.target
        if t.scheme == "http":
            return t.url
        if self.options.http_port:
            port = self.options.http_port
        elif t.default_port:
            port = 80
        else:
            return None
        host = f"[{t.host}]" if ":" in t.host else t.host
        return f"http://{host if port == 80 else f'{host}:{port}'}{t.path}"

    @property
    def variant(self) -> str | None:
        """The www/apex counterpart of the target, if it is worth checking."""
        if "variant" not in self.meta:
            t = self.target
            other = None
            if t.has_public_dns and t.default_port and t.path == "/":
                other = t.host[4:] if t.host.startswith("www.") else "www." + t.host
                # On deep names with wildcard DNS (e.g. foo.example.com), www.foo resolves only by accident.
                wildcard = (not t.host.startswith("www.") and t.host.count(".") >= 2
                            and self.resolver.resolves(f"checkmyweb-{secrets.token_hex(4)}.{t.host}"))
                if wildcard or not self.resolver.resolves(other):
                    other = None
            self.meta["variant"] = other
        return self.meta["variant"]

    def url(self, path: str, root: bool = False) -> str:
        """Absolute URL for a path relative to the scanned base path (or the site root)."""
        if "://" in path:
            return path
        return urllib.parse.urljoin(self.origin + "/" if root else self.base_url, path.lstrip("/"))

    def get(self, target: str, method: str = "GET", headers: dict | None = None,
            max_body: int | None = None, cache: bool = True, root: bool = False) -> Response | None:
        url = self.url(target, root=root)
        key = (method, url, max_body) if cache and not headers else None
        if key is not None and key in self._cache:
            return self._cache[key]
        try:
            resp = self.client.request(method, url, headers=headers, max_body=max_body)
        except NET_ERRORS as e:
            self.log(f"{method} {url} -> {type(e).__name__}: {e}")
            resp = None
        if key is not None:
            self._cache[key] = resp
        return resp

    def follow(self, url: str, max_hops: int = 8) -> list[Response]:
        chain: list[Response] = []
        while len(chain) < max_hops:
            resp = self.get(url)
            if resp is None:
                break
            chain.append(resp)
            if not resp.is_redirect:
                break
            url = resp.location
            if any(r.url == url for r in chain):
                break
        return chain

    @property
    def homepage_chain(self) -> list[Response]:
        if self._homepage_chain is None:
            chain = self.follow(self.target.url)
            if not chain and self.target.scheme == "https" and self.target.default_port:
                # No HTTPS at all; fall back so the other checks still have a page.
                chain = self.follow(f"http://{self.target.netloc}{self.target.path}")
            self._homepage_chain = chain
        return self._homepage_chain

    @property
    def homepage(self) -> Response | None:
        chain = self.homepage_chain
        return chain[-1] if chain else None

    def responses(self) -> list[Response]:
        """Every response fetched so far (homepage chain first)."""
        seen = {id(r) for r in self.homepage_chain}
        rest = [r for r in self._cache.values() if r is not None and id(r) not in seen]
        return list(self.homepage_chain) + rest


def _detect_platform(ctx: ScanContext) -> None:
    ctx.current_check = "platform"
    cnames = ctx.resolver.cname_chain(ctx.host) if ctx.target.has_public_dns else []
    ctx.platform = fingerprint.detect(ctx.responses(), cnames)
    ctx.meta["platform"] = ctx.platform.to_dict()
    p = ctx.platform
    ctx.add("platform.summary", Severity.INFO, f"서버 환경 추정: {p.summary}",
            detail="응답 헤더·쿠키 이름·오류 페이지·DNS로 추정했습니다. 조치 방법은 이 환경에 맞춰 안내합니다.",
            evidence="\n".join(p.evidence) or "추정 근거를 찾지 못해 Apache·nginx 기준으로 안내합니다.")
    if p.cdn:
        ctx.add("platform.cdn", Severity.INFO, f"CDN/프록시 뒤에서 운영 중입니다: {fingerprint.CDN_LABELS[p.cdn]}",
                detail="TLS·응답 헤더 결과는 CDN 엣지 서버 기준이며, 설정도 CDN 콘솔에서 바꾸는 경우가 많습니다.\n"
                       "원본(오리진) 서버가 인터넷에 직접 열려 있으면 CDN의 보호가 우회될 수 있으므로, "
                       "오리진 방화벽에서 CDN의 IP 대역만 허용하는 것을 권장합니다.",
                evidence="\n".join(e for e in p.evidence if e.startswith("CDN")))


def run_scan(target: Target | str, options: Options, checks: list, progress=None) -> ScanResult:
    if isinstance(target, str):
        target = Target.parse(target)
    ctx = ScanContext(target, options)
    t_start = time.monotonic()
    result = ScanResult(target=target.label, url=target.url,
                        started=dt.datetime.now().astimezone().isoformat(timespec="seconds"))

    try:
        infos = socket.getaddrinfo(target.host, target.port, proto=socket.IPPROTO_TCP)
        ctx.meta["ip"] = sorted({info[4][0] for info in infos})
    except OSError as e:
        raise RuntimeError(f"{target.host} 의 IP 주소를 확인할 수 없습니다: {e}") from e

    home = ctx.homepage
    if home is not None:
        final = urllib.parse.urlsplit(home.url)
        # Follow an http->https or apex->www hop so probes hit the canonical origin, not a redirect stub.
        if final.hostname and _apex(final.hostname) == target.apex:
            ctx.origin = f"{final.scheme}://{final.netloc}"
            ctx.base_url = ctx.origin + target.path
        ctx.meta.update(final_url=home.url, status=home.status, server=home.header("server"))
    ctx.meta["target_url"] = target.url
    ctx.meta["base_url"] = ctx.base_url

    t0 = time.monotonic()
    _detect_platform(ctx)
    result.checks.append(CheckRun("platform", "서버 환경 / CDN", time.monotonic() - t0))

    if any(getattr(m, "REQUIRES_VERIFICATION", False) for m in checks):
        loopback = options.local_autoverify and all_loopback(ctx.meta["ip"])
        ctx.verification = verify.check(target, ctx.resolver,
                                        lambda url: ctx.get(url, max_body=4096, cache=False), loopback)
        ctx.meta["verification"] = {"verified": ctx.verification.verified, "method": ctx.verification.method,
                                    "detail": ctx.verification.detail, "label": ctx.verification.label}

    explained = False
    for index, module in enumerate(checks, 1):
        run = CheckRun(module.NAME, module.TITLE)
        if progress:
            progress(index, len(checks), run, None)
        ctx.current_check = module.NAME
        t0 = time.monotonic()
        if getattr(module, "REQUIRES_VERIFICATION", False) and not ctx.verification.verified:
            run.skipped = "소유 확인 필요"
            detail = ("민감 파일 탐색과 포트 점검은 사이트의 약점을 그대로 드러내므로, 도메인 소유를 확인한 뒤에만 실행합니다.")
            if not explained:
                detail += "\n\n" + verify.instructions(target, ctx.verification.token)
                explained = True
            ctx.add(f"{module.NAME}.unverified", Severity.INFO, f"{module.TITLE}: 소유 확인 전이라 건너뛰었습니다",
                    detail=detail, fix=f"checkmyweb verify {target.label}  (확인 방법과 현재 상태 보기)")
        else:
            try:
                module.run(ctx)
            except Exception as e:  # a broken check must not abort the whole scan
                run.error = f"{type(e).__name__}: {e}"
                ctx.add(f"{module.NAME}.error", Severity.INFO, "점검 중 내부 오류가 발생했습니다",
                        detail=run.error, evidence=traceback.format_exc(limit=4))
        run.duration = time.monotonic() - t0
        result.checks.append(run)
        if progress:
            progress(index, len(checks), run, ctx.findings)

    result.findings = ctx.findings
    result.meta = ctx.meta
    result.meta["requests"] = ctx.client.requests
    result.meta["notes"] = ctx.notes
    result.duration = time.monotonic() - t_start
    result.finished = dt.datetime.now().astimezone().isoformat(timespec="seconds")
    return result
