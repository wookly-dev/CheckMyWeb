"""Guess the web server, application platform and CDN in front of a site.

Only passive signals are used (response headers, cookie names, error-page
signatures and the DNS CNAME chain). The result picks which remediation
snippets to show and tells the user when results describe a CDN edge rather
than their own server.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

WEB_LABELS = {"apache": "Apache", "nginx": "nginx", "iis": "IIS", "litespeed": "LiteSpeed", "caddy": "Caddy"}
APP_LABELS = {"php": "PHP", "express": "Node.js(Express)", "django": "Django", "aspnet": "ASP.NET", "java": "Java"}
CDN_LABELS = {
    "cloudflare": "Cloudflare", "cloudfront": "Amazon CloudFront", "akamai": "Akamai", "fastly": "Fastly",
    "azure": "Azure Front Door/CDN", "google": "Google Cloud", "sucuri": "Sucuri", "imperva": "Imperva",
    "vercel": "Vercel", "netlify": "Netlify", "bunny": "Bunny CDN",
}

_SERVER_PATTERNS = [
    (r"^apache", "apache"), (r"nginx|openresty|tengine", "nginx"), (r"microsoft-iis", "iis"),
    (r"litespeed", "litespeed"), (r"^caddy", "caddy"),
]
_POWERED_BY_PATTERNS = [
    (r"php", "php"), (r"express", "express"), (r"next\.js|nuxt", "express"),
    (r"asp\.net", "aspnet"), (r"servlet|jsp|tomcat", "java"),
]
_COOKIE_PATTERNS = [
    (r"^(phpsessid|laravel_session|ci_session|wordpress_)", "php"), (r"^connect\.sid$", "express"),
    (r"^(csrftoken|sessionid)$", "django"), (r"^(asp\.net_sessionid|\.aspnetcore\.)", "aspnet"),
    (r"^jsessionid$", "java"),
]
_CNAME_SUFFIXES = {
    ".cdn.cloudflare.net": "cloudflare", ".cloudfront.net": "cloudfront", ".akamaiedge.net": "akamai",
    ".edgekey.net": "akamai", ".edgesuite.net": "akamai", ".akamai.net": "akamai", ".fastly.net": "fastly",
    ".fastlylb.net": "fastly", ".azureedge.net": "azure", ".azurefd.net": "azure", ".vercel-dns.com": "vercel",
    ".netlify.app": "netlify", ".b-cdn.net": "bunny", ".incapdns.net": "imperva",
}


@dataclass
class Platform:
    web: str | None = None
    app: str | None = None
    cdn: str | None = None
    evidence: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        parts = [WEB_LABELS.get(self.web, ""), APP_LABELS.get(self.app, "")]
        text = " · ".join(p for p in parts if p) or "알 수 없음"
        return text + (f" (CDN: {CDN_LABELS[self.cdn]})" if self.cdn else "")

    def to_dict(self) -> dict:
        return {"web": self.web, "app": self.app, "cdn": self.cdn, "summary": self.summary, "evidence": self.evidence}


def _cdn_from_headers(h) -> tuple[str, str] | None:
    """h(name) -> header value or "".  Returns (cdn, evidence)."""
    server, via = h("server").lower(), h("via").lower()
    checks = [
        ("cloudflare", h("cf-ray") and f"CF-Ray: {h('cf-ray')}" or ("cloudflare" in server and f"Server: {h('server')}")),
        ("cloudfront", h("x-amz-cf-id") and "X-Amz-Cf-Id 헤더" or ("cloudfront" in via and f"Via: {h('via')}")),
        ("akamai", server.startswith("akamai") and f"Server: {h('server')}" or (h("akamai-grn") and "Akamai-GRN 헤더")),
        ("fastly", h("x-fastly-request-id") and "X-Fastly-Request-Id 헤더"
         or ("varnish" in via and h("x-served-by").startswith("cache-") and f"X-Served-By: {h('x-served-by')}")),
        ("azure", h("x-azure-ref") and "X-Azure-Ref 헤더"),
        ("sucuri", h("x-sucuri-id") and "X-Sucuri-Id 헤더"),
        ("imperva", h("x-iinfo") and "X-Iinfo 헤더" or ("imperva" in h("x-cdn").lower() and f"X-CDN: {h('x-cdn')}")),
        ("vercel", h("x-vercel-id") and "X-Vercel-Id 헤더"),
        ("netlify", h("x-nf-request-id") and "X-Nf-Request-Id 헤더"),
        ("bunny", "bunnycdn" in server and f"Server: {h('server')}"),
        ("google", re.search(r"\bgoogle\b", via) and f"Via: {h('via')}"),
    ]
    for cdn, evidence in checks:
        if evidence:
            return cdn, evidence
    return None


def detect(responses: list, cnames: list[str] | None = None) -> Platform:
    """responses: homepage chain plus any other fetched pages (first = most relevant)."""
    platform = Platform()
    for resp in responses:
        def h(name, _resp=resp):
            return (_resp.header(name) or "").strip()

        if platform.cdn is None:
            found = _cdn_from_headers(h)
            if found:
                platform.cdn = found[0]
                platform.evidence.append(f"CDN {CDN_LABELS[found[0]]}: {found[1]}")
        server = h("server")
        if platform.web is None and server:
            for pattern, key in _SERVER_PATTERNS:
                if re.search(pattern, server, re.I):
                    platform.web = key
                    platform.evidence.append(f"웹 서버: Server: {server}")
                    break
        powered = h("x-powered-by") or h("x-aspnet-version") and "ASP.NET"
        if platform.app is None and powered:
            for pattern, key in _POWERED_BY_PATTERNS:
                if re.search(pattern, powered, re.I):
                    platform.app = key
                    platform.evidence.append(f"애플리케이션: X-Powered-By: {powered}")
                    break
        if platform.app is None:
            for cookie in resp.header_all("set-cookie"):
                name = cookie.split("=", 1)[0].strip()
                for pattern, key in _COOKIE_PATTERNS:
                    if re.search(pattern, name, re.I):
                        platform.app = key
                        platform.evidence.append(f"애플리케이션: 쿠키 이름 {name}")
                        break
                if platform.app:
                    break
        if platform.web is None and resp.status >= 400:
            text = resp.text[:20000]
            m = re.search(r"<address>\s*(Apache|LiteSpeed)", text, re.I) or \
                re.search(r"<center>\s*(nginx|openresty)", text, re.I)
            if m:
                key = {"apache": "apache", "litespeed": "litespeed", "nginx": "nginx", "openresty": "nginx"}[m.group(1).lower()]
                platform.web = key
                platform.evidence.append(f"웹 서버: 오류 페이지 서명 ({m.group(1)})")
    for name in cnames or []:
        for suffix, cdn in _CNAME_SUFFIXES.items():
            if name.endswith(suffix) and platform.cdn is None:
                platform.cdn = cdn
                platform.evidence.append(f"CDN {CDN_LABELS[cdn]}: CNAME {name}")
    return platform
