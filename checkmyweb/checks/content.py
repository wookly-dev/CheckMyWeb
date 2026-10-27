"""Homepage HTML: mixed content, SRI, insecure forms, outdated JS libraries, security.txt, robots.txt."""
from __future__ import annotations

import datetime as dt
import re
import urllib.parse
from html.parser import HTMLParser

from ..models import Severity as S

NAME = "content"
TITLE = "페이지 콘텐츠"
DEFAULT = True


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts: list[dict] = []
        self.styles: list[dict] = []
        self.passive: list[tuple[str, str]] = []  # (tag, url) images/media
        self.frames: list[tuple[str, str]] = []
        self.forms: list[dict] = []
        self.password_fields = 0
        self.inline_scripts = 0

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script":
            if a.get("src"):
                self.scripts.append(a)
            else:
                self.inline_scripts += 1
        elif tag == "link" and "stylesheet" in a.get("rel", "").lower() and a.get("href"):
            self.styles.append(a)
        elif tag in ("img", "audio", "video", "source", "track") and a.get("src"):
            self.passive.append((tag, a["src"]))
        elif tag in ("iframe", "frame", "embed") and a.get("src"):
            self.frames.append((tag, a["src"]))
        elif tag == "object" and a.get("data"):
            self.frames.append((tag, a["data"]))
        elif tag == "form":
            self.forms.append(a)
        elif tag == "input" and a.get("type", "").lower() == "password":
            self.password_fields += 1


DYNAMIC_HOSTS = re.compile(
    r"(^|\.)(googlesyndication\.com|googletagmanager\.com|google-analytics\.com|googleadservices\.com|"
    r"doubleclick\.net|adservice\.google\.com|connect\.facebook\.net|t1\.daumcdn\.net|wcs\.naver\.net|"
    r"static\.cloudflareinsights\.com|cdn\.channel\.io|challenges\.cloudflare\.com|www\.google\.com|"
    r"www\.gstatic\.com|js\.stripe\.com|pagead2\.googlesyndication\.com)$", re.I)


def _version(text: str) -> tuple[int, ...]:
    return tuple(int(x) for x in text.split("."))


# (library, URL pattern, banner pattern in file, predicate(version) -> vulnerable, advisory)
LIBRARIES = [
    ("jQuery", r"jquery(?:@|/|-|\.)v?(\d+\.\d+\.\d+)", r"jQuery (?:JavaScript Library )?v(\d+\.\d+\.\d+)",
     lambda v: v < (3, 5, 0), "3.5.0 미만은 CVE-2020-11022/11023 (htmlPrefilter XSS)에 취약합니다."),
    ("Bootstrap", r"bootstrap(?:@|/|-)v?(\d+\.\d+\.\d+)", r"Bootstrap v(\d+\.\d+\.\d+)",
     lambda v: v < (3, 4, 1) or (4, 0, 0) <= v < (4, 3, 1), "3.4.1 / 4.3.1 미만은 CVE-2019-8331 (tooltip XSS)에 취약합니다."),
    ("AngularJS", r"angular(?:js)?(?:@|/|-)v?(1\.\d+\.\d+)", r"AngularJS v(1\.\d+\.\d+)",
     lambda v: True, "AngularJS(1.x)는 2022년 지원이 종료되어 보안 패치가 나오지 않습니다."),
    ("Moment.js", r"moment(?:@|/|-)v?(\d+\.\d+\.\d+)", r"//! moment\.js\s*\n//! version : (\d+\.\d+\.\d+)",
     lambda v: v < (2, 29, 4), "2.29.4 미만은 CVE-2022-31129 (ReDoS) / CVE-2022-24785 (경로 조작)에 취약합니다."),
]


def _abs(page_url: str, ref: str) -> str:
    return urllib.parse.urljoin(page_url, ref.strip())


def _check_libraries(ctx, page_url: str, script_urls: list[str]) -> None:
    page_host = urllib.parse.urlsplit(page_url).hostname
    found: dict[str, tuple[str, str]] = {}
    for url in script_urls:
        for name, url_rx, _, _, _ in LIBRARIES:
            m = re.search(url_rx, url, re.I)
            if m and name not in found:
                found[name] = (m.group(1), url)
    # Self-hosted files usually carry the version only in their banner comment.
    same_origin = [u for u in script_urls if urllib.parse.urlsplit(u).hostname == page_host][:6]
    for url in same_origin:
        r = ctx.get(url, max_body=4096)
        if r is None or r.status != 200:
            continue
        head = r.text
        for name, _, banner_rx, _, _ in LIBRARIES:
            m = re.search(banner_rx, head)
            if m and name not in found:
                found[name] = (m.group(1), url)

    for name, url_rx, banner_rx, vulnerable, advisory in LIBRARIES:
        if name not in found:
            continue
        version, url = found[name]
        if vulnerable(_version(version)):
            ctx.add(f"content.lib.{name.lower()}", S.MEDIUM, f"취약한 {name} {version} 을(를) 사용합니다",
                    detail=advisory, evidence=url, fix=f"{name}를 최신 버전으로 업데이트하세요.",
                    refs=["https://security.snyk.io/"])
        else:
            ctx.add(f"content.lib.{name.lower()}", S.PASS, f"{name} {version} — 알려진 주요 취약 버전이 아닙니다",
                    evidence=url)


def _check_security_txt(ctx) -> None:
    for path in ("/.well-known/security.txt", "/security.txt"):
        r = ctx.get(path, max_body=65536, root=True)
        if r is not None and r.status == 200 and not r.looks_like_html and re.search(r"^Contact:", r.text, re.M | re.I):
            m = re.search(r"^Expires:\s*(\S+)", r.text, re.M | re.I)
            if m:
                try:
                    expires = dt.datetime.fromisoformat(m.group(1).replace("Z", "+00:00"))
                    if expires.tzinfo and expires < dt.datetime.now(dt.timezone.utc):
                        ctx.add("content.security_txt", S.LOW, "security.txt 의 Expires 가 지났습니다",
                                evidence=f"{r.url}\n{m.group(0)}", fix="Expires 날짜를 갱신하세요 (1년 이내 권장).")
                        return
                except ValueError:
                    pass
            ctx.add("content.security_txt", S.PASS, "security.txt 가 게시되어 있습니다", evidence=r.url)
            return
    ctx.add("content.security_txt", S.INFO, "security.txt 가 없습니다",
            detail="보안 연구자가 취약점을 제보할 연락처를 알 수 있도록 /.well-known/security.txt 게시를 권장합니다 (RFC 9116).",
            fix=f"예:\nContact: mailto:security@{ctx.apex}\nExpires: 2027-12-31T00:00:00Z\nPreferred-Languages: ko, en",
            refs=["https://securitytxt.org/", "https://www.rfc-editor.org/rfc/rfc9116"])


def _check_robots(ctx) -> None:
    r = ctx.get("/robots.txt", max_body=65536, root=True)
    if r is None or r.status != 200 or r.looks_like_html:
        return
    disallowed = re.findall(r"^\s*Disallow:\s*(\S+)", r.text, re.M | re.I)
    sensitive = [p for p in disallowed
                 if re.search(r"admin|backup|bak|private|secret|config|db|sql|dump|test|dev|old|tmp|staging|internal", p, re.I)]
    if sensitive:
        ctx.add("content.robots", S.INFO, "robots.txt 에 민감해 보이는 경로가 나열되어 있습니다",
                detail="robots.txt 는 누구나 볼 수 있어 숨기고 싶은 경로의 지도가 됩니다. "
                       "접근 통제는 인증/IP 제한으로 하고 robots.txt 에는 검색 제외 목적의 경로만 두세요.",
                evidence=f"{r.url}\n" + "\n".join(sensitive[:20]))


def run(ctx) -> None:
    home = ctx.homepage
    if home is None or not home.looks_like_html:
        ctx.add("content.unavailable", S.INFO, "홈페이지 HTML을 받지 못해 콘텐츠 점검을 건너뜁니다")
        _check_security_txt(ctx)
        return

    parser = PageParser()
    try:
        parser.feed(home.text)
    except Exception as e:  # malformed markup should not stop the scan
        ctx.log(f"HTML 파싱 오류: {e}")
    page_url = home.url
    page_host = urllib.parse.urlsplit(page_url).hostname
    https = page_url.startswith("https://")

    scripts = [_abs(page_url, s["src"]) for s in parser.scripts]
    styles = [_abs(page_url, s["href"]) for s in parser.styles]
    ctx.meta["page"] = {"scripts": len(scripts), "inline_scripts": parser.inline_scripts,
                        "stylesheets": len(styles), "forms": len(parser.forms)}

    # Mixed content
    if https:
        active = [u for u in scripts + styles + [_abs(page_url, u) for _, u in parser.frames] if u.startswith("http://")]
        passive = [_abs(page_url, u) for _, u in parser.passive if _abs(page_url, u).startswith("http://")]
        if active:
            ctx.add("content.mixed.active", S.MEDIUM, "HTTPS 페이지가 HTTP로 스크립트/스타일/프레임을 불러옵니다 (Mixed Content)",
                    detail="브라우저가 차단하여 기능이 깨지거나, 허용될 경우 중간자가 스크립트를 바꿔치기할 수 있습니다.",
                    evidence="\n".join(active[:15]), fix="모든 리소스 URL을 https:// 로 바꾸세요.")
        if passive:
            ctx.add("content.mixed.passive", S.LOW, "HTTPS 페이지가 HTTP로 이미지/미디어를 불러옵니다",
                    evidence="\n".join(passive[:15]), fix="모든 리소스 URL을 https:// 로 바꾸세요.")
        if not active and not passive:
            ctx.add("content.mixed", S.PASS, "혼합 콘텐츠(Mixed Content)가 없습니다")

    # Subresource Integrity for third-party scripts/styles. Ad/analytics loaders change
    # content without a URL change, so SRI cannot be applied to them.
    external = [(u, item) for u, item in zip(scripts + styles, parser.scripts + parser.styles)
                if urllib.parse.urlsplit(u).hostname not in (page_host, None)]
    dynamic = [u for u, _ in external if DYNAMIC_HOSTS.search(urllib.parse.urlsplit(u).hostname or "")]
    no_sri = [u for u, item in external if not item.get("integrity") and u not in dynamic]
    if no_sri:
        ctx.add("content.sri", S.LOW, f"외부 CDN 리소스 {len(no_sri)}개에 SRI(integrity) 검증이 없습니다",
                detail="CDN이 침해되거나 파일이 변조되면 악성 스크립트/스타일이 그대로 적용됩니다 (공급망 공격). "
                       "버전이 고정된 CDN 파일은 SRI 해시를 붙일 수 있습니다.",
                evidence="\n".join(no_sri[:15]),
                fix='<link href="..." integrity="sha384-..." crossorigin="anonymous"> 처럼 해시를 지정하세요.\n'
                    "해시 생성: https://www.srihash.org/ 또는 "
                    "curl -s URL | openssl dgst -sha384 -binary | openssl base64 -A",
                refs=["https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity"])
    elif external and len(dynamic) < len(external):
        ctx.add("content.sri", S.PASS, "외부 CDN 리소스에 SRI가 적용되어 있습니다")
    if dynamic:
        ctx.add("content.third_party", S.INFO, f"동적 서드파티 스크립트 {len(dynamic)}개를 불러옵니다 (광고/분석)",
                detail="이 스크립트들은 SRI를 적용할 수 없어 해당 업체를 신뢰하는 구조입니다. "
                       "CSP를 도입할 때 이 출처들을 script-src 에 허용해야 합니다.",
                evidence="\n".join(dynamic[:15]))

    # Forms
    for form in parser.forms:
        action = _abs(page_url, form.get("action") or page_url)
        if action.startswith("http://"):
            ctx.add("content.form.insecure", S.HIGH, "폼이 HTTP(평문)로 전송됩니다",
                    detail="입력값(비밀번호 등)이 암호화되지 않은 채 전송됩니다.",
                    evidence=f'<form action="{form.get("action")}">', fix="폼 action을 https:// 로 바꾸세요.")
    if parser.password_fields and not https:
        ctx.add("content.password.http", S.HIGH, "HTTP 페이지에 비밀번호 입력란이 있습니다",
                fix="로그인 페이지는 반드시 HTTPS로 제공하세요.")

    _check_libraries(ctx, page_url, scripts)
    _check_security_txt(ctx)
    _check_robots(ctx)
