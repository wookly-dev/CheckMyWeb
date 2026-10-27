"""Information leakage: version banners, generator tags, verbose error pages."""
from __future__ import annotations

import html
import re
import secrets

from ..models import Severity as S

NAME = "disclosure"
TITLE = "정보 노출"
DEFAULT = True

VERSION_HEADERS = [
    "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-drupal-cache",
    "x-runtime", "x-version", "x-backend-server", "x-served-by", "x-litespeed-cache",
]

ERROR_PATTERNS = [
    (r"Traceback \(most recent call last\)", "Python 스택 트레이스"),
    (r"at [\w$.]+\([\w]+\.java:\d+\)", "Java 스택 트레이스"),
    (r"(Fatal error|Warning|Parse error|Notice)</b>:.+ on line <b>\d+", "PHP 오류 메시지"),
    (r"Stack trace:\s*<br|#0 /\S+\.php\(\d+\)", "PHP 스택 트레이스"),
    (r"Microsoft OLE DB|ODBC Driver|SQLSTATE\[", "DB 오류 메시지"),
    (r"You have an error in your SQL syntax", "SQL 오류 메시지"),
    (r"Whoops! There was an error|Whoops, looks like something went wrong", "Laravel/Whoops 디버그 페이지"),
    (r"DEBUG = True|Django tried these URL patterns", "Django DEBUG 모드"),
]

def _generator(text: str) -> str | None:
    for pattern in (r'<meta[^>]+name=["\']generator["\'][^>]*content=["\']([^"\']+)',
                    r'<meta[^>]+content=["\']([^"\']+)["\'][^>]*name=["\']generator["\']'):
        m = re.search(pattern, text, re.I)
        if m:
            return html.unescape(m.group(1))
    return None


def _signature(text: str) -> str | None:
    m = re.search(r"<address>(.*?)</address>", text, re.I | re.S)
    if m and re.search(r"\d", m.group(1)):
        return re.sub(r"<[^>]+>", "", m.group(1)).strip()
    m = re.search(r"<hr><center>((?:nginx|openresty|Microsoft-IIS)[^<]*\d[^<]*)</center>", text, re.I)
    return m.group(1).strip() if m else None


def run(ctx) -> None:
    home = ctx.homepage
    if home is None:
        return

    server = home.header("server")
    if server and re.search(r"/\s*\d", server):
        ctx.add("disclosure.server", S.LOW, "Server 헤더에 소프트웨어 버전이 노출됩니다",
                detail="공격자가 버전별 알려진 취약점(CVE)을 바로 대입해 볼 수 있습니다. "
                       "(배포판 패키지는 보안 패치가 백포트되므로 버전 숫자만으로 취약 여부를 판단할 수는 없습니다.)",
                evidence=f"Server: {server}", fix=ctx.fix("server_tokens"))
    elif server:
        ctx.add("disclosure.server", S.PASS, f"Server 헤더에 버전 정보가 없습니다 ({server})")
    else:
        ctx.add("disclosure.server", S.PASS, "Server 헤더가 노출되지 않습니다")

    leaked = [f"{h}: {home.header(h)}" for h in VERSION_HEADERS if home.header(h)]
    if leaked:
        ctx.add("disclosure.headers", S.LOW, "기술 스택을 드러내는 응답 헤더가 있습니다",
                evidence="\n".join(leaked),
                fix=ctx.fix("powered_by"))

    gen = _generator(home.text) if home.looks_like_html else None
    if gen:
        ctx.add("disclosure.generator", S.LOW if re.search(r"\d", gen) else S.INFO,
                f"페이지에 generator 메타 태그가 있습니다: {gen}",
                detail="CMS 종류와 버전이 노출됩니다.", evidence=f'<meta name="generator" content="{gen}">',
                fix=ctx.fix("generator"))

    # Error pages: a missing path and a malformed request.
    probe = f"checkmyweb-{secrets.token_hex(6)}"
    not_found = ctx.get(probe, max_body=65536)
    bad = ctx.get("%", max_body=65536)
    signatures = []
    for resp in (not_found, bad):
        if resp is None:
            continue
        sig = _signature(resp.text)
        if sig:
            signatures.append(f"{resp.status} {resp.url}\n  {sig}")
        for pattern, label in ERROR_PATTERNS:
            if re.search(pattern, resp.text):
                ctx.add("disclosure.error_detail", S.MEDIUM, f"오류 페이지에 내부 정보가 노출됩니다: {label}",
                        detail="스택 트레이스·파일 경로·쿼리 등 내부 구현이 공격자에게 보입니다.",
                        evidence=f"{resp.status} {resp.url}",
                        fix=ctx.fix("error_pages"))
                break
    if signatures:
        ctx.add("disclosure.signature", S.LOW, "오류 페이지 하단에 서버 서명(버전)이 표시됩니다",
                evidence="\n".join(signatures), fix=ctx.fix("server_tokens"))

    if not_found is not None:
        ctx.meta["soft_404"] = not_found.status == 200
        if not_found.status == 200:
            ctx.add("disclosure.soft404", S.INFO, "존재하지 않는 경로에 200 OK로 응답합니다 (soft 404)",
                    detail="SPA/CMS에서는 흔한 동작이지만, 404를 반환하면 스캐너와 검색엔진이 실제 페이지를 구분하기 쉽습니다.",
                    evidence=f"{not_found.status} {not_found.url}")
