"""HTTP -> HTTPS redirection and the www / apex variants."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from .. import remedies
from ..models import Severity as S

NAME = "redirects"
TITLE = "HTTPS 리다이렉트"
DEFAULT = True


PASSWORD_INPUT = re.compile(r"<input[^>]+type\s*=\s*[\"']?password", re.I)


def _chain_text(chain) -> str:
    return "\n".join(f"{r.status} {r.url}" + (f" -> {r.location}" if r.is_redirect else "") for r in chain)


def _check_http(ctx, url: str, label: str) -> None:
    host = urlsplit(url).hostname
    chain = ctx.follow(url)
    if not chain:
        ctx.add(f"redirects.http.{label}", S.INFO, f"{url} 에 응답이 없습니다 (HTTP 포트 닫힘)",
                detail="HTTP 포트를 닫아두는 것도 방법이지만, 주소창에 도메인만 입력하는 사용자를 위해 "
                       "HTTPS로 리다이렉트하는 80 포트를 두는 것이 일반적입니다.")
        return
    first, final = chain[0], chain[-1]
    evidence = _chain_text(chain)
    if not final.url.startswith("https://"):
        login = final.looks_like_html and PASSWORD_INPUT.search(final.text)
        title = f"{url} 접속이 HTTPS로 전환되지 않습니다"
        detail = "평문 HTTP로 페이지가 제공되어 중간자(MITM)가 내용을 엿보거나 변조할 수 있습니다."
        if login:
            title += " (평문 로그인 페이지)"
            detail += (f"\n{final.url} 에 비밀번호 입력란이 있어, http:// 로 접속한 사용자의 아이디·비밀번호와 "
                       "세션 쿠키가 암호화 없이 전송됩니다. 같은 Wi-Fi 등에서 그대로 탈취될 수 있습니다.")
        ctx.add(f"redirects.http.{label}", S.HIGH, title, detail=detail, evidence=evidence,
                fix=remedies.render("http_redirect", ctx.platform, host=host))
        return
    if first.is_redirect and first.location.startswith("https://"):
        ctx.add(f"redirects.http.{label}", S.PASS, f"{url} 가 HTTPS로 리다이렉트됩니다", evidence=evidence)
    else:
        ctx.add(f"redirects.http.{label}", S.LOW, f"{url} 가 다른 HTTP 주소를 거쳐 HTTPS로 이동합니다",
                detail="첫 번째 리다이렉트가 HTTPS가 아니면 그 구간은 평문으로 노출되고 HSTS도 적용되지 않습니다.",
                evidence=evidence, fix="첫 응답에서 바로 https:// 주소로 리다이렉트하세요.")
    if first.status in (302, 303, 307):
        ctx.add(f"redirects.http.{label}.temporary", S.INFO, f"임시 리다이렉트({first.status})를 사용합니다",
                detail="영구 이동에는 301 또는 308을 쓰는 것이 캐시와 검색엔진에 유리합니다.", evidence=evidence)


def run(ctx) -> None:
    http_url = ctx.http_url
    if http_url:
        _check_http(ctx, http_url, "main")
    else:
        ctx.add("redirects.http.unknown", S.INFO, "HTTP 포트를 알 수 없어 리다이렉트 점검을 건너뛰었습니다",
                detail="HTTPS를 비표준 포트로 지정하면 짝이 되는 HTTP 포트를 추정하지 않습니다. "
                       "--http-port 8080 처럼 지정하면 점검합니다.")

    other = ctx.variant
    if not other:
        return

    _check_http(ctx, f"http://{other}/", "variant")
    chain = ctx.follow(f"https://{other}/")
    if not chain:
        ctx.add("redirects.variant.https", S.LOW, f"https://{other}/ 에 연결할 수 없습니다",
                detail=f"{other} 가 DNS에는 있지만 HTTPS 응답이 없습니다.")
        return
    if chain[0].insecure:
        ctx.add("redirects.variant.cert", S.MEDIUM, f"https://{other}/ 의 인증서 검증에 실패합니다",
                detail="사용자가 이 주소로 접속하면 브라우저 경고가 표시됩니다.", evidence=_chain_text(chain),
                fix=f"인증서 SAN에 {other} 를 포함하세요.")
    main_final = ctx.homepage.url if ctx.homepage else ""
    if main_final and urlsplit(chain[-1].url).hostname == urlsplit(main_final).hostname:
        ctx.add("redirects.variant.canonical", S.PASS, f"{other} 가 대표 주소로 통일됩니다", evidence=_chain_text(chain))
    else:
        ctx.add("redirects.variant.canonical", S.INFO, f"{other} 와 {ctx.host} 가 서로 다른 최종 주소를 사용합니다",
                detail="같은 콘텐츠를 두 주소로 제공하면 쿠키/HSTS 범위가 나뉘고 SEO에도 불리합니다. "
                       "한쪽으로 301 리다이렉트하는 것을 권장합니다.",
                evidence=_chain_text(chain) + f"\n(대표 주소: {main_final})")
