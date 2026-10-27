"""CORS: does the server reflect arbitrary Origins (possibly with credentials)?"""
from __future__ import annotations

from ..models import Severity as S

NAME = "cors"
TITLE = "CORS 설정"
DEFAULT = True


def run(ctx) -> None:
    url = ctx.homepage.url if ctx.homepage else ctx.base_url
    tests = [
        ("arbitrary", "임의 외부 Origin", "https://checkmyweb-cors-test.example"),
        ("null", "null Origin", "null"),
        ("suffix", "도메인 접미사 우회 Origin", f"https://{ctx.apex}.checkmyweb-cors-test.example"),
        ("http", "HTTP Origin", f"http://{ctx.host}"),
    ]
    problems, wildcard = 0, False
    for tid, label, origin in tests:
        r = ctx.get(url, headers={"Origin": origin})
        if r is None:
            continue
        acao = (r.header("access-control-allow-origin") or "").strip()
        creds = (r.header("access-control-allow-credentials") or "").strip().lower() == "true"
        evidence = f"Origin: {origin}\n-> Access-Control-Allow-Origin: {acao}\n" \
                   f"-> Access-Control-Allow-Credentials: {r.header('access-control-allow-credentials') or '-'}"
        if acao == "*":
            wildcard = True
        elif acao == origin:
            problems += 1
            if tid == "http":
                ctx.add("cors.http_origin", S.LOW, "CORS가 HTTP(평문) Origin을 신뢰합니다",
                        detail="중간자가 HTTP 페이지에 스크립트를 주입해 HTTPS 응답을 읽을 수 있습니다.", evidence=evidence,
                        fix="허용 Origin을 https:// 로만 제한하세요.")
            else:
                ctx.add(f"cors.reflect.{tid}", S.HIGH if creds else S.MEDIUM,
                        f"CORS가 {label}을(를) 그대로 허용합니다" + (" (자격증명 포함)" if creds else ""),
                        detail="악성 사이트가 방문자의 브라우저로 이 사이트의 응답을 읽어갈 수 있습니다"
                               + (" — 쿠키가 함께 전송되므로 로그인 사용자의 데이터가 유출될 수 있습니다." if creds else "."),
                        evidence=evidence,
                        fix="요청 Origin을 그대로 반사하지 말고, 허용 목록(allowlist)과 정확히 일치할 때만 응답 헤더를 넣으세요.",
                        refs=["https://portswigger.net/web-security/cors"])
    if wildcard:
        ctx.add("cors.wildcard", S.INFO, "Access-Control-Allow-Origin: * (공개 리소스)",
                detail="자격증명(쿠키)은 함께 전송되지 않으므로 공개 데이터라면 문제없습니다. "
                       "인증이 필요한 API라면 와일드카드를 쓰지 마세요.")
    if not problems:
        ctx.add("cors.ok", S.PASS, "임의 Origin을 반사하는 CORS 설정이 발견되지 않았습니다")
