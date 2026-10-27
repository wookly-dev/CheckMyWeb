"""HTTP methods: what OPTIONS advertises, and whether TRACE echoes requests.

Nothing state-changing (PUT/DELETE/...) is ever sent; only OPTIONS and TRACE.
"""
from __future__ import annotations

from ..models import Severity as S

NAME = "methods"
TITLE = "HTTP 메서드"
DEFAULT = True

RISKY = {"PUT", "DELETE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"}


def run(ctx) -> None:
    url = ctx.homepage.url if ctx.homepage else ctx.base_url

    r = ctx.get(url, method="OPTIONS", cache=False)
    if r is not None:
        allow = r.header("allow") or ""
        methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
        risky = sorted(methods & RISKY)
        if risky:
            ctx.add("methods.allow", S.LOW, f"OPTIONS 응답이 위험할 수 있는 메서드를 허용한다고 알립니다: {', '.join(risky)}",
                    detail="실제 동작 여부는 확인하지 않았습니다(쓰기 요청은 보내지 않음). "
                           "WebDAV 등이 의도치 않게 켜져 있다면 파일 업로드/삭제가 가능할 수 있습니다.",
                    evidence=f"{r.status} OPTIONS {url}\nAllow: {allow}",
                    fix=ctx.fix("methods_limit"))
        elif allow:
            ctx.add("methods.allow", S.PASS, "OPTIONS 응답에 위험한 메서드가 없습니다", evidence=f"Allow: {allow}")

    marker = "checkmyweb-trace-probe"
    r = ctx.get(url, method="TRACE", headers={"X-Checkmyweb-Trace": marker})
    if r is not None and r.status == 200 and marker in r.text:
        ctx.add("methods.trace", S.LOW, "TRACE 메서드가 활성화되어 있습니다",
                detail="요청을 그대로 되돌려주므로 다른 취약점과 결합하면 HttpOnly 쿠키나 인증 헤더가 노출될 수 있습니다 "
                       "(Cross-Site Tracing). Apache는 기본값이 On 입니다.",
                evidence=f"{r.status} TRACE {url}\n{r.text[:300]}",
                fix=ctx.fix("trace"),
                refs=["https://owasp.org/www-community/attacks/Cross_Site_Tracing"])
    elif r is not None:
        ctx.add("methods.trace", S.PASS, f"TRACE 메서드가 비활성화되어 있습니다 ({r.status})")
