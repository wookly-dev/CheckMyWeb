"""Browser security headers on the homepage response."""
from __future__ import annotations

import re

from ..models import Severity as S

NAME = "headers"
TITLE = "보안 헤더"
DEFAULT = True

MDN = "https://developer.mozilla.org/docs/Web/HTTP/Headers/"
OWASP = "https://owasp.org/www-project-secure-headers/"


def parse_csp(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens:
            directives.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return directives


def analyze_csp(value: str) -> list[tuple[str, S, str, str]]:
    """Returns (id, severity, title, detail) for weaknesses in a CSP header."""
    d = parse_csp(value)
    issues = []
    script = d.get("script-src", d.get("default-src"))
    if script is None:
        issues.append(("csp.no_script_src", S.MEDIUM, "CSP에 script-src/default-src가 없습니다",
                       "스크립트 출처가 제한되지 않아 XSS 방어 효과가 거의 없습니다."))
    else:
        has_nonce = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in script)
        strict_dynamic = "'strict-dynamic'" in script
        if "'unsafe-inline'" in script and not has_nonce:
            issues.append(("csp.unsafe_inline", S.MEDIUM, "CSP script-src에 'unsafe-inline'이 허용되어 있습니다",
                           "인라인 스크립트 주입(XSS)을 막지 못합니다. nonce 또는 hash 방식으로 전환하세요."))
        if "'unsafe-eval'" in script:
            issues.append(("csp.unsafe_eval", S.LOW, "CSP script-src에 'unsafe-eval'이 허용되어 있습니다",
                           "eval()/new Function() 기반 공격면이 남습니다."))
        wide = [t for t in script if t in ("*", "http:", "https:", "data:", "blob:") or t.startswith("*.")]
        if wide and not strict_dynamic:
            issues.append(("csp.wide_source", S.MEDIUM, f"CSP script-src가 너무 넓은 출처를 허용합니다: {' '.join(wide)}",
                           "공격자가 제어할 수 있는 임의 출처의 스크립트도 실행됩니다."))
    if "object-src" not in d and d.get("default-src") != ["'none'"]:
        issues.append(("csp.object_src", S.LOW, "CSP에 object-src 'none'이 없습니다",
                       "플러그인(<object>/<embed>)을 통한 스크립트 실행 경로가 남습니다."))
    if "base-uri" not in d:
        issues.append(("csp.base_uri", S.INFO, "CSP에 base-uri가 없습니다",
                       "<base> 태그 주입으로 상대 경로 스크립트를 가로챌 수 있습니다. base-uri 'self' 또는 'none'을 권장합니다."))
    return issues


def run(ctx) -> None:
    r = ctx.homepage
    if r is None:
        ctx.add("headers.unavailable", S.INFO, "홈페이지 응답을 받지 못해 헤더를 점검하지 못했습니다")
        return
    https = r.url.startswith("https://")
    evidence_url = f"{r.status} {r.url}"

    # Strict-Transport-Security
    hsts = r.header("strict-transport-security")
    if https and not hsts:
        ctx.add("headers.hsts", S.HIGH, "HSTS(Strict-Transport-Security) 헤더가 없습니다",
                detail="첫 접속이나 http:// 링크를 통한 접속 시 SSL stripping(HTTPS→HTTP 다운그레이드) 공격에 노출됩니다.",
                evidence=evidence_url,
                fix=ctx.fix("hsts"),
                refs=[MDN + "Strict-Transport-Security", "https://hstspreload.org/"])
    elif hsts:
        m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
        max_age = int(m.group(1)) if m else 0
        sub = "includesubdomains" in hsts.lower()
        if max_age == 0:
            ctx.add("headers.hsts", S.MEDIUM, "HSTS max-age가 0이거나 없어 HSTS가 비활성화되어 있습니다",
                    evidence=hsts, fix="max-age=31536000 (1년) 이상으로 설정하세요.")
        elif max_age < 15552000:
            ctx.add("headers.hsts", S.LOW, f"HSTS max-age가 짧습니다 ({max_age // 86400}일)",
                    detail="권장값은 최소 6개월, 일반적으로 1년(31536000) 이상입니다.", evidence=hsts,
                    fix="max-age=31536000 이상으로 늘리세요.")
        else:
            ctx.add("headers.hsts", S.PASS, "HSTS가 설정되어 있습니다", evidence=hsts)
        if max_age and not sub:
            ctx.add("headers.hsts.subdomains", S.INFO, "HSTS에 includeSubDomains가 없습니다",
                    detail="서브도메인을 통한 쿠키 주입 등을 막으려면 includeSubDomains를 권장합니다.", evidence=hsts)

    # Content-Security-Policy
    csp = r.header("content-security-policy")
    csp_ro = r.header("content-security-policy-report-only")
    if not csp:
        if csp_ro:
            ctx.add("headers.csp", S.LOW, "CSP가 Report-Only 모드로만 설정되어 있습니다",
                    detail="위반을 보고만 하고 차단하지 않습니다.", evidence=csp_ro,
                    fix="충분히 모니터링한 뒤 Content-Security-Policy 헤더로 전환하세요.")
        else:
            ctx.add("headers.csp", S.MEDIUM, "Content-Security-Policy(CSP) 헤더가 없습니다",
                    detail="CSP는 XSS·데이터 유출·클릭재킹 피해를 줄이는 핵심 방어선입니다.",
                    evidence=evidence_url,
                    fix=ctx.fix("csp"),
                    refs=[MDN + "Content-Security-Policy", "https://csp-evaluator.withgoogle.com/"])
    else:
        issues = analyze_csp(csp)
        for cid, sev, title, detail in issues:
            ctx.add(f"headers.{cid}", sev, title, detail=detail, evidence=csp,
                    refs=["https://csp-evaluator.withgoogle.com/"])
        if not any(sev >= S.LOW for _, sev, _, _ in issues):
            ctx.add("headers.csp", S.PASS, "CSP가 설정되어 있습니다", evidence=csp)

    # Clickjacking
    xfo = (r.header("x-frame-options") or "").strip()
    frame_ancestors = "frame-ancestors" in parse_csp(csp or "")
    if frame_ancestors or xfo.upper() in ("DENY", "SAMEORIGIN"):
        ctx.add("headers.clickjacking", S.PASS, "클릭재킹 방어가 설정되어 있습니다",
                evidence=f"X-Frame-Options: {xfo or '-'} / CSP frame-ancestors: {'있음' if frame_ancestors else '없음'}")
    elif xfo:
        ctx.add("headers.clickjacking", S.LOW, f"X-Frame-Options 값이 올바르지 않습니다: {xfo}",
                detail="ALLOW-FROM 등은 최신 브라우저가 무시합니다.", evidence=xfo,
                fix="X-Frame-Options: SAMEORIGIN 또는 CSP frame-ancestors 'self' 를 사용하세요.")
    else:
        ctx.add("headers.clickjacking", S.MEDIUM, "클릭재킹 방어 헤더가 없습니다 (X-Frame-Options / frame-ancestors)",
                detail="다른 사이트가 이 페이지를 투명 iframe으로 덮어 사용자의 클릭을 가로챌 수 있습니다.",
                evidence=evidence_url,
                fix=ctx.fix("xfo"),
                refs=[MDN + "X-Frame-Options"])

    # X-Content-Type-Options
    xcto = (r.header("x-content-type-options") or "").strip().lower()
    if xcto == "nosniff":
        ctx.add("headers.xcto", S.PASS, "X-Content-Type-Options: nosniff 가 설정되어 있습니다")
    else:
        ctx.add("headers.xcto", S.LOW, "X-Content-Type-Options: nosniff 헤더가 없습니다",
                detail="브라우저가 Content-Type을 추측(MIME sniffing)해 업로드 파일 등을 스크립트로 실행할 수 있습니다.",
                evidence=evidence_url, fix=ctx.fix("xcto"),
                refs=[MDN + "X-Content-Type-Options"])

    # Referrer-Policy
    rp = (r.header("referrer-policy") or "").strip().lower()
    if not rp:
        ctx.add("headers.referrer", S.LOW, "Referrer-Policy 헤더가 없습니다",
                detail="최신 브라우저 기본값(strict-origin-when-cross-origin)에 의존하게 됩니다. "
                       "명시적으로 설정하면 구형 브라우저에서도 URL 경로·쿼리 유출을 막을 수 있습니다.",
                evidence=evidence_url, fix=ctx.fix("referrer"),
                refs=[MDN + "Referrer-Policy"])
    elif rp.split(",")[-1].strip() in ("unsafe-url", "no-referrer-when-downgrade"):
        ctx.add("headers.referrer", S.LOW, f"Referrer-Policy가 느슨합니다: {rp}",
                detail="외부 사이트로 전체 URL(경로·쿼리)이 전송됩니다.", evidence=rp,
                fix="strict-origin-when-cross-origin 또는 no-referrer 를 사용하세요.")
    else:
        ctx.add("headers.referrer", S.PASS, f"Referrer-Policy가 설정되어 있습니다: {rp}")

    # Permissions-Policy
    if r.header("permissions-policy"):
        ctx.add("headers.permissions", S.PASS, "Permissions-Policy가 설정되어 있습니다",
                evidence=r.header("permissions-policy"))
    else:
        ctx.add("headers.permissions", S.LOW, "Permissions-Policy 헤더가 없습니다",
                detail="카메라·마이크·위치 등 사용하지 않는 브라우저 기능을 차단해 두면 삽입된 서드파티 코드의 악용을 막을 수 있습니다.",
                evidence=evidence_url,
                fix=ctx.fix("permissions"),
                refs=[MDN + "Permissions-Policy"])

    # Cross-origin isolation headers (informational)
    missing = [h for h in ("cross-origin-opener-policy", "cross-origin-resource-policy") if not r.header(h)]
    if missing:
        ctx.add("headers.cross_origin", S.INFO, "Cross-Origin 격리 헤더 일부가 없습니다: " + ", ".join(missing),
                detail="COOP: same-origin 은 window.opener 기반 공격과 XS-Leaks를 줄여줍니다. 필수는 아니지만 권장됩니다.",
                refs=[OWASP])

    # Deprecated X-XSS-Protection
    xxp = (r.header("x-xss-protection") or "").strip()
    if xxp and not xxp.startswith("0"):
        ctx.add("headers.xxp", S.INFO, f"폐기된 X-XSS-Protection 헤더를 사용합니다: {xxp}",
                detail="최신 브라우저는 무시하며, 구형 브라우저에서는 오히려 정보 유출에 악용된 사례가 있습니다. "
                       "제거하거나 0으로 설정하고 CSP를 사용하세요.", refs=[MDN + "X-XSS-Protection"])
