"""Set-Cookie attributes (Secure, HttpOnly, SameSite, prefixes)."""
from __future__ import annotations

import re

from ..models import Severity as S

NAME = "cookies"
TITLE = "쿠키 보안 속성"
DEFAULT = True

SENSITIVE = re.compile(r"sess|sid\b|token|auth|jwt|login|remember|csrf|xsrf|phpsessid|jsessionid|asp\.net|wordpress_", re.I)

# Pages that commonly set session cookies, fetched in addition to the homepage.
EXTRA_PATHS = ["login", "wp-login.php", "admin/"]  # relative to the scanned base path


def parse_set_cookie(header: str) -> tuple[str, dict[str, str]]:
    parts = [p.strip() for p in header.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs = {}
    for p in parts[1:]:
        if not p:
            continue
        key, _, value = p.partition("=")
        attrs[key.strip().lower()] = value.strip()
    return name, attrs


def cookie_issues(name: str, attrs: dict[str, str], https: bool) -> list[tuple[S, str]]:
    sensitive = bool(SENSITIVE.search(name))
    issues = []
    samesite = attrs.get("samesite", "").lower()
    if https and "secure" not in attrs:
        issues.append((S.MEDIUM if sensitive else S.LOW, "Secure 속성 없음 (HTTP로도 전송될 수 있음)"))
    if "httponly" not in attrs:
        issues.append((S.MEDIUM if sensitive else S.INFO, "HttpOnly 속성 없음 (JavaScript로 읽을 수 있음)"))
    if not samesite:
        issues.append((S.LOW if sensitive else S.INFO, "SameSite 속성 없음 (브라우저 기본값 Lax에 의존)"))
    elif samesite == "none" and "secure" not in attrs:
        issues.append((S.MEDIUM, "SameSite=None 인데 Secure 가 없음 (브라우저가 거부)"))
    if name.startswith("__Host-") and ("secure" not in attrs or "domain" in attrs or attrs.get("path") != "/"):
        issues.append((S.LOW, "__Host- 접두사 요구사항(Secure, Path=/, Domain 없음) 위반"))
    if name.startswith("__Secure-") and "secure" not in attrs:
        issues.append((S.LOW, "__Secure- 접두사인데 Secure 속성 없음"))
    return issues


def run(ctx) -> None:
    for path in EXTRA_PATHS:
        ctx.get(path, max_body=65536)

    seen: dict[str, tuple[str, str]] = {}
    for resp in ctx.responses():
        for header in resp.header_all("set-cookie"):
            name, _ = parse_set_cookie(header)
            seen.setdefault(name, (resp.url, header))

    if not seen:
        ctx.add("cookies.none", S.INFO, "점검한 페이지에서 설정되는 쿠키가 없습니다",
                detail="로그인 등 쿠키를 사용하는 기능이 있다면 해당 페이지 URL로 별도 확인이 필요합니다.")
        return

    for name, (url, header) in seen.items():
        _, attrs = parse_set_cookie(header)
        issues = cookie_issues(name, attrs, url.startswith("https://"))
        shown = header if len(header) < 200 else header[:200] + "..."
        worst = max((sev for sev, _ in issues), default=S.PASS)
        if worst <= S.INFO:
            ctx.add(f"cookies.{name}", S.PASS, f"쿠키 '{name}' 보안 속성 양호",
                    detail="\n".join(msg for _, msg in issues), evidence=f"{url}\nSet-Cookie: {shown}")
            continue
        ctx.add(f"cookies.{name}", worst, f"쿠키 '{name}' 보안 속성 미흡",
                detail="\n".join(f"- {msg}" for _, msg in issues),
                evidence=f"{url}\nSet-Cookie: {shown}",
                fix=ctx.fix("cookie_flags"),
                refs=["https://developer.mozilla.org/docs/Web/HTTP/Cookies#restrict_access_to_cookies"])
