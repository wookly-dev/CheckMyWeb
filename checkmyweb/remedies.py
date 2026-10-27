"""Remediation snippets per platform.

Each topic maps platform keys (web server, application platform, CDN, or
"generic") to the configuration that fixes the finding there. render() picks
the entries that match the detected platform, so an nginx site gets nginx
syntax and a site behind Cloudflare is pointed at the dashboard first.
@HOST@ in a snippet is replaced with the scanned host name.
"""
from __future__ import annotations

from .fingerprint import APP_LABELS, CDN_LABELS, WEB_LABELS, Platform

LABELS = {**WEB_LABELS, **APP_LABELS, **CDN_LABELS, "cdn": "CDN", "generic": "공통"}

MOZILLA_INTERMEDIATE = ("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
                        "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
                        "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305")


def _header(name: str, value: str, helmet: str, note: str = "") -> dict[str, str]:
    entries = {
        "apache": f'Header always set {name} "{value}"\n(httpd.conf의 VirtualHost 또는 .htaccess, mod_headers 필요)',
        "litespeed": f'Header always set {name} "{value}"\n(.htaccess — LiteSpeed는 Apache의 Header 지시어를 지원)',
        "nginx": f'add_header {name} "{value}" always;\n(server 블록 — location에 add_header가 따로 있으면 거기에도 넣어야 상속됩니다)',
        "iis": f'<add name="{name}" value="{value}" />\n(web.config → system.webServer/httpProtocol/customHeaders)',
        "caddy": f'header {name} "{value}"',
        "express": helmet,
        "cloudflare": f"Rules → Transform Rules → Modify Response Header 에서 {name}: {value} 추가\n(또는 오리진 서버에서 설정)",
        "cdn": f"CDN 콘솔의 응답 헤더 규칙에서 {name}: {value} 추가 (또는 오리진 서버에서 설정)",
    }
    if note:
        entries["note"] = note
    return entries


FIXES: dict[str, dict[str, str]] = {
    "hsts": {
        **_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains",
                  "app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }))",
                  "includeSubDomains는 모든 서브도메인이 HTTPS를 지원할 때만 넣으세요."),
        "apache": 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"\n'
                  "(HTTPS용 <VirtualHost *:443> 안, mod_headers 필요)",
        "cloudflare": "SSL/TLS → Edge Certificates → HTTP Strict Transport Security (HSTS) 활성화",
    },
    "csp": _header("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
                   "app.use(helmet())  // 기본 CSP 포함, 필요한 출처는 contentSecurityPolicy.directives 로 추가",
                   "외부 스크립트(광고·분석·CDN)를 쓰면 해당 출처를 추가해야 합니다. "
                   "먼저 Content-Security-Policy-Report-Only 로 바꿔 넣고 브라우저 콘솔 경고를 확인한 뒤 전환하세요."),
    "xfo": _header("X-Frame-Options", "SAMEORIGIN", "app.use(helmet.frameguard({ action: 'sameorigin' }))",
                   "CSP를 쓴다면 frame-ancestors 'self' 로도 같은 효과를 냅니다."),
    "xcto": _header("X-Content-Type-Options", "nosniff", "app.use(helmet.noSniff())"),
    "referrer": _header("Referrer-Policy", "strict-origin-when-cross-origin",
                        "app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }))"),
    "permissions": _header("Permissions-Policy", "camera=(), microphone=(), geolocation=()",
                           "res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')",
                           "사이트가 실제로 쓰는 기능(예: 지도 → geolocation)은 목록에서 빼세요."),
    "server_tokens": {
        "apache": "ServerTokens Prod\nServerSignature Off\n(httpd.conf 또는 conf.d/security.conf, 재시작 필요)",
        "litespeed": "WebAdmin 콘솔 → Server → General 의 서버 서명(Server Signature) 설정을 'Hide Version'으로",
        "nginx": "server_tokens off;\n(http 블록)",
        "iis": '<security><requestFiltering removeServerHeader="true" /></security>\n(IIS 10 이상, web.config의 system.webServer)',
        "caddy": "header -Server",
        "generic": "웹 서버 설정에서 Server 헤더의 버전 표시를 끄세요.",
    },
    "powered_by": {
        "php": "expose_php = Off\n(php.ini, PHP-FPM/Apache 재시작)",
        "apache": "Header always unset X-Powered-By",
        "nginx": "fastcgi_hide_header X-Powered-By;\nproxy_hide_header X-Powered-By;",
        "iis": '<customHeaders><remove name="X-Powered-By" /></customHeaders>\n'
               '<httpRuntime enableVersionHeader="false" />  (X-AspNet-Version, system.web)',
        "express": "app.disable('x-powered-by')  // helmet()을 쓰면 자동",
        "generic": "애플리케이션/프레임워크 설정에서 버전을 알리는 헤더를 끄세요.",
    },
    "generator": {
        "generic": "CMS 설정에서 generator 메타 태그를 제거하세요.\n"
                   "WordPress: functions.php 에 remove_action('wp_head', 'wp_generator');",
    },
    "error_pages": {
        "php": "display_errors = Off\nlog_errors = On\n(php.ini)",
        "django": "DEBUG = False\n(settings.py, ALLOWED_HOSTS 함께 설정)",
        "aspnet": 'ASPNETCORE_ENVIRONMENT=Production  /  <customErrors mode="On" />',
        "express": "NODE_ENV=production 으로 실행하고 오류 처리 미들웨어에서 스택을 응답하지 마세요.",
        "java": "server.error.include-stacktrace=never  (Spring Boot)",
        "generic": "운영 환경에서 디버그 모드를 끄고 사용자 정의 오류 페이지를 사용하세요.",
    },
    "trace": {
        "apache": "TraceEnable Off\n(httpd.conf)",
        "nginx": "nginx 자체는 TRACE를 거부(405)합니다. 앞단 프록시나 백엔드 서버 설정을 확인하세요.",
        "iis": '<security><requestFiltering><verbs><add verb="TRACE" allowed="false" /></verbs></requestFiltering></security>',
        "generic": "웹 서버·프록시 설정에서 TRACE 메서드를 비활성화하세요.",
    },
    "methods_limit": {
        "apache": "<LimitExcept GET POST HEAD>\n    Require all denied\n</LimitExcept>\n(<Directory> 안, 쓰지 않는 mod_dav 비활성화)",
        "nginx": "limit_except GET POST { deny all; }\n(location 블록, GET에는 HEAD 포함)",
        "iis": '<requestFiltering><verbs allowUnlisted="false"><add verb="GET" allowed="true" />'
               '<add verb="POST" allowed="true" /><add verb="HEAD" allowed="true" /></verbs></requestFiltering>',
        "generic": "사용하지 않는 HTTP 메서드(PUT, DELETE, WebDAV 등)를 웹 서버에서 막으세요.",
    },
    "http_redirect": {
        "apache": "<VirtualHost *:80>\n    ServerName @HOST@\n    Redirect permanent / https://@HOST@/\n</VirtualHost>",
        "litespeed": "RewriteEngine On\nRewriteCond %{HTTPS} !=on\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n(.htaccess)",
        "nginx": "server {\n    listen 80;\n    server_name @HOST@;\n    return 301 https://$host$request_uri;\n}",
        "iis": '<rewrite><rules><rule name="HTTPS" stopProcessing="true"><match url="(.*)" />'
               '<conditions><add input="{HTTPS}" pattern="off" /></conditions>'
               '<action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent" /></rule></rules></rewrite>\n'
               "(URL Rewrite 모듈 필요)",
        "caddy": "Caddy는 자동 HTTPS가 켜져 있으면 HTTP를 HTTPS로 리다이렉트합니다. 사이트 주소를 http:// 로 적지 않았는지 확인하세요.",
        "cloudflare": "SSL/TLS → Edge Certificates → Always Use HTTPS 켜기",
        "cdn": "CDN 콘솔에서 HTTP→HTTPS 리다이렉트를 켜세요.",
        "note": "HSTS 헤더도 함께 설정하면 브라우저가 이후 접속을 처음부터 HTTPS로 바꿉니다.",
    },
    "dir_listing": {
        "apache": "Options -Indexes\n(해당 <Directory> 또는 .htaccess)",
        "litespeed": "Options -Indexes\n(.htaccess)",
        "nginx": "autoindex off;",
        "iis": '<directoryBrowse enabled="false" />',
        "caddy": "file_server 에서 browse 옵션을 빼세요.",
    },
    "block_dotfiles": {
        "apache": "RedirectMatch 404 /\\.(?!well-known)\n(.git, .env 등 점으로 시작하는 경로 전체 차단)",
        "litespeed": "RedirectMatch 404 /\\.(?!well-known)\n(.htaccess)",
        "nginx": "location ~ /\\.(?!well-known) {\n    deny all;\n}",
        "iis": '<requestFiltering><hiddenSegments><add segment=".git" /><add segment=".env" /></hiddenSegments></requestFiltering>',
        "caddy": "@dotfiles {\n    path */.*\n    not path /.well-known/*\n}\nrespond @dotfiles 404",
        "note": "차단과 별개로, 이미 노출된 키·비밀번호는 즉시 교체(rotate)하고 배포 디렉터리에서 .git 등을 제거하세요.",
    },
    "remove_backups": {
        "generic": "백업·덤프·압축 파일을 웹 루트에서 삭제하고 웹 루트 밖에 보관하세요. 노출됐던 DB 계정 비밀번호는 교체하세요.",
    },
    "status_pages": {
        "apache": '<Location "/server-status">\n    Require local\n</Location>\n(server-info도 같은 방식, 또는 mod_status/mod_info 비활성화)',
        "generic": "서버 상태 페이지는 끄거나 내부 IP에서만 접근하게 제한하세요.",
    },
    "admin_tools": {
        "apache": '<Location "/phpmyadmin">\n    Require ip 203.0.113.10\n</Location>\n(203.0.113.10 자리에 관리자 IP)',
        "nginx": "location /phpmyadmin {\n    allow 203.0.113.10;\n    deny all;\n}\n(203.0.113.10 자리에 관리자 IP)",
        "generic": "관리 도구는 삭제하거나 IP 제한·VPN·추가 인증 뒤로 옮기세요.",
    },
    "tls_protocols": {
        "apache": "SSLProtocol -all +TLSv1.2 +TLSv1.3",
        "nginx": "ssl_protocols TLSv1.2 TLSv1.3;",
        "iis": "Windows SCHANNEL 레지스트리에서 TLS 1.0/1.1을 끄세요 (IIS Crypto 도구의 Best Practices 템플릿 권장, 재부팅 필요).",
        "litespeed": "WebAdmin → Listeners → SSL → Protocol Version 에서 TLS v1.2, v1.3만 선택",
        "caddy": "tls {\n    protocols tls1.2 tls1.3\n}\n(Caddy 기본값은 이미 TLS 1.2 이상)",
        "cloudflare": "SSL/TLS → Edge Certificates → Minimum TLS Version 을 TLS 1.2로",
        "cdn": "CDN 콘솔의 TLS 설정에서 최소 버전을 TLS 1.2로 올리세요.",
    },
    "tls_ciphers": {
        "apache": f"SSLCipherSuite {MOZILLA_INTERMEDIATE}\nSSLHonorCipherOrder off",
        "nginx": f"ssl_ciphers {MOZILLA_INTERMEDIATE};\nssl_prefer_server_ciphers off;",
        "iis": "IIS Crypto 도구의 Best Practices 템플릿으로 cipher suite 순서를 정리하세요.",
        "cloudflare": "SSL/TLS → Edge Certificates 에서 Minimum TLS Version 1.2 이상 (cipher 지정은 유료 플랜)",
        "generic": "Mozilla SSL Configuration Generator의 Intermediate 설정을 사용하세요: https://ssl-config.mozilla.org/",
    },
    "tls13": {
        "apache": "SSLProtocol -all +TLSv1.2 +TLSv1.3\n(OpenSSL 1.1.1 이상)",
        "nginx": "ssl_protocols TLSv1.2 TLSv1.3;\n(OpenSSL 1.1.1 이상)",
        "iis": "Windows Server 2022 / Windows 11 이상에서 TLS 1.3을 지원합니다.",
        "generic": "OpenSSL 1.1.1 이상으로 올리고 TLS 1.3을 켜세요.",
    },
    "http2": {
        "apache": "Protocols h2 http/1.1\n(mod_http2, prefork MPM에서는 동작하지 않음)",
        "nginx": "http2 on;\n(nginx 1.25.1 이상, 이전 버전은 listen 443 ssl http2;)",
        "iis": "Windows Server 2016 이상의 IIS 10은 HTTPS에서 HTTP/2를 기본 지원합니다.",
        "generic": "웹 서버에서 HTTP/2를 켜세요 (성능 개선 항목).",
    },
    "cert_renew": {
        "generic": "certbot renew --dry-run 으로 자동 갱신을 확인하세요 (systemctl list-timers | grep certbot).",
        "iis": "win-acme 같은 자동 갱신 도구를 쓰고 예약 작업이 동작하는지 확인하세요.",
        "cloudflare": "엣지 인증서는 Cloudflare가 갱신합니다. 오리진 서버 인증서의 만료일도 확인하세요.",
    },
    "cert_chain": {
        "apache": "SSLCertificateFile 에 fullchain.pem 을 지정하세요 (Apache 2.4.8 이상).",
        "nginx": "ssl_certificate 에 fullchain.pem 을 지정하세요.",
        "generic": "공인 CA(예: Let's Encrypt)에서 발급한 인증서와 중간 인증서를 포함한 전체 체인을 설정하세요.",
    },
    "cookie_flags": {
        "php": "session.cookie_secure = 1\nsession.cookie_httponly = 1\nsession.cookie_samesite = Lax\n(php.ini)",
        "express": "express-session: cookie: { secure: true, httpOnly: true, sameSite: 'lax' }\n"
                   "(리버스 프록시 뒤라면 app.set('trust proxy', 1))",
        "django": "SESSION_COOKIE_SECURE = True\nCSRF_COOKIE_SECURE = True\nSESSION_COOKIE_SAMESITE = 'Lax'\n(settings.py)",
        "aspnet": "options.Cookie.SecurePolicy = CookieSecurePolicy.Always;\n"
                  "options.Cookie.HttpOnly = true;\noptions.Cookie.SameSite = SameSiteMode.Lax;",
        "java": "<session-config><cookie-config><http-only>true</http-only><secure>true</secure></cookie-config></session-config>\n(web.xml)",
        "generic": "세션·인증 쿠키는 Secure; HttpOnly; SameSite=Lax(또는 Strict)를 모두 지정하세요.",
    },
}


def _block(label: str, text: str) -> str:
    first, _, rest = text.partition("\n")
    if rest and not rest.startswith("("):
        # A multi-line config block: keep it unindented so it can be pasted as is.
        return f"[{label}]\n{text}"
    out = f"[{label}] {first}"
    if rest:
        out += "\n" + "\n".join("    " + line for line in rest.splitlines())
    return out


def render(topic: str, platform: Platform | None, **values) -> str:
    entries = FIXES.get(topic)
    if entries is None:
        return topic  # plain text passed through
    platform = platform or Platform()
    keys: list[str] = []
    if platform.cdn:
        keys.append(platform.cdn if platform.cdn in entries else "cdn")
    for key in (platform.web, platform.app):
        if key and key in entries and key not in keys:
            keys.append(key)
    if not any(k in (platform.web, platform.app) for k in keys):
        # Web server unknown: show the two most common servers, or the generic advice.
        common = [k for k in ("apache", "nginx") if k in entries and not platform.web]
        keys += common or (["generic"] if "generic" in entries else [])
    keys = [k for k in dict.fromkeys(keys) if k in entries]
    if not keys and "generic" in entries:
        keys = ["generic"]
    blocks = [_block(LABELS.get(k, k), entries[k]) if k != "generic" else entries[k] for k in keys]
    if "note" in entries:
        blocks.append(entries["note"])
    text = "\n".join(blocks)
    for name, value in values.items():
        text = text.replace(f"@{name.upper()}@", str(value))
    return text
