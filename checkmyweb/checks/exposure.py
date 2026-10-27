"""Publicly reachable files and endpoints that should not be (VCS, secrets, backups, admin tools).

Only GET requests are sent, and a hit is reported only when the body matches a
content signature, so soft-404 pages that answer 200 for everything do not
produce false positives.
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import Callable

from ..models import Severity as S

NAME = "exposure"
TITLE = "민감 파일/경로 노출"
DEFAULT = True
REQUIRES_VERIFICATION = True  # tells an outsider exactly where a site leaks; owners only


@dataclass
class Probe:
    path: str
    severity: S
    title: str
    match: Callable
    fix: str = ""  # remedies topic, or literal text
    root: bool = False  # server-level path: probe the site root, not the scanned base path


def _text(r) -> str:
    return r.text[:20000]


def has(*needles, raw=True):
    return lambda r: r.status == 200 and (not raw or not r.looks_like_html) and all(n in _text(r) for n in needles)


def regex(pattern, flags=0, raw=True):
    rx = re.compile(pattern, flags)
    return lambda r: r.status == 200 and (not raw or not r.looks_like_html) and bool(rx.search(_text(r)))


def magic(*prefixes):
    return lambda r: r.status == 200 and r.body.startswith(prefixes)


GIT_FIX = "block_dotfiles"
ENV_FIX = "block_dotfiles"
BACKUP_FIX = "remove_backups"
ADMIN_FIX = "admin_tools"

ENV_RX = r"^\s*[A-Z][A-Z0-9_]{2,}\s*=\s*\S"

PROBES = [
    Probe("/.git/HEAD", S.CRITICAL, "Git 저장소(.git)가 노출되어 있습니다",
          regex(r"^(ref: refs/|[0-9a-f]{40}\s*$)"), GIT_FIX),
    Probe("/.git/config", S.CRITICAL, "Git 설정 파일(.git/config)이 노출되어 있습니다", has("[core]"), GIT_FIX),
    Probe("/.svn/entries", S.HIGH, "SVN 메타데이터(.svn)가 노출되어 있습니다", regex(r"\A(\d+\s*(\n|\Z)|<\?xml)"), GIT_FIX),
    Probe("/.svn/wc.db", S.HIGH, "SVN 작업 DB(.svn/wc.db)가 노출되어 있습니다", magic(b"SQLite format 3"), GIT_FIX),
    Probe("/.hg/requires", S.HIGH, "Mercurial 저장소(.hg)가 노출되어 있습니다", regex(r"^(revlogv1|store|fncache)", re.M), GIT_FIX),
    Probe("/.env", S.CRITICAL, ".env 환경변수 파일이 노출되어 있습니다", regex(ENV_RX, re.M), ENV_FIX),
    Probe("/.env.local", S.CRITICAL, ".env.local 파일이 노출되어 있습니다", regex(ENV_RX, re.M), ENV_FIX),
    Probe("/.env.production", S.CRITICAL, ".env.production 파일이 노출되어 있습니다", regex(ENV_RX, re.M), ENV_FIX),
    Probe("/.aws/credentials", S.CRITICAL, "AWS 자격증명 파일이 노출되어 있습니다", has("aws_access_key_id"), ENV_FIX),
    Probe("/.vscode/sftp.json", S.HIGH, "VS Code SFTP 설정(접속 정보 포함 가능)이 노출되어 있습니다",
          has('"host"'), ENV_FIX),
    Probe("/.htpasswd", S.HIGH, ".htpasswd(비밀번호 해시)가 노출되어 있습니다",
          regex(r"^[^:\s]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|\$[56]\$)", re.M), ENV_FIX),
    Probe("/.htaccess", S.LOW, ".htaccess 내용이 노출되어 있습니다",
          regex(r"^\s*(RewriteEngine|RewriteRule|Require|Deny from|Options|AuthType)", re.M | re.I),
          ENV_FIX),
    Probe("/.DS_Store", S.LOW, ".DS_Store(macOS 폴더 메타데이터, 파일 목록 포함)가 노출되어 있습니다",
          lambda r: r.status == 200 and r.body[4:8] == b"Bud1", "배포 전 .DS_Store 파일을 삭제하세요."),
    Probe("/wp-config.php.bak", S.CRITICAL, "WordPress 설정 백업이 노출되어 있습니다", has("DB_PASSWORD"), BACKUP_FIX),
    Probe("/wp-config.php~", S.CRITICAL, "WordPress 설정 백업(~)이 노출되어 있습니다", has("DB_PASSWORD"), BACKUP_FIX),
    Probe("/wp-config.php.save", S.CRITICAL, "WordPress 설정 백업(.save)이 노출되어 있습니다", has("DB_PASSWORD"), BACKUP_FIX),
    Probe("/config.php.bak", S.HIGH, "설정 파일 백업(config.php.bak)이 노출되어 있습니다", has("<?php"), BACKUP_FIX),
    Probe("/backup.sql", S.CRITICAL, "DB 덤프(backup.sql)가 노출되어 있습니다",
          regex(r"CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump"), BACKUP_FIX),
    Probe("/dump.sql", S.CRITICAL, "DB 덤프(dump.sql)가 노출되어 있습니다",
          regex(r"CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump"), BACKUP_FIX),
    Probe("/db.sql", S.CRITICAL, "DB 덤프(db.sql)가 노출되어 있습니다",
          regex(r"CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump"), BACKUP_FIX),
    Probe("/backup.zip", S.HIGH, "백업 압축 파일(backup.zip)이 노출되어 있습니다", magic(b"PK\x03\x04"), BACKUP_FIX),
    Probe("/backup.tar.gz", S.HIGH, "백업 압축 파일(backup.tar.gz)이 노출되어 있습니다", magic(b"\x1f\x8b"), BACKUP_FIX),
    Probe("/site.zip", S.HIGH, "사이트 압축 파일(site.zip)이 노출되어 있습니다", magic(b"PK\x03\x04"), BACKUP_FIX),
    Probe("/www.zip", S.HIGH, "사이트 압축 파일(www.zip)이 노출되어 있습니다", magic(b"PK\x03\x04"), BACKUP_FIX),
    Probe("/docker-compose.yml", S.MEDIUM, "docker-compose.yml(구성/비밀값 포함 가능)이 노출되어 있습니다",
          regex(r"^\s*services\s*:", re.M), "웹 루트에 배포 설정 파일을 두지 마세요."),
    Probe("/server-status", S.MEDIUM, "Apache server-status 페이지가 공개되어 있습니다",
          has("Apache Server Status", raw=False),
          "status_pages", root=True),
    Probe("/server-info", S.MEDIUM, "Apache server-info 페이지(전체 설정 노출)가 공개되어 있습니다",
          has("Apache Server Information", raw=False), "status_pages", root=True),
    Probe("/phpinfo.php", S.HIGH, "phpinfo() 페이지가 공개되어 있습니다",
          regex(r"<title>PHP \d|phpinfo\(\)|PHP Version \d", raw=False), "phpinfo 파일을 삭제하세요."),
    Probe("/info.php", S.HIGH, "phpinfo() 페이지(info.php)가 공개되어 있습니다",
          regex(r"<title>PHP \d|phpinfo\(\)|PHP Version \d", raw=False), "phpinfo 파일을 삭제하세요."),
    Probe("/phpmyadmin/", S.MEDIUM, "phpMyAdmin 로그인 페이지가 공개되어 있습니다", has("phpMyAdmin", raw=False), ADMIN_FIX, root=True),
    Probe("/pma/", S.MEDIUM, "phpMyAdmin(/pma/)이 공개되어 있습니다", has("phpMyAdmin", raw=False), ADMIN_FIX, root=True),
    Probe("/adminer.php", S.MEDIUM, "Adminer DB 관리 도구가 공개되어 있습니다", has("Adminer", raw=False), ADMIN_FIX),
    Probe("/actuator/env", S.HIGH, "Spring Boot actuator /env 가 공개되어 있습니다",
          has('"propertySources"'), "management.endpoints.web.exposure.include 를 health 정도로 제한하세요."),
    Probe("/wp-json/wp/v2/users", S.MEDIUM, "WordPress REST API로 사용자 계정 목록을 조회할 수 있습니다",
          regex(r'^\s*\[\s*\{.*"slug"', re.S), "플러그인 또는 rest_endpoints 필터로 /wp/v2/users 를 비로그인 사용자에게 차단하세요."),
    Probe("/xmlrpc.php", S.LOW, "WordPress XML-RPC가 활성화되어 있습니다 (무차별 대입 증폭에 악용)",
          lambda r: r.status in (200, 405) and "XML-RPC server accepts POST requests only" in r.text,
          "사용하지 않는다면 xmlrpc.php 접근을 차단하세요."),
    Probe("/readme.html", S.LOW, "WordPress readme.html(버전 노출)이 공개되어 있습니다",
          has("WordPress", raw=False), "readme.html 을 삭제하세요."),
    Probe("/crossdomain.xml", S.LOW, "crossdomain.xml 이 모든 도메인을 허용합니다",
          regex(r'allow-access-from\s+domain="\*"'), "불필요하다면 삭제하고, 필요하면 허용 도메인을 명시하세요.", root=True),
    Probe("/manual/", S.LOW, "Apache 매뉴얼(/manual/)이 설치되어 공개되어 있습니다",
          has("Apache HTTP Server", raw=False), "httpd-manual 패키지를 제거하거나 manual.conf 를 비활성화하세요.", root=True),
    Probe("/icons/README", S.INFO, "Apache 기본 /icons/ 디렉터리가 공개되어 있습니다",
          has("Public Domain Icons"), "Alias /icons/ 설정(autoindex.conf)을 제거하면 서버 종류 추정을 줄일 수 있습니다.", root=True),
]

LISTING_RX = re.compile(r"<title>\s*Index of /|<h1>\s*Index of /|Directory listing for /", re.I)
COMMON_DIRS = ["/uploads/", "/files/", "/backup/", "/images/", "/img/", "/assets/", "/static/",
               "/css/", "/js/", "/data/", "/tmp/", "/wp-content/uploads/"]


def _asset_dirs(ctx) -> list[str]:
    """Directories referenced by the homepage's own assets (e.g. /assets/css/)."""
    home = ctx.homepage
    if home is None or not home.looks_like_html:
        return []
    base_host = urllib.parse.urlsplit(home.url).hostname
    dirs = []
    for ref in re.findall(r'(?:src|href)=["\']([^"\'#?]+)', home.text, re.I):
        parts = urllib.parse.urlsplit(urllib.parse.urljoin(home.url, ref))
        if parts.hostname != base_host or "/" not in parts.path.strip("/"):
            continue
        d = parts.path.rsplit("/", 1)[0] + "/"
        if d not in dirs:
            dirs.append(d)
    return dirs[:10]


def run(ctx) -> None:
    hits = 0
    for probe in PROBES:
        r = ctx.get(probe.path, max_body=262144, root=probe.root)
        if r is None:
            continue
        try:
            matched = probe.match(r)
        except (IndexError, ValueError):
            matched = False
        if matched:
            hits += 1
            snippet = r.text[:300].strip() if not r.body.startswith((b"PK", b"\x1f\x8b", b"SQLite")) else \
                f"(바이너리 {len(r.body)} bytes)"
            ctx.add(f"exposure{probe.path.replace('/', '.').rstrip('.')}", probe.severity, probe.title,
                    evidence=f"{r.status} {r.url}\n{snippet}", fix=ctx.fix(probe.fix))

    # Common directory names live under the scanned base path; asset directories are absolute.
    candidates = [(d, False) for d in COMMON_DIRS] + [(d, True) for d in _asset_dirs(ctx)]
    listings = []
    for d, root in dict.fromkeys(candidates):
        if d == "/icons/":
            continue
        r = ctx.get(d, max_body=65536, root=root)
        if r is not None and r.status == 200 and LISTING_RX.search(r.text) and r.url not in listings:
            listings.append(r.url)
    if listings:
        hits += 1
        ctx.add("exposure.dir_listing", S.MEDIUM, "디렉터리 목록(Directory Listing)이 노출됩니다",
                detail="디렉터리 안의 모든 파일 이름이 보여 백업·임시 파일 등 의도치 않은 파일이 발견될 수 있습니다.",
                evidence="\n".join(listings), fix=ctx.fix("dir_listing"))

    if not hits:
        ctx.add("exposure.none", S.PASS,
                f"민감 파일/관리 페이지 {len(PROBES)}개 경로와 디렉터리 목록 노출이 발견되지 않았습니다")
