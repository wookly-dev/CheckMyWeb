"""Common service ports reachable from the internet (opt-in, TCP connect only).

For mail ports the probe also reads the greeting and capability list (EHLO /
CAPA / CAPABILITY) to see whether STARTTLS is offered, then disconnects
without authenticating.
"""
from __future__ import annotations

import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor

from ..models import Severity as S

NAME = "ports"
TITLE = "외부 노출 포트"
DEFAULT = False  # enabled with --ports
REQUIRES_VERIFICATION = True

# port: (service, severity when open, note)
PORTS = {
    21: ("FTP", S.MEDIUM, "평문으로 계정/파일이 전송됩니다. SFTP(SSH)로 대체하세요."),
    22: ("SSH", S.INFO, "비밀번호 로그인을 끄고(PasswordAuthentication no) 키 인증·fail2ban 사용을 권장합니다."),
    23: ("Telnet", S.HIGH, "평문 원격 접속입니다. 즉시 비활성화하세요."),
    25: ("SMTP", S.INFO, "메일 서버라면 정상입니다. 오픈 릴레이가 아닌지 확인하세요."),
    110: ("POP3", S.LOW, "평문 POP3입니다. POP3S(995)만 사용하는 것을 권장합니다."),
    143: ("IMAP", S.LOW, "평문 IMAP입니다. IMAPS(993)만 사용하는 것을 권장합니다."),
    445: ("SMB", S.HIGH, "파일 공유 프로토콜을 인터넷에 노출하면 웜/랜섬웨어의 주요 침투 경로가 됩니다."),
    465: ("SMTPS", S.INFO, "암호화된 메일 제출 포트입니다."),
    587: ("Submission", S.INFO, "메일 제출 포트입니다. 인증 전에 STARTTLS를 강제하세요."),
    993: ("IMAPS", S.INFO, "암호화된 IMAP 포트입니다."),
    995: ("POP3S", S.INFO, "암호화된 POP3 포트입니다."),
    1433: ("MSSQL", S.HIGH, "DB 포트는 외부에 공개하지 말고 방화벽으로 제한하세요."),
    2375: ("Docker API (평문)", S.CRITICAL, "인증 없는 Docker API는 서버 전체 장악으로 이어집니다."),
    3000: ("개발 서버(Node/Grafana 등)", S.LOW, "개발용 서버가 외부에 노출되어 있지 않은지 확인하세요."),
    3306: ("MySQL/MariaDB", S.HIGH, "DB 포트는 외부에 공개하지 말고 bind-address=127.0.0.1 또는 방화벽으로 제한하세요."),
    3389: ("RDP", S.HIGH, "원격 데스크톱은 무차별 대입 공격의 주요 대상입니다. VPN 뒤로 옮기세요."),
    5432: ("PostgreSQL", S.HIGH, "DB 포트는 외부에 공개하지 말고 listen_addresses/pg_hba.conf 로 제한하세요."),
    5900: ("VNC", S.HIGH, "VNC는 인증이 약한 경우가 많습니다. 외부 노출을 막으세요."),
    6379: ("Redis", S.HIGH, "Redis는 기본적으로 인증이 없어 원격 코드 실행으로 이어질 수 있습니다."),
    8080: ("HTTP 대체 포트", S.INFO, "관리 콘솔/개발 서버가 아닌지 확인하세요."),
    8443: ("HTTPS 대체 포트", S.INFO, "관리 콘솔이 아닌지 확인하세요."),
    9090: ("Cockpit/Prometheus", S.LOW, "Rocky/RHEL의 Cockpit 웹 콘솔이라면 IP 제한을 권장합니다."),
    9200: ("Elasticsearch", S.HIGH, "인증 없는 Elasticsearch는 데이터 유출 사고의 단골 원인입니다."),
    10000: ("Webmin", S.MEDIUM, "서버 관리 패널은 IP 제한 또는 VPN 뒤에 두세요."),
    11211: ("Memcached", S.HIGH, "DDoS 증폭 및 데이터 노출 위험이 있습니다."),
    27017: ("MongoDB", S.HIGH, "인증 없는 MongoDB는 데이터 유출/랜섬 사고의 단골 원인입니다."),
}

GREETS_FIRST = {21, 22, 25, 110, 143, 587}
# port: (capability query, end-of-reply pattern, STARTTLS token, goodbye)
CAPABILITIES = {
    25: (b"EHLO checkmyweb.invalid\r\n", rb"(^|\n)250 [^\n]*\n", "STARTTLS", b"QUIT\r\n"),
    587: (b"EHLO checkmyweb.invalid\r\n", rb"(^|\n)250 [^\n]*\n", "STARTTLS", b"QUIT\r\n"),
    110: (b"CAPA\r\n", rb"\r\n\.\r\n|^-ERR", "STLS", b"QUIT\r\n"),
    143: (b"a1 CAPABILITY\r\n", rb"a1 (OK|NO|BAD)", "STARTTLS", b"a2 LOGOUT\r\n"),
}


MAIL_FIX = {
    25: "Sendmail: sendmail.mc 에 define(`confAUTH_OPTIONS', `A p')dnl ('p' = TLS 없이 평문 AUTH 금지)\n"
        "Postfix: smtpd_tls_auth_only = yes",
    587: "Sendmail: define(`confAUTH_OPTIONS', `A p')dnl / Postfix: smtpd_tls_auth_only = yes "
         "(submission 포트는 smtpd_tls_security_level=encrypt 권장)",
    110: "Dovecot: /etc/dovecot/conf.d/10-auth.conf 에 disable_plaintext_auth = yes, "
         "10-ssl.conf 에 ssl = required — 또는 110을 닫고 995(POP3S)만 사용",
    143: "Dovecot: ssl = required, disable_plaintext_auth = yes — 또는 143을 닫고 993(IMAPS)만 사용",
}


def _recv_until(sock: socket.socket, pattern: bytes, timeout: float) -> bytes:
    data = b""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and len(data) < 8192:
        sock.settimeout(max(0.1, deadline - time.monotonic()))
        try:
            chunk = sock.recv(2048)
        except OSError:
            break
        if not chunk:
            break
        data += chunk
        if re.search(pattern, data, re.M):
            break
    return data


def _probe(ip: str, port: int, timeout: float) -> dict:
    result = {"port": port, "open": False, "banner": "", "caps": ""}
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return result
    result["open"] = True
    with sock:
        if port in GREETS_FIRST:
            greeting = _recv_until(sock, rb"\r?\n$", timeout)
            result["banner"] = greeting.decode("latin-1", "replace").strip().splitlines()[0][:200] if greeting else ""
        if port in CAPABILITIES and result["banner"]:
            query, end, _, bye = CAPABILITIES[port]
            try:
                sock.sendall(query)
                result["caps"] = _recv_until(sock, end, timeout).decode("latin-1", "replace")
                sock.sendall(bye)
            except OSError:
                pass
    return result


def _mail_assessment(port: int, caps: str) -> tuple[S, str, str] | None:
    """Returns (severity, short problem label or "", explanation)."""
    if port not in CAPABILITIES or not caps:
        return None
    token = CAPABILITIES[port][2]
    has_tls = re.search(rf"\b{token}\b", caps, re.I) is not None
    if port in (25, 587):
        if not has_tls:
            return S.MEDIUM, "STARTTLS 미지원", "STARTTLS를 지원하지 않아 메일과 계정 정보가 평문으로 오갑니다."
        if re.search(r"^250[- ]AUTH\b.*\b(PLAIN|LOGIN)\b", caps, re.M | re.I):
            return S.MEDIUM, "암호화 전 평문 AUTH 허용", ("STARTTLS 이전(평문 연결)에서 AUTH PLAIN/LOGIN을 제공합니다. "
                              "메일 클라이언트 설정에 따라 계정 비밀번호가 암호화 없이 전송될 수 있습니다.")
        return S.INFO, "", "STARTTLS를 지원하며 평문 연결에서는 AUTH를 제공하지 않습니다."
    if not has_tls:
        return S.MEDIUM, f"{token} 미지원", f"{token}를 지원하지 않아 로그인 정보가 평문으로 전송됩니다."
    # Before TLS, IMAP should advertise LOGINDISABLED and POP3 should not offer USER.
    if port == 143 and "LOGINDISABLED" not in caps.upper():
        return S.LOW, "암호화 전 평문 로그인 허용", "STARTTLS는 지원하지만 암호화 전 평문 로그인이 허용됩니다 (LOGINDISABLED 미표시)."
    if port == 110 and re.search(r"^USER\b", caps, re.M | re.I):
        return S.LOW, "암호화 전 평문 로그인 허용", "STLS는 지원하지만 암호화 전 단계에서 USER 명령을 광고합니다 — 평문 USER/PASS 로그인이 허용되는 것으로 보입니다."
    return S.INFO, "", f"{token}를 지원하며 암호화 전 평문 로그인은 차단된 것으로 보입니다."


def run(ctx) -> None:
    if ctx.platform.cdn:
        ctx.add("ports.cdn", S.INFO, "CDN 엣지 주소라 포트 점검을 건너뛰었습니다",
                detail="이 도메인의 IP는 CDN 서버이므로 포트 결과가 내 서버 상태를 나타내지 않습니다. "
                       "원본 서버의 포트는 서버의 실제 IP를 대상으로 따로 점검하세요 (소유 확인 파일 방식).")
        return
    ips = [ip for ip in ctx.meta.get("ip", []) if ":" not in ip][:1] or ctx.meta.get("ip", [])[:1]
    if not ips:
        return
    ip = ips[0]
    timeout = min(3.0, ctx.options.timeout)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = sorted(pool.map(lambda p: _probe(ip, p, timeout), PORTS), key=lambda r: r["port"])
    opened = [r for r in results if r["open"]]
    ctx.meta["open_ports"] = [r["port"] for r in opened]

    for r in opened:
        port = r["port"]
        service, sev, note = PORTS[port]
        evidence = f"{ip}:{port}" + (f"\n배너: {r['banner']}" if r["banner"] else "")
        fix = ("필요 없는 서비스는 중지하고, 필요한 경우 firewalld 등으로 접근 IP를 제한하세요.\n"
               f"예) firewall-cmd --permanent --remove-port={port}/tcp && firewall-cmd --reload")
        title = f"{port}/tcp ({service}) 포트가 열려 있습니다"
        mail = _mail_assessment(port, r["caps"])
        if mail:
            sev, problem, note = mail
            if problem:
                title = f"{port}/tcp ({service}): {problem}"
            fix = MAIL_FIX.get(port, fix)
            caps = " ".join(line.strip() for line in r["caps"].splitlines() if line.strip())
            evidence += f"\n기능: {caps[:300]}"
        ctx.add(f"ports.{port}", sev, title, detail=note, evidence=evidence, fix=fix if sev >= S.LOW else "")

    smtp = [r for r in opened if r["port"] in (25, 587) and r["banner"]]
    if smtp and re.search(r"^220[- ]localhost\b", smtp[0]["banner"], re.I):
        ctx.add("ports.smtp.hostname", S.LOW, "메일 서버가 자신을 localhost.localdomain 으로 소개합니다",
                detail="SMTP 배너/HELO 호스트명이 MX 이름과 다르면 수신 서버의 스팸 판정 점수가 올라가고, "
                       "서버 설정이 기본값 그대로라는 신호가 됩니다.",
                evidence=smtp[0]["banner"],
                fix=f"hostnamectl set-hostname mail.{ctx.apex} 또는 sendmail.mc 에 "
                    f"define(`confDOMAIN_NAME', `mail.{ctx.apex}')dnl 추가 후 재빌드\n"
                    "(서버 IP의 역방향 DNS(PTR)도 같은 이름으로 맞추는 것을 권장)")
    closed = [str(r["port"]) for r in results if not r["open"]]
    ctx.add("ports.closed", S.PASS, f"점검한 {len(PORTS)}개 포트 중 {len(closed)}개가 닫혀(필터링되어) 있습니다",
            evidence=f"{ip} 닫힘/필터됨: {', '.join(closed)}")
