"""TLS protocol versions, cipher suites and the server certificate."""
from __future__ import annotations

import os
import socket
import ssl
import tempfile
import time
import warnings

from ..httpclient import verified_context
from ..models import Severity as S
from . import _der

NAME = "tls"
TITLE = "TLS / 인증서"
DEFAULT = True

PROTOCOLS = [
    ("TLS 1.0", ssl.TLSVersion.TLSv1),
    ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
    ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
    ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
]

# (id, label, OpenSSL cipher string, severity if accepted, why it matters)
WEAK_CIPHERS = [
    ("null", "NULL/익명(aNULL) 암호", "aNULL:eNULL", S.HIGH, "암호화나 서버 인증이 없는 cipher suite입니다."),
    ("export", "EXPORT 등급 암호", "EXPORT", S.HIGH, "FREAK/Logjam 공격에 취약한 40~56bit 암호입니다."),
    ("rc4", "RC4", "RC4", S.HIGH, "RC4는 통계적 편향으로 평문 복구가 가능합니다 (RFC 7465에서 금지)."),
    ("3des", "3DES (SWEET32)", "3DES", S.MEDIUM, "64bit 블록 암호로 SWEET32 공격에 취약합니다."),
    ("kRSA", "정적 RSA 키교환 (Forward Secrecy 없음)", "kRSA", S.LOW,
     "서버 개인키가 유출되면 과거에 기록된 트래픽까지 복호화될 수 있습니다."),
    ("cbc", "CBC 모드 (비-AEAD) 암호", "SHA1:SHA256:SHA384", S.INFO,
     "CBC 계열은 Lucky13 등 패딩 오라클류 공격 이력이 있어 Mozilla 'intermediate' 권장안에서 제외되었습니다."),
]

MOZILLA_REF = "https://ssl-config.mozilla.org/"


def _connect(host: str, port: int, ctx: ssl.SSLContext, timeout: float) -> ssl.SSLSocket:
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        return ctx.wrap_socket(sock, server_hostname=host)
    except BaseException:
        sock.close()
        raise


def _probe(host: str, port: int, timeout: float, minimum=None, maximum=None, ciphers: str | None = None):
    """Returns ("yes" | "no" | "unknown", detail)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            if minimum is not None:
                ctx.minimum_version = minimum
            if maximum is not None:
                ctx.maximum_version = maximum
            ctx.set_ciphers((ciphers or "ALL:COMPLEMENTOFALL") + ":@SECLEVEL=0")
        except (ssl.SSLError, ValueError) as e:
            return "unknown", f"로컬 OpenSSL에서 테스트 불가: {e}"
    try:
        with _connect(host, port, ctx, timeout) as s:
            return "yes", f"{s.version()} / {s.cipher()[0]}"
    except ssl.SSLError as e:
        if "NO_PROTOCOLS_AVAILABLE" in str(e).upper():
            return "unknown", f"로컬 OpenSSL에서 테스트 불가: {e}"
        return "no", str(e)
    except (socket.timeout, TimeoutError) as e:
        return "unknown", f"시간 초과: {e}"
    except OSError as e:  # reset / closed by peer = refused
        return "no", str(e)


def _decode_der(der: bytes) -> dict:
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(pem)
        return ssl._ssl._test_decode_cert(path)  # stdlib has no public DER decoder
    finally:
        os.unlink(path)


def _name(rdns) -> str:
    return ", ".join(f"{k}={v}" for rdn in rdns or () for k, v in rdn)


def _covers(pattern: str, host: str) -> bool:
    pattern, host = pattern.lower(), host.lower()
    if pattern.startswith("*."):
        return host.count(".") == pattern.count(".") and host.endswith(pattern[1:])
    return pattern == host


def run(ctx) -> None:
    host, port, timeout = ctx.host, ctx.tls_port, ctx.options.timeout
    if port is None:
        ctx.add("tls.skipped", S.INFO, "HTTPS 포트를 알 수 없어 TLS 점검을 건너뛰었습니다",
                detail="http:// 대상에 비표준 포트를 지정하면 HTTPS 포트를 추정하지 않습니다. "
                       "https://호스트:포트/ 형식으로 따로 점검하세요.")
        return
    where = host if port == 443 else f"{host}:{port}"

    # 1. Handshake with full verification (what browsers do).
    verify_error = None
    trusted = verified_context(ctx.options.ca_file)
    trusted.set_alpn_protocols(["h2", "http/1.1"])
    try:
        sock = _connect(host, port, trusted, timeout)
    except ssl.SSLCertVerificationError as e:
        verify_error = e
        insecure = ssl.create_default_context()
        insecure.check_hostname = False
        insecure.verify_mode = ssl.CERT_NONE
        insecure.set_alpn_protocols(["h2", "http/1.1"])
        try:
            sock = _connect(host, port, insecure, timeout)
        except (OSError, ssl.SSLError) as e2:
            ctx.add("tls.unavailable", S.CRITICAL, f"HTTPS({port}) 연결에 실패했습니다", detail=str(e2),
                    fix=ctx.fix("cert_chain"))
            return
    except (OSError, ssl.SSLError) as e:
        sev = S.CRITICAL if ctx.target.scheme == "https" else S.HIGH
        ctx.add("tls.unavailable", sev, f"HTTPS({port}) 연결에 실패했습니다", detail=str(e),
                fix="웹 서버에 TLS 인증서를 설치하고 HTTPS를 제공하세요 (예: Let's Encrypt + certbot).\n"
                    + ctx.fix("cert_chain"))
        return

    with sock:
        version, cipher = sock.version(), sock.cipher()
        alpn = sock.selected_alpn_protocol()
        leaf_der = sock.getpeercert(binary_form=True)
        cert = sock.getpeercert() if verify_error is None else _decode_der(leaf_der)
        try:
            chain = [c if isinstance(c, bytes) else c.public_bytes() for c in sock.get_unverified_chain()]
        except (AttributeError, TypeError):
            chain = [leaf_der]

    ctx.meta["tls"] = {"version": version, "cipher": cipher[0], "alpn": alpn, "port": port}
    edge = " (CDN 엣지 기준)" if ctx.platform.cdn else ""
    ctx.add("tls.negotiated", S.INFO, f"기본 협상 결과{edge}",
            evidence=f"{where}: {version} / {cipher[0]} ({cipher[2]}bit), ALPN={alpn or '없음'}")
    if alpn != "h2":
        ctx.add("tls.http2", S.INFO, "HTTP/2를 지원하지 않습니다 (보안 영향 없음, 성능 개선 항목)",
                detail="HTTP/2는 연결 재사용과 헤더 압축으로 HTTPS 페이지 로딩을 빠르게 합니다.",
                fix=ctx.fix("http2"))

    # 2. Certificate validity.
    sans = [v for k, v in cert.get("subjectAltName", ()) if k in ("DNS", "IP Address")]
    issuer = _name(cert.get("issuer"))
    subject = _name(cert.get("subject"))
    cert_summary = f"subject: {subject}\nissuer: {issuer}\nSAN: {', '.join(sans) or '-'}\n" \
                   f"유효기간: {cert.get('notBefore')} ~ {cert.get('notAfter')}\n체인 인증서 수: {len(chain)}"

    reason = getattr(verify_error, "verify_message", "") or str(verify_error or "")
    if verify_error is None:
        ctx.add("tls.cert.valid", S.PASS, "인증서 체인과 호스트명 검증에 성공했습니다", evidence=cert_summary)
    elif "expired" not in reason.lower():  # expiry gets its own finding below
        hint = ""
        if "local issuer" in reason and len(chain) <= 1:
            hint = " 서버가 중간(intermediate) 인증서를 함께 보내지 않는 것으로 보입니다 — fullchain.pem을 사용하세요."
        elif "Hostname mismatch" in reason or "hostname" in reason.lower() or "IP address mismatch" in reason:
            hint = f" 인증서가 {host} 를 포함하지 않습니다."
        elif "self" in reason.lower():
            hint = " 자체 서명(self-signed) 인증서입니다. 사내 CA라면 --ca-file 로 CA 인증서를 지정해 점검하세요."
        ctx.add("tls.cert.invalid", S.HIGH, "인증서 검증에 실패했습니다 (브라우저 경고 발생)",
                detail=reason + hint, evidence=cert_summary, fix=ctx.fix("cert_chain"))

    not_after = cert.get("notAfter")
    if not_after:
        days = (ssl.cert_time_to_seconds(not_after) - time.time()) / 86400
        ctx.meta["cert_days_left"] = int(days)
        if days < 0:
            ctx.add("tls.cert.expired", S.CRITICAL, "인증서가 만료되었습니다", evidence=f"notAfter={not_after}",
                    fix="인증서를 즉시 갱신하세요.\n" + ctx.fix("cert_renew"))
        elif days < 7:
            ctx.add("tls.cert.expiring", S.HIGH, f"인증서가 {int(days)}일 후 만료됩니다", evidence=f"notAfter={not_after}",
                    fix="인증서를 갱신하세요.\n" + ctx.fix("cert_renew"))
        elif days < 21:
            ctx.add("tls.cert.expiring", S.MEDIUM, f"인증서가 {int(days)}일 후 만료됩니다", evidence=f"notAfter={not_after}",
                    fix="자동 갱신이 동작하는지 확인하세요 (Let's Encrypt는 만료 30일 전부터 갱신).\n" + ctx.fix("cert_renew"))
        else:
            ctx.add("tls.cert.expiry", S.PASS, f"인증서 만료까지 {int(days)}일 남았습니다", evidence=f"notAfter={not_after}")

    www = ctx.variant
    if sans and www and not any(_covers(p, www) for p in sans):
        ctx.add("tls.cert.www", S.MEDIUM, f"인증서가 {www} 를 포함하지 않습니다",
                detail=f"{www} 가 DNS에 등록되어 있지만 인증서 SAN에 없어 해당 주소로 접속하면 경고가 발생합니다.",
                evidence=f"SAN: {', '.join(sans)}", fix=f"인증서 발급 시 {www} 도 함께 포함하세요 (certbot -d {host} -d {www}).")

    try:
        key = _der.cert_info(leaf_der)
    except (IndexError, ValueError) as e:
        ctx.log(f"인증서 DER 파싱 실패: {e}")
        key = None
    if key:
        desc = f"{key['key_type']} {key['key_bits'] or '?'}bit" + (f" ({key['curve']})" if key["curve"] else "")
        desc += f", 서명 {key['sig_alg']}"
        weak_key = (key["key_type"] == "RSA" and (key["key_bits"] or 0) < 2048) or \
                   (key["key_type"] == "EC" and (key["key_bits"] or 0) < 256)
        weak_sig = any(x in key["sig_alg"].lower() for x in ("md5", "sha1"))
        if weak_key:
            ctx.add("tls.cert.weak_key", S.HIGH, "인증서 공개키 길이가 짧습니다", evidence=desc,
                    fix="RSA 2048bit 이상 또는 ECDSA P-256 이상으로 재발급하세요.")
        if weak_sig:
            ctx.add("tls.cert.weak_sig", S.HIGH, "인증서가 취약한 해시(MD5/SHA-1)로 서명되었습니다", evidence=desc,
                    fix="SHA-256 이상으로 서명된 인증서로 교체하세요.")
        if not weak_key and not weak_sig:
            ctx.add("tls.cert.key", S.PASS, "인증서 키/서명 알고리즘이 안전합니다", evidence=desc)

    # 3. Protocol versions.
    support = {}
    for label, ver in PROTOCOLS:
        support[label] = _probe(host, port, timeout, minimum=ver, maximum=ver)
    ctx.meta["tls_protocols"] = {k: v[0] for k, v in support.items()}
    evidence = "\n".join(f"{k}: {v[0]} ({v[1]})" for k, v in support.items())

    legacy = [k for k in ("TLS 1.0", "TLS 1.1") if support[k][0] == "yes"]
    if legacy:
        ctx.add("tls.protocol.legacy", S.MEDIUM, f"구버전 프로토콜 {', '.join(legacy)} 을(를) 허용합니다",
                detail="TLS 1.0/1.1은 2021년 RFC 8996으로 폐기되었고 주요 브라우저도 지원을 중단했습니다.",
                evidence=evidence, fix=ctx.fix("tls_protocols"),
                refs=["https://www.rfc-editor.org/rfc/rfc8996", MOZILLA_REF])
    elif all(support[k][0] == "no" for k in ("TLS 1.0", "TLS 1.1")):
        ctx.add("tls.protocol.legacy", S.PASS, "TLS 1.0/1.1이 비활성화되어 있습니다", evidence=evidence)
    else:
        ctx.add("tls.protocol.legacy", S.INFO, "TLS 1.0/1.1 지원 여부를 확인하지 못했습니다", evidence=evidence)

    if support["TLS 1.3"][0] == "yes":
        ctx.add("tls.protocol.tls13", S.PASS, "TLS 1.3을 지원합니다")
    elif support["TLS 1.3"][0] == "no":
        ctx.add("tls.protocol.tls13", S.LOW, "TLS 1.3을 지원하지 않습니다",
                detail="TLS 1.3은 핸드셰이크가 빠르고 취약한 암호 옵션이 제거된 버전입니다.",
                fix=ctx.fix("tls13"), refs=[MOZILLA_REF])

    # 4. Weak cipher suites (TLS <= 1.2; TLS 1.3 suites are all AEAD).
    if support["TLS 1.2"][0] != "yes" and not legacy:
        return
    accepted, untestable = [], []
    for cid, label, spec, sev, why in WEAK_CIPHERS:
        state, detail = _probe(host, port, timeout, minimum=ssl.TLSVersion.TLSv1, maximum=ssl.TLSVersion.TLSv1_2,
                               ciphers=spec)
        if state == "yes" and cid == "cbc" and any(x in detail for x in ("GCM", "CHACHA", "CCM")):
            state = "no"
        if state == "yes":
            if sev >= S.LOW:
                accepted.append(label)
            title = f"취약/구식 암호 허용: {label}" if sev >= S.LOW else f"참고: {label}도 허용합니다"
            ctx.add(f"tls.cipher.{cid}", sev, title, detail=why,
                    evidence=f"협상됨: {detail}", fix=ctx.fix("tls_ciphers"), refs=[MOZILLA_REF])
        elif state == "unknown":
            untestable.append(label)
    if not accepted:
        ctx.add("tls.cipher", S.PASS, "점검한 취약 암호군을 허용하지 않습니다",
                evidence=("로컬에서 테스트 불가: " + ", ".join(untestable)) if untestable else "")
