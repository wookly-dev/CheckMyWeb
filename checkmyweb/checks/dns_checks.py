"""DNS hygiene and e-mail anti-spoofing: SPF, DMARC, DKIM, MTA-STS, CAA, DNSSEC."""
from __future__ import annotations

import base64
import re

from ..models import Severity as S
from . import _der

NAME = "dns"
TITLE = "DNS / 이메일 보안"
DEFAULT = True

DKIM_SELECTORS = ["default", "dkim", "mail", "selector1", "selector2", "google", "k1", "k2", "s1", "s2",
                  "smtp", "key1", "mx", "zoho", "zmail", "daum", "naver"]


def spf_record(resolver, domain: str) -> list[str]:
    return [t for t in resolver.txt(domain) if t.lower().startswith("v=spf1")]


def spf_lookups(resolver, domain: str, depth: int = 0, seen: set | None = None) -> int:
    """Number of DNS-querying SPF terms, following include/redirect (RFC 7208 limit: 10)."""
    seen = seen if seen is not None else set()
    seen.add(domain)
    records = spf_record(resolver, domain)
    if not records:
        return 0
    count = 0
    for term in records[0].split()[1:]:
        t = term.lstrip("+-~?").lower()
        target = None
        if t.startswith("include:"):
            target = t.split(":", 1)[1]
        elif t.startswith("redirect="):
            target = t.split("=", 1)[1]
        elif t in ("a", "mx", "ptr") or t.startswith(("a:", "a/", "mx:", "mx/", "ptr:", "exists:")):
            count += 1
            continue
        if target:
            count += 1
            if depth < 6 and target not in seen and "%" not in target:
                count += spf_lookups(resolver, target, depth + 1, seen)
    return count


def parse_tags(record: str) -> dict[str, str]:
    tags = {}
    for part in record.split(";"):
        key, sep, value = part.partition("=")
        if sep:
            tags[key.strip().lower()] = value.strip()
    return tags


def _spf_suggestion(ctx, domain: str, has_mx: bool) -> str:
    if has_mx:
        return f'TXT {domain} "v=spf1 mx -all"  (실제 메일 발송 서버/서비스에 맞게 include 추가)'
    mx_hosts = {m.split()[-1].rstrip(".").lower() for m in ctx.resolver.records(ctx.org_domain, "MX")}
    if domain in mx_hosts:
        # Receivers also run SPF on the HELO name, which is this host for the mail server itself.
        return (f'TXT {domain} "v=spf1 a -all"  ({domain} 는 메일 서버의 HELO 이름으로도 쓰이므로 '
                "자기 IP(a)만 허용하고 나머지는 거부)")
    return f'TXT {domain} "v=spf1 -all"  (이 이름으로는 메일을 보내지 않는다고 선언)'


def _check_spf(ctx, domain: str, has_mx: bool) -> None:
    records = spf_record(ctx.resolver, domain)
    no_mail_sev = S.MEDIUM if has_mx else S.LOW
    if not records:
        ctx.add("dns.spf", no_mail_sev, "SPF 레코드가 없습니다",
                detail="누구나 이 도메인을 발신자로 사칭한 메일을 보낼 수 있습니다."
                       + ("" if has_mx else " 메일을 보내지 않는 도메인이라도 'v=spf1 -all' 로 사칭을 막을 수 있습니다."),
                fix=_spf_suggestion(ctx, domain, has_mx),
                refs=["https://www.rfc-editor.org/rfc/rfc7208"])
        return
    if len(records) > 1:
        ctx.add("dns.spf.multiple", S.MEDIUM, "SPF 레코드가 여러 개입니다 (permerror)",
                detail="SPF 레코드가 2개 이상이면 수신 서버가 SPF를 무효로 처리합니다.",
                evidence="\n".join(records), fix="하나의 v=spf1 레코드로 합치세요.")
    record = records[0]
    terms = record.lower().split()
    all_term = next((t for t in terms if t.lstrip("+-~?") == "all"), None)
    lookups = spf_lookups(ctx.resolver, domain)
    evidence = f"{record}\nDNS 조회 수: {lookups}/10"
    if all_term in ("+all", "all"):
        ctx.add("dns.spf.all", S.HIGH, "SPF가 모든 발신 서버를 허용합니다 (+all)", evidence=evidence,
                fix="'-all'(거부) 또는 최소 '~all'(소프트 실패)로 바꾸세요.")
    elif all_term == "?all" or all_term is None:
        ctx.add("dns.spf.all", S.MEDIUM, f"SPF 정책이 중립({all_term or 'all 미지정'})이라 사칭 메일을 막지 못합니다",
                evidence=evidence, fix="'-all' 또는 '~all'로 끝나도록 설정하세요.")
    elif all_term == "~all":
        ctx.add("dns.spf.all", S.PASS, "SPF가 설정되어 있습니다 (~all, 소프트 실패)",
                detail="DMARC를 p=quarantine/reject 로 함께 운영하면 충분합니다. 발송 서버가 확정되었다면 -all 도 고려하세요.",
                evidence=evidence)
    else:
        ctx.add("dns.spf.all", S.PASS, "SPF가 엄격하게 설정되어 있습니다 (-all)", evidence=evidence)
    if lookups > 10:
        ctx.add("dns.spf.lookups", S.MEDIUM, f"SPF DNS 조회 수가 한도(10)를 넘습니다: {lookups}",
                detail="한도를 넘으면 SPF가 permerror 가 되어 정상 메일도 실패할 수 있습니다.", evidence=evidence,
                fix="include 를 줄이거나 IP(ip4:/ip6:)로 평탄화하세요.")
    if any(t.lstrip("+-~?").startswith("ptr") for t in terms):
        ctx.add("dns.spf.ptr", S.LOW, "SPF에 폐기 권고된 ptr 메커니즘이 있습니다", evidence=record,
                fix="ptr 대신 ip4:/ip6:/a/mx 를 사용하세요.")


def _dmarc_records(resolver, domain: str) -> list[str]:
    return [t for t in resolver.txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]


def _check_dmarc(ctx, domain: str, has_mx: bool) -> None:
    records = _dmarc_records(ctx.resolver, domain)
    org = ctx.org_domain
    inherited = False
    if not records and org != domain:
        # RFC 7489 6.6.3: subdomains without their own record use the organizational domain's policy.
        records = _dmarc_records(ctx.resolver, org)
        inherited = bool(records)
    if not records:
        where = domain if org == domain else f"{domain} 와 상위 도메인 {org}"
        ctx.add("dns.dmarc", S.MEDIUM if has_mx else S.LOW, f"DMARC 레코드가 없습니다 ({where})",
                detail="SPF/DKIM 검증에 실패한 사칭 메일을 수신 서버가 어떻게 처리할지 정해지지 않아 피싱에 악용될 수 있습니다.",
                fix=f'TXT _dmarc.{org} "v=DMARC1; p=quarantine; rua=mailto:dmarc@{org}"\n'
                    "(상위 도메인에 두면 sp= 로 서브도메인까지 적용됩니다. 처음에는 p=none 으로 보고서를 받아보며 점진적으로 강화)",
                refs=["https://dmarc.org/overview/"])
        return
    tags = parse_tags(records[0])
    tag = "sp" if inherited and "sp" in tags else "p"
    policy = tags.get(tag, "").lower()
    source = f" — 상위 도메인 {org} 의 {tag}= 적용" if inherited else ""
    evidence = (f"_dmarc.{org}: " if inherited else "") + records[0]
    if policy == "none":
        ctx.add("dns.dmarc", S.LOW, f"DMARC 정책이 {tag}=none (모니터링 전용) 입니다{source}",
                detail="사칭 메일을 차단하지 않습니다. 보고서를 확인한 뒤 quarantine/reject 로 강화하세요.",
                evidence=evidence, fix=f"{tag}=quarantine 또는 {tag}=reject 로 변경")
    elif policy in ("quarantine", "reject"):
        ctx.add("dns.dmarc", S.PASS, f"DMARC 정책이 설정되어 있습니다 ({tag}={policy}){source}", evidence=evidence)
    else:
        ctx.add("dns.dmarc", S.MEDIUM, "DMARC 레코드의 p= 값이 올바르지 않습니다", evidence=records[0])
    if tags.get("pct") and tags["pct"] != "100":
        ctx.add("dns.dmarc.pct", S.INFO, f"DMARC가 메일의 {tags['pct']}%에만 적용됩니다", evidence=records[0])
    if "rua" not in tags:
        ctx.add("dns.dmarc.rua", S.INFO, "DMARC 집계 보고서 수신 주소(rua)가 없습니다",
                detail="rua 를 지정하면 누가 이 도메인으로 메일을 보내는지(사칭 포함) 보고서로 받을 수 있습니다.",
                evidence=records[0])


def dkim_key_bits(record: str) -> int | None:
    key = parse_tags(record).get("p", "").replace(" ", "")
    if not key:
        return None
    try:
        info = _der.public_key_info(base64.b64decode(key + "=" * (-len(key) % 4)))
    except (ValueError, IndexError):
        return None
    return info["key_bits"] if info["key_type"] == "RSA" else None


def _check_dkim(ctx, domain: str) -> None:
    found, weak = [], []
    for selector in DKIM_SELECTORS:
        for txt in ctx.resolver.txt(f"{selector}._domainkey.{domain}"):
            if "p=" in txt:
                bits = dkim_key_bits(txt)
                line = f"{selector}._domainkey.{domain}: RSA {bits or '?'}bit — {txt[:60]}..."
                found.append(line)
                if bits and bits < 2048:
                    weak.append(line)
                break
    if weak:
        ctx.add("dns.dkim.weak", S.LOW, "DKIM 서명 키가 2048bit 미만입니다",
                detail="RFC 8301은 DKIM 서명 키로 최소 1024bit, 권장 2048bit 이상을 요구합니다. "
                       "1024bit는 최소 기준만 충족하며 장기적으로는 안전 여유가 부족합니다.",
                evidence="\n".join(weak),
                fix="2048bit 키를 새 selector로 생성해 DNS에 게시한 뒤 메일 서버(OpenDKIM 등) 설정을 교체하고, "
                    "이전 selector는 일정 기간 후 삭제하세요.\n예) opendkim-genkey -b 2048 -s s2026 -d " + domain,
                refs=["https://www.rfc-editor.org/rfc/rfc8301"])
    if found:
        ctx.add("dns.dkim", S.PASS, "DKIM 공개키가 발견되었습니다", evidence="\n".join(found))
    else:
        ctx.add("dns.dkim", S.INFO, "자주 쓰이는 selector에서 DKIM 키를 찾지 못했습니다",
                detail="DKIM selector는 임의 이름이라 외부에서 전수 확인할 수 없습니다. "
                       "수신한 메일 헤더의 DKIM-Signature: s= 값으로 직접 확인하세요.",
                evidence="확인한 selector: " + ", ".join(DKIM_SELECTORS))


def _check_ptr(ctx, mx_records: list[str]) -> None:
    """Forward-confirmed reverse DNS for the primary MX — receivers penalise mismatches."""
    best = sorted(mx_records, key=lambda m: int(m.split()[0]) if m.split()[0].isdigit() else 99)[0]
    mx_host = best.split()[-1].rstrip(".").lower()
    ips = ctx.resolver.records(mx_host, "A")
    if not ips:
        return
    ip = ips[0]
    ptr = [p.rstrip(".").lower() for p in ctx.resolver.records(".".join(reversed(ip.split("."))) + ".in-addr.arpa", "PTR")]
    evidence = f"MX {mx_host} -> {ip} -> PTR {', '.join(ptr) or '(없음)'}"
    if mx_host in ptr:
        ctx.add("dns.ptr", S.PASS, "메일 서버 IP의 역방향 DNS(PTR)가 MX 이름과 일치합니다", evidence=evidence)
    else:
        ctx.add("dns.ptr", S.LOW, "메일 서버 IP의 역방향 DNS(PTR)가 MX 이름과 일치하지 않습니다",
                detail="Gmail·Naver 등 수신 서버는 PTR이 없거나 불일치하면 메일을 스팸 처리하거나 거부합니다. "
                       "도메인 사칭 판단에도 쓰이는 기본 신뢰 지표입니다.",
                evidence=evidence,
                fix=f"PTR은 IP를 관리하는 ISP/호스팅 업체에서 설정합니다. {ip} 의 PTR을 {mx_host} 로 요청하세요.")


def run(ctx) -> None:
    if not ctx.target.has_public_dns:
        ctx.add("dns.skipped", S.INFO, "공인 DNS 이름이 아닌 대상이라 DNS·이메일 점검을 건너뛰었습니다",
                detail="IP 주소나 localhost·사내 도메인은 SPF/DMARC/CAA/DNSSEC 점검 대상이 아닙니다.")
        return
    r = ctx.resolver
    domain = ctx.apex
    ctx.meta["dns"] = {
        "A": r.records(ctx.host, "A"),
        "AAAA": r.records(ctx.host, "AAAA"),
        "NS": r.records(ctx.org_domain, "NS"),
        "MX": r.records(domain, "MX"),
    }
    if r.query(ctx.org_domain, "NS").error:
        ctx.add("dns.unavailable", S.INFO, "DNS-over-HTTPS 조회에 실패해 DNS 점검을 건너뜁니다",
                detail=r.query(ctx.org_domain, "NS").error)
        return

    ns = ctx.meta["dns"]["NS"]
    ctx.add("dns.info", S.INFO, "DNS 기본 정보",
            evidence=f"A: {', '.join(ctx.meta['dns']['A']) or '-'}\nAAAA: {', '.join(ctx.meta['dns']['AAAA']) or '-'}\n"
                     f"NS: {', '.join(ns) or '-'}\nMX: {', '.join(ctx.meta['dns']['MX']) or '-'}")

    mx = ctx.meta["dns"]["MX"]
    null_mx = any(re.fullmatch(r"0\s+\.?", m.strip()) for m in mx)
    has_mx = bool(mx) and not null_mx

    _check_spf(ctx, domain, has_mx)
    _check_dmarc(ctx, domain, has_mx)
    if has_mx:
        _check_dkim(ctx, domain)
        _check_ptr(ctx, mx)
        if not r.txt(f"_mta-sts.{domain}"):
            ctx.add("dns.mta_sts", S.INFO, "MTA-STS가 설정되어 있지 않습니다",
                    detail="MTA-STS는 다른 메일 서버가 이 도메인으로 메일을 보낼 때 TLS를 강제하도록 합니다.",
                    refs=["https://www.rfc-editor.org/rfc/rfc8461"])
        if not r.txt(f"_smtp._tls.{domain}"):
            ctx.add("dns.tls_rpt", S.INFO, "SMTP TLS 보고(TLS-RPT)가 설정되어 있지 않습니다",
                    refs=["https://www.rfc-editor.org/rfc/rfc8460"])

    # CAA: which CAs may issue certificates. Inherited from parent names.
    caa, caa_name = [], None
    labels = ctx.host.split(".")
    for i in range(len(labels) - 1):
        name = ".".join(labels[i:])
        caa = r.records(name, "CAA")
        if caa:
            caa_name = name
            break
    if caa:
        ctx.add("dns.caa", S.PASS, "CAA 레코드로 인증서 발급 기관이 제한되어 있습니다",
                evidence=f"{caa_name}:\n" + "\n".join(caa))
    else:
        ctx.add("dns.caa", S.LOW, "CAA 레코드가 없습니다",
                detail="어느 CA든 이 도메인의 인증서를 발급할 수 있습니다. CAA로 사용하는 CA만 허용하면 오발급 위험이 줄어듭니다.",
                fix=f'{ctx.org_domain}. CAA 0 issue "letsencrypt.org"\n'
                    f'{ctx.org_domain}. CAA 0 iodef "mailto:security@{ctx.org_domain}"\n'
                    "(상위 도메인에 한 번 설정하면 모든 서브도메인에 적용됩니다)",
                refs=["https://letsencrypt.org/docs/caa/"])

    # DNSSEC
    # DS lives at the zone apex; the AD bit on the host's own answer is what matters to resolvers.
    ds = r.records(ctx.org_domain, "DS")
    validated = r.query(ctx.host, "A").ad
    if ds and validated:
        ctx.add("dns.dnssec", S.PASS, "DNSSEC 서명이 검증됩니다", evidence="DS: " + "; ".join(ds))
    elif ds:
        ctx.add("dns.dnssec", S.MEDIUM, "DS 레코드는 있지만 DNSSEC 검증이 되지 않습니다",
                detail="서명 키 교체 실패 등으로 DNSSEC가 깨지면 검증 리졸버 사용자에게 도메인이 아예 조회되지 않습니다.",
                evidence="DS: " + "; ".join(ds), fix="DNS 호스팅의 DNSSEC 서명 상태와 등록기관의 DS 값을 확인하세요.")
    else:
        ctx.add("dns.dnssec", S.LOW, "DNSSEC가 적용되어 있지 않습니다",
                detail="DNS 응답 위조(캐시 포이즈닝)를 암호학적으로 막지 못합니다. DNS 호스팅/등록기관에서 활성화할 수 있습니다.",
                evidence=f"NS: {', '.join(ns)}")
