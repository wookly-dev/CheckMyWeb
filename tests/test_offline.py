"""Offline unit tests for the parsers and matchers (no network access)."""
import os
import tempfile
import unittest

from checkmyweb import fingerprint, remedies, verify
from checkmyweb.checks import _der, cookies, dns_checks, exposure, headers, ports
from checkmyweb.httpclient import Response
from checkmyweb.models import CheckRun, Finding, ScanResult, Severity
from checkmyweb.report import render_html
from checkmyweb.resolver import _parse_caa, _parse_txt
from checkmyweb.scanner import Options, ScanContext, org_domain
from checkmyweb.target import Target, all_loopback


def resp(body: bytes, status: int = 200, ctype: str = "text/plain") -> Response:
    return Response(url="https://example.test/x", method="GET", status=status, reason="OK",
                    headers=[("Content-Type", ctype)], body=body, elapsed=0.0)


def der(tag: int, content: bytes) -> bytes:
    n = len(content)
    length = bytes([n]) if n < 0x80 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + length + content


class CspTests(unittest.TestCase):
    def ids(self, value):
        return {i[0] for i in headers.analyze_csp(value)}

    def test_unsafe_inline_flagged(self):
        self.assertIn("csp.unsafe_inline", self.ids("default-src 'self'; script-src 'self' 'unsafe-inline'"))

    def test_nonce_neutralises_unsafe_inline(self):
        self.assertNotIn("csp.unsafe_inline", self.ids("script-src 'nonce-abc' 'unsafe-inline'; object-src 'none'"))

    def test_strict_policy_has_no_real_issues(self):
        issues = headers.analyze_csp("default-src 'self'; object-src 'none'; base-uri 'none'")
        self.assertEqual(issues, [])

    def test_wildcard_source(self):
        self.assertIn("csp.wide_source", self.ids("script-src https: 'self'"))


class CookieTests(unittest.TestCase):
    def test_parse(self):
        name, attrs = cookies.parse_set_cookie("PHPSESSID=abc; path=/; HttpOnly; SameSite=Lax")
        self.assertEqual(name, "PHPSESSID")
        self.assertIn("httponly", attrs)
        self.assertEqual(attrs["samesite"], "Lax")

    def test_session_cookie_without_secure_is_medium(self):
        name, attrs = cookies.parse_set_cookie("PHPSESSID=abc; path=/; HttpOnly; SameSite=Lax")
        sevs = [s for s, _ in cookies.cookie_issues(name, attrs, https=True)]
        self.assertEqual(max(sevs), Severity.MEDIUM)

    def test_well_configured_cookie(self):
        name, attrs = cookies.parse_set_cookie("sid=1; Secure; HttpOnly; SameSite=Strict; Path=/")
        self.assertEqual(cookies.cookie_issues(name, attrs, https=True), [])


class FakeResolver:
    def __init__(self, txt):
        self._txt = txt

    def txt(self, name):
        return self._txt.get(name, [])


class DnsTests(unittest.TestCase):
    def test_spf_lookup_count_follows_includes(self):
        r = FakeResolver({
            "a.test": ["v=spf1 mx a include:b.test -all"],
            "b.test": ["v=spf1 include:c.test ip4:1.2.3.4 ~all"],
            "c.test": ["v=spf1 a ~all"],
        })
        self.assertEqual(dns_checks.spf_lookups(r, "a.test"), 5)

    def test_dmarc_tags(self):
        tags = dns_checks.parse_tags("v=DMARC1; p=reject; rua=mailto:x@y.test; pct=50")
        self.assertEqual(tags["p"], "reject")
        self.assertEqual(tags["pct"], "50")

    def test_txt_chunks_are_joined(self):
        self.assertEqual(_parse_txt('"v=spf1 include:a" " -all"'), "v=spf1 include:a -all")

    def test_caa_generic_form(self):
        raw = bytes([0, 5]) + b"issue" + b"letsencrypt.org"
        data = f"\\# {len(raw)} " + " ".join(f"{b:02x}" for b in raw)
        self.assertEqual(_parse_caa(data), '0 issue "letsencrypt.org"')

    def test_dkim_key_bits(self):
        modulus = b"\x00" + b"\xc3" + bytes(127)  # 1024-bit
        rsa_key = der(0x30, der(0x02, modulus) + der(0x02, b"\x01\x00\x01"))
        alg = der(0x30, der(0x06, bytes.fromhex("2a864886f70d010101")) + b"\x05\x00")
        spki = der(0x30, alg + der(0x03, b"\x00" + rsa_key))
        self.assertEqual(_der.public_key_info(spki)["key_bits"], 1024)
        import base64
        self.assertEqual(dns_checks.dkim_key_bits("v=DKIM1; k=rsa; p=" + base64.b64encode(spki).decode()), 1024)


class FakeContext:
    def __init__(self, host, txt):
        self.host = host
        self.org_domain = org_domain(host)
        self.resolver = FakeResolver(txt)
        self.findings = []

    def add(self, id, severity, title, **kw):
        self.findings.append((id, severity, title))


class SubdomainTests(unittest.TestCase):
    def test_org_domain(self):
        self.assertEqual(org_domain("ai.wookly.dev"), "wookly.dev")
        self.assertEqual(org_domain("wookly.dev"), "wookly.dev")
        self.assertEqual(org_domain("www.example.co.kr"), "example.co.kr")

    def test_dmarc_inherits_subdomain_policy(self):
        ctx = FakeContext("ai.example.test", {"_dmarc.example.test": ["v=DMARC1; p=reject; sp=none"]})
        dns_checks._check_dmarc(ctx, "ai.example.test", has_mx=False)
        _, severity, title = ctx.findings[0]  # followed by an INFO about the missing rua=
        self.assertEqual(severity, Severity.LOW)  # sp=none wins over p=reject for subdomains
        self.assertIn("sp=none", title)

    def test_dmarc_missing_everywhere(self):
        ctx = FakeContext("ai.example.test", {})
        dns_checks._check_dmarc(ctx, "ai.example.test", has_mx=False)
        self.assertIn("example.test", ctx.findings[0][2])


class ExposureTests(unittest.TestCase):
    def probe(self, path):
        return next(p for p in exposure.PROBES if p.path == path)

    def test_env_file_detected(self):
        self.assertTrue(self.probe("/.env").match(resp(b"APP_KEY=base64:xyz\nDB_PASSWORD=secret\n")))

    def test_soft_404_html_not_detected(self):
        page = b"<!doctype html><html><body>DB_PASSWORD=not really</body></html>"
        self.assertFalse(self.probe("/.env").match(resp(page, ctype="text/html")))

    def test_git_head(self):
        self.assertTrue(self.probe("/.git/HEAD").match(resp(b"ref: refs/heads/main\n")))
        self.assertFalse(self.probe("/.git/HEAD").match(resp(b"Not found", status=404)))


class ReportTests(unittest.TestCase):
    def test_grade_capped_by_critical(self):
        result = ScanResult(target="example.test", started="now",
                            findings=[Finding("x", "x.1", Severity.CRITICAL, "bad")])
        self.assertEqual(result.score, 70)
        self.assertEqual(result.grade, "D")

    def test_html_escapes_content(self):
        result = ScanResult(target="example.test", started="now",
                            findings=[Finding("x", "x.1", Severity.LOW, "<script>alert(1)</script>")])
        page = render_html(result)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_json_round_trip(self):
        result = ScanResult(target="example.test", started="now", url="https://example.test/",
                            findings=[Finding("x", "x.1", Severity.MEDIUM, "t", fix="f", refs=["r"])],
                            checks=[CheckRun("x", "X", 1.0, skipped="소유 확인 필요")])
        again = ScanResult.from_dict(result.to_dict())
        self.assertEqual(again.to_dict(), result.to_dict())


class TargetTests(unittest.TestCase):
    def test_parse_variants(self):
        t = Target.parse("wookly.dev")
        self.assertEqual((t.scheme, t.host, t.port, t.path, t.url), ("https", "wookly.dev", 443, "/", "https://wookly.dev/"))
        t = Target.parse("https://Example.com:8443/app")
        self.assertEqual((t.port, t.path, t.label), (8443, "/app/", "example.com:8443/app/"))
        t = Target.parse("http://10.0.0.5:8080/x/index.php")
        self.assertEqual((t.url, t.has_public_dns), ("http://10.0.0.5:8080/x/", False))
        self.assertEqual(Target.parse("[::1]:8443").url, "https://[::1]:8443/")

    def test_rejects_bad_input(self):
        for text in ("ftp://example.com", "https://example.com:99999/", ""):
            with self.assertRaises(ValueError):
                Target.parse(text)

    def test_url_scoping(self):
        ctx = ScanContext(Target.parse("https://h.example:8443/app/"), Options())
        self.assertEqual(ctx.url(".env"), "https://h.example:8443/app/.env")
        self.assertEqual(ctx.url("/.env"), "https://h.example:8443/app/.env")
        self.assertEqual(ctx.url("/robots.txt", root=True), "https://h.example:8443/robots.txt")
        self.assertIsNone(ctx.http_url)  # custom HTTPS port: HTTP port unknown
        self.assertEqual(ScanContext(Target.parse("h.example"), Options()).http_url, "http://h.example/")
        self.assertEqual(ScanContext(Target.parse("https://h.example:8443/"), Options(http_port=8080)).http_url,
                         "http://h.example:8080/")

    def test_loopback(self):
        self.assertTrue(all_loopback(["127.0.0.1", "::1"]))
        self.assertFalse(all_loopback(["127.0.0.1", "203.0.113.5"]))
        self.assertFalse(all_loopback([]))


def fake(headers=(), status=200, body=b""):
    return Response(url="https://example.test/", method="GET", status=status, reason="",
                    headers=list(headers), body=body, elapsed=0.0)


class FingerprintTests(unittest.TestCase):
    def test_servers_and_apps(self):
        p = fingerprint.detect([fake([("Server", "Microsoft-IIS/10.0"), ("X-Powered-By", "ASP.NET")])])
        self.assertEqual((p.web, p.app, p.cdn), ("iis", "aspnet", None))
        p = fingerprint.detect([fake([("Server", "openresty"), ("Set-Cookie", "JSESSIONID=1; Path=/")])])
        self.assertEqual((p.web, p.app), ("nginx", "java"))

    def test_error_page_signature(self):
        p = fingerprint.detect([fake(), fake(status=404, body=b"<hr><address>Apache/2.4.1 Server at x</address>")])
        self.assertEqual(p.web, "apache")

    def test_cdn_by_header_and_cname(self):
        self.assertEqual(fingerprint.detect([fake([("CF-Ray", "abc-ICN"), ("Server", "cloudflare")])]).cdn, "cloudflare")
        self.assertEqual(fingerprint.detect([fake()], ["d111.cloudfront.net"]).cdn, "cloudfront")
        self.assertIsNone(fingerprint.detect([fake([("Server", "Apache")])], ["origin.example.com"]).cdn)


class RemedyTests(unittest.TestCase):
    def test_platform_specific(self):
        text = remedies.render("hsts", fingerprint.Platform(web="nginx"))
        self.assertIn("add_header Strict-Transport-Security", text)
        self.assertNotIn("[Apache]", text)

    def test_unknown_server_shows_common_ones(self):
        text = remedies.render("xcto", fingerprint.Platform())
        self.assertIn("[Apache]", text)
        self.assertIn("[nginx]", text)

    def test_cdn_first_and_host_substitution(self):
        text = remedies.render("http_redirect", fingerprint.Platform(web="apache", cdn="cloudflare"), host="a.example")
        self.assertTrue(text.startswith("[Cloudflare]"))
        self.assertIn("ServerName a.example", text)

    def test_app_specific_cookie_fix(self):
        self.assertIn("SESSION_COOKIE_SECURE", remedies.render("cookie_flags", fingerprint.Platform(app="django")))
        self.assertNotIn("[", remedies.render("cookie_flags", fingerprint.Platform(web="apache")))

    def test_literal_text_passes_through(self):
        self.assertEqual(remedies.render("phpinfo 파일을 삭제하세요.", None), "phpinfo 파일을 삭제하세요.")


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old = os.environ.get("CHECKMYWEB_CONFIG_DIR")
        os.environ["CHECKMYWEB_CONFIG_DIR"] = self.tmp.name

    def tearDown(self):
        if self.old is None:
            os.environ.pop("CHECKMYWEB_CONFIG_DIR", None)
        else:
            os.environ["CHECKMYWEB_CONFIG_DIR"] = self.old
        self.tmp.cleanup()

    def test_token_is_stable_per_registrable_domain(self):
        a = verify.token_for(Target.parse("wookly.dev"))
        self.assertEqual(a, verify.token_for(Target.parse("https://ai.wookly.dev:8443/x/")))
        self.assertNotEqual(a, verify.token_for(Target.parse("example.com")))
        self.assertRegex(a, r"^checkmyweb-verify=[0-9a-f]{32}$")

    def test_dns_record_verifies(self):
        target = Target.parse("ai.wookly.dev")
        token = verify.token_for(target)
        found = verify.check(target, FakeResolver({"_checkmyweb.wookly.dev": ["other", token]}), lambda url: None, False)
        self.assertEqual((found.verified, found.method), (True, "dns"))
        missing = verify.check(target, FakeResolver({}), lambda url: None, False)
        self.assertFalse(missing.verified)
        self.assertTrue(verify.check(target, FakeResolver({}), lambda url: None, True).verified)


class MailPortTests(unittest.TestCase):
    def test_auth_before_starttls(self):
        caps = "250-mail Hello\r\n250-AUTH LOGIN PLAIN\r\n250-STARTTLS\r\n250 HELP\r\n"
        severity, problem, _ = ports._mail_assessment(25, caps)
        self.assertEqual((severity, problem), (Severity.MEDIUM, "암호화 전 평문 AUTH 허용"))

    def test_imap_login_disabled_is_fine(self):
        caps = "* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED\r\na1 OK\r\n"
        self.assertEqual(ports._mail_assessment(143, caps)[0], Severity.INFO)


if __name__ == "__main__":
    unittest.main()
