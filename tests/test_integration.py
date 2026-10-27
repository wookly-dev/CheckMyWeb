"""End-to-end scans of the local fixture site (tests/fixture_server.py). No external network."""
import contextlib
import glob
import io
import json
import os
import tempfile
import unittest

from checkmyweb import cli, verify
from checkmyweb.checks import ALL, BY_NAME
from checkmyweb.models import Severity
from checkmyweb.scanner import Options, run_scan
from checkmyweb.target import Target
from fixture_server import CA_FILE, FixtureSite, ensure_certs

DEFAULT_CHECKS = [m for m in ALL if m.DEFAULT]


def setUpModule():
    if not ensure_certs():
        raise unittest.SkipTest("openssl not found: needed once to create the local test certificates")


class FixtureTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._config = tempfile.TemporaryDirectory()
        cls._old_config = os.environ.get("CHECKMYWEB_CONFIG_DIR")
        os.environ["CHECKMYWEB_CONFIG_DIR"] = cls._config.name

    @classmethod
    def tearDownClass(cls):
        if cls._old_config is None:
            os.environ.pop("CHECKMYWEB_CONFIG_DIR", None)
        else:
            os.environ["CHECKMYWEB_CONFIG_DIR"] = cls._old_config
        cls._config.cleanup()

    def scan(self, site, checks=DEFAULT_CHECKS, **options):
        opts = Options(timeout=5, delay=0, http_port=site.http_port, ca_file=CA_FILE, **options)
        result = run_scan(Target.parse(site.https_url), opts, checks)
        return result, {f.id: f for f in result.findings}


class WeakSiteTests(FixtureTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.site = FixtureSite("weak").start()
        cls.opts = Options(timeout=5, delay=0, http_port=cls.site.http_port, ca_file=CA_FILE)
        cls.result = run_scan(Target.parse(cls.site.https_url), cls.opts, DEFAULT_CHECKS)
        cls.by_id = {f.id: f for f in cls.result.findings}

    @classmethod
    def tearDownClass(cls):
        cls.site.stop()
        super().tearDownClass()

    def assertFinding(self, fid, severity):
        self.assertIn(fid, self.by_id, f"{fid} not reported")
        self.assertEqual(self.by_id[fid].severity, severity, fid)

    def test_platform_detected(self):
        platform = self.result.meta["platform"]
        self.assertEqual((platform["web"], platform["app"]), ("apache", "php"))

    def test_exposed_files(self):
        self.assertFinding("exposure..env", Severity.CRITICAL)
        self.assertFinding("exposure..git.HEAD", Severity.CRITICAL)
        self.assertFinding("exposure.dir_listing", Severity.MEDIUM)
        self.assertEqual(self.result.grade, "F")

    def test_headers_and_cookies(self):
        self.assertFinding("headers.hsts", Severity.HIGH)
        self.assertFinding("headers.csp", Severity.MEDIUM)
        self.assertFinding("headers.clickjacking", Severity.MEDIUM)
        self.assertFinding("cookies.PHPSESSID", Severity.MEDIUM)

    def test_plain_http_login_page(self):
        self.assertFinding("redirects.http.main", Severity.HIGH)
        self.assertIn("평문 로그인 페이지", self.by_id["redirects.http.main"].title)

    def test_other_weaknesses(self):
        self.assertFinding("cors.reflect.arbitrary", Severity.HIGH)
        self.assertFinding("methods.trace", Severity.LOW)
        self.assertFinding("methods.allow", Severity.LOW)
        self.assertFinding("disclosure.server", Severity.LOW)
        self.assertFinding("disclosure.signature", Severity.LOW)
        self.assertFinding("content.lib.jquery", Severity.MEDIUM)
        self.assertFinding("content.mixed.passive", Severity.LOW)

    def test_fixes_match_platform(self):
        self.assertIn("[Apache]", self.by_id["headers.hsts"].fix)
        self.assertNotIn("[nginx]", self.by_id["headers.hsts"].fix)
        self.assertIn("session.cookie_secure", self.by_id["cookies.PHPSESSID"].fix)
        self.assertIn("TraceEnable Off", self.by_id["methods.trace"].fix)

    def test_tls_against_test_ca(self):
        self.assertFinding("tls.cert.valid", Severity.PASS)
        self.assertFinding("tls.protocol.legacy", Severity.PASS)


class TypicalSiteTests(FixtureTestCase):
    def test_moderate_report(self):
        with FixtureSite("typical") as site:
            result, by_id = self.scan(site)
        self.assertEqual(result.grade, "B")  # the example used for the manual and product screenshots
        self.assertFalse([f.id for f in result.findings if f.severity >= Severity.HIGH])
        self.assertEqual(by_id["headers.csp"].severity, Severity.MEDIUM)
        self.assertEqual(by_id["headers.hsts"].severity, Severity.PASS)
        self.assertIn("[Apache]", by_id["headers.csp"].fix)


class HardenedSiteTests(FixtureTestCase):
    def test_clean_report(self):
        with FixtureSite("hardened") as site:
            result, by_id = self.scan(site)
        self.assertEqual(result.grade, "A")
        self.assertFalse([f.id for f in result.findings if f.severity >= Severity.LOW])
        for fid in ("headers.hsts", "headers.csp", "redirects.http.main", "exposure.none", "cors.ok",
                    "methods.trace", "cookies.__Host-sid", "content.security_txt"):
            self.assertEqual(by_id[fid].severity, Severity.PASS, fid)
        self.assertEqual(result.meta["platform"]["web"], "nginx")


class CdnSiteTests(FixtureTestCase):
    def test_cdn_detected_and_ports_skipped(self):
        with FixtureSite("cdn") as site:
            result, by_id = self.scan(site, checks=DEFAULT_CHECKS + [BY_NAME["ports"]])
        self.assertEqual(result.meta["platform"]["cdn"], "cloudflare")
        self.assertIn("platform.cdn", by_id)
        self.assertIn("ports.cdn", by_id)
        self.assertNotIn("ports.closed", by_id)
        self.assertTrue(by_id["headers.hsts"].fix.startswith("[Cloudflare]"))


class VerificationTests(FixtureTestCase):
    def test_unverified_target_skips_sensitive_checks(self):
        with FixtureSite("weak") as site:
            result, by_id = self.scan(site, local_autoverify=False)
        self.assertIn("exposure.unverified", by_id)
        self.assertNotIn("exposure..env", by_id)
        run = next(c for c in result.checks if c.name == "exposure")
        self.assertEqual(run.skipped, "소유 확인 필요")
        self.assertIn(verify.WELL_KNOWN_PATH, by_id["exposure.unverified"].detail)

    def test_verification_file_enables_sensitive_checks(self):
        token = verify.token_for(Target.parse("https://127.0.0.1/"))
        with FixtureSite("weak", verify_token=token) as site:
            result, by_id = self.scan(site, local_autoverify=False)
        self.assertEqual(result.meta["verification"]["method"], "file")
        self.assertIn("exposure..env", by_id)

    def test_wrong_token_is_rejected(self):
        with FixtureSite("weak", verify_token="checkmyweb-verify=" + "0" * 32) as site:
            result, by_id = self.scan(site, local_autoverify=False)
        self.assertFalse(result.meta["verification"]["verified"])
        self.assertNotIn("exposure..env", by_id)


class BatchCliTests(FixtureTestCase):
    def test_batch_writes_summary(self):
        with FixtureSite("weak") as weak, FixtureSite("hardened") as hardened, \
                tempfile.TemporaryDirectory() as out:
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = cli.main([weak.https_url, hardened.https_url, "--ca-file", CA_FILE, "--delay", "0",
                                 "--timeout", "5", "-o", out, "--no-color", "--fail-on", "high"])
            self.assertEqual(code, 1)  # the weak site has high findings
            batch_dir, = glob.glob(os.path.join(out, "batch-*"))
            with open(os.path.join(batch_dir, "summary.json"), encoding="utf-8") as fh:
                summary = json.load(fh)
            grades = {t["target"]: t["grade"] for t in summary["targets"]}
            self.assertEqual(grades[f"127.0.0.1:{weak.https_port}"], "F")
            self.assertEqual(grades[f"127.0.0.1:{hardened.https_port}"], "A")
            with open(os.path.join(batch_dir, "index.html"), encoding="utf-8") as fh:
                index = fh.read()
            for t in summary["targets"]:
                self.assertTrue(os.path.exists(os.path.join(batch_dir, t["report"])))
                self.assertIn(t["report"], index)
            self.assertIn("일괄 점검 요약", stdout.getvalue())

    def test_unresolvable_target_sets_exit_code_2(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(["does-not-exist.invalid", "--no-report", "--delay", "0", "--timeout", "3"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
