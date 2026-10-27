"""Manual and product-page screenshots from the local fixture site (no real site is scanned).

    python scripts/make_screenshots.py

Scans the typical (grade B) / hardened / CDN fixtures, renames them to example domains,
renders the HTML report, the batch summary and a console transcript into
dist/screens/, and captures PNGs with headless Microsoft Edge into
packaging/images/. The PNGs are committed because build_release.py embeds
them in manual.html; rerun this after a version bump or a report change.
"""
from __future__ import annotations

import html
import io
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]

from checkmyweb import __version__  # noqa: E402
from checkmyweb.checks import ALL  # noqa: E402
from checkmyweb.cli import NOTICE  # noqa: E402
from checkmyweb.models import ScanResult, Severity  # noqa: E402
from checkmyweb.report import render_console, render_html, render_index  # noqa: E402
from checkmyweb.scanner import Options, run_scan  # noqa: E402
from checkmyweb.target import Target  # noqa: E402
from fixture_server import CA_FILE, FixtureSite  # noqa: E402

OUT = ROOT / "dist" / "screens"
IMAGES = ROOT / "packaging" / "images"
CHECKS = [m for m in ALL if m.DEFAULT]
EDGE = [r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"]
# The public images show an ordinary, mostly well-kept site rather than the deliberately broken one.
SITES = [("typical", "shop.example.com"), ("hardened", "www.example.org"), ("cdn", "blog.example.net")]


def _rename(value, mapping):
    if isinstance(value, str):
        for old, new in mapping:
            value = value.replace(old, new)
        return value
    if isinstance(value, list):
        return [_rename(v, mapping) for v in value]
    if isinstance(value, dict):
        return {k: _rename(v, mapping) for k, v in value.items()}
    return value


def scan_fixtures() -> dict[str, ScanResult]:
    results = {}
    with tempfile.TemporaryDirectory() as config:
        os.environ["CHECKMYWEB_CONFIG_DIR"] = config
        for profile, name in SITES:
            with FixtureSite(profile) as site:
                opts = Options(timeout=5, delay=0, http_port=site.http_port, ca_file=CA_FILE)
                result = run_scan(Target.parse(site.https_url), opts, CHECKS)
            mapping = [(f"127.0.0.1:{site.https_port}", name), (f"127.0.0.1:{site.http_port}", name),
                       ("127.0.0.1", name), ("Port 443", "Port 443")]
            data = _rename(result.to_dict(), mapping)
            # Present the sample as a verified production site rather than a local test server.
            data["meta"]["ip"] = ["203.0.113.10"]
            data["meta"]["cert_days_left"] = 63
            org = name.split(".", 1)[1]
            data["meta"]["verification"] = {"verified": True, "method": "dns", "detail": f"_checkmyweb.{org}",
                                            "label": f"DNS TXT (_checkmyweb.{org})"}
            data["meta"]["requests"] = data["meta"].get("requests", 0)
            data["meta"]["notes"] = []
            results[profile] = ScanResult.from_dict(data)
    return results


ANSI_CLASS = {"97;41": "c", "91": "h", "93": "m", "96": "l", "90": "d", "92": "p", "1": "b", "2": "d"}


def ansi_to_html(text: str) -> str:
    out, open_span = [], False
    for part in re.split(r"(\x1b\[[0-9;]*m)", text):
        m = re.fullmatch(r"\x1b\[([0-9;]*)m", part)
        if not m:
            out.append(html.escape(part))
            continue
        if open_span:
            out.append("</span>")
            open_span = False
        if m.group(1) not in ("", "0"):
            out.append(f'<span class="{ANSI_CLASS.get(m.group(1), "d")}">')
            open_span = True
    return "".join(out) + ("</span>" if open_span else "")


TERMINAL = """<!doctype html><html lang="ko"><head><meta charset="utf-8"><style>
body {{ margin:0; background:#0d1117; }}
.win {{ margin:24px; border-radius:10px; overflow:hidden; box-shadow:0 8px 30px rgba(0,0,0,.45); background:#11151c; }}
.bar {{ background:#1d232d; padding:9px 14px; color:#8b95a7; font:13px "Segoe UI","Malgun Gothic",sans-serif; }}
pre {{ margin:0; padding:16px 20px; color:#d7dce4; font:14.5px/1.5 Consolas,"D2Coding","Malgun Gothic",monospace; white-space:pre-wrap; }}
.c {{ color:#fff; background:#c92a2a; }} .h {{ color:#ff6b6b; }} .m {{ color:#ffd43b; }} .l {{ color:#4dabf7; }}
.d {{ color:#8b95a7; }} .p {{ color:#69db7c; }} .b {{ color:#fff; font-weight:700; }}
</style></head><body><div class="win"><div class="bar">명령 프롬프트 — checkmyweb.cmd shop.example.com</div><pre>{body}</pre></div></body></html>"""


def console_page(result: ScanResult) -> str:
    buf = io.StringIO()
    render_console(result, color=True, min_severity=Severity.LOW, stream=buf)
    lines = buf.getvalue().strip("\n").splitlines()
    head = ["C:\\Tools\\CheckMyWeb&gt; checkmyweb.cmd shop.example.com",
            f"CheckMyWeb {__version__} · 1개 대상, {len(CHECKS)}개 점검", html.escape(NOTICE), ""]
    keep = [line for line in lines if not line.startswith(("        근거",))]
    if len(keep) > 38:
        keep = keep[:34] + ["  ..."] + keep[-4:]
    body = "\n".join(head) + "\n" + ansi_to_html("\n".join(keep))
    return TERMINAL.format(body=body)


def edge() -> str:
    for path in EDGE:
        if os.path.exists(path):
            return path
    raise SystemExit("Microsoft Edge not found")


def shoot(page: Path, png: Path, width: int, height: int) -> None:
    png.unlink(missing_ok=True)
    subprocess.run([edge(), "--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=1",
                    f"--window-size={width},{height}", f"--screenshot={png}", page.resolve().as_uri()],
                   check=True, capture_output=True, timeout=60)
    # Edge can return before its renderer has finished writing the file.
    last, deadline = -1, time.monotonic() + 20
    while time.monotonic() < deadline:
        size = png.stat().st_size if png.exists() else -1
        if size > 0 and size == last:
            return
        last = size
        time.sleep(0.5)
    raise SystemExit(f"screenshot not written: {png}")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    IMAGES.mkdir(parents=True, exist_ok=True)
    results = scan_fixtures()
    example = results["typical"]
    (OUT / "report.html").write_text(render_html(example), encoding="utf-8")
    entries = [{"label": r.target, "result": r, "error": None, "html": None} for r in results.values()]
    (OUT / "batch.html").write_text(render_index(entries, "2026-10-26 09:00"), encoding="utf-8")
    (OUT / "console.html").write_text(console_page(example), encoding="utf-8")
    shoot(OUT / "report.html", IMAGES / "report-overview.png", 1200, 820)
    focus = ("<style>.summary, .card, main > h2, section.check:not(#check-headers), footer { display:none; }"
             " #check-headers h2 { margin-top: 8px; }</style></head>")
    (OUT / "report-fixes.html").write_text(render_html(example).replace("</head>", focus, 1), encoding="utf-8")
    shoot(OUT / "report-fixes.html", IMAGES / "report-fixes.png", 1200, 820)
    shoot(OUT / "batch.html", IMAGES / "batch-summary.png", 1200, 460)
    shoot(OUT / "console.html", IMAGES / "console.png", 1200, 880)  # tall enough for the closing summary lines
    for png in sorted(IMAGES.glob("*.png")):
        print(png, png.stat().st_size)


if __name__ == "__main__":
    main()
