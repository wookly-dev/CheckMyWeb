"""Console, JSON and HTML renderers for scan results (single target and batch summary)."""
from __future__ import annotations

import html
import json
import os
import re
import sys
import textwrap
import urllib.parse

from . import __version__
from .models import ScanResult, Severity

PRODUCT_URL = "https://wookly.dev/products/checkmyweb/"

ANSI = {
    Severity.CRITICAL: "\033[97;41m",
    Severity.HIGH: "\033[91m",
    Severity.MEDIUM: "\033[93m",
    Severity.LOW: "\033[96m",
    Severity.INFO: "\033[90m",
    Severity.PASS: "\033[92m",
}
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"

# The CheckMyWeb mark: a shield with a check. Also published as the product icon.
ICON_SVG = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
            '<path d="M32 4 8 13v17c0 15.5 10.2 26.8 24 30 13.8-3.2 24-14.5 24-30V13Z" fill="#1c64c8"/>'
            '<path d="M32 10.5 14 17.3v12.9c0 12 7.6 20.9 18 23.8 10.4-2.9 18-11.8 18-23.8V17.3Z" fill="#3b8ff0"/>'
            '<path d="m22.5 32.5 6.8 6.8 13.2-14.6" fill="none" stroke="#fff" stroke-width="5.2" '
            'stroke-linecap="round" stroke-linejoin="round"/></svg>')
ICON_DATA_URI = "data:image/svg+xml," + urllib.parse.quote(ICON_SVG)


def enable_ansi() -> bool:
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return False
    if os.name == "nt":
        os.system("")  # turns on VT100 escape processing in the Windows console
    return True


def _sorted(findings):
    return sorted(findings, key=lambda f: -f.severity)


def _groups(result: ScanResult):
    """(name, title, run, findings) per check in run order; findings of unlisted checks go last."""
    runs = [(c.name, c.title, c) for c in result.checks]
    known = {name for name, _, _ in runs}
    runs += [(name, name, None) for name in dict.fromkeys(f.check for f in result.findings) if name not in known]
    for name, title, run in runs:
        yield name, title, run, _sorted(f for f in result.findings if f.check == name)


def _first_line(text: str) -> str:
    """One-line preview of a fix: the first block, with a multi-line config joined by " | "."""
    lines = [line.strip() for line in text.strip().splitlines() if line.strip()]
    if not lines:
        return ""
    if not re.fullmatch(r"\[[^\]]+\]", lines[0]):
        return lines[0]
    block = []
    for line in lines[1:]:
        if line.startswith("["):
            break  # next platform
        block.append(line)
    return f"{lines[0]} " + " | ".join(block)


def render_console(result: ScanResult, color: bool = True, min_severity: Severity = Severity.PASS,
                   stream=None) -> None:
    out = stream or sys.stdout

    def paint(code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if color else text

    def badge(sev: Severity) -> str:
        return paint(ANSI[sev], f"[{sev.ko}]")

    width = 100
    meta = result.meta
    platform = (meta.get("platform") or {}).get("summary")
    verification = (meta.get("verification") or {}).get("label")
    print(paint(BOLD, f"\n◆ {result.target}") + paint(DIM, f"  {result.url}"), file=out)
    info = [f"서버 환경: {platform}" if platform else "", f"소유 확인: {verification}" if verification else ""]
    if any(info):
        print(paint(DIM, "  " + " · ".join(i for i in info if i)), file=out)

    for _, title, run, findings in _groups(result):
        findings = [f for f in findings if f.severity >= min_severity]
        if not findings:
            continue
        took = f"  ({run.duration:.1f}s)" if run else ""
        skipped = f"  · 건너뜀: {run.skipped}" if run and run.skipped else ""
        print("\n" + paint(BOLD, f"■ {title}") + paint(DIM, took + skipped), file=out)
        for f in findings:
            print(f"  {badge(f.severity)} {f.title}", file=out)
            if f.severity >= Severity.LOW:
                if f.evidence:
                    first = f.evidence.strip().splitlines()[0]
                    print(paint(DIM, "        근거: " + textwrap.shorten(first, width)), file=out)
                if f.fix:
                    print("        조치: " + textwrap.shorten(_first_line(f.fix), width), file=out)

    counts = result.counts()
    summary = "  ".join(paint(ANSI[s], f"{s.ko} {counts[s]}") for s in sorted(Severity, reverse=True))
    print("\n" + "─" * 60, file=out)
    print(paint(BOLD, f"점수 {result.score}/100  등급 {result.grade}") + f"   {summary}", file=out)
    print(paint(DIM, f"요청 {meta.get('requests', 0)}회, 소요 {result.duration:.1f}s"), file=out)


def render_batch_console(entries: list[dict], color: bool = True, stream=None) -> None:
    """entries: {"label", "result" (ScanResult | None), "error"}."""
    out = stream or sys.stdout

    def paint(code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if color else text

    width = max([len(e["label"]) for e in entries] + [4])
    print("\n" + paint(BOLD, "일괄 점검 요약"), file=out)
    print(paint(DIM, f"  {'대상':<{width}}  등급  점수  심각 높음 보통 낮음"), file=out)
    for e in entries:
        r = e["result"]
        if r is None:
            print(f"  {e['label']:<{width}}  " + paint(ANSI[Severity.HIGH], f"오류: {e['error']}"), file=out)
            continue
        c = r.counts()
        print(f"  {e['label']:<{width}}  {r.grade:^4}  {r.score:>4}  "
              f"{c[Severity.CRITICAL]:>4} {c[Severity.HIGH]:>4} {c[Severity.MEDIUM]:>4} {c[Severity.LOW]:>4}", file=out)


def write_json(result: ScanResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result.to_dict(), fh, ensure_ascii=False, indent=2)


GRADE_COLOR = {"A": "var(--pass)", "B": "var(--low)", "C": "var(--medium)", "D": "var(--high)", "F": "var(--critical)"}

CSS = """
:root {
  --bg: #f6f7f9; --surface: #ffffff; --text: #1d2330; --muted: #5d6676; --border: #e2e5ea; --code: #f1f3f6;
  --critical: #b3261e; --high: #d9480f; --medium: #b7791f; --low: #1c7ed6; --info: #6b7280; --pass: #2f9e44;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #12151b; --surface: #1b1f27; --text: #e6e8ec; --muted: #9aa3b2; --border: #2b313c; --code: #232833;
    --critical: #ff6b6b; --high: #ff922b; --medium: #fcc419; --low: #4dabf7; --info: #9aa3b2; --pass: #51cf66;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.6 "Pretendard", "Apple SD Gothic Neo", "Malgun Gothic", system-ui, sans-serif; }
main { max-width: 980px; margin: 0 auto; padding: 32px 16px 64px; }
.brand { display: flex; align-items: center; gap: 12px; margin: 0 0 4px; }
.brand svg { width: 36px; height: 36px; flex: none; }
h1 { font-size: 24px; margin: 0; }
h2 { font-size: 18px; margin: 36px 0 12px; display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
h2 small { color: var(--muted); font-weight: 400; font-size: 13px; }
.sub { color: var(--muted); margin: 0 0 24px; overflow-wrap: anywhere; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px; }
.summary { display: grid; grid-template-columns: auto 1fr; gap: 24px; align-items: center; }
.grade { width: 112px; height: 112px; border-radius: 50%; display: grid; place-items: center; text-align: center;
  border: 6px solid var(--grade); color: var(--grade); }
.grade b { font-size: 40px; line-height: 1; display: block; }
.grade span { font-size: 13px; color: var(--muted); }
.chips { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; }
.chip { border: 1px solid var(--border); border-radius: 999px; padding: 3px 12px; font-size: 13px; cursor: pointer;
  background: var(--surface); color: var(--text); font-family: inherit; }
.chip i { font-style: normal; font-weight: 700; color: var(--c); margin-right: 4px; }
.chip[aria-pressed="false"] { opacity: .4; }
dl.meta { display: grid; grid-template-columns: max-content 1fr; gap: 2px 16px; margin: 0; font-size: 13px; }
dl.meta dt { color: var(--muted); }
dl.meta dd { margin: 0; overflow-wrap: anywhere; }
.top li { margin: 4px 0; }
.skip { color: var(--muted); font-size: 13px; margin: -4px 0 8px; }
.finding { background: var(--surface); border: 1px solid var(--border); border-left: 4px solid var(--c);
  border-radius: 8px; margin: 8px 0; }
.finding summary { cursor: pointer; padding: 10px 14px; display: flex; gap: 10px; align-items: baseline; list-style: none; }
.finding summary::-webkit-details-marker { display: none; }
.sev { flex: none; font-size: 12px; font-weight: 700; color: var(--c); min-width: 34px; }
.finding .body { padding: 0 14px 14px 58px; }
.finding .body p { margin: 6px 0; white-space: pre-line; }
.label { font-size: 12px; color: var(--muted); margin-top: 10px; }
pre { background: var(--code); border-radius: 6px; padding: 10px 12px; margin: 4px 0; font-size: 12.5px;
  white-space: pre-wrap; overflow-wrap: anywhere; font-family: ui-monospace, Consolas, monospace; }
.refs a, a.link { color: var(--low); overflow-wrap: anywhere; }
.refs a { font-size: 13px; margin-right: 12px; }
table.batch { width: 100%; border-collapse: collapse; font-size: 14px; }
table.batch th, table.batch td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); }
table.batch th { color: var(--muted); font-weight: 600; font-size: 13px; }
table.batch th.num, table.batch td.num { text-align: right; font-variant-numeric: tabular-nums; }
.pill { display: inline-block; min-width: 28px; text-align: center; border-radius: 6px; font-weight: 700;
  color: #fff; background: var(--c); padding: 0 6px; }
.table-wrap { overflow-x: auto; }
.hidden { display: none; }
footer { color: var(--muted); font-size: 12px; margin-top: 48px; }
@media (max-width: 600px) {
  .summary { grid-template-columns: 1fr; justify-items: center; }
  .finding .body { padding-left: 14px; }
}
"""

JS = """
document.querySelectorAll('.chip').forEach(function (chip) {
  chip.addEventListener('click', function () {
    var on = chip.getAttribute('aria-pressed') !== 'true';
    chip.setAttribute('aria-pressed', on);
    document.querySelectorAll('.finding[data-sev="' + chip.dataset.sev + '"]').forEach(function (el) {
      el.classList.toggle('hidden', !on);
    });
    document.querySelectorAll('section.check').forEach(function (sec) {
      sec.classList.toggle('hidden', !sec.querySelector('.finding:not(.hidden)'));
    });
  });
});
"""

FOOTER = (f"CheckMyWeb {__version__} · <a class=\"link\" href=\"{PRODUCT_URL}\">{PRODUCT_URL}</a><br>"
          "이 보고서는 비침투적 자동 점검 결과입니다. 쓰기 요청이나 공격 페이로드는 보내지 않았으며, "
          "발견되지 않은 항목이 곧 안전함을 뜻하지는 않습니다. 조치 예시는 일반적인 설정 예이므로 "
          "적용하기 전에 설정을 백업하고 내 환경에서 검토하세요. 본인 소유이거나 점검 권한을 받은 사이트에만 "
          "사용하세요. 사용 조건은 프로그램과 함께 배포된 LICENSE.txt를 따릅니다.")


def _e(text) -> str:
    return html.escape(str(text or ""))


def _page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)}</title>
<link rel="icon" href="{ICON_DATA_URI}">
<style>{CSS}</style>
</head>
<body>
<main>
{body}
<footer>{FOOTER}</footer>
</main>
<script>{JS}</script>
</body>
</html>
"""


def render_html(result: ScanResult) -> str:
    counts = result.counts()
    meta = result.meta
    tls = meta.get("tls") or {}
    platform = meta.get("platform") or {}
    verification = meta.get("verification") or {}
    rows = [
        ("대상", result.url or result.target),
        ("최종 URL", meta.get("final_url", "-")),
        ("IP", ", ".join(meta.get("ip", [])) or "-"),
        ("서버 환경", platform.get("summary") or "-"),
        ("Server 헤더", meta.get("server") or "-"),
        ("TLS", f"{tls.get('version', '-')} / {tls.get('cipher', '-')}" if tls else "-"),
        ("인증서 만료까지", f"{meta['cert_days_left']}일" if "cert_days_left" in meta else "-"),
        ("소유 확인", verification.get("label") or "해당 점검 없음"),
        ("점검 시각", result.started),
        ("요청 수 / 소요", f"{meta.get('requests', 0)}회 / {result.duration:.1f}초"),
    ]
    meta_html = "".join(f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in rows)

    chips = "".join(
        f'<button class="chip" type="button" data-sev="{s.label}" aria-pressed="true" style="--c:var(--{s.label})">'
        f"<i>{counts[s]}</i>{s.ko}</button>"
        for s in sorted(Severity, reverse=True)
    )

    urgent = [f for f in _sorted(result.findings) if f.severity >= Severity.MEDIUM]
    titles = {c.name: c.title for c in result.checks}
    if urgent:
        top = "<ol class='top'>" + "".join(
            f'<li><span class="sev" style="--c:var(--{f.severity.label})">{f.severity.ko}</span> '
            f'{_e(f.title)} <small style="color:var(--muted)">· {_e(titles.get(f.check, f.check))}</small></li>'
            for f in urgent) + "</ol>"
    else:
        top = "<p>보통 이상 위험도의 항목이 없습니다.</p>"

    sections = []
    for name, title, run, findings in _groups(result):
        if not findings:
            continue
        items = []
        for f in findings:
            body = []
            if f.detail:
                body.append(f"<p>{_e(f.detail)}</p>")
            if f.evidence:
                body.append(f'<div class="label">근거</div><pre>{_e(f.evidence)}</pre>')
            if f.fix:
                body.append(f'<div class="label">조치 방법</div><pre>{_e(f.fix)}</pre>')
            if f.refs:
                links = "".join(f'<a href="{_e(u)}" rel="noopener noreferrer">{_e(u)}</a>' for u in f.refs)
                body.append(f'<div class="label">참고</div><div class="refs">{links}</div>')
            opened = " open" if f.severity >= Severity.MEDIUM else ""
            inner = f'<div class="body">{"".join(body)}</div>' if body else ""
            items.append(
                f'<details class="finding" data-sev="{f.severity.label}" style="--c:var(--{f.severity.label})"{opened}>'
                f'<summary><span class="sev">{f.severity.ko}</span><span>{_e(f.title)}</span></summary>{inner}</details>')
        took = f" <small>{run.duration:.1f}s</small>" if run else ""
        skip = f'<p class="skip">건너뜀: {_e(run.skipped)}</p>' if run and run.skipped else ""
        sections.append(f'<section class="check" id="check-{_e(name)}"><h2>{_e(title)}{took}</h2>{skip}{"".join(items)}</section>')

    grade_color = GRADE_COLOR.get(result.grade, "var(--muted)")
    body = f"""<div class="brand">{ICON_SVG}<h1>웹사이트 보안 점검 보고서</h1></div>
<p class="sub">{_e(result.target)} · {_e(result.started)}</p>

<div class="card summary">
  <div class="grade" style="--grade:{grade_color}"><div><b>{result.grade}</b><span>{result.score} / 100</span></div></div>
  <div>
    <div class="chips">{chips}</div>
    <dl class="meta">{meta_html}</dl>
  </div>
</div>

<h2>우선 조치 항목 <small>보통 이상</small></h2>
<div class="card">{top}</div>

{"".join(sections)}"""
    return _page(f"{result.target} 보안 점검", body)


def render_index(entries: list[dict], started: str) -> str:
    """Batch summary page. entries: {"label", "result", "error", "html" (relative link)}."""
    rows = []
    for e in entries:
        r = e["result"]
        label = _e(e["label"])
        if r is None:
            rows.append(f'<tr><td>{label}</td><td colspan="6">오류: {_e(e["error"])}</td></tr>')
            continue
        c = r.counts()
        color = GRADE_COLOR.get(r.grade, "var(--muted)")
        link = f'<a class="link" href="{_e(e["html"])}">{label}</a>' if e.get("html") else label
        rows.append(
            f'<tr><td>{link}</td><td><span class="pill" style="--c:{color}">{r.grade}</span></td>'
            f'<td class="num">{r.score}</td><td class="num">{c[Severity.CRITICAL]}</td><td class="num">{c[Severity.HIGH]}</td>'
            f'<td class="num">{c[Severity.MEDIUM]}</td><td class="num">{c[Severity.LOW]}</td></tr>')
    done = [e["result"] for e in entries if e["result"] is not None]
    worst = min(done, key=lambda r: r.score) if done else None
    lead = (f"{len(entries)}개 대상 · 가장 낮은 점수 {worst.score}점 ({_e(worst.target)})" if worst
            else f"{len(entries)}개 대상")
    body = f"""<div class="brand">{ICON_SVG}<h1>일괄 점검 요약</h1></div>
<p class="sub">{lead} · {_e(started)}</p>
<div class="card table-wrap">
<table class="batch">
<thead><tr><th>대상</th><th>등급</th><th class="num">점수</th><th class="num">심각</th><th class="num">높음</th>
<th class="num">보통</th><th class="num">낮음</th></tr></thead>
<tbody>{"".join(rows)}</tbody>
</table>
</div>"""
    return _page("일괄 점검 요약", body)


def write_html(result: ScanResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_html(result))
