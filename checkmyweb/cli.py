from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import socket
import sys

from . import __version__, verify
from .checks import ALL, BY_NAME
from .httpclient import HttpClient
from .models import Severity
from .report import enable_ansi, render_batch_console, render_console, render_index, write_html, write_json
from .resolver import Resolver
from .scanner import NET_ERRORS, Options, run_scan
from .target import Target, all_loopback

SEVERITY_CHOICES = [s.label for s in Severity]
MAX_TARGETS = 50  # a self-check tool for your own sites, not a mass scanner

NOTICE = "※ 본인 소유이거나 점검 권한을 받은 사이트에만 사용하세요. 권한 없는 점검은 법적 책임이 따를 수 있습니다."


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="checkmyweb",
        description="비침투적 웹사이트 보안 자가 점검 도구. " + NOTICE,
        epilog="소유 확인:  checkmyweb verify <도메인>   (민감 파일·포트 점검을 켜는 방법 안내)",
    )
    p.add_argument("targets", nargs="*", metavar="TARGET",
                   help="점검할 도메인 또는 URL. 포트·경로 지정 가능 (예: wookly.dev, https://example.com:8443/app/)")
    p.add_argument("-f", "--targets-file", metavar="FILE", help="한 줄에 하나씩 대상을 적은 파일 (# 주석 가능)")
    p.add_argument("--only", metavar="CHECKS", help="이 점검만 실행 (쉼표 구분, --list-checks 참고)")
    p.add_argument("--skip", metavar="CHECKS", help="제외할 점검 (쉼표 구분)")
    p.add_argument("--ports", action="store_true", help="주요 TCP 포트 점검 포함 (소유 확인 필요)")
    p.add_argument("--list-checks", action="store_true", help="점검 항목 목록 출력")
    p.add_argument("--http-port", type=int, metavar="PORT",
                   help="HTTPS를 비표준 포트로 운영할 때 리다이렉트를 점검할 HTTP 포트")
    p.add_argument("--ca-file", metavar="PEM", help="추가로 신뢰할 CA 인증서 (사내 CA 등)")
    p.add_argument("-o", "--output-dir", default="reports", help="보고서 저장 폴더 (기본: reports)")
    p.add_argument("--json", metavar="PATH", help="JSON 보고서 경로 (대상이 하나일 때)")
    p.add_argument("--html", metavar="PATH", help="HTML 보고서 경로 (대상이 하나일 때)")
    p.add_argument("--no-report", action="store_true", help="파일 보고서를 만들지 않음")
    p.add_argument("--details", action="store_true", help="여러 대상을 점검할 때도 항목별 결과를 모두 출력")
    p.add_argument("--min-severity", choices=SEVERITY_CHOICES, default="pass", help="콘솔에 표시할 최소 위험도")
    p.add_argument("--fail-on", choices=SEVERITY_CHOICES[2:] + ["none"], default="high",
                   help="이 위험도 이상이 발견되면 종료 코드 1 (기본: high)")
    p.add_argument("--timeout", type=float, default=10.0, help="요청 타임아웃(초)")
    p.add_argument("--delay", type=float, default=0.15, help="HTTP 요청 사이 지연(초), 서버 부하 조절")
    p.add_argument("--no-color", action="store_true", help="색상 없이 출력")
    p.add_argument("--version", action="version", version=f"checkmyweb {__version__}")
    return p


def build_verify_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="checkmyweb verify",
                                description="도메인 소유 확인 토큰과 설정 방법을 보여주고 현재 확인 상태를 점검합니다.")
    p.add_argument("target", help="소유를 확인할 도메인 또는 URL")
    p.add_argument("--timeout", type=float, default=10.0, help="요청 타임아웃(초)")
    p.add_argument("--ca-file", metavar="PEM", help="추가로 신뢰할 CA 인증서")
    return p


def select_checks(args) -> list:
    def names(value: str) -> list[str]:
        items = [n.strip() for n in value.split(",") if n.strip()]
        unknown = [n for n in items if n not in BY_NAME]
        if unknown:
            raise SystemExit(f"알 수 없는 점검: {', '.join(unknown)} (사용 가능: {', '.join(BY_NAME)})")
        return items

    if args.only:
        chosen = set(names(args.only))
    else:
        chosen = {m.NAME for m in ALL if m.DEFAULT or (m.NAME == "ports" and args.ports)}
    if args.skip:
        chosen -= set(names(args.skip))
    return [m for m in ALL if m.NAME in chosen]


def read_targets(args) -> list[str]:
    targets = list(args.targets)
    if args.targets_file:
        with open(args.targets_file, encoding="utf-8-sig") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    targets.append(line)
    return list(dict.fromkeys(targets))


def _reconfigure_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            # Consoles handle Unicode natively; pipes/files would otherwise get the ANSI code page.
            stream.reconfigure(errors="replace", **({} if stream.isatty() else {"encoding": "utf-8"}))
        except AttributeError:
            pass


def run_verify(argv: list[str]) -> int:
    args = build_verify_parser().parse_args(argv)
    try:
        target = Target.parse(args.target)
    except ValueError as e:
        print(f"오류: {e}", file=sys.stderr)
        return 2
    try:
        ips = sorted({i[4][0] for i in socket.getaddrinfo(target.host, target.port, proto=socket.IPPROTO_TCP)})
    except OSError as e:
        print(f"오류: {target.host} 의 IP 주소를 확인할 수 없습니다: {e}", file=sys.stderr)
        return 2
    client = HttpClient(timeout=args.timeout, delay=0, ca_file=args.ca_file)

    def fetch(url):
        try:
            return client.request("GET", url, max_body=4096)
        except NET_ERRORS:
            return None

    result = verify.check(target, Resolver(timeout=args.timeout), fetch, loopback=all_loopback(ips))
    print(f"대상: {target.label}  (토큰 발급 기준: {verify.subject(target)})")
    if result.method == "local":
        print("상태: 확인됨 - 이 컴퓨터(루프백 주소)의 대상이라 소유 확인이 필요 없습니다.")
        return 0
    token = result.token or verify.token_for(target)
    print(f"토큰: {token}\n")
    print(verify.instructions(target, token))
    print()
    if result.verified:
        print(f"상태: 확인됨 ({result.label}) - 민감 파일·포트 점검을 실행할 수 있습니다.")
        return 0
    print("상태: 아직 확인되지 않았습니다. 위 방법 중 하나를 설정한 뒤 다시 실행하세요.")
    print("      (DNS 변경은 반영까지 몇 분에서 수 시간이 걸릴 수 있습니다)")
    return 1


def main(argv: list[str] | None = None) -> int:
    _reconfigure_streams()
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["verify"]:
        return run_verify(argv[1:])

    parser = build_parser()
    args = parser.parse_args(argv)
    if args.list_checks:
        for m in ALL:
            flags = []
            if not m.DEFAULT:
                flags.append("옵션: --ports" if m.NAME == "ports" else "기본 꺼짐")
            if getattr(m, "REQUIRES_VERIFICATION", False):
                flags.append("소유 확인 필요")
            print(f"{m.NAME:<12} {m.TITLE}" + (f"  ({', '.join(flags)})" if flags else ""))
        return 0

    try:
        raw_targets = read_targets(args)
    except OSError as e:
        parser.error(f"대상 파일을 읽을 수 없습니다: {e}")
    if not raw_targets:
        parser.error("점검할 대상을 입력하세요. 예: checkmyweb wookly.dev")
    if len(raw_targets) > MAX_TARGETS:
        parser.error(f"한 번에 최대 {MAX_TARGETS}개 대상까지 점검합니다 ({len(raw_targets)}개 입력). "
                     "CheckMyWeb은 내 사이트 자가 점검용입니다.")
    targets = []
    for text in raw_targets:
        try:
            targets.append(Target.parse(text))
        except ValueError as e:
            parser.error(str(e))
    batch = len(targets) > 1
    if batch and (args.html or args.json):
        parser.error("--html/--json 은 대상이 하나일 때만 쓸 수 있습니다. 여러 대상은 -o 폴더에 저장됩니다.")

    color = enable_ansi() and not args.no_color
    checks = select_checks(args)
    options = Options(timeout=args.timeout, delay=args.delay, http_port=args.http_port, ca_file=args.ca_file)
    min_severity = Severity.parse(args.min_severity)
    print(f"CheckMyWeb {__version__} · {len(targets)}개 대상, {len(checks)}개 점검", file=sys.stderr)
    print(NOTICE, file=sys.stderr)

    def progress(index, total, run, findings):
        if findings is None:
            print(f"  [{index:>2}/{total}] {run.title} ...", end="", file=sys.stderr, flush=True)
        else:
            mine = [f for f in findings if f.check == run.name and f.severity >= Severity.LOW]
            status = "오류" if run.error else ("건너뜀" if run.skipped else f"{len(mine)}건")
            print(f" {status} ({run.duration:.1f}s)", file=sys.stderr)

    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = os.path.join(args.output_dir, f"batch-{stamp}") if batch else args.output_dir
    entries = []
    for number, target in enumerate(targets, 1):
        if batch:
            print(f"\n[{number}/{len(targets)}] {target.label}", file=sys.stderr)
        entry = {"label": target.label, "result": None, "error": None, "html": None}
        try:
            result = run_scan(target, options, checks, progress)
        except RuntimeError as e:
            entry["error"] = str(e)
            print(f"오류: {e}", file=sys.stderr)
            entries.append(entry)
            continue
        except KeyboardInterrupt:
            print("\n중단되었습니다.", file=sys.stderr)
            return 130
        entry["result"] = result
        if not batch or args.details:
            render_console(result, color=color, min_severity=min_severity)
        if not args.no_report:
            base = os.path.join(out_dir, target.slug if batch else f"{target.slug}-{stamp}")
            html_path = args.html or base + ".html"
            json_path = args.json or base + ".json"
            for path in (html_path, json_path):
                os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            write_html(result, html_path)
            write_json(result, json_path)
            entry["html"] = os.path.basename(html_path)
            if not batch:
                print(f"\n보고서: {html_path}\n        {json_path}")
        entries.append(entry)

    if batch:
        render_batch_console(entries, color=color)
        if not args.no_report:
            os.makedirs(out_dir, exist_ok=True)
            index_path = os.path.join(out_dir, "index.html")
            with open(index_path, "w", encoding="utf-8") as fh:
                fh.write(render_index(entries, dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M")))
            summary = [{"target": e["label"], "error": e["error"], "report": e["html"],
                        **({"score": e["result"].score, "grade": e["result"].grade,
                            "counts": {s.label: n for s, n in e["result"].counts().items()}} if e["result"] else {})}
                       for e in entries]
            with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as fh:
                json.dump({"started": stamp, "version": __version__, "targets": summary}, fh, ensure_ascii=False, indent=2)
            print(f"\n요약 보고서: {index_path}")

    if any(e["error"] for e in entries):
        return 2
    results = [e["result"] for e in entries if e["result"]]
    if args.fail_on != "none" and any(r.worst >= Severity.parse(args.fail_on) for r in results):
        return 1
    return 0
