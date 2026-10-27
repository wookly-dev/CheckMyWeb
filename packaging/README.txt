CheckMyWeb @VERSION@ · 웹사이트 보안 자가 점검 도구
https://wookly.dev/products/checkmyweb/

본인 소유이거나 점검 권한을 받은 사이트에만 사용하세요.
권한 없는 점검은 관련 법령에 위반될 수 있으며, 그 책임은 사용자에게 있습니다.


[준비]
  Python 3.11 이상이 필요합니다: https://www.python.org/downloads/
  Windows에서는 설치 화면의 "py launcher"와 "Add python.exe to PATH"를 함께 선택하세요.

[실행 - Windows]
  압축을 푼 폴더에서 명령 프롬프트를 열고 실행합니다.
    checkmyweb.cmd example.com
  PowerShell에서는 앞에 .\ 를 붙입니다.
    .\checkmyweb.cmd example.com

[실행 - macOS / Linux]
    python3 checkmyweb.pyz example.com
  (현재 Windows에서 검증했으며, macOS·Linux 실행은 아직 직접 검증하지 않았습니다.)

[결과]
  화면에 요약이 나오고, reports 폴더에 HTML·JSON 보고서가 저장됩니다.
  HTML 보고서를 브라우저로 열면 항목별 근거와 서버 종류에 맞는 조치 방법을 볼 수 있습니다.

[자주 쓰는 명령]
  여러 사이트 한 번에    checkmyweb.cmd example.com shop.example.com
  목록 파일로 점검       checkmyweb.cmd -f sites.txt
  포트·경로 지정         checkmyweb.cmd https://example.com:8443/app/
  포트 점검 포함         checkmyweb.cmd example.com --ports
  전체 옵션 보기         checkmyweb.cmd --help

[소유 확인]
  .env·.git 같은 민감 파일 노출 점검과 포트 점검은 도메인 소유를 확인한 뒤에만 실행됩니다.
    checkmyweb.cmd verify example.com
  안내에 따라 DNS TXT 레코드나 확인 파일을 올린 뒤 다시 점검하세요.

[유의사항]
  - 점검 결과는 문제가 없음을 보증하지 않습니다.
  - 조치 예시는 일반적인 설정 예입니다. 적용하기 전에 설정을 백업하고 내 환경에서 검토하세요.
  - DNS 조회에는 Cloudflare와 Google의 공개 DNS-over-HTTPS 서비스를 사용합니다.
    점검 결과는 WooklyDev로 전송되지 않습니다.
  - 프로그램은 "있는 그대로" 제공되며, 사용 조건은 LICENSE.txt를 따릅니다.

자세한 사용법은 manual.html(사용 설명서)을 참고하세요.
사용권: LICENSE.txt   문의: contact@wookly.dev   홈페이지: https://wookly.dev
