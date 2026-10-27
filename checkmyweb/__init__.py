"""checkmyweb - 비침투적(non-intrusive) 웹사이트 보안 자가 점검 도구."""
import sys

__version__ = "1.0.2"

if sys.version_info < (3, 11):
    sys.exit("CheckMyWeb에는 Python 3.11 이상이 필요합니다 (현재 %d.%d). "
             "https://www.python.org/downloads/" % sys.version_info[:2])
