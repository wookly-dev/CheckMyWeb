"""Domain ownership verification for the intrusive checks.

Sensitive-file probing and port scanning tell an outsider exactly where a
site is weak, so they only run once the person running the scan shows
control of the site: a TXT record or a file containing a token. The token is
an HMAC of the domain with a secret kept on this computer, so nobody can copy
someone else's token and every machine gets its own.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from .target import Target

TXT_LABEL = "_checkmyweb"
WELL_KNOWN_PATH = "/.well-known/checkmyweb-verify.txt"
TOKEN_PREFIX = "checkmyweb-verify="


def config_dir() -> Path:
    override = os.environ.get("CHECKMYWEB_CONFIG_DIR")
    if override:
        return Path(override)
    if os.name == "nt":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "checkmyweb"


def _secret() -> bytes:
    path = config_dir() / "secret"
    try:
        value = path.read_text(encoding="ascii").strip()
        if len(value) >= 32:
            return value.encode()
    except FileNotFoundError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    value = secrets.token_hex(32)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:  # another process created it first
        return path.read_text(encoding="ascii").strip().encode()
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(value)
    return value.encode()


def subject(target: Target) -> str:
    """What a token is issued for: the registrable domain, or the IP address."""
    return target.org_domain


def token_for(target: Target) -> str:
    digest = hmac.new(_secret(), subject(target).encode(), hashlib.sha256).hexdigest()[:32]
    return TOKEN_PREFIX + digest


def txt_names(target: Target) -> list[str]:
    if not target.has_public_dns:
        return []
    return list(dict.fromkeys([f"{TXT_LABEL}.{target.org_domain}", f"{TXT_LABEL}.{target.host}"]))


def file_url(target: Target) -> str:
    return target.origin + WELL_KNOWN_PATH


@dataclass
class Verification:
    verified: bool
    method: str = ""  # "local" | "dns" | "file"
    detail: str = ""
    token: str = ""

    @property
    def label(self) -> str:
        return {"local": "로컬 대상(자동)", "dns": f"DNS TXT ({self.detail})",
                "file": f"확인 파일 ({self.detail})"}.get(self.method, "미확인")


def check(target: Target, resolver, fetch, loopback: bool) -> Verification:
    """fetch(url) -> Response | None.  loopback: the host resolves only to this machine."""
    if loopback:
        return Verification(True, "local", "루프백 주소")
    token = token_for(target)
    for name in txt_names(target):
        if any(value.strip() == token for value in resolver.txt(name)):
            return Verification(True, "dns", name, token)
    resp = fetch(file_url(target))
    if resp is not None and resp.status == 200 and token in resp.text[:4096]:
        return Verification(True, "file", file_url(target), token)
    return Verification(False, token=token)


def instructions(target: Target, token: str) -> str:
    lines = []
    names = txt_names(target)
    if names:
        lines += [
            "방법 1 · DNS TXT 레코드 (권장)",
            f"  이름: {names[0]}",
            f"  값:   {token}",
            f"  {target.org_domain} 와 그 서브도메인 전체에 적용됩니다.",
            "",
        ]
    lines += [
        f"방법 {2 if names else 1} · 확인 파일",
        f"  주소: {file_url(target)}",
        f"  내용: {token}",
        f"  {target.origin} 에만 적용됩니다.",
        "",
        "토큰은 이 컴퓨터에 저장된 비밀값으로 만들어지므로 컴퓨터마다 다릅니다.",
        "여러 컴퓨터에서 점검하려면 각 컴퓨터의 토큰을 TXT 레코드로 모두 추가하세요.",
    ]
    return "\n".join(lines)
