"""What to scan: scheme, host, port and base path parsed from user input."""
from __future__ import annotations

import ipaddress
import re
import urllib.parse
from dataclasses import dataclass

# Second-level labels under country TLDs that act as public suffixes (example.co.kr).
_CC_SECOND_LEVEL = {"co", "or", "go", "ac", "ne", "re", "pe", "com", "net", "org", "gov", "edu"}

# Names that never exist in public DNS (RFC 6761 / 6762 / 8375 and common LAN suffixes).
_PRIVATE_SUFFIXES = (".localhost", ".local", ".lan", ".home", ".internal", ".intranet",
                     ".home.arpa", ".test", ".invalid", ".example", ".corp")


def org_domain(host: str) -> str:
    """Registrable ("organizational") domain, e.g. ai.wookly.dev -> wookly.dev."""
    labels = host.split(".")
    n = 3 if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _CC_SECOND_LEVEL else 2
    return ".".join(labels[-n:])


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int
    path: str = "/"

    @classmethod
    def parse(cls, text: str) -> "Target":
        value = text.strip()
        if not value:
            raise ValueError("점검할 대상이 비어 있습니다")
        if "://" not in value:
            value = "https://" + value
        parts = urllib.parse.urlsplit(value)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"http/https 주소만 점검할 수 있습니다: {text!r}")
        host = (parts.hostname or "").lower().rstrip(".")
        if not host or not re.fullmatch(r"[a-z0-9._:-]+", host):
            raise ValueError(f"호스트 이름을 해석할 수 없습니다: {text!r}")
        try:
            port = parts.port or (443 if scheme == "https" else 80)
        except ValueError:
            raise ValueError(f"포트 번호가 올바르지 않습니다: {text!r}") from None
        path = parts.path or "/"
        if not path.endswith("/"):
            head, _, last = path.rpartition("/")
            # "/app" is a directory; "/app/index.php" means its directory "/app/".
            path = head + "/" if "." in last else path + "/"
        return cls(scheme, host, port, path)

    @property
    def default_port(self) -> bool:
        return self.port == (443 if self.scheme == "https" else 80)

    @property
    def netloc(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return host if self.default_port else f"{host}:{self.port}"

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.netloc}"

    @property
    def url(self) -> str:
        return self.origin + self.path

    @property
    def label(self) -> str:
        """Short display name: wookly.dev, wookly.dev:8443/app/, http://intranet:8080"""
        text = self.netloc + (self.path if self.path != "/" else "")
        return text if self.scheme == "https" else f"http://{text}"

    @property
    def slug(self) -> str:
        """File-name-safe form of the label."""
        return re.sub(r"[^A-Za-z0-9.-]+", "_", self.label.replace("://", "_")).strip("_.") or "target"

    @property
    def ip(self):
        try:
            return ipaddress.ip_address(self.host)
        except ValueError:
            return None

    @property
    def is_ip(self) -> bool:
        return self.ip is not None

    @property
    def has_public_dns(self) -> bool:
        return not self.is_ip and "." in self.host and not self.host.endswith(_PRIVATE_SUFFIXES)

    @property
    def apex(self) -> str:
        return self.host[4:] if self.host.startswith("www.") else self.host

    @property
    def org_domain(self) -> str:
        return self.host if self.is_ip else org_domain(self.host)


def all_loopback(addresses: list[str]) -> bool:
    try:
        return bool(addresses) and all(ipaddress.ip_address(a.split("%")[0]).is_loopback for a in addresses)
    except ValueError:
        return False
