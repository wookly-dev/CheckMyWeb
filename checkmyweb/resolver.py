"""DNS lookups over HTTPS (JSON API), so no third-party resolver library is needed."""
from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from .httpclient import USER_AGENT

RESOLVERS = (
    ("cloudflare", "https://cloudflare-dns.com/dns-query"),
    ("google", "https://dns.google/resolve"),
)

RTYPES = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
    "AAAA": 28, "DS": 43, "DNSKEY": 48, "CAA": 257,
}


@dataclass
class DnsAnswer:
    name: str
    rtype: str
    status: int = -1  # DNS RCODE: 0 NOERROR, 3 NXDOMAIN
    ad: bool = False  # resolver validated the answer with DNSSEC
    records: list[str] = field(default_factory=list)
    error: str | None = None
    cnames: list[str] = field(default_factory=list)  # CNAME chain seen while resolving

    @property
    def ok(self) -> bool:
        return self.status == 0


def _parse_txt(data: str) -> str:
    chunks = re.findall(r'"((?:[^"\\]|\\.)*)"', data)
    if not chunks:
        return data
    return "".join(c.replace('\\"', '"').replace("\\\\", "\\") for c in chunks)


def _parse_caa(data: str) -> str:
    # Some resolvers return CAA in RFC 3597 generic form: "\# 22 00 05 69 73 ..."
    if not data.startswith("\\#"):
        return data
    raw = bytes.fromhex("".join(data.split()[2:]))
    flags, tag_len = raw[0], raw[1]
    tag = raw[2:2 + tag_len].decode("ascii", "replace")
    value = raw[2 + tag_len:].decode("utf-8", "replace")
    return f'{flags} {tag} "{value}"'


class Resolver:
    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout
        self._cache: dict[tuple[str, str], DnsAnswer] = {}

    def query(self, name: str, rtype: str) -> DnsAnswer:
        name = name.lower().rstrip(".")
        key = (name, rtype)
        if key in self._cache:
            return self._cache[key]

        code = RTYPES[rtype]
        errors = []
        answer = None
        for label, base in RESOLVERS:
            url = base + "?" + urllib.parse.urlencode({"name": name, "type": rtype, "do": "1"})
            req = urllib.request.Request(url, headers={"Accept": "application/dns-json", "User-Agent": USER_AGENT})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    data = json.loads(resp.read())
            except (OSError, ValueError) as e:
                errors.append(f"{label}: {e}")
                continue
            records, cnames = [], []
            for ans in data.get("Answer") or []:
                value = ans.get("data", "")
                if ans.get("type") == RTYPES["CNAME"] and code != RTYPES["CNAME"]:
                    cnames.append(value.rstrip(".").lower())  # aliases followed on the way
                    continue
                if ans.get("type") != code:
                    continue
                if rtype == "TXT":
                    value = _parse_txt(value)
                elif rtype == "CAA":
                    value = _parse_caa(value)
                records.append(value)
            answer = DnsAnswer(name, rtype, data.get("Status", -1), bool(data.get("AD")), records, cnames=cnames)
            break
        if answer is None:
            answer = DnsAnswer(name, rtype, error="; ".join(errors))
        self._cache[key] = answer
        return answer

    def records(self, name: str, rtype: str) -> list[str]:
        return self.query(name, rtype).records

    def txt(self, name: str) -> list[str]:
        return self.records(name, "TXT")

    def resolves(self, name: str) -> bool:
        return bool(self.records(name, "A") or self.records(name, "AAAA"))

    def cname_chain(self, name: str) -> list[str]:
        return self.query(name, "A").cnames
