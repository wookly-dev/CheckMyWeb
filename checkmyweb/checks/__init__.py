"""Check modules. Each exposes NAME, TITLE, DEFAULT and run(ctx)."""
from . import content, cookies, cors, disclosure, dns_checks, exposure, headers, methods, ports, redirects, tls

ALL = [tls, redirects, headers, cookies, disclosure, content, cors, methods, exposure, dns_checks, ports]
BY_NAME = {m.NAME: m for m in ALL}
