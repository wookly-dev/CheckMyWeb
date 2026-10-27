"""Create the throwaway CA and localhost certificate used by the local test server.

tests/fixture_server.py calls ensure() when the files are missing, so nothing here is
committed. It needs the openssl command (Git for Windows ships one). The CA key is
deleted right after signing, so the CA cannot issue anything else.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILES = ("ca.pem", "server.pem", "server.key")
SERVER_EXT = """basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
"""


def find_openssl() -> str | None:
    found = shutil.which("openssl")
    if found:
        return found
    for candidate in (r"C:\Program Files\Git\mingw64\bin\openssl.exe", r"C:\Program Files\Git\usr\bin\openssl.exe"):
        if os.path.exists(candidate):
            return candidate
    return None


def ensure(directory: Path = HERE) -> bool:
    """True when the certificate files exist (creating them if needed), False without openssl."""
    if all((directory / name).exists() for name in FILES):
        return True
    openssl = find_openssl()
    if not openssl:
        return False
    env = dict(os.environ, MSYS_NO_PATHCONV="1")  # keep "/CN=..." intact for MSYS builds of openssl
    with tempfile.TemporaryDirectory() as tmp:
        def run(*args: str) -> None:
            subprocess.run([openssl, *args], cwd=tmp, env=env, check=True, capture_output=True)

        run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", "ca.key", "-out", "ca.pem", "-days", "3650", "-subj", "/CN=CheckMyWeb Test CA",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash")
        run("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", "server.key", "-out", "server.csr", "-subj", "/CN=localhost")
        Path(tmp, "server.ext").write_text(SERVER_EXT, encoding="ascii")
        run("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
            "-out", "server.pem", "-days", "3650", "-sha256", "-extfile", "server.ext")
        directory.mkdir(parents=True, exist_ok=True)
        for name in FILES:
            shutil.copyfile(Path(tmp, name), directory / name)
    return True


if __name__ == "__main__":
    raise SystemExit(0 if ensure() else "openssl not found")
