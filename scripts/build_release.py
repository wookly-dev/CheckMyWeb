"""Build the public release package.

    python scripts/build_release.py

Writes dist/CheckMyWeb-<version>.zip (and SHA256SUMS.txt) containing only the
user-facing files: the program, the Windows launcher, a short guide, the
manual and the license. Tests, source tree and development notes stay out.
The manual's screenshots (packaging/images/) are inlined so it stays one file.
Entries get fixed timestamps so rebuilding the same version gives the same bytes.
It also copies manual.html and LICENSE.txt to dist/site/ for the product page.
"""
from __future__ import annotations

import base64
import hashlib
import io
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from checkmyweb import __version__  # noqa: E402

PACKAGING = ROOT / "packaging"
IMAGES = PACKAGING / "images"
DIST = ROOT / "dist"
STAMP = (2026, 10, 26, 0, 0, 0)
PACKAGE_FILES = ["checkmyweb.pyz", "checkmyweb.cmd", "README.txt", "manual.html", "LICENSE.txt"]
PYZ_MAIN = b"import sys\nfrom checkmyweb.cli import main\nsys.exit(main())\n"


def _add(zf: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=STAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    zf.writestr(info, data)


def build_pyz() -> bytes:
    buf = io.BytesIO()
    buf.write(b"#!/usr/bin/env python3\n")
    with zipfile.ZipFile(buf, "w") as zf:
        _add(zf, "__main__.py", PYZ_MAIN)
        for path in sorted((ROOT / "checkmyweb").rglob("*.py")):
            # LF regardless of the checkout's line endings, so a fresh clone rebuilds the same bytes.
            _add(zf, path.relative_to(ROOT).as_posix(), path.read_bytes().replace(b"\r\n", b"\n"))
    return buf.getvalue()


def embed_images(text: str) -> str:
    """Replace @IMAGE:name.png@ with a data URI so the manual works offline as a single file."""
    def data_uri(match: re.Match) -> str:
        return "data:image/png;base64," + base64.b64encode((IMAGES / match.group(1)).read_bytes()).decode("ascii")
    return re.sub(r"@IMAGE:([\w.-]+\.png)@", data_uri, text)


def text_file(name: str, *, crlf: bool, bom: bool) -> bytes:
    text = embed_images((PACKAGING / name).read_text(encoding="utf-8").replace("@VERSION@", __version__))
    if crlf:
        text = text.replace("\r\n", "\n").replace("\n", "\r\n")
    return text.encode("utf-8-sig" if bom else "utf-8")


def build() -> Path:
    contents = {
        "checkmyweb.pyz": build_pyz(),
        "checkmyweb.cmd": text_file("checkmyweb.cmd", crlf=True, bom=False),
        "README.txt": text_file("README.txt", crlf=True, bom=True),
        "manual.html": text_file("manual.html", crlf=False, bom=False),
        "LICENSE.txt": text_file("LICENSE.txt", crlf=True, bom=True),
    }
    assert list(contents) == PACKAGE_FILES
    contents["checkmyweb.cmd"].decode("ascii")  # cmd.exe reads batch files in the OEM code page

    DIST.mkdir(exist_ok=True)
    archive = DIST / f"CheckMyWeb-{__version__}.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for name, data in contents.items():
            _add(zf, name, data)

    site = DIST / "site"
    site.mkdir(exist_ok=True)
    for name in ("manual.html", "LICENSE.txt"):
        (site / name).write_bytes(contents[name])

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (DIST / "SHA256SUMS.txt").write_text(f"{digest}  {archive.name}\n", encoding="ascii", newline="\n")
    return archive


def verify(archive: Path) -> None:
    with zipfile.ZipFile(archive) as zf:
        names = zf.namelist()
        if names != PACKAGE_FILES:
            raise SystemExit(f"unexpected package contents: {names}")
        for name in names:
            if name != "checkmyweb.pyz" and re.search(rb"@(VERSION|IMAGE:[^@]*)@", zf.read(name)):
                raise SystemExit(f"unreplaced placeholder in {name}")
        with tempfile.TemporaryDirectory() as tmp:
            zf.extractall(tmp)
            out = subprocess.run([sys.executable, str(Path(tmp) / "checkmyweb.pyz"), "--version"],
                                 capture_output=True, text=True, encoding="utf-8", check=True).stdout.strip()
    if out != f"checkmyweb {__version__}":
        raise SystemExit(f"packaged program reports {out!r}")


def main() -> None:
    archive = build()
    verify(archive)
    size = archive.stat().st_size
    print(f"{archive}  {size:,} bytes")
    print((DIST / "SHA256SUMS.txt").read_text(encoding="ascii").strip())


if __name__ == "__main__":
    main()
