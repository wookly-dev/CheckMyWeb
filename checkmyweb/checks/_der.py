"""Minimal DER reader: just enough X.509 to get the signature algorithm and key size."""
from __future__ import annotations

RSA = "1.2.840.113549.1.1.1"
EC = "1.2.840.10045.2.1"

NAMES = {
    RSA: "RSA",
    EC: "EC",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
}

CURVES = {
    "1.2.840.10045.3.1.7": ("P-256", 256),
    "1.3.132.0.34": ("P-384", 384),
    "1.3.132.0.35": ("P-521", 521),
}


def _tlv(data: bytes, pos: int) -> tuple[int, int, int]:
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    return tag, pos, pos + length


def _children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out = []
    while start < end:
        node = _tlv(data, start)
        out.append(node)
        start = node[2]
    return out


def _oid(raw: bytes) -> str:
    parts = [raw[0] // 40, raw[0] % 40]
    value = 0
    for b in raw[1:]:
        value = (value << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(value)
            value = 0
    return ".".join(map(str, parts))


def _key_info(der: bytes, spki_node: tuple[int, int, int]) -> dict:
    spki = _children(der, spki_node[1], spki_node[2])
    alg = _children(der, spki[0][1], spki[0][2])
    key_oid = _oid(der[alg[0][1]:alg[0][2]])
    info = {"key_type": NAMES.get(key_oid, key_oid), "key_bits": None, "curve": None}
    if key_oid == RSA:
        bit_string = spki[1]
        _, rs, re_ = _tlv(der, bit_string[1] + 1)  # skip "unused bits" byte
        modulus = der[slice(*_children(der, rs, re_)[0][1:])]
        info["key_bits"] = int.from_bytes(modulus, "big").bit_length()
    elif key_oid == EC and len(alg) > 1 and alg[1][0] == 0x06:
        curve = CURVES.get(_oid(der[alg[1][1]:alg[1][2]]))
        if curve:
            info["curve"], info["key_bits"] = curve
    elif info["key_type"] == "Ed25519":
        info["key_bits"] = 256
    return info


def public_key_info(spki_der: bytes) -> dict:
    """Key type/size of a bare SubjectPublicKeyInfo (e.g. a DKIM p= value)."""
    return _key_info(spki_der, _tlv(spki_der, 0))


def cert_info(der: bytes) -> dict:
    _, start, end = _tlv(der, 0)
    tbs_node, sig_alg_node = _children(der, start, end)[:2]

    sig_alg = _children(der, sig_alg_node[1], sig_alg_node[2])
    sig_oid = _oid(der[sig_alg[0][1]:sig_alg[0][2]])

    tbs = _children(der, tbs_node[1], tbs_node[2])
    offset = 1 if tbs[0][0] == 0xA0 else 0  # optional [0] version
    spki_node = tbs[offset + 5]  # serial, signature, issuer, validity, subject, spki
    return {"sig_alg": NAMES.get(sig_oid, sig_oid), **_key_info(der, spki_node)}
