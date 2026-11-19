"""疑似サーバー用の自己署名証明書と、証明書のissuer取得 (標準ライブラリのみ)。
FWがSSLインスペクション(復号)していると、クライアントが見る証明書のissuerが
ここの TEST_ISSUER ではなくFWのCAに変わる → それで復号を検出する。
"""
import os
import ssl
import tempfile

TEST_ISSUER = "CN=tgen-test-server, O=TGEN Test Server, C=JP"

CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIB9zCCAZ6gAwIBAgIUZW+PZHhRnC61t8j6IkYH2ByeQXMwCgYIKoZIzj0EAwIw
QzEZMBcGA1UEAwwQdGdlbi10ZXN0LXNlcnZlcjEZMBcGA1UECgwQVEdFTiBUZXN0
IFNlcnZlcjELMAkGA1UEBhMCSlAwHhcNMjYxMTE5MTUzMzA1WhcNNDYxMTE0MTUz
MzA1WjBDMRkwFwYDVQQDDBB0Z2VuLXRlc3Qtc2VydmVyMRkwFwYDVQQKDBBUR0VO
IFRlc3QgU2VydmVyMQswCQYDVQQGEwJKUDBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABOT85aUCg1ow/ulKrtp2jSToLC+sUJtSjld9S0QXvOsPZolzYEKMBk9/qY9O
YidFPbl7iaMrWZerygGDzKIaQbCjcDBuMB0GA1UdDgQWBBRdG2W+pZhakU7sTfq+
RPtow9KV5TAfBgNVHSMEGDAWgBRdG2W+pZhakU7sTfq+RPtow9KV5TAPBgNVHRMB
Af8EBTADAQH/MBsGA1UdEQQUMBKCEHRnZW4tdGVzdC1zZXJ2ZXIwCgYIKoZIzj0E
AwIDRwAwRAIgL6ZgjHEpiMJQcFRMK0RKcW6OokfZ8mgey5CtVQz2bpsCIGqQj0Nj
vprUDdGkUrea6/x1QMv1DZatt+8x4WzKEZs+
-----END CERTIFICATE-----
"""
KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVj/FZq5Ylpa5sqNS
FYoQep7tjCbT1+fSiHja/9uKgtWhRANCAATk/OWlAoNaMP7pSq7ado0k6CwvrFCb
Uo5XfUtEF7zrD2aJc2BCjAZPf6mPTmInRT25e4mjK1mXq8oBg8yiGkGw
-----END PRIVATE KEY-----
"""

_ctx = None


def server_context():
    global _ctx
    if _ctx is None:
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        d = tempfile.mkdtemp(prefix="tgen")
        cp, kp = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
        with open(cp, "w") as f:
            f.write(CERT_PEM)
        with open(kp, "w") as f:
            f.write(KEY_PEM)
        c.load_cert_chain(cp, kp)
        for p in (cp, kp):
            os.remove(p)
        os.rmdir(d)
        _ctx = c
    return _ctx


def client_context():
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


# ---- 最小限のDERパーサ (issuerの取得用)
def _tlv(b, i):
    tag = b[i]
    ln = b[i + 1]
    i += 2
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(b[i:i + n], "big")
        i += n
    return tag, i, i + ln


_OID = {b"\x55\x04\x03": "CN", b"\x55\x04\x0a": "O", b"\x55\x04\x06": "C", b"\x55\x04\x0b": "OU"}


def issuer_of(der: bytes) -> str:
    """DER証明書 -> 'CN=..., O=..., C=..' (取得できなければ '')"""
    try:
        _, s, _ = _tlv(der, 0)            # Certificate
        _, s, _ = _tlv(der, s)            # TBSCertificate
        t, a, b = _tlv(der, s)            # [0] version か serial
        if t == 0xA0:
            s = b
            t, a, b = _tlv(der, s)
        s = b                             # serial の後ろ
        t, a, b = _tlv(der, s)            # signature alg
        s = b
        t, a, b = _tlv(der, s)            # issuer (SEQUENCE of SET)
        parts = []
        p = a
        while p < b:
            _, sa, sb = _tlv(der, p)      # SET
            _, qa, qb = _tlv(der, sa)     # SEQUENCE
            _, oa, ob = _tlv(der, qa)     # OID
            oid = der[oa:ob]
            _, va, vb = _tlv(der, ob)
            name = _OID.get(oid)
            if name:
                parts.append("%s=%s" % (name, der[va:vb].decode("utf-8", "replace")))
            p = sb
        return ", ".join(parts)
    except Exception:
        return ""
