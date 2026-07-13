"""Mutual TLS for the HTTP transport (chp-v0.2.md §5, proposal 0031). A client
presenting a CA-signed cert authenticates over mTLS and its cert identity binds to
the evidence subject (verified); a client with an unknown-CA cert is refused at the
handshake — no bytes reach a handler."""

from __future__ import annotations

import datetime
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chp_core import CapabilityDescriptor, LocalCapabilityHost, SQLiteEvidenceStore
from chp_core.http import RemoteCapabilityHost, create_http_server

crypto = pytest.importorskip("cryptography")


def _make_ca(name: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import NameOID

    key = ed25519.Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2020, 1, 1))
            .not_valid_after(datetime.datetime(2040, 1, 1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, None))
    return key, cert


def _issue(ca_key, ca_cert, cn: str, *, san: str | None = None, ip: str | None = None):
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import NameOID

    key = ed25519.Ed25519PrivateKey.generate()
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
         .issuer_name(ca_cert.subject).public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(datetime.datetime(2020, 1, 1))
         .not_valid_after(datetime.datetime(2040, 1, 1)))
    names: list = []
    if san:
        names.append(x509.DNSName(san))
    if ip:  # IP hostname verification requires an IPAddress SAN (CN/DNS are ignored)
        names.append(x509.IPAddress(ipaddress.ip_address(ip)))
    if names:
        b = b.add_extension(x509.SubjectAlternativeName(names), critical=False)
    return key, b.sign(ca_key, None)


def _write(tmp: Path, stem: str, key, cert) -> tuple[str, str]:
    from cryptography.hazmat.primitives import serialization
    cpath, kpath = tmp / f"{stem}.crt", tmp / f"{stem}.key"
    cpath.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kpath.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return str(cpath), str(kpath)


def _serve(tmp: Path, cafile: str, server_cert, server_key):
    host = LocalCapabilityHost("mtls-host", store=SQLiteEvidenceStore(":memory:"))

    async def add(_c, p):
        return {"sum": p["a"] + p["b"]}

    host.register(CapabilityDescriptor(id="math.add", version="1.0.0", description="."), add)
    scrt, skey = _write(tmp, "server", server_key, server_cert)
    server = create_http_server(host, port=0, certfile=scrt, keyfile=skey, cafile=cafile)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return host, server, thread


def test_mtls_verified_client_binds_subject(tmp_path):
    ca_key, ca_cert = _make_ca("chp-test-ca")
    cafile, _ = _write(tmp_path, "ca", ca_key, ca_cert)  # cert PEM is the CA bundle
    server_key, server_cert = _issue(ca_key, ca_cert, "127.0.0.1", san="localhost", ip="127.0.0.1")
    client_key, client_cert = _issue(ca_key, ca_cert, "agent-a")
    ccrt, ckey = _write(tmp_path, "client", client_key, client_cert)

    host, server, thread = _serve(tmp_path, cafile, server_cert, server_key)
    try:
        url = f"https://127.0.0.1:{server.server_port}"
        remote = RemoteCapabilityHost(url, client_cert=ccrt, client_key=ckey, cafile=cafile)
        result = remote.invoke("math.add", {"a": 2, "b": 3},
                               correlation={"correlation_id": "mtls-corr"})
        assert result.success and result.data == {"sum": 5}
        # the verified cert identity (CN) is the evidence subject — verified, type mtls
        replay = host.replay("mtls-corr")
        subj = replay[0]["subject"]
        assert subj == {"id": "agent-a", "type": "mtls", "verified": True}
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)


def test_mtls_unknown_ca_client_refused(tmp_path):
    ca_key, ca_cert = _make_ca("chp-test-ca")
    cafile, _ = _write(tmp_path, "ca", ca_key, ca_cert)
    server_key, server_cert = _issue(ca_key, ca_cert, "127.0.0.1", san="localhost", ip="127.0.0.1")
    # a client cert signed by a DIFFERENT (rogue) CA the server does not trust
    rogue_key, rogue_cert = _make_ca("rogue-ca")
    bad_key, bad_cert = _issue(rogue_key, rogue_cert, "impostor")
    bcrt, bkey = _write(tmp_path, "bad", bad_key, bad_cert)

    host, server, thread = _serve(tmp_path, cafile, server_cert, server_key)
    try:
        url = f"https://127.0.0.1:{server.server_port}"
        remote = RemoteCapabilityHost(url, client_cert=bcrt, client_key=bkey, cafile=cafile)
        with pytest.raises(Exception):  # handshake refused — no bytes reach a handler
            remote.invoke("math.add", {"a": 1, "b": 1},
                          correlation={"correlation_id": "rogue"})
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)


def test_peer_identity_helper():
    from chp_core.http import _mtls_peer_identity

    class _Sock:
        def __init__(self, cert): self._c = cert
        def getpeercert(self): return self._c

    assert _mtls_peer_identity(_Sock({"subject": ((("commonName", "agent-x"),),)})) == "agent-x"
    assert _mtls_peer_identity(_Sock({"subjectAltName": (("DNS", "svc.local"),)})) == "svc.local"
    assert _mtls_peer_identity(_Sock({})) is None       # server-only TLS, no client cert
    assert _mtls_peer_identity(object()) is None         # plain TCP (no getpeercert)


if __name__ == "__main__":
    import unittest
    unittest.main()
