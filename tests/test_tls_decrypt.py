"""Déchiffrement TLS sur de vraies sessions OpenSSL (en mémoire) avec SSLKEYLOGFILE."""
import datetime
import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from packetphantom.engine import Engine, EngineConfig
from packetphantom.tlsdecrypt import KeyLog, decrypt_conversation

REQUEST = b"GET /secret HTTP/1.1\r\nHost: phantom.test\r\n\r\n"
RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\ntop secret"


@pytest.fixture(scope="module")
def certificate(tmp_path_factory):
    folder = tmp_path_factory.mktemp("pki")
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "phantom.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("phantom.test")]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = folder / "cert.pem", folder / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert_path, key_path


def tls_session(certificate, keylog, version: ssl.TLSVersion, cipher: str | None = None):
    """Joue une session client/serveur réelle ; retourne les octets échangés, dans l'ordre."""
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(*certificate)
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.check_hostname, client_ctx.verify_mode = False, ssl.CERT_NONE
    client_ctx.keylog_filename = str(keylog)
    for ctx in (server_ctx, client_ctx):
        ctx.minimum_version = ctx.maximum_version = version
    if cipher:
        client_ctx.set_ciphers(cipher)

    bios = [ssl.MemoryBIO() for _ in range(4)]
    client = client_ctx.wrap_bio(bios[0], bios[1], server_hostname="phantom.test")
    server = server_ctx.wrap_bio(bios[2], bios[3], server_side=True)
    chunks = []

    def pump():
        for is_client, outgoing, incoming in ((True, bios[1], bios[2]), (False, bios[3], bios[0])):
            if data := outgoing.read():
                chunks.append((is_client, data))
                incoming.write(data)

    pending = {client, server}
    for _ in range(20):
        for side in list(pending):
            try:
                side.do_handshake()
                pending.discard(side)
            except ssl.SSLWantReadError:
                pass
            pump()
        if not pending:
            break
    client.write(REQUEST)
    pump()
    assert server.read(4096) == REQUEST
    server.write(RESPONSE)
    pump()
    assert client.read(4096) == RESPONSE
    return chunks, client.cipher()[0]


CASES = [
    (ssl.TLSVersion.TLSv1_3, None),
    (ssl.TLSVersion.TLSv1_2, "ECDHE-ECDSA-AES128-GCM-SHA256"),
    (ssl.TLSVersion.TLSv1_2, "ECDHE-ECDSA-AES256-GCM-SHA384"),
    (ssl.TLSVersion.TLSv1_2, "ECDHE-ECDSA-CHACHA20-POLY1305"),
]


@pytest.mark.parametrize("version, cipher", CASES)
def test_decrypt_real_sessions(certificate, tmp_path, version, cipher):
    keylog = tmp_path / "keys.log"
    chunks, negotiated = tls_session(certificate, keylog, version, cipher)
    plaintext, note = decrypt_conversation(chunks, KeyLog(keylog))
    assert plaintext == [(True, REQUEST), (False, RESPONSE)], note
    assert note.startswith("Déchiffré")


def test_missing_keys_are_reported(certificate, tmp_path):
    chunks, _ = tls_session(certificate, tmp_path / "keys.log", ssl.TLSVersion.TLSv1_3)
    (tmp_path / "empty.log").write_text("")
    plaintext, note = decrypt_conversation(chunks, KeyLog(tmp_path / "empty.log"))
    assert plaintext is None and "absents du keylog" in note


def test_engine_conversation_decrypts_captured_packets(certificate, tmp_path):
    keylog = tmp_path / "keys.log"
    chunks, _ = tls_session(certificate, keylog, ssl.TLSVersion.TLSv1_3)
    engine = Engine(EngineConfig(keylog=str(keylog)))
    seq = {True: 1000, False: 9000}
    for i, (is_client, data) in enumerate(chunks):
        ends = (("10.0.0.5", 51000), ("93.184.216.34", 443))
        (src, sport), (dst, dport) = ends if is_client else ends[::-1]
        frame = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=seq[is_client]) / Raw(data)
        seq[is_client] += len(data)
        engine.process(bytes(frame), 1_700_000_000 + i * 0.01)
    conv = engine.conversation(1)
    engine.close()
    assert engine.get_packet(1).domain == "phantom.test"
    assert conv.plaintext == [(True, REQUEST), (False, RESPONSE)] and conv.note.startswith("Déchiffré · TLS 1.3")
