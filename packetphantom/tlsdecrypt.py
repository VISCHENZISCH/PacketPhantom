"""Déchiffrement TLS 1.2 / 1.3 à partir d'un fichier SSLKEYLOGFILE (format NSS).

Suites AEAD prises en charge : AES-128/256-GCM et ChaCha20-Poly1305
(soit l'immense majorité du trafic actuel). Les données applicatives
déchiffrées sont restituées dans l'ordre de la conversation.
"""
from __future__ import annotations

import hmac
import os
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from . import _core

CHANGE_CIPHER_SPEC, HANDSHAKE, APPLICATION_DATA = 20, 22, 23
TLS13 = 0x0304


@dataclass(frozen=True)
class Suite:
    name: str
    aead: type
    key_len: int
    sha384: bool = False

    @property
    def hash_name(self) -> str:
        return "sha384" if self.sha384 else "sha256"


_AES128 = ("AES_128_GCM", AESGCM, 16)
_AES256 = ("AES_256_GCM", AESGCM, 32, True)
_CHACHA = ("CHACHA20_POLY1305", ChaCha20Poly1305, 32)
SUITES: dict[int, Suite] = {
    0x1301: Suite(*_AES128), 0x1302: Suite(*_AES256), 0x1303: Suite(*_CHACHA),
    **{c: Suite(*_AES128) for c in (0xC02B, 0xC02F, 0x009C, 0x009E)},
    **{c: Suite(*_AES256) for c in (0xC02C, 0xC030, 0x009D, 0x009F)},
    **{c: Suite(*_CHACHA) for c in (0xCCA8, 0xCCA9, 0xCCAA)},
}


class DecryptError(Exception):
    pass


class KeyLog:
    """Secrets d'un SSLKEYLOGFILE, relu automatiquement quand le fichier change."""

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path).expanduser()
        self._mtime: float | None = None
        self._secrets: dict[tuple[str, str], bytes] = {}

    def get(self, label: str, client_random: str) -> bytes | None:
        self._reload()
        return self._secrets.get((label, client_random.lower()))

    def __len__(self) -> int:
        self._reload()
        return len(self._secrets)

    def _reload(self) -> None:
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            return
        if mtime == self._mtime:
            return
        self._mtime = mtime
        secrets = {}
        for line in self.path.read_text(errors="ignore").splitlines():
            parts = line.split()
            if len(parts) == 3 and not line.startswith("#"):
                try:
                    secrets[(parts[0], parts[1].lower())] = bytes.fromhex(parts[2])
                except ValueError:
                    continue
        self._secrets = secrets


def _hkdf_expand_label(secret: bytes, label: bytes, length: int, sha384: bool) -> bytes:
    full = b"tls13 " + label
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + b"\x00"
    algorithm = hashes.SHA384() if sha384 else hashes.SHA256()
    return HKDFExpand(algorithm=algorithm, length=length, info=info).derive(secret)


def _prf(secret: bytes, label: bytes, seed: bytes, length: int, hash_name: str) -> bytes:
    """PRF TLS 1.2 (P_hash, RFC 5246 §5)."""
    seed = label + seed
    out, a = b"", seed
    while len(out) < length:
        a = hmac.new(secret, a, hash_name).digest()
        out += hmac.new(secret, a + seed, hash_name).digest()
    return out[:length]


def _xor_nonce(iv: bytes, seq: int) -> bytes:
    return bytes(a ^ b for a, b in zip(iv, seq.to_bytes(len(iv), "big"), strict=True))


@dataclass
class _Direction:
    buffer: bytes = b""
    keys: list[tuple[object, bytes]] = field(default_factory=list)   # (aead, iv) par époque
    epoch: int = 0
    seq: int = 0
    encrypted: bool = False   # TLS 1.2 : après ChangeCipherSpec


class TlsSession:
    """État de déchiffrement d'une connexion ; alimenté côté client et serveur."""

    def __init__(self, keylog: KeyLog):
        self.keylog = keylog
        self.client_random: str | None = None
        self.server_random: str | None = None
        self.version = 0
        self.suite: Suite | None = None
        self.cipher = 0
        self.sides = {True: _Direction(), False: _Direction()}

    @property
    def description(self) -> str:
        return f"{_core.tls_version_name(self.version)} · TLS_{self.suite.name if self.suite else '?'}"

    def feed(self, is_client: bool, data: bytes) -> bytes:
        side = self.sides[is_client]
        side.buffer += data
        plaintext = []
        while len(side.buffer) >= 5:
            length = int.from_bytes(side.buffer[3:5], "big")
            if len(side.buffer) < 5 + length:
                break
            record, side.buffer = side.buffer[:5 + length], side.buffer[5 + length:]
            plaintext.append(self._record(is_client, side, record))
        return b"".join(plaintext)

    def _record(self, is_client: bool, side: _Direction, record: bytes) -> bytes:
        content_type = record[0]
        if content_type == HANDSHAKE and not side.encrypted:
            self._learn_hello(is_client, record)
            return b""
        if content_type == CHANGE_CIPHER_SPEC:
            if self.version != TLS13:
                side.encrypted, side.seq = True, 0
            return b""
        if content_type == APPLICATION_DATA or side.encrypted:
            inner_type, plain = self._decrypt(is_client, side, record)
            return plain if inner_type == APPLICATION_DATA else b""
        return b""

    def _learn_hello(self, is_client: bool, record: bytes) -> None:
        try:
            if is_client and self.client_random is None:
                hello = _core.parse_client_hello(record)
                self.client_random = hello.random if hello else None
            elif not is_client and self.server_random is None:
                hello = _core.parse_server_hello(record)
                if hello:
                    self.server_random, self.version, self.cipher = hello.random, hello.version, hello.cipher
                    self.suite = SUITES.get(hello.cipher)
        except ValueError:
            pass

    # ---------------------------------------------------------------- clés

    def _ensure_keys(self, is_client: bool, side: _Direction) -> None:
        if side.keys:
            return
        if self.client_random is None or self.server_random is None:
            raise DecryptError("ClientHello ou ServerHello absent de la capture")
        if self.suite is None:
            raise DecryptError(f"Suite 0x{self.cipher:04x} non prise en charge (AEAD uniquement)")
        side.keys = self._tls13_keys(is_client) if self.version == TLS13 else self._tls12_keys(is_client)
        if not side.keys:
            raise DecryptError("Secrets de cette session absents du keylog")

    def _tls13_keys(self, is_client: bool) -> list[tuple[object, bytes]]:
        role = "CLIENT" if is_client else "SERVER"
        keys = []
        for label in (f"{role}_HANDSHAKE_TRAFFIC_SECRET", f"{role}_TRAFFIC_SECRET_0"):
            secret = self.keylog.get(label, self.client_random)
            if secret is not None:
                key = _hkdf_expand_label(secret, b"key", self.suite.key_len, self.suite.sha384)
                iv = _hkdf_expand_label(secret, b"iv", 12, self.suite.sha384)
                keys.append((self.suite.aead(key), iv))
        return keys

    def _tls12_keys(self, is_client: bool) -> list[tuple[object, bytes]]:
        master = self.keylog.get("CLIENT_RANDOM", self.client_random)
        if master is None:
            return []
        key_len = self.suite.key_len
        iv_len = 12 if self.suite.aead is ChaCha20Poly1305 else 4
        block = _prf(master, b"key expansion", bytes.fromhex(self.server_random + self.client_random),
                     2 * (key_len + iv_len), self.suite.hash_name)
        client_key, server_key = block[:key_len], block[key_len:2 * key_len]
        client_iv, server_iv = block[2 * key_len:2 * key_len + iv_len], block[2 * key_len + iv_len:]
        return [(self.suite.aead(client_key if is_client else server_key), client_iv if is_client else server_iv)]

    # ---------------------------------------------------------------- AEAD

    def _decrypt(self, is_client: bool, side: _Direction, record: bytes) -> tuple[int, bytes]:
        self._ensure_keys(is_client, side)
        if self.version == TLS13:
            return self._decrypt13(side, record)
        return self._decrypt12(side, record)

    @staticmethod
    def _decrypt13(side: _Direction, record: bytes) -> tuple[int, bytes]:
        header, body = record[:5], record[5:]
        # Bascule automatique de l'époque handshake vers l'époque applicative.
        for epoch in range(side.epoch, len(side.keys)):
            seq = side.seq if epoch == side.epoch else 0
            aead, iv = side.keys[epoch]
            try:
                inner = aead.decrypt(_xor_nonce(iv, seq), body, header).rstrip(b"\x00")
            except InvalidTag:
                continue
            side.epoch, side.seq = epoch, seq + 1
            return inner[-1], inner[:-1]
        raise DecryptError("Échec d'authentification AEAD (clé ou séquence incorrecte)")

    def _decrypt12(self, side: _Direction, record: bytes) -> tuple[int, bytes]:
        content_type, version, body = record[0], record[1:3], record[5:]
        aead, iv = side.keys[0]
        if self.suite.aead is ChaCha20Poly1305:
            nonce, ciphertext = _xor_nonce(iv, side.seq), body
        else:
            nonce, ciphertext = iv + body[:8], body[8:]
        aad = side.seq.to_bytes(8, "big") + bytes([content_type]) + version + (len(ciphertext) - 16).to_bytes(2, "big")
        try:
            plain = aead.decrypt(nonce, ciphertext, aad)
        except InvalidTag as exc:
            raise DecryptError("Échec d'authentification AEAD (clé ou séquence incorrecte)") from exc
        side.seq += 1
        return content_type, plain


def decrypt_conversation(chunks: list[tuple[bool, bytes]], keylog: KeyLog) -> tuple[list[tuple[bool, bytes]] | None, str]:
    """Déchiffre une conversation reconstituée. Retourne (texte clair ou None, note)."""
    session = TlsSession(keylog)
    plaintext: list[tuple[bool, bytes]] = []
    try:
        for is_client, data in chunks:
            clear = session.feed(is_client, data)
            if not clear:
                continue
            if plaintext and plaintext[-1][0] == is_client:
                plaintext[-1] = (is_client, plaintext[-1][1] + clear)
            else:
                plaintext.append((is_client, clear))
    except DecryptError as exc:
        return (plaintext or None), f"Déchiffrement {'partiel' if plaintext else 'impossible'} : {exc}"
    if session.client_random is None:
        return None, "Pas de handshake TLS dans les paquets conservés"
    return plaintext, f"Déchiffré · {session.description}"
