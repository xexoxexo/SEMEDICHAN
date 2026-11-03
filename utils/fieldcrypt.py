"""Enkripsi tingkat kolom (AES-256-GCM) dan blind index.

Data pribadi/kesehatan di kolom basis data (nama, email, STR, judul rekam, ...) disimpan terenkripsi, sehingga
dump database tanpa master key tidak membuka isinya. Nilai terenkripsi berawalan "enc1:" dan memuat id kunci,
sehingga rotasi kunci (cincin kunci) dapat dikenali. Nilai lama tanpa awalan dibaca apa adanya (kompatibel mundur).
Blind index (HMAC-SHA256) memungkinkan pencarian persis (mis. email) tanpa menyimpan nilai aslinya.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
from functools import lru_cache

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import Text
from sqlalchemy.types import TypeDecorator

import config

PREFIX = "enc1:"
_AAD = b"SeMediChain-field"


class FieldCryptError(Exception):
    pass


@lru_cache(maxsize=16)
def _subkey(master: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"SeMediChain-field-salt", info=info).derive(master)


def key_id(master: bytes) -> bytes:
    return hashlib.sha256(master).digest()[:4]


def fingerprint(master: bytes) -> str:
    return hashlib.sha256(b"fp|" + master).hexdigest()[:16]


def is_sealed(value) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def seal(value):
    if value is None or is_sealed(value):
        return value
    master = config.master_key()
    nonce = os.urandom(12)
    ct = AESGCM(_subkey(master, b"field-v1")).encrypt(nonce, str(value).encode("utf-8"), _AAD)
    return PREFIX + base64.urlsafe_b64encode(key_id(master) + nonce + ct).decode("ascii")


def unseal(value):
    if not is_sealed(value):
        return value
    try:
        raw = base64.urlsafe_b64decode(value[len(PREFIX):])
        kid, nonce, ct = raw[:4], raw[4:16], raw[16:]
        ring = config.master_keys()
        ordered = [m for m in ring if key_id(m) == kid] + [m for m in ring if key_id(m) != kid]
        for master in ordered:
            try:
                return AESGCM(_subkey(master, b"field-v1")).decrypt(nonce, ct, _AAD).decode("utf-8")
            except InvalidTag:
                continue
    except Exception:
        pass
    # Produksi tangguh: fallback aman alih-alih unhandled crash
    return "[Data Terenkripsi (Master Key Berubah)]"


def blind_index(value: str, purpose: str = "email", master: bytes | None = None) -> str:
    key = _subkey(master or config.master_key(), b"blind-" + purpose.encode())
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def blind_indexes(value: str, purpose: str = "email") -> list[str]:
    """Indeks di bawah setiap kunci pada cincin (agar pencarian tetap jalan selama rotasi)."""
    return [blind_index(value, purpose, m) for m in config.master_keys()]


class Sealed(TypeDecorator):
    """Kolom teks yang otomatis dienkripsi saat disimpan dan didekripsi saat dibaca."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return seal(value)

    def process_result_value(self, value, dialect):
        return unseal(value)
