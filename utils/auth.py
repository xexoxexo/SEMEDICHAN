"""Autentikasi email + password: validasi, hashing scrypt, dan kebijakan kunci akun."""
from __future__ import annotations

import hashlib
import hmac
import os
import re
from functools import lru_cache

import config

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}$")
GMAIL_DOMAINS = {"gmail.com", "googlemail.com"}
MAX_FAILED = 5          # percobaan gagal berturut-turut sebelum akun dikunci sementara
LOCK_SECONDS = 300
_N, _R, _P = 2**14, 8, 1  # parameter scrypt (16 MB memori)


# --------------------------------------------------------------------------- email
def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def canonical_email(email: str) -> str:
    """Bentuk kanonik untuk keunikan: Gmail mengabaikan titik dan +alias (a.b+x@gmail.com == ab@gmail.com)."""
    local, _, domain = normalize_email(email).partition("@")
    if domain in GMAIL_DOMAINS:
        local, domain = local.split("+", 1)[0].replace(".", ""), "gmail.com"
    return f"{local}@{domain}"


def validate_email(email: str) -> str | None:
    e = normalize_email(email)
    if len(e) > 254 or not EMAIL_RE.match(e):
        return "Format email tidak valid."
    allowed = config.ALLOWED_EMAIL_DOMAINS
    if allowed and e.rsplit("@", 1)[1] not in allowed:
        return "Gunakan alamat Gmail (berakhiran @gmail.com)." if allowed <= GMAIL_DOMAINS else (
            "Email harus berakhiran: " + ", ".join("@" + d for d in sorted(allowed)) + "."
        )
    return None


def admin_email_keys() -> set[str]:
    return {canonical_email(e) for e in config.ADMIN_EMAILS}


# --------------------------------------------------------------------------- password
COMMON_PASSWORDS = {
    "password", "password1", "password123", "passw0rd", "qwerty123", "qwertyuiop", "12345678", "123456789",
    "1234567890", "iloveyou1", "admin123", "admin1234", "welcome1", "welcome123", "letmein123", "abc12345",
    "abcd1234", "11111111", "00000000", "kataSandi1".lower(), "katasandi123", "indonesia1", "indonesia123",
    "rahasia123", "sayangku123", "bismillah123", "bismillah1", "sandi12345", "passwordku1", "gantipassword1",
}


def validate_password(password: str, email: str | None = None) -> str | None:
    if len(password) < 8:
        return "Password minimal 8 karakter."
    if len(password) > 128:
        return "Password maksimal 128 karakter."
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return "Password harus memuat huruf dan angka."
    low = password.lower()
    if low in COMMON_PASSWORDS or len(set(low)) <= 3:
        return "Password terlalu umum atau mudah ditebak."
    local = normalize_email(email or "").split("@")[0].replace(".", "")
    if len(local) >= 4 and local in low.replace(".", ""):
        return "Password tidak boleh memuat nama email Anda."
    return None


def validate_license(license_no: str) -> str | None:
    """Format dasar nomor STR (verifikasi keaslian tetap oleh admin ke sumber resmi)."""
    value = (license_no or "").strip()
    if not value:
        return "Dokter wajib mengisi nomor STR."
    if not re.fullmatch(r"[A-Za-z0-9./\- ]{6,40}", value):
        return "Format nomor STR tidak valid (6-40 karakter huruf, angka, titik, garis)."
    return None


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, expected = stored.split("$")
        dk = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p),
                            dklen=len(expected) // 2)
        return hmac.compare_digest(dk.hex(), expected)
    except (ValueError, TypeError):
        return False


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    return hash_password("dummy-password-1")


def dummy_verify(password: str) -> None:
    """Samakan waktu respons saat email tidak dikenal (mencegah enumerasi akun lewat selisih waktu)."""
    verify_password(password, _dummy_hash())
