"""Konfigurasi aplikasi StegoMed-Web3 (dibaca dari environment / file .env).

APP_ENV=development (bawaan) memudahkan uji lokal. APP_ENV=production mengaktifkan pemeriksaan ketat:
aplikasi menolak start bila pengaturan tidak aman (lihat production_problems()).
"""
from __future__ import annotations

import hashlib
import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def _flag(name: str, default: str) -> bool:
    return (os.getenv(name) or default).strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: str) -> int:
    return int(os.getenv(name) or default)


def _csv(name: str, default: str = "") -> set[str]:
    return {x.strip().lower() for x in (os.getenv(name) or default).split(",") if x.strip()}


APP_ENV = (os.getenv("APP_ENV") or "development").strip().lower()
IS_PROD = APP_ENV == "production"

DATA_DIR = Path(os.getenv("DATA_DIR") or (BASE_DIR / "data"))
STEGO_DIR = DATA_DIR / "stego"
DATABASE_URL = os.getenv("DATABASE_URL") or f"sqlite:///{(DATA_DIR / 'stegomed.db').as_posix()}"
ALLOW_SQLITE_IN_PRODUCTION = _flag("ALLOW_SQLITE_IN_PRODUCTION", "0")

APP_DOMAIN = os.getenv("APP_DOMAIN") or "localhost:8501"
APP_URI = os.getenv("APP_URI") or "http://localhost:8501"
CHAIN_ID = _int("CHAIN_ID", "1")
NONCE_TTL_SECONDS = 300

# Bawaan aman di produksi, nyaman di pengembangan.
ALLOW_DEV_WALLET = _flag("ALLOW_DEV_WALLET", "0" if IS_PROD else "1")
AUTO_APPROVE_DOCTORS = _flag("AUTO_APPROVE_DOCTORS", "0" if IS_PROD else "1")
REQUIRE_EMAIL_VERIFICATION = _flag("REQUIRE_EMAIL_VERIFICATION", "1" if IS_PROD else "0")
REQUIRE_MFA_ROLES = _csv("REQUIRE_MFA_ROLES", "admin,doctor" if IS_PROD else "")
ENABLE_LAB = _flag("ENABLE_LAB", "0" if IS_PROD else "1")

ADMIN_EMAILS = _csv("ADMIN_EMAILS")
_domains = (os.getenv("ALLOWED_EMAIL_DOMAINS") or "gmail.com,googlemail.com").strip().lower()
ALLOWED_EMAIL_DOMAINS = set() if _domains == "*" else {d.strip() for d in _domains.split(",") if d.strip()}

PRIVACY_VERSION = os.getenv("PRIVACY_VERSION") or "2026-10-v1"   # naikkan saat pemberitahuan privasi berubah
STEGO_UNLOCK_MINUTES = _int("STEGO_UNLOCK_MINUTES", "30")
SESSION_IDLE_MINUTES = _int("SESSION_IDLE_MINUTES", "20" if IS_PROD else "120")
SESSION_MAX_HOURS = _int("SESSION_MAX_HOURS", "8")
MAX_COVER_PIXELS = _int("MAX_COVER_PIXELS", "16000000")

# Email (OTP verifikasi & reset password). Di pengembangan, kode ditampilkan di layar (backend "console").
MAIL_BACKEND = (os.getenv("MAIL_BACKEND") or ("smtp" if IS_PROD else "console")).strip().lower()
SMTP_HOST = os.getenv("SMTP_HOST") or ""
SMTP_PORT = _int("SMTP_PORT", "587")
SMTP_USER = os.getenv("SMTP_USER") or ""
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD") or ""
SMTP_FROM = os.getenv("SMTP_FROM") or SMTP_USER
SMTP_STARTTLS = _flag("SMTP_STARTTLS", "1")
OTP_TTL_SECONDS = 600
OTP_MAX_ATTEMPTS = 5

# Pembatas laju. IP klien hanya dipercaya dari X-Forwarded-For bila di belakang reverse proxy tepercaya.
TRUST_PROXY_HEADERS = _flag("TRUST_PROXY_HEADERS", "0")
RATE_LOGIN_PER_IP = _int("RATE_LOGIN_PER_IP", "30")            # per 10 menit
RATE_REGISTER_PER_IP = _int("RATE_REGISTER_PER_IP", "10")      # per jam
RATE_OTP_PER_EMAIL = _int("RATE_OTP_PER_EMAIL", "5")           # per jam


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    STEGO_DIR.mkdir(parents=True, exist_ok=True)


def _derive(raw: str) -> bytes:
    return hashlib.sha256(raw.encode("utf-8")).digest()


def master_key() -> bytes:
    """Master key aktif (32 byte). Dari MEDICRYPT_MASTER_KEY, atau (hanya pengembangan) file data/.master_key."""
    env = os.getenv("MEDICRYPT_MASTER_KEY")
    if env:
        return _derive(env)
    ensure_dirs()
    path = DATA_DIR / ".master_key"
    if not path.exists():
        path.write_bytes(secrets.token_bytes(32))
        try:
            path.chmod(0o600)
        except OSError:
            pass
    return path.read_bytes()


def master_keys() -> list[bytes]:
    """Cincin kunci: aktif lebih dulu, lalu kunci lama (MEDICRYPT_MASTER_KEY_OLD, pisah koma) selama rotasi."""
    keys = [master_key()]
    for raw in (os.getenv("MEDICRYPT_MASTER_KEY_OLD") or "").split(","):
        if raw.strip():
            keys.append(_derive(raw.strip()))
    return keys


def production_problems() -> list[str]:
    """Daftar pengaturan yang tidak boleh ada di produksi. Kosong = lolos (atau bukan produksi)."""
    if not IS_PROD:
        return []
    p: list[str] = []
    raw = os.getenv("MEDICRYPT_MASTER_KEY") or ""
    if ALLOW_DEV_WALLET:
        p.append("ALLOW_DEV_WALLET harus 0 (dompet demo tidak boleh aktif).")
    if AUTO_APPROVE_DOCTORS:
        p.append("AUTO_APPROVE_DOCTORS harus 0 (dokter wajib diverifikasi admin).")
    if len(raw) < 32:
        p.append("MEDICRYPT_MASTER_KEY wajib diisi minimal 32 karakter acak (jangan memakai file otomatis).")
    if DATABASE_URL.startswith("sqlite") and not ALLOW_SQLITE_IN_PRODUCTION:
        p.append("Gunakan PostgreSQL (DATABASE_URL), atau set ALLOW_SQLITE_IN_PRODUCTION=1 dengan sadar risikonya.")
    if not APP_URI.startswith("https://"):
        p.append("APP_URI harus https:// dan APP_DOMAIN sesuai domain publik.")
    if not ADMIN_EMAILS:
        p.append("ADMIN_EMAILS wajib diisi minimal satu admin.")
    if MAIL_BACKEND != "smtp" or not SMTP_HOST:
        p.append("MAIL_BACKEND=smtp dan SMTP_HOST wajib dikonfigurasi (OTP email).")
    if not REQUIRE_EMAIL_VERIFICATION:
        p.append("REQUIRE_EMAIL_VERIFICATION harus 1.")
    if not {"admin", "doctor"} <= REQUIRE_MFA_ROLES:
        p.append("REQUIRE_MFA_ROLES minimal harus memuat admin dan doctor.")
    return p
