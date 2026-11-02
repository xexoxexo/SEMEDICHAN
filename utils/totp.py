"""TOTP (RFC 6238, HMAC-SHA1) dan kode pemulihan, tanpa dependensi tambahan."""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import os
import secrets
import struct
import time
from urllib.parse import quote

ISSUER = "StegoMed-Web3"


def new_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def _key(secret: str) -> bytes:
    s = secret.strip().replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def code_at(secret: str, t: float, step: int = 30, digits: int = 6) -> str:
    digest = hmac.new(_key(secret), struct.pack(">Q", int(t // step)), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    num = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(num).zfill(digits)


def verify(secret: str, code: str, last_step: int = 0, now: float | None = None, window: int = 1, step: int = 30) -> int | None:
    """Return nomor langkah waktu yang cocok (untuk mencegah pemakaian ulang), atau None."""
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return None
    now = time.time() if now is None else now
    for delta in range(-window, window + 1):
        counter = int(now // step) + delta
        if counter > last_step and hmac.compare_digest(code_at(secret, counter * step), code):
            return counter
    return None


def provisioning_uri(secret: str, email: str) -> str:
    return f"otpauth://totp/{quote(ISSUER)}:{quote(email)}?secret={secret}&issuer={quote(ISSUER)}&algorithm=SHA1&digits=6&period=30"


def qr_png(uri: str) -> bytes | None:
    try:
        import qrcode
    except ImportError:
        return None
    buf = io.BytesIO()
    qrcode.make(uri).save(buf, format="PNG")
    return buf.getvalue()


def new_recovery_codes(n: int = 8) -> list[str]:
    return [f"{secrets.token_hex(4)}-{secrets.token_hex(4)}" for _ in range(n)]


def normalize_recovery(code: str) -> str:
    return (code or "").strip().lower().replace(" ", "")
