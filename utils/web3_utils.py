"""Utilitas Web3: pesan Sign-In with Ethereum (EIP-4361) & verifikasi tanda tangan.

Tanpa transaksi, tanpa gas fee, tanpa testnet/mainnet: hanya personal_sign off-chain.
"""
from __future__ import annotations

import hashlib
import re
import secrets
from datetime import datetime, timezone

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils.address import to_checksum_address

import config

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
STATEMENT = (
    "Masuk ke SeMediChain. Tanda tangan ini gratis (tanpa gas fee) dan tidak "
    "mengirim transaksi apa pun."
)


def is_valid_address(address: str) -> bool:
    return bool(address) and bool(ADDRESS_RE.match(address))


def short(address: str) -> str:
    return f"{address[:6]}…{address[-4:]}"


def new_nonce() -> str:
    return secrets.token_hex(16)


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


ADDRESS_TOKEN = "{{ADDRESS}}"


def siwe_template(nonce: str, issued_ts: float, expires_ts: float) -> str:
    """Pesan SIWE (EIP-4361) dengan placeholder alamat. Frontend mengisi alamat (EIP-55) setelah
    pengguna memilih akun, sehingga pesan bisa disiapkan server SEBELUM dompet terhubung."""
    return (
        f"{config.APP_DOMAIN} wants you to sign in with your Ethereum account:\n"
        f"{ADDRESS_TOKEN}\n\n"
        f"{STATEMENT}\n\n"
        f"URI: {config.APP_URI}\n"
        f"Version: 1\n"
        f"Chain ID: {config.CHAIN_ID}\n"
        f"Nonce: {nonce}\n"
        f"Issued At: {_iso(issued_ts)}\n"
        f"Expiration Time: {_iso(expires_ts)}"
    )


def build_siwe_message(address: str, nonce: str, issued_ts: float, expires_ts: float) -> str:
    return siwe_template(nonce, issued_ts, expires_ts).replace(ADDRESS_TOKEN, to_checksum_address(address))


def verify_signature(message: str, signature: str, address: str) -> bool:
    try:
        recovered = Account.recover_message(encode_defunct(text=message), signature=signature)
    except Exception:  # noqa: BLE001
        return False
    return recovered.lower() == address.lower()


# --------------------------------------------------------------------------- dompet demo (dev saja)
def dev_wallet(label: str):
    """Dompet deterministik untuk demo/uji; kuncinya diturunkan dari master key server."""
    seed = hashlib.sha256(config.master_key() + b"|dev-wallet|" + label.strip().lower().encode()).digest()
    return Account.from_key(seed)


def sign_with_dev_wallet(label: str, message: str) -> tuple[str, str]:
    acct = dev_wallet(label)
    sig = acct.sign_message(encode_defunct(text=message)).signature.hex()
    return acct.address.lower(), "0x" + sig.removeprefix("0x")
